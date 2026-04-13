# ─────────────────────────────────────────────────────────────
# ANSI colors (linPEAS style)
# ─────────────────────────────────────────────────────────────
R  = "\033[1;31m"   # red bold   — high interest / likely vuln
Y  = "\033[1;33m"   # yellow     — medium interest
G  = "\033[1;32m"   # green      — safe / expected
B  = "\033[1;34m"   # blue       — informational
C  = "\033[1;36m"   # cyan       — headers
M  = "\033[1;35m"   # magenta    — section titles
W  = "\033[1;37m"   # white bold
RS = "\033[0m"      # reset

ANSI_RE    = /\033\[[0-9;]*[mKJH]/
SEPARATOR  = "#{M}#{"═" * 60}#{RS}"

SENSITIVE_ENV_RE   = /(^|_)(pass|password|passwd|secret|token|key|api|cred|credential|auth|pwd|hash)(_|$)/i
BENIGN_ENV_NAMES   = Set{"PWD", "OLDPWD"}
INFO_ENV_KEYS      = %w[path home shell hist user]

INTERACTIVE_SHELLS = Set{
  "/bin/bash", "/bin/sh", "/bin/zsh", "/bin/fish",
  "/usr/bin/bash", "/usr/bin/zsh", "/usr/bin/fish",
}

MENU_RULE = "#{C}#{"─" * 56}#{RS}"

CRON_DIRS = %w[/etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron]

CRED_KEYWORDS   = %w[password passwd secret api_key apikey token auth_token credential]
CRED_EXTS       = %w[conf config cfg ini env php py rb xml yaml yml toml].map { |e| "--include=\"*.#{e}\"" }.join(" ")
CRED_JS_EXTS    = %w[js json].map { |e| "--include=\"*.#{e}\"" }.join(" ")
CRED_JS_DIRS    = %w[/var/www /srv /opt]
CRED_PATTERN    = "(#{CRED_KEYWORDS.join("|")})\\s*[=:]\\s*\\S+"
CRED_PATTERN_RE = /#{CRED_PATTERN}/i
CRED_CAPTURE_RE = /(#{CRED_KEYWORDS.join("|")})\s*[=:]\s*(\S+)/i

# Config placeholders and system defaults that look like credentials but aren't
CRED_SENTINELS = Set{"ask", "*", "none", "no", "yes", "true", "false", "null", "undefined",
                      "files", "systemd", "compat", "nis", "dns", "ldap"}
CRED_NOISE_RE  = /PublicKeyToken=|Version=.*Culture=|PDFPassword=%/i

LOCKED_HASH_MARKERS = Set{"*", "!", "!!", "x"}

PAM_CRED_RE = /\b(passwd|bindpw|ldap_bind_pw|secret|credentials)\s*=\s*\S+|^\s*bindpw\s+\S+/i
PAM_CRED_CONFIGS = %w[/etc/pam_ldap.conf /etc/ldap.conf /etc/ldap/ldap.conf /etc/pam_mysql.conf /etc/pam_pgsql.conf]

# ─────────────────────────────────────────────────────────────
# Hardcoded secret patterns — matched by format, not keyword
# ─────────────────────────────────────────────────────────────
SECRET_PATTERNS = [
  {name: "AWS access key",              re: /AKIA[0-9A-Z]{16}/,                                    severity: :hi},
  {name: "GCP service account",         re: /"type"\s*:\s*"service_account"/,                       severity: :hi},
  {name: "GitHub token",                re: /ghp_[A-Za-z0-9]{36}/,                                 severity: :hi},
  {name: "GitHub token (fine-grained)", re: /github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}/,          severity: :hi},
  {name: "GitLab token",               re: /glpat-[A-Za-z0-9\-]{20}/,                             severity: :hi},
  {name: "Slack token",                re: /xox[bpors]-[0-9]{10,13}-[A-Za-z0-9\-]+/,              severity: :hi},
  {name: "Embedded private key",        re: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/, severity: :med},
]

SECRET_GREP_PRE  = "AKIA[0-9A-Z]|\"service_account\"|ghp_[A-Za-z0-9]|github_pat_|glpat-|xox[bpors]-|BEGIN.*PRIVATE KEY"
SECRET_SCAN_EXTS = %w[conf config cfg ini env php py rb xml yaml yml toml json sh js].map { |e| "--include=\"*.#{e}\"" }.join(" ")

RSERVICE_PORTS  = {"0200" => 512, "0201" => 513, "0202" => 514}
RSERVICE_RE     = /\b(shell|login|exec|rsh|rlogin|rexec)\b/i

CONFIG_NAMES = %w[wp-config.php configuration.php config.php .env database.yml settings.py
  application.properties web.config jdbc.properties hibernate.cfg.xml
  tomcat-users.xml credentials.xml]
CONFIG_PREDICATES = CONFIG_NAMES.map { |c| "-name '#{c}'" }.join(" -o ")

# Directory prefixes where SUID binaries are expected from package managers.
# SUIDs outside these trees are candidates for deeper analysis.
STANDARD_SUID_PREFIXES = {"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
                          "/usr/lib/", "/usr/lib64/", "/usr/libexec/"}

# Short words that appear in strings output as C symbols, not command names
STRINGS_NOISE = Set{"file", "free", "main", "more", "read", "split", "write"}

# Standard library search directories for NEEDED .so resolution
LIB_SEARCH_DIRS = ["/lib", "/usr/lib", "/lib64", "/usr/lib64",
                   "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
                   "/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu"]

SUID_CMD_RE = /\A[a-zA-Z][a-zA-Z0-9_-]*\z/

# ─────────────────────────────────────────────────────────────
# GTFOBins — common SUID/SGID escalation binaries
# ─────────────────────────────────────────────────────────────
GTFOBINS = Set{
  "bash", "sh", "dash", "zsh", "ksh", "tcsh", "csh", "fish",
  "python", "python2", "python2.7", "python3",
  "python3.6", "python3.7", "python3.8", "python3.9", "python3.10", "python3.11", "python3.12",
  "perl", "perl5", "ruby", "lua", "lua5.1", "lua5.2", "lua5.3", "lua5.4", "php",
  "node", "nodejs", "java", "jjs", "jrunscript",
  "nmap", "vim", "vim.basic", "vi", "less", "more", "man",
  "awk", "gawk", "mawk", "nawk",
  "find", "cp", "mv", "tee", "dd", "cat", "head", "tail", "cut", "sort", "uniq",
  "env", "time", "watch", "nice", "ionice", "timeout", "xargs", "printf",
  "git", "tar", "zip", "unzip", "gzip", "bzip2", "7z", "ar", "cpio",
  "curl", "wget", "nc", "netcat", "ncat", "socat", "tftp", "ftp",
  "strace", "ltrace", "gdb", "objdump", "readelf",
  "screen", "tmux",
  "base64", "base32", "xxd", "od", "hexdump", "openssl",
  "ssh", "scp", "rsync", "sftp",
  "sed", "make", "gcc", "as",
  "mount", "umount",
  "pkexec", "sudo", "su", "doas", "newgrp", "sg",
  "passwd", "chpasswd",
  "chmod", "chown", "chattr", "install", "setcap",
  "docker", "lxc", "lxd", "runc", "podman",
  "systemctl", "service", "journalctl",
  "apt", "apt-get", "yum", "dnf", "pip", "pip3", "gem", "npm", "composer",
  "mysql", "psql", "sqlite3", "mongo",
  "arp", "ip", "ifconfig", "tcpdump",
  "crontab", "at", "batch",
  "mail", "sendmail", "mutt",
  "ld.so", "ldconfig",
  "pdb", "irb", "julia", "tclsh", "wish", "expect",
  "cpan", "cpanm", "bundler",
  "flock", "stdbuf", "logsave",
  "emacs", "nano", "pico", "ed", "ex",
  "taskset", "chroot", "capsh",
  "msgfmt", "msgmerge", "cobc",
}

DANGEROUS_CAPS = {
  "cap_setuid"           => "can set UID → trivial root",
  "cap_setgid"           => "can set GID → trivial root",
  "cap_sys_admin"        => "near-root, many escalation paths",
  "cap_sys_ptrace"       => "ptrace processes → shellcode injection",
  "cap_dac_override"     => "bypass file permission checks",
  "cap_dac_read_search"  => "read any file → /etc/shadow",
  "cap_net_raw"          => "raw sockets → packet sniffing",
  "cap_sys_module"       => "load kernel modules → root",
  "cap_sys_rawio"        => "raw I/O device access",
  "cap_sys_chroot"       => "chroot() → may escape jail",
  "cap_mknod"            => "create device files",
  "cap_chown"            => "change file ownership arbitrarily",
  "cap_fowner"           => "bypass ownership permission checks",
  "cap_net_bind_service" => "bind to privileged ports (<1024)",
  "cap_kill"             => "signal any process → DoS or race conditions",
  "cap_net_admin"        => "network config → ARP spoofing, route injection",
  "cap_bpf"              => "eBPF programs → kernel memory read/write",
  "cap_perfmon"          => "perf subsystem → kernel address leak",
  "cap_setpcap"          => "modify process capabilities → grant caps to self",
  "cap_setfcap"          => "set file capabilities → grant caps to any binary",
  "cap_fsetid"           => "preserve SUID/SGID on file modification",
}

# ─────────────────────────────────────────────────────────────
# Capability bit positions (linux/capability.h, stable ABI)
# Used for native hex→cap decoding without capsh dependency
# ─────────────────────────────────────────────────────────────
CAP_BITS = {
   0_u8 => "cap_chown",
   1_u8 => "cap_dac_override",
   2_u8 => "cap_dac_read_search",
   3_u8 => "cap_fowner",
   4_u8 => "cap_fsetid",
   5_u8 => "cap_kill",
   6_u8 => "cap_setgid",
   7_u8 => "cap_setuid",
   8_u8 => "cap_setpcap",
   9_u8 => "cap_linux_immutable",
  10_u8 => "cap_net_bind_service",
  11_u8 => "cap_net_broadcast",
  12_u8 => "cap_net_admin",
  13_u8 => "cap_net_raw",
  14_u8 => "cap_ipc_lock",
  15_u8 => "cap_ipc_owner",
  16_u8 => "cap_sys_module",
  17_u8 => "cap_sys_rawio",
  18_u8 => "cap_sys_chroot",
  19_u8 => "cap_sys_ptrace",
  20_u8 => "cap_sys_pacct",
  21_u8 => "cap_sys_admin",
  22_u8 => "cap_sys_boot",
  23_u8 => "cap_sys_nice",
  24_u8 => "cap_sys_resource",
  25_u8 => "cap_sys_time",
  26_u8 => "cap_sys_tty_config",
  27_u8 => "cap_mknod",
  28_u8 => "cap_lease",
  29_u8 => "cap_audit_write",
  30_u8 => "cap_audit_control",
  31_u8 => "cap_setfcap",
  32_u8 => "cap_mac_override",
  33_u8 => "cap_mac_admin",
  34_u8 => "cap_syslog",
  35_u8 => "cap_wake_alarm",
  36_u8 => "cap_block_suspend",
  37_u8 => "cap_audit_read",
  38_u8 => "cap_perfmon",
  39_u8 => "cap_bpf",
  40_u8 => "cap_checkpoint_restore",
}

# Caps that warrant hi() when found in a process CapEff/CapAmb —
# direct root or equivalent without additional steps
HI_CAPS = Set{
  "cap_setuid", "cap_setgid", "cap_sys_admin", "cap_sys_ptrace",
  "cap_sys_module", "cap_dac_override", "cap_dac_read_search",
  "cap_sys_rawio", "cap_bpf",
}

# Chromium/Electron processes — cap_sys_admin from user namespace sandboxing
CHROMIUM_SANDBOX_NAMES = Set{
  "brave", "chrome", "chromium", "electron",
  "Discord", "obsidian", "signal-desktop",
  "WeChatAppEx", "slack", "code", "codium",
  "spotify", "teams", "skypeforlinux",
}

SUID_HELPER_NAMES = Set{"fusermount3", "fusermount"}

# Standard SUID binaries shipped on every distro — demoted to med()
DEFAULT_SUID_BINS = Set{
  "su", "sudo", "mount", "umount", "pkexec",
  "newgrp", "passwd", "chpasswd", "crontab",
}

KNOWN_DAEMON_CAPS = {
  "rtkit-daemon" => Set{"cap_dac_read_search", "cap_sys_nice"},
}

# ─────────────────────────────────────────────────────────────
# Kernel CVE registry — data-driven, NVD-verified
# Two-stage detection: distro fixed version (authoritative when
# available) with upstream version range as fallback.
# fixed_versions: minimum patched package version per distro release,
#   keyed as "distro_version" (e.g. "ubuntu_16.04", "rhel_7").
#   Compared via dpkg_ver_compare or rpm_ver_compare.
#   nil = no distro-aware data, upstream check only.
# check: upstream version range proc, fallback when no fixed version matches.
# Severity: :hi = reliable public PoC, :med = theoretical/partial
# ─────────────────────────────────────────────────────────────
KERNEL_CVES = [
  {
    cve:      "CVE-2016-5195",
    name:     "DirtyCow",
    ref:      "https://nvd.nist.gov/vuln/detail/CVE-2016-5195",
    severity: :hi,
    distro_gate: nil,
    fixed_versions: {
      "debian_8"     => "3.16.36-1+deb8u2",
      "ubuntu_14.04" => "3.13.0-100.147",
      "ubuntu_16.04" => "4.4.0-45.66",
      "rhel_6"       => "2.6.32-642.6.2.el6",
      "rhel_7"       => "3.10.0-327.36.3.el7",
    } of String => String,
    check: ->(maj : Int32, mn : Int32, pat : Int32) {
      # Kernels 2.6.22 through 4.8.2 (fixed in 4.8.3)
      (maj > 2 || (maj == 2 && (mn > 6 || (mn == 6 && pat >= 22)))) &&
        (maj < 4 || (maj == 4 && (mn < 8 || (mn == 8 && pat < 3))))
    },
  },
  {
    cve:      "CVE-2021-3490",
    name:     "eBPF ALU32 bounds tracking",
    ref:      "https://nvd.nist.gov/vuln/detail/CVE-2021-3490",
    severity: :med,
    distro_gate: nil,
    fixed_versions: {
      "debian_11"    => "5.10.251-1",
      "ubuntu_20.04" => "5.8.0-53.60~20.04.1",
      "ubuntu_20.10" => "5.8.0-53.60",
      "ubuntu_21.04" => "5.11.0-17.18",
    } of String => String,
    check: ->(maj : Int32, mn : Int32, pat : Int32) {
      # Introduced in 5.7, per-branch fixes from NVD:
      #   5.7/5.8/5.9 EOL — never patched
      #   5.10 LTS fixed at .37 | 5.11 fixed at .21 | 5.12 fixed at .4
      return false unless maj == 5 && mn >= 7 && mn <= 12
      case mn
      when 7, 8, 9 then true
      when 10       then pat < 37
      when 11       then pat < 21
      when 12       then pat < 4
      else               false
      end
    },
  },
  {
    cve:      "CVE-2022-0847",
    name:     "Dirty Pipe",
    ref:      "https://nvd.nist.gov/vuln/detail/CVE-2022-0847",
    severity: :hi,
    distro_gate: nil,
    fixed_versions: {
      "debian_11"    => "5.10.92-2",
      "ubuntu_20.04" => "5.13.0-35.40~20.04.1",
      "ubuntu_21.10" => "5.13.0-35.40",
      "rhel_8"       => "4.18.0-348.20.1.el8_5",
    } of String => String,
    check: ->(maj : Int32, mn : Int32, pat : Int32) {
      # Per-branch fix versions from NVD:
      #   5.10 LTS fixed at .102 | 5.15 LTS fixed at .25 | mainline fixed at 5.16.11
      #   5.8/5.9/5.11–5.14 EOL — never patched
      return false unless maj == 5 && mn >= 8
      case mn
      when 8, 9           then true
      when 10             then pat < 102
      when 11, 12, 13, 14 then true
      when 15             then pat < 25
      when 16             then pat < 11
      else                     false
      end
    },
  },
  {
    cve:      "CVE-2023-0386",
    name:     "OverlayFS FUSE SUID copy-up",
    ref:      "https://nvd.nist.gov/vuln/detail/CVE-2023-0386",
    severity: :hi,
    distro_gate: nil,
    fixed_versions: {
      "debian_11"    => "5.10.251-1",
      "debian_12"    => "6.1.164-1",
      "ubuntu_20.04" => "5.15.0-70.77~20.04.1",
      "ubuntu_22.04" => "5.15.0-70.77",
      "rhel_8"       => "4.18.0-425.19.2.el8_7",
      "rhel_9"       => "5.14.0-70.53.1.el9_0",
    } of String => String,
    check: ->(maj : Int32, mn : Int32, pat : Int32) {
      # 5.11 through 6.1.x (fixed in 6.2-rc6)
      # 5.11–5.19 EOL — never patched upstream
      (maj == 5 && mn >= 11) || (maj == 6 && mn <= 1)
    },
  },
  {
    cve:      "CVE-2023-35001",
    name:     "nf_tables OOB read/write",
    ref:      "https://nvd.nist.gov/vuln/detail/CVE-2023-35001",
    severity: :hi,
    distro_gate: nil,
    fixed_versions: {
      "debian_11"    => "5.10.251-1",
      "debian_12"    => "6.1.164-1",
      "ubuntu_20.04" => "5.4.0-155.172",
      "ubuntu_22.04" => "5.15.0-78.85",
      "rhel_8"       => "4.18.0-477.27.1.el8_8",
      "rhel_9"       => "5.14.0-284.30.1.el9_2",
    } of String => String,
    check: ->(maj : Int32, mn : Int32, pat : Int32) {
      # Four disjoint ranges per NVD: 3.13–4.14, 4.20–5.4, 5.5–5.10, 5.16–6.1
      return false if maj < 3 || (maj == 3 && mn < 13)
      return false if maj == 4 && mn >= 15 && mn <= 19
      return false if maj == 5 && mn >= 11 && mn <= 15
      return false if maj > 6 || (maj == 6 && mn >= 2)
      case {maj, mn}
      when {4, 14}  then pat < 322
      when {5, 4}   then pat < 251
      when {5, 10}  then pat < 188
      when {6, 1}   then pat < 39
      else               true
      end
    },
  },
  {
    cve:      "CVE-2024-1086",
    name:     "nf_tables use-after-free",
    ref:      "https://nvd.nist.gov/vuln/detail/CVE-2024-1086",
    severity: :hi,
    distro_gate: nil,
    fixed_versions: {
      "debian_11"    => "5.10.251-1",
      "debian_12"    => "6.1.164-1",
      "ubuntu_20.04" => "5.4.0-174.193",
      "ubuntu_22.04" => "5.15.0-101.111",
      "rhel_8"       => "4.18.0-513.24.1.el8_9",
      "rhel_9"       => "5.14.0-427.13.1.el9_4",
    } of String => String,
    check: ->(maj : Int32, mn : Int32, pat : Int32) {
      # 3.15 through 6.7 — fixed in 6.8-rc2, stable backports: 5.15.149, 6.1.76, 6.6.15
      return false if maj < 3 || (maj == 3 && mn < 15)
      return false if maj > 6 || (maj == 6 && mn >= 8)
      case {maj, mn}
      when {5, 15} then pat < 149
      when {6, 1}  then pat < 76
      when {6, 6}  then pat < 15
      else              true
      end
    },
  },
  {
    cve:      "CVE-2023-32629",
    name:     "GameOverlay ovl_copy_up",
    ref:      "https://nvd.nist.gov/vuln/detail/CVE-2023-32629",
    severity: :hi,
    distro_gate: "ubuntu",
    fixed_versions: {
      "ubuntu_20.04" => "5.4.0-155.172",
      "ubuntu_22.04" => "5.19.0-50.50",
    } of String => String,
    check: ->(maj : Int32, mn : Int32, pat : Int32) {
      false # Ubuntu-patched OverlayFS only — distro version comparison handles detection
    },
  },
  {
    cve:      "CVE-2023-2640",
    name:     "GameOverlay ovl_setxattr",
    ref:      "https://nvd.nist.gov/vuln/detail/CVE-2023-2640",
    severity: :hi,
    distro_gate: "ubuntu",
    fixed_versions: {
      "ubuntu_22.04" => "6.2.0-26.26~22.04.1",
    } of String => String,
    check: ->(maj : Int32, mn : Int32, pat : Int32) {
      false # same — Ubuntu HWE 6.2 only
    },
  },
  {
    cve:      "CVE-2018-18955",
    name:     "User namespace ID map bypass",
    ref:      "https://nvd.nist.gov/vuln/detail/CVE-2018-18955",
    severity: :hi,
    distro_gate: nil,
    fixed_versions: {
      "ubuntu_18.04" => "4.15.0-42.45",
    } of String => String,
    check: ->(maj : Int32, mn : Int32, pat : Int32) {
      # NVD: 4.15 through 4.19.1 (fixed in 4.19.2)
      maj == 4 && ((mn >= 15 && mn <= 18) || (mn == 19 && pat < 2))
    },
  },
  {
    cve:      "CVE-2019-13272",
    name:     "PTRACE_TRACEME credential handling",
    ref:      "https://nvd.nist.gov/vuln/detail/CVE-2019-13272",
    severity: :hi,
    distro_gate: nil,
    fixed_versions: {
      "debian_9"     => "4.9.168-1+deb9u4",
      "debian_10"    => "4.19.37-5+deb10u1",
      "ubuntu_16.04" => "4.4.0-159.187",
      "ubuntu_18.04" => "4.15.0-58.64",
      "rhel_8"       => "4.18.0-80.7.2.el8_0",
    } of String => String,
    check: ->(maj : Int32, mn : Int32, pat : Int32) {
      # NVD: disjoint ranges across LTS branches. 4.10–5.1.17 mainline,
      # plus LTS backport fixes at 4.4.185, 4.9.185, 4.14.133, 4.19.58
      # 4.8.16–4.8.x also affected (EOL, never patched)
      return false if maj < 4 || maj > 5
      return false if maj == 5 && mn >= 2
      case {maj, mn}
      when {4, 4}  then pat >= 40 && pat < 185
      when {4, 8}  then pat >= 16          # NVD: 4.8.16–4.8.x (EOL)
      when {4, 9}  then pat >= 1 && pat < 185 # NVD starts at 4.9.1, not 4.9.0
      when {4, 14} then pat < 133
      when {4, 19} then pat < 58
      when {5, 1}  then pat < 17
      else
        (maj == 4 && ((mn >= 10 && mn <= 13) || (mn >= 15 && mn <= 18))) ||
          (maj == 5 && mn == 0)
      end
    },
  },
  {
    cve:      "CVE-2021-22555",
    name:     "Netfilter setsockopt OOB write",
    ref:      "https://nvd.nist.gov/vuln/detail/CVE-2021-22555",
    severity: :hi,
    distro_gate: nil,
    fixed_versions: {
      "debian_10"    => "4.19.194-1",
      "debian_11"    => "5.10.46-4",
      "ubuntu_16.04" => "4.4.0-213.245",
      "ubuntu_18.04" => "4.15.0-144.148",
      "ubuntu_20.04" => "5.4.0-74.83",
      "rhel_7"       => "3.10.0-1160.41.1.el7",
      "rhel_8"       => "4.18.0-305.12.1.el8_4",
    } of String => String,
    check: ->(maj : Int32, mn : Int32, pat : Int32) {
      # NVD: 2.6.19 through 5.11.x (fixed per-branch up to 5.12)
      return false if maj < 2 || (maj == 2 && (mn < 6 || (mn == 6 && pat < 19)))
      return false if maj > 5 || (maj == 5 && mn >= 12)
      case {maj, mn}
      when {4, 4}  then pat < 267
      when {4, 9}  then pat < 267
      when {4, 14} then pat < 231
      when {4, 19} then pat < 188
      when {5, 4}  then pat < 113
      when {5, 10} then pat < 31
      else              true # 2.6.19–4.3, 4.5–4.8, 4.10–4.13, 4.15–4.18, 4.20–5.3, 5.5–5.9, 5.11 — all EOL, never patched
      end
    },
  },
  {
    cve:      "CVE-2022-0185",
    name:     "legacy_parse_param heap overflow",
    ref:      "https://nvd.nist.gov/vuln/detail/CVE-2022-0185",
    severity: :hi,
    distro_gate: nil,
    fixed_versions: {
      "debian_11"    => "5.10.92-1",
      "ubuntu_20.04" => "5.4.0-96.109",
      "rhel_8"       => "4.18.0-348.12.2.el8_5",
    } of String => String,
    check: ->(maj : Int32, mn : Int32, pat : Int32) {
      # NVD: 5.4 through 5.16.1 (per-branch fixes)
      return false unless maj == 5
      return false if mn < 4 || mn > 16
      case mn
      when 4                    then pat < 173
      when 5, 6, 7, 8, 9       then true # EOL — never patched
      when 10                   then pat < 93
      when 11, 12, 13, 14      then true # EOL
      when 15                   then pat < 16
      when 16                   then pat < 2
      else                           false
      end
    },
  },
  {
    cve:      "CVE-2022-0492",
    name:     "Cgroup release_agent escape",
    ref:      "https://nvd.nist.gov/vuln/detail/CVE-2022-0492",
    severity: :hi,
    distro_gate: nil,
    fixed_versions: {
      "debian_10"    => "4.19.232-1",
      "debian_11"    => "5.10.103-1",
      "ubuntu_18.04" => "4.15.0-173.182",
      "ubuntu_20.04" => "5.4.0-105.119",
      "rhel_7"       => "3.10.0-1160.66.1.el7",
      "rhel_8"       => "4.18.0-348.20.1.el8_5",
    } of String => String,
    check: ->(maj : Int32, mn : Int32, pat : Int32) {
      # NVD: 2.6.24 through 5.16.5 (per-branch fixes)
      return false if maj < 2 || (maj == 2 && (mn < 6 || (mn == 6 && pat < 24)))
      return false if maj > 5 || (maj == 5 && mn > 16)
      case {maj, mn}
      when {4, 9}  then pat < 301
      when {4, 14} then pat < 266
      when {4, 19} then pat < 229
      when {5, 4}  then pat < 177
      when {5, 10} then pat < 97
      when {5, 15} then pat < 20
      when {5, 16} then pat < 6
      else              true
      end
    },
  },
  {
    cve:      "CVE-2022-2588",
    name:     "cls_route use-after-free",
    ref:      "https://nvd.nist.gov/vuln/detail/CVE-2022-2588",
    severity: :hi,
    distro_gate: nil,
    fixed_versions: {
      "debian_10"    => "4.19.260-1",
      "debian_11"    => "5.10.136-1",
      "ubuntu_18.04" => "4.15.0-191.202",
      "ubuntu_20.04" => "5.4.0-124.140",
      "ubuntu_22.04" => "5.15.0-46.49",
      "rhel_7"       => "3.10.0-1160.80.1.el7",
      "rhel_8"       => "4.18.0-372.32.1.el8_6",
    } of String => String,
    check: ->(maj : Int32, mn : Int32, pat : Int32) {
      # NVD: all kernels through 5.19.1 (per-branch fixes)
      return false if maj > 5 || (maj == 5 && mn > 19)
      return false if maj < 2 || (maj == 2 && mn < 6)
      case {maj, mn}
      when {4, 9}  then pat < 326
      when {4, 14} then pat < 291
      when {4, 19} then pat < 256
      when {5, 4}  then pat < 211
      when {5, 10} then pat < 137
      when {5, 15} then pat < 61
      when {5, 18} then pat < 18
      when {5, 19} then pat < 2
      else              true
      end
    },
  },
  {
    cve:      "CVE-2022-32250",
    name:     "nf_tables set use-after-free",
    ref:      "https://nvd.nist.gov/vuln/detail/CVE-2022-32250",
    severity: :hi,
    distro_gate: nil,
    fixed_versions: {
      "debian_10"    => "4.19.249-2",
      "debian_11"    => "5.10.120-1",
      "ubuntu_18.04" => "4.15.0-184.194",
      "ubuntu_20.04" => "5.4.0-117.132",
      "ubuntu_22.04" => "5.15.0-37.39",
      "rhel_7"       => "3.10.0-1160.71.1.el7",
      "rhel_8"       => "4.18.0-372.19.1.el8_6",
      "rhel_9"       => "5.14.0-70.17.1.el9_0",
    } of String => String,
    check: ->(maj : Int32, mn : Int32, pat : Int32) {
      # NVD: 4.1 through 5.18.1 (per-branch fixes)
      return false if maj < 4 || (maj == 4 && mn < 1)
      return false if maj > 5 || (maj == 5 && mn > 18)
      case {maj, mn}
      when {4, 9}  then pat < 318
      when {4, 14} then pat < 283
      when {4, 19} then pat < 247
      when {5, 4}  then pat < 198
      when {5, 10} then pat < 120
      when {5, 15} then pat < 45
      when {5, 17} then pat < 13
      when {5, 18} then pat < 2
      else              true
      end
    },
  },
]

# Cap+binary combos where the specific binary can leverage the specific
# capability for escalation. More precise than linPEAS capsVB which maps
# all GTFOBins-capabilities binaries to cap_setuid/cap_setgid regardless
# of whether the binary can actually make that syscall.
# Sources: GTFOBins capabilities page, linPEAS capsVB variable.
DANGEROUS_CAP_COMBOS = {
  "cap_setuid" => [
    {bin: "python",  desc: "os.setuid(0) → root shell",              severity: :hi},
    {bin: "perl",    desc: "POSIX::setuid(0) → root shell",          severity: :hi},
    {bin: "ruby",    desc: "Process::Sys.setuid(0) → root shell",    severity: :hi},
    {bin: "php",     desc: "posix_setuid(0) → root shell",           severity: :hi},
    {bin: "node",    desc: "process.setuid(0) → root shell",         severity: :hi},
    {bin: "gdb",     desc: "call (int)setuid(0) in debugger → root", severity: :hi},
    {bin: "tclsh",   desc: "exec setuid 0 → root shell",             severity: :hi},
  ],
  "cap_setgid" => [
    {bin: "python",  desc: "os.setgid(0) → root group",              severity: :hi},
    {bin: "perl",    desc: "POSIX::setgid(0) → root group",          severity: :hi},
    {bin: "ruby",    desc: "Process::Sys.setgid(0) → root group",    severity: :hi},
    {bin: "php",     desc: "posix_setgid(0) → root group",           severity: :hi},
    {bin: "node",    desc: "process.setgid(0) → root group",         severity: :hi},
    {bin: "gdb",     desc: "call (int)setgid(0) in debugger",        severity: :hi},
    {bin: "tclsh",   desc: "exec setgid 0 → root group",             severity: :hi},
  ],
  "cap_sys_admin" => [
    {bin: "python",  desc: "mount/namespace manipulation → root",          severity: :hi},
    {bin: "mount",   desc: "mount overlays → root filesystem access",      severity: :hi},
  ],
  "cap_sys_ptrace" => [
    {bin: "python",  desc: "inject into privileged process → root",        severity: :hi},
    {bin: "gdb",     desc: "attach to privileged process → inject/hijack", severity: :hi},
  ],
  "cap_sys_module" => [
    {bin: "python",  desc: "init_module() → load kernel module → root",    severity: :hi},
    {bin: "kmod",    desc: "insmod/modprobe → load kernel module → root",  severity: :hi},
  ],
  "cap_dac_override" => [
    {bin: "python",  desc: "read/write any file → /etc/shadow, /etc/passwd", severity: :hi},
    {bin: "vim",     desc: "edit any file → /etc/shadow, /etc/passwd",       severity: :hi},
  ],
  "cap_chown" => [
    {bin: "python",  desc: "os.chown() → take ownership of /etc/shadow",  severity: :hi},
    {bin: "chown",   desc: "take ownership of any file → /etc/shadow",     severity: :hi},
  ],
  "cap_fowner" => [
    {bin: "python",  desc: "bypass ownership checks → chmod any file",     severity: :hi},
    {bin: "chmod",   desc: "chmod any file regardless of ownership",       severity: :hi},
  ],
  "cap_setfcap" => [
    {bin: "python",  desc: "grant cap_setuid to any binary → two-step root", severity: :med},
    {bin: "perl",    desc: "grant cap_setuid to any binary → two-step root", severity: :med},
    {bin: "ruby",    desc: "grant cap_setuid to any binary → two-step root", severity: :med},
    {bin: "php",     desc: "grant cap_setuid to any binary → two-step root", severity: :med},
    {bin: "node",    desc: "grant cap_setuid to any binary → two-step root", severity: :med},
    {bin: "lua",     desc: "grant cap_setuid to any binary → two-step root", severity: :med},
    {bin: "bash",    desc: "grant cap_setuid to any binary → two-step root", severity: :med},
  ],
  "cap_setpcap" => [
    {bin: "python",  desc: "modify own capability set → self-escalate", severity: :med},
    {bin: "perl",    desc: "modify own capability set → self-escalate", severity: :med},
    {bin: "ruby",    desc: "modify own capability set → self-escalate", severity: :med},
    {bin: "php",     desc: "modify own capability set → self-escalate", severity: :med},
    {bin: "node",    desc: "modify own capability set → self-escalate", severity: :med},
    {bin: "lua",     desc: "modify own capability set → self-escalate", severity: :med},
    {bin: "bash",    desc: "modify own capability set → self-escalate", severity: :med},
  ],
  "cap_net_raw" => [
    {bin: "python",  desc: "raw sockets → packet capture, ARP spoof",  severity: :med},
    {bin: "tcpdump", desc: "packet capture on any interface",           severity: :med},
    {bin: "dumpcap", desc: "packet capture on any interface",           severity: :med},
    {bin: "tcpflow", desc: "TCP stream reassembly and capture",         severity: :med},
  ],
}

DANGEROUS_ENV_KEEP = {
  "LD_PRELOAD"      => "any allowed command loads attacker .so as root",
  "LD_LIBRARY_PATH" => "library search path hijack → attacker .so loaded as root",
  "BASH_ENV"        => "executed on non-interactive bash startup as root",
  "ENV"             => "executed on sh startup as root",
  "PATH"            => "command hijack via writable directory in PATH",
}

INTERESTING_GROUPS = {
  "sudo"      => "sudo group member",
  "docker"    => "docker group → root via socket",
  "lxd"       => "lxd group → container escape to root",
  "lxc"       => "lxc group → container escape to root",
  "disk"      => "disk group → raw disk access (dd/debugfs) → shadow",
  "adm"       => "adm group → may read sensitive logs",
  "shadow"    => "shadow group → read /etc/shadow directly",
  "wheel"     => "wheel group → may allow sudo",
  "wireshark" => "wireshark group → raw packet capture (dumpcap)",
  "kvm"       => "kvm group → VM memory read/write (/dev/kvm)",
}

INTERPRETER_LIB_VARS = {
  "PYTHONPATH" => "python",
  "RUBYLIB"    => "ruby",
  "PERL5LIB"   => "perl",
  "NODE_PATH"  => "node",
}

# Ports worth flagging post-foothold — the rest get listed without comment
INTERESTING_PORTS = {
  "2375"  => "Docker API (unauth) → root",
  "2376"  => "Docker API (TLS)",
  "3306"  => "MySQL — check for unauth access or credential reuse",
  "5432"  => "PostgreSQL — check for unauth access or credential reuse",
  "6379"  => "Redis — often unauthenticated, RCE via modules",
  "6443"  => "Kubernetes API",
  "8443"  => "admin interface — check auth",
  "8080"  => "HTTP alt — Jenkins/Tomcat/admin panel",
  "9200"  => "Elasticsearch — often unauthenticated",
  "27017" => "MongoDB — check for unauth access",
  "11211" => "Memcached — no auth by default, data exfil",
  "5900"  => "VNC — check for weak/no auth",
  "1433"  => "MSSQL — credential reuse",
  "3389"  => "RDP — lateral movement",
  "8888"  => "Jupyter — often no auth, code execution",
  "10250" => "Kubelet API — node-level container access",
  "2049"  => "NFS — check exports for no_root_squash",
  "873"   => "rsync — may expose writable modules",
}

DOAS_OPTIONS = Set{"nopass", "keepenv", "persist", "nolog", "setenv"}

MOUNT_CHECK_PATHS = %w[/ /tmp /dev/shm /var/tmp /home /opt /srv]

CONTAINER_IGNORE_FS = Set{"overlay", "proc", "tmpfs", "devpts", "sysfs", "cgroup", "cgroup2"}

# Ubuntu codename → VERSION_ID mapping for derivative distro resolution.
# Used when ID_LIKE=ubuntu and UBUNTU_CODENAME is present in /etc/os-release
# (Mint, Pop!_OS, elementary, etc. share Ubuntu kernel packages).
UBUNTU_CODENAME_MAP = {
  "noble"   => "24.04",
  "jammy"   => "22.04",
  "focal"   => "20.04",
  "bionic"  => "18.04",
  "xenial"  => "16.04",
  "trusty"  => "14.04",
}

CRON_WILDCARD_RE = /\b(tar|chown|chmod)\b.*\*/

# ─────────────────────────────────────────────────────────────
# D-Bus / PolicyKit paths and constants
# ─────────────────────────────────────────────────────────────
POLKIT_ACTION_DIRS  = {"/usr/share/polkit-1/actions"}
POLKIT_RULES_DIRS   = {"/etc/polkit-1/rules.d", "/usr/share/polkit-1/rules.d"}
DBUS_SERVICE_DIRS   = {"/usr/share/dbus-1/system-services"}
DBUS_POLKIT_WRITABLE_DIRS = {
  "/etc/polkit-1/rules.d",
  "/usr/share/polkit-1/rules.d",
  "/usr/share/polkit-1/actions",
  "/etc/dbus-1/system.d",
  "/usr/share/dbus-1/system-services",
}

POLKIT_RESULT_RE    = /polkit\.Result\.(YES|AUTH_SELF)/
POLKIT_GROUP_RE     = /subject\.isInGroup\s*\(\s*"([^"]+)"\s*\)|subject\.groups\.indexOf\s*\(\s*"([^"]+)"\s*\)/
POLKIT_ACTION_EXACT_RE = /action\.id\s*==\s*"([^"]+)"/
POLKIT_ACTION_MATCH_RE = /action\.id\.(?:indexOf|match)\s*\(\s*"([^"]+)"/

# ─────────────────────────────────────────────────────────────
# Container escape surfaces — procfs/sysfs writable paths
# ─────────────────────────────────────────────────────────────
ESCAPE_SURFACES_HI = {
  "/proc/sys/kernel/core_pattern"     => "overwrite → host code execution on crash",
  "/proc/sys/fs/binfmt_misc/register" => "register handler → host code execution on binary exec",
  "/sys/kernel/uevent_helper"         => "overwrite → host code execution on device event",
}

ESCAPE_SURFACES_MED = {
  "/proc/sys/kernel/modprobe"  => "overwrite modprobe path → code execution on unknown module load",
  "/proc/sysrq-trigger"        => "trigger host kernel actions (DoS)",
  "/proc/sys/vm/panic_on_oom"  => "force host kernel panic on OOM (DoS)",
  "/proc/sys/fs/suid_dumpable" => "enable core dumps from SUID binaries (info leak)",
}

# ─────────────────────────────────────────────────────────────
# Container runtime sockets
# ─────────────────────────────────────────────────────────────
RUNTIME_SOCKETS = {
  "/var/run/docker.sock"          => "Docker",
  "/run/containerd/containerd.sock" => "containerd",
  "/var/run/crio/crio.sock"       => "CRI-O",
  "/run/podman/podman.sock"       => "Podman (rootful)",
}

# Escape-relevant tools — presence enumerated at info level
CONTAINER_ESCAPE_TOOLS = %w[nsenter unshare chroot capsh mount fdisk debugfs ip]

# Host init process names — PID 1 matching these means shared PID namespace
HOST_INIT_NAMES = Set{"systemd", "init", "launchd"}

# Host-like daemons whose presence suggests non-containerized or weakly isolated environment
HOST_DAEMON_NAMES = Set{"sshd", "cron", "crond", "systemd-journald", "rsyslogd", "auditd", "NetworkManager"}

# Physical/host NIC prefixes that never appear inside a default container namespace
HOST_NIC_PREFIXES = %w[enp ens eno wlp wls wlo em docker br- veth virbr]

# ─────────────────────────────────────────────────────────────
# Internal service detection — process name → label
# Cross-referenced against ps output and localhost listeners.
# Sources: HackTricks lateral movement, HTB (Ready, Doctor,
# LogForge, Haze, Ghoul).
# ─────────────────────────────────────────────────────────────
INTERNAL_SERVICES = {
  "gitea"         => {label: "Gitea",          port: "3000"},
  "gogs"          => {label: "Gogs",           port: "3000"},
  "gitlab-workhorse" => {label: "GitLab",      port: "8181"},
  "gitlab-puma"   => {label: "GitLab",         port: "8080"},
  "jenkins"       => {label: "Jenkins",        port: "8080"},
  "grafana-server" => {label: "Grafana",       port: "3000"},
  "vault"         => {label: "HashiCorp Vault", port: "8200"},
  "consul"        => {label: "Consul",         port: "8500"},
}

# ─────────────────────────────────────────────────────────────
# Software-specific config credential paths — zero spawns
# ─────────────────────────────────────────────────────────────
GITLAB_CRED_PATHS = %w[
  /etc/gitlab/gitlab.rb
  /etc/gitlab/gitlab-secrets.json
  /opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml
  /opt/gitlab/embedded/service/gitlab-rails/config/database.yml
]

GITLAB_CRED_RE = /(?:db_password|smtp_password|secret_token|otp_key_base|db_key_base|secret_key_base|openid_connect_signing_key)\s*[=:]\s*['"]?(\S+)/

SPLUNK_CRED_PATHS = %w[
  /opt/splunk/etc/system/local/server.conf
  /opt/splunk/etc/system/local/web.conf
  /opt/splunk/etc/system/local/authentication.conf
  /opt/splunkforwarder/etc/system/local/server.conf
  /opt/splunkforwarder/etc/system/local/outputs.conf
]

SPLUNK_CRED_RE = /(?:pass4SymmKey|sslPassword|bindDNpassword)\s*=\s*(\S+)/

# Log4j: flag < 2.17.1 (CVE-2021-44228 + CVE-2021-45046 + CVE-2021-45105 + CVE-2021-44832)
LOG4J_SCAN_DIRS = %w[/opt /usr/share /var/lib /srv]
LOG4J_JAR_RE    = /log4j-core-(\d+\.\d+(?:\.\d+)?)/

# ─────────────────────────────────────────────────────────────
# Userspace CVEs — binary or package version checks
# Same distro-gated pattern as KERNEL_CVES.
# Sources: NVD, HTB (Sandworm, Conversor, DevVortex, blog).
# ─────────────────────────────────────────────────────────────
USERSPACE_CVES = [
  {
    cve:          "CVE-2022-31214",
    name:         "Firejail chroot escalation",
    binary:       "firejail",
    pkg:          "firejail",
    severity:     :hi,
    distro_gate:  nil.as(String?),
    fixed_versions: {
      "debian_11"    => "0.9.68-2+deb11u1",
      "ubuntu_20.04" => "0.9.62-3ubuntu0.1",
      "ubuntu_22.04" => "0.9.68-2ubuntu0.1",
    } of String => String,
    check: ->(maj : Int32, mn : Int32, pat : Int32) {
      # All versions before 0.9.70
      maj == 0 && (mn < 9 || (mn == 9 && pat < 70))
    },
  },
  {
    cve:          "CVE-2024-48990",
    name:         "needrestart interpreter escalation",
    binary:       nil.as(String?),
    pkg:          "needrestart",
    severity:     :hi,
    distro_gate:  nil.as(String?),
    fixed_versions: {
      "debian_12"    => "3.6-4+deb12u2",
      "ubuntu_22.04" => "3.5-5ubuntu2.2",
      "ubuntu_24.04" => "3.6-7ubuntu4.3",
    } of String => String,
    check: ->(maj : Int32, mn : Int32, pat : Int32) {
      # All versions before 3.8
      maj < 3 || (maj == 3 && mn < 8)
    },
  },
  {
    cve:          "CVE-2023-4911",
    name:         "Looney Tunables glibc ld.so",
    binary:       nil.as(String?),
    pkg:          "libc6",
    severity:     :hi,
    distro_gate:  nil.as(String?),
    fixed_versions: {
      "debian_12"    => "2.36-9+deb12u3",
      "ubuntu_22.04" => "2.35-0ubuntu3.4",
      "ubuntu_23.04" => "2.37-0ubuntu2.1",
      "rhel_8"       => "2.28-225.el8_8.6",
      "rhel_9"       => "2.34-60.el9_2.7",
    } of String => String,
    check: ->(maj : Int32, mn : Int32, pat : Int32) {
      # glibc 2.34 through 2.39 (upstream fix)
      maj == 2 && mn >= 34 && mn <= 39
    },
  },
  {
    cve:          "CVE-2023-1326",
    name:         "apport-cli pager escalation",
    binary:       nil.as(String?),
    pkg:          "apport",
    severity:     :hi,
    distro_gate:  "ubuntu",
    fixed_versions: {
      "ubuntu_20.04" => "2.20.11-0ubuntu27.27",
      "ubuntu_22.04" => "2.20.11-0ubuntu82.4",
    } of String => String,
    check: ->(maj : Int32, mn : Int32, pat : Int32) {
      # All versions before 2.26.0
      maj < 2 || (maj == 2 && mn < 26)
    },
  },
]

# ─────────────────────────────────────────────────────────────
# AD domain membership indicators — zero spawns, file reads
# ─────────────────────────────────────────────────────────────
AD_DOMAIN_CONFIGS = {
  "/etc/krb5.conf"    => /default_realm\s*=\s*(\S+)/i,
  "/etc/sssd/sssd.conf" => /^\s*\[domain\/([^\]]+)\]/,
}

AD_NSSWITCH_TOKENS = Set{"sss", "winbind"}

AD_DOMAIN_BINARIES = %w[realm adcli winbindd sssd adssod]

# ─────────────────────────────────────────────────────────────
# sshd_config security directives
# ─────────────────────────────────────────────────────────────
SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"

SSHD_DIRECTIVES = {
  "permitrootlogin" => {bad: Set{"yes"},
    severity: :med, desc: "root login enabled — direct root SSH if creds found"},
  "permitemptypasswords" => {bad: Set{"yes"},
    severity: :hi, desc: "empty passwords allowed — trivial login"},
  "passwordauthentication" => {bad: Set{"yes"},
    severity: :info, desc: "password auth enabled — brute-forceable"},
  "allowagentforwarding" => {bad: Set{"yes"},
    severity: :med, desc: "agent forwarding enabled — hijack connected agents"},
}
