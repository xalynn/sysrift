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

CRED_EXTS    = %w[conf config cfg ini env php py rb js xml yaml yml json toml].map { |e| "--include=\"*.#{e}\"" }.join(" ")
CRED_PATTERN = "(password|passwd|secret|api_key|apikey|token|auth_token|credential)\\s*[=:]\\s*\\S+"

LOCKED_HASH_MARKERS = Set{"*", "!", "!!", "x"}

CONFIG_NAMES = %w[wp-config.php configuration.php config.php .env database.yml settings.py
  application.properties web.config jdbc.properties hibernate.cfg.xml
  tomcat-users.xml credentials.xml]
CONFIG_PREDICATES = CONFIG_NAMES.map { |c| "-name '#{c}'" }.join(" -o ")

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
# Kernel CVE registry — data-driven, NVD-verified
# Each entry: check proc receives (major, minor, patch) → Bool
# Severity: :hi = reliable public PoC, :med = theoretical/partial
# ─────────────────────────────────────────────────────────────
KERNEL_CVES = [
  {
    cve:      "CVE-2016-5195",
    name:     "DirtyCow",
    ref:      "https://nvd.nist.gov/vuln/detail/CVE-2016-5195",
    severity: :hi,
    check:    ->(maj : Int32, mn : Int32, pat : Int32) {
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
    check:    ->(maj : Int32, mn : Int32, pat : Int32) {
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
    check:    ->(maj : Int32, mn : Int32, pat : Int32) {
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
]

DANGEROUS_ENV_KEEP = {
  "LD_PRELOAD"      => "any allowed command loads attacker .so as root",
  "LD_LIBRARY_PATH" => "library search path hijack → attacker .so loaded as root",
  "BASH_ENV"        => "executed on non-interactive bash startup as root",
  "ENV"             => "executed on sh startup as root",
  "PATH"            => "command hijack via writable directory in PATH",
}

INTERESTING_GROUPS = {
  "sudo"   => "sudo group member",
  "docker" => "docker group → root via socket",
  "lxd"    => "lxd group → container escape to root",
  "lxc"    => "lxc group → container escape to root",
  "disk"   => "disk group → raw disk access (dd/debugfs) → shadow",
  "adm"    => "adm group → may read sensitive logs",
  "shadow" => "shadow group → read /etc/shadow directly",
  "wheel"  => "wheel group → may allow sudo",
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

MOUNT_CHECK_PATHS = %w[/ /tmp /dev/shm /var/tmp /home /opt /srv]

CONTAINER_IGNORE_FS = Set{"overlay", "proc", "tmpfs", "devpts", "sysfs", "cgroup", "cgroup2"}
