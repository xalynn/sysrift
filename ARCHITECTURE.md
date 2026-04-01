# Architecture

## Why Crystal

The primary reason is `crystal build --static` -- musl libc target, single binary, zero runtime dependencies. No interpreter, no shared libraries, nothing to install on the target. That's the operational advantage over Bash/Python/Ruby alternatives.

Crystal also enforces types at compile time while reading like Ruby. Union types and nil safety (`String?`, `if x = maybe_nil`) catch bugs before the tool reaches a target. Methods that shell out return `String` or `Array(String)` with explicit empty-string handling on failure, so there's no silent `nil` propagation through the enumeration logic.

On the performance side: compiled native code, value types on the stack, hash-backed `Set` for O(1) membership tests (GTFOBins lookup, group checks), `IO::Memory` for process output capture. All fixed data structures are top-level constants allocated once at program start.

### Why union types and nil safety matter here

Enumeration tools parse a lot of system output that may or may not exist. `/etc/shadow` might not be readable. `sudo -l` might return nothing. `getcap` might not be installed. In a dynamically typed language, a missing value silently becomes `nil` and propagates until something breaks at runtime -- on a target, during an engagement, with no debugger.

Crystal's type system forces you to handle these cases at compile time. `Data.shadow` returns `String` -- if the file isn't readable, it returns `""`, and every consumer handles that explicitly. `Hash#[]?` returns `String?` instead of raising on a missing key, so the compiler won't let you use the value without a nil check. `if m = line.match(regex)` narrows the type inside the block -- you can't accidentally access capture groups on a failed match.

The practical effect is that the binary either compiles cleanly or it doesn't. There's no class of "works on my machine but crashes on the target because some edge case returned nil." For a tool that needs to run reliably across unknown systems with no opportunity to debug, that tradeoff is worth the stricter syntax.

## Project structure

```
sysrift.cr              -> entry point, requires, main loop
src/constants.cr        -> colors, GTFOBINS, DANGEROUS_CAPS, INTERESTING_GROUPS, INTERESTING_PORTS, etc.
src/output.cr           -> Out module, tee/hi/med/info/ok/blank/section helpers
src/runner.cr           -> read_file(), run(), run_lines()
src/data.cr             -> Data module (lazy-cached system data, 17 properties)
src/menu.cr             -> module_list, print_menu, banner
src/findings.cr         -> Finding struct, Findings collector module
src/utils.cr            -> gtfo_match, list_reports, self_destruct
src/modules/            -> 14 module files (mod_sysinfo.cr through mod_files.cr)
```

Files are required in explicit dependency order. Modules use glob require (`require "./src/modules/*"`) since they are all leaf nodes with identical dependency profiles. `src/menu.cr` is required last because `module_list` creates `Proc` literals referencing all `mod_*` functions.

## Design decisions

### Data collection layer (`src/data.cr`)

Modeled after linPEAS's startup variable pre-computation (`$suids_files`, `$mygroups`, `$sh_usrs`, etc.). The `Data` module provides 17 lazy-cached properties -- expensive commands like `find / -perm -4000` and `ps aux` run once on first access and are cached for the duration of execution. Properties that don't need external commands avoid spawning entirely: hostname via `System.hostname`, kernel version via `/proc/sys/kernel/osrelease`, environment variables via Crystal's `ENV.each`, mount table via `/proc/mounts`. Static file reads use native `File.read` via `read_file()` instead of spawning shell processes.

No disk persistence between runs -- each foothold starts fresh, which is correct behavior since the tool is designed to be re-run per user account context.

### Module isolation

Each of the 14 modules is a standalone function in its own file under `src/modules/`. Modules are pure consumers of the shared layers (constants, output, runner, data, utils) with no cross-module dependencies. Domain-specific checks live in their domain module -- cron writability in `mod_processes`, service writability in `mod_services` -- rather than being centralized in a generic writable-files module.

### Runner design (`src/runner.cr`)

Three functions, all returning empty on error (never crash, never leak output to the terminal):

- `read_file(path)` -- native `File.read` with `File.exists?` + `File::Info.readable?` guards. Used for all static file reads to avoid spawning `/bin/sh` + `cat`.
- `run(cmd)` -- `Process.run("/bin/sh", args: ["-c", cmd])` with `IO::Memory` capture and stderr suppression. Reserved for commands that require shell features or external binaries.
- `run_lines(cmd)` -- splits `run()` output into stripped, non-empty lines.

All command strings passed to `run()` use hardcoded inputs, not filesystem-derived or user-supplied values. Where module logic previously interpolated filesystem paths into shell commands (e.g., grep on discovered files), those have been converted to in-process matching on `read_file()` content.

### Output system (`src/output.cr`)

All output goes through the `Out` module which tees to both stdout and a log file simultaneously. The log file strips ANSI codes for clean text suitable for exfiltration. Severity helpers (`hi`, `med`, `info`, `ok`) prepend colored tags. Menu and prompt text goes to stdout only (not logged).

### Findings collector (`src/findings.cr`)

Records every `hi()` and `med()` call during module execution. After modules complete, `Findings.summary` prints a severity-sorted digest -- critical findings first, then medium. The collector hooks transparently into the output helpers; modules require no changes. Findings are cleared between menu selections. Duplicate module selection (e.g., `1,1,3`) is deduplicated via `Set(Int32)`.

### Mount options and SUID cross-referencing

`Data.mounts` parses `/proc/mounts` into a sorted array of `NamedTuple(mount: String, fstype: String, opts: Set(String))`, longest mountpoint first. `Data.mount_for(path)` does a longest-prefix lookup to find the governing mount for any file path. `Data.nosuid_mount?(path)` is the convenience wrapper most modules use.

This enables something linPEAS doesn't do: cross-referencing SUID/SGID findings against mount flags. A SUID binary on a `nosuid` mount has its set-uid bit ignored by the kernel -- it cannot escalate. mod_suid downgrades these to `info()` and skips GTFOBins analysis. Writable SUID/SGID binaries on nosuid mounts are flagged at `med()` since they become exploitable if the mount is ever reconfigured.

mod_sysinfo reports mount flag coverage for key operator paths (`/`, `/tmp`, `/dev/shm`, `/var/tmp`, `/home`, `/opt`, `/srv`) -- where an operator would drop and execute payloads. Unmounted `/etc/fstab` entries are flagged as potential remount targets. Credentials embedded in fstab (CIFS `password=`, `credentials=`, `authentication=`) are flagged at `hi()`.

The mount data is also consumed by mod_docker (host mount detection replaces a grep spawn), mod_nfs (active NFS mount listing replaces a mount|grep spawn), and mod_files (SUID-outside-standard-paths check respects nosuid mounts for severity consistency with mod_suid).

## False positive reduction

- **Environment variables** -- word-boundary regex requires keywords like `password`, `token`, `auth` to appear as complete segments delimited by `_` or string boundaries. `DB_PASSWORD` matches; `OLDPWD`, `XAUTHORITY`, `KEYBOARD` do not.
- **Log credential scanning** -- results grouped by filename with match count and one sample line per file. Prevents a single noisy log from consuming all output.
- **Listening ports** -- checked against `INTERESTING_PORTS` map (databases, container APIs, admin interfaces, lateral movement targets). Unmatched listeners listed without editorializing.
- **Writable service files** -- paths resolved via `File.realpath` and deduplicated. Handles Debian/Ubuntu where `/lib/systemd/system` symlinks to `/usr/lib/systemd/system`.
- **SSH files** -- in the current user's own home, only private key files are flagged. Other users' `.ssh/` directories remain fully flagged.
- **SUID on nosuid mounts** -- binaries with SUID/SGID bits on a `nosuid` mount are downgraded to `info()` since the kernel ignores the set-uid bit. Neither linPEAS nor other enumeration tools currently do this cross-reference.

## CVE detection

### Kernel CVEs

Kernel version is parsed into numeric components for correct range comparison (string comparison fails: `"5.10" < "5.9"` lexicographically). The patch component strips non-numeric suffixes (`"102-lts"` -> `102`, `"0-100-generic"` -> `0`). Components are parsed once and cached.

Detection uses a data-driven `KERNEL_CVES` registry in `constants.cr`. Each entry is a `NamedTuple` with CVE ID, name, NVD URL, severity, and a check `Proc`. Adding a new CVE means appending a tuple -- no control flow changes.

Currently detects:

- **DirtyCow** (CVE-2016-5195) -- kernel 2.6.22 through 4.8.2. Severity: high.
- **eBPF privilege escalation** (CVE-2021-3490) -- kernel 5.7+, per-branch backport awareness. Severity: medium.
- **Dirty Pipe** (CVE-2022-0847) -- kernel 5.8+, per-branch backport awareness. Severity: high.

All version ranges verified against NVD CPE match criteria.

### Sudo CVEs

Sudo version is parsed into major, minor, patch, and p-level components to detect:

- **CVE-2019-14287** -- sudo < 1.8.28 (`sudo -u#-1` bypass). NVD verified.
- **CVE-2021-3156 Baron Samedit** -- sudo 1.8.2-1.8.31 and 1.9.0-1.9.5p1 (heap overflow). NVD verified.
- **CVE-2019-18634** -- sudo 1.7.1-1.8.25 with pwfeedback enabled. Version-gated: only flags when both pwfeedback is present and sudo version is vulnerable. NVD verified.

Additionally checks for `env_keep LD_PRELOAD` in both `sudo -l` output and `/etc/sudoers` using per-line matching.

### GTFOBins cross-referencing

SUID/SGID binaries and sudo rules are cross-referenced against a 140+ entry `Set` of known-exploitable binaries from [GTFOBins](https://gtfobins.github.io/). Binary names are normalized (lowercased, version suffixes stripped) to catch variants like `python3.11` matching `python3`.

## Process spawn reduction

linPEAS is bash -- every command is a subprocess. The Crystal port avoids spawning where possible:

- `read_file()` replaces `cat` for all static file reads (`/etc/passwd`, `/etc/shadow`, `/proc` entries, cron files, etc.)
- `Dir.each_child` replaces `ls` for directory enumeration
- `Process.find_executable()` replaces `which` for binary existence checks
- `System.hostname`, `/proc/sys/kernel/osrelease`, `ENV.each` replace their shell equivalents
- Data layer caching ensures commands duplicated across modules (`id`, `ps`, `find -4000`, `/etc/sudoers`) run once
- Config file search uses a single `find` with combined `-o` predicates instead of 12 separate filesystem walks
- History and config file credential scanning uses `read_file()` + in-process regex instead of spawning grep
- `Data.mounts` replaces grep/mount spawns in mod_docker (host mount filter), mod_nfs (NFS mount listing), and provides mount data to mod_sysinfo and mod_suid without any process spawn
- `Dir.each_child` replaces `ls` + `find -writable` in mod_services init.d enumeration

## Roadmap

### Required for completeness

**Security protection enumeration.** AppArmor, SELinux, ASLR, seccomp, grsecurity, kernel hardening sysctls (`kernel.randomize_va_space`, `kernel.dmesg_restrict`, `kernel.kptr_restrict`), lockdown mode. Knowing what defenses are active determines which exploits are viable. Most checks are single `/proc/sys/` or `/sys/` reads. `/proc/self/status` should be promoted to `Data.proc_status` as part of this work -- it's currently read separately by mod_docker and Data.proc_caps, and this module would add a third consumer.

**Capability coverage: cap+binary combos.** `cap_setuid` on python = `os.setuid(0)` = instant root. Needs a `DANGEROUS_CAP_COMBOS` map cross-referenced during the getcap loop. Reference: linPEAS `capsVB` and GTFOBins capabilities page.

**Capability coverage: process capability enumeration.** Currently only `/proc/self/status` is checked. All `/proc/[pid]/status` should be enumerated for non-zero CapEff and CapAmb -- a privileged process with dangerous caps is an injection target (especially with `cap_sys_ptrace`). Needs native `/proc` iteration and hex bitmask parsing.

**ld.so.conf recursive path writability.** `/etc/ld.so.preload` writability is checked, but `/etc/ld.so.conf` and its `include` directives are not parsed. Writable directories in the library search path = shared object injection into any dynamically linked SUID binary.

**Kernel CVE registry expansion.** Currently 3 entries. The registry infrastructure supports adding a CVE by appending a NamedTuple to `KERNEL_CVES` with no control flow changes. Needs population with post-2022 kernel LPEs, all NVD-verified.

### Design decisions open

**SUID deep analysis.** For non-GTFOBins SUID binaries, linPEAS runs `ldd` (writable shared library paths), `readelf -d` (RPATH/RUNPATH to writable locations), and `strings` (relative path calls exploitable via PATH hijacking). Each adds 1-2 spawns per unknown SUID binary. Open question: run on all unknowns, or scope to SUIDs outside `/usr /bin /sbin`? The nosuid mount cross-reference already filters out a class of false positives.

**SGID group-aware escalation context.** Cross-reference SGID binary group ownership against `INTERESTING_GROUPS` to surface multi-hop chains -- SGID `find` with group `disk` = raw filesystem access to `/etc/shadow`. Relevant because sysrift is designed to be re-run per foothold as different users, where each account exposes different group memberships.

**Container runtime expansion.** Currently limited to Docker socket. Should cover containerd, CRI-O, podman sockets, runc CVE-2019-5736 and containerd CVE-2020-15257 version checks, and escape tool detection (`nsenter`, `unshare`, `chroot`, `capsh`). Separately, ambient capability enumeration via `capsh --print` and namespace inode comparison (`/proc/1/ns/*` vs `/proc/self/ns/*`) would strengthen container escape assessment.

### Optional

**Kubernetes enumeration** -- service account token permissions, secret/pod/service enumeration, host filesystem mounts, user namespace mappings. Gate behind K8s detection. Heavier scope than other modules due to RBAC-aware logic.

**Cloud metadata harvesting** -- AWS IMDSv1 = instant IAM credential theft across 9 cloud providers via instance metadata APIs. Open question: sysrift currently makes zero network calls; is that worth breaking?

**Firewall rules** -- iptables/nftables/ufw for pivoting assessment and egress mapping.

### Known issues

- mod_network port regex may match wrong field on IPv6 listeners depending on ss column alignment
- mod_capabilities defaults unmatched getcap lines to `med()` -- should be `info()` for benign caps
- mod_processes cron writable binary severity doesn't account for the owning user (www-data cron is med at best, not hi)
- mod_users home directory symlink comparison uses string equality instead of `File.realpath`
- mod_sudo CVE-2019-18634 has a false positive edge on sudo 1.7.0 (essentially extinct)
- Three minor spawns remain that could be converted to native reads: `Data.proc_caps` grep, mod_creds history file grep (content already loaded), and mod_processes dual ps invocations

### OPSEC

mod_suid embeds `https://gtfobins.github.io/gtfobins/...` in output and mod_docker embeds the Docker socket escape command. Both appear in `strings` output and are matchable by threat intel rules. Not yet decided: strip from binary output, obfuscate at compile time, or accept as operational tradeoff.
