# Architecture

## Why Crystal

The primary reason is `crystal build --static` -- musl libc target, single binary, zero runtime dependencies. No interpreter, no shared libraries, nothing to install on the target. That's the operational advantage over Bash/Python/Ruby alternatives.

Crystal also enforces types at compile time while reading like Ruby. Union types and nil safety (`String?`, `if x = maybe_nil`) catch bugs before the tool reaches a target. Methods that shell out return `String` or `Array(String)` with explicit empty-string handling on failure, so there's no silent `nil` propagation through the enumeration logic.

On the performance side: compiled native code, value types on the stack, hash-backed `Set` for O(1) membership tests (GTFOBins lookup, group checks), `IO::Memory` for process output capture. All fixed data structures are top-level constants allocated once at program start.

### Why union types and nil safety matter here

Enumeration tools parse a lot of system output that may or may not exist. `/etc/shadow` might not be readable. `sudo -l` might return nothing. `getcap` might not be installed. In a dynamically typed language, a missing value silently becomes `nil` and propagates until something breaks at runtime -- on a target, during an engagement, with no debugger.

Crystal's type system forces you to handle these cases at compile time. `Data.shadow` returns `String` -- if the file isn't readable, it returns `""`, and every consumer handles that explicitly. `Hash#[]?` returns `String?` instead of raising on a missing key, so the compiler won't let you use the value without a nil check. `if m = line.match(regex)` narrows the type inside the block -- you can't accidentally access capture groups on a failed match.

The practical effect is that the binary either compiles cleanly or it doesn't. There's no class of "works on my machine but crashes on the target because some edge case returned nil." For a tool that needs to run reliably across unknown systems with no opportunity to debug, that tradeoff is worth the stricter syntax.

### Where the type system doesn't help

`File::Info#owner_id` returns `String`, not a numeric type. `stat.owner_id == 0` compiles cleanly -- Crystal allows `String == Int32` comparisons -- but evaluates to `false` at runtime regardless of the actual UID. This silently broke the SUID root-owner filter for every build until caught by testing against a real report. The fix is `stat.owner_id == "0"`. Any future code checking file ownership must compare against String, not Int. The compiler won't catch this class of bug because cross-type `==` is valid Crystal -- it just always returns `false`.

## Project structure

```
sysrift.cr              -> entry point, requires, main loop
src/constants.cr        -> colors, GTFOBINS, DANGEROUS_CAPS, INTERESTING_GROUPS, INTERESTING_PORTS, etc.
src/output.cr           -> Out module, tee/hi/med/info/ok/blank/section helpers
src/runner.cr           -> read_file(), run(), run_lines()
src/data.cr             -> Data module (lazy-cached system data, 19 properties)
src/menu.cr             -> module_list, print_menu, banner
src/findings.cr         -> Finding struct, Findings collector module
src/utils.cr            -> gtfo_match, decode_caps, list_reports, self_destruct
src/modules/            -> 15 module files (mod_sysinfo.cr through mod_defenses.cr)
```

Files are required in explicit dependency order. Modules use glob require (`require "./src/modules/*"`) since they are all leaf nodes with identical dependency profiles. `src/menu.cr` is required last because `module_list` creates `Proc` literals referencing all `mod_*` functions.

## Design decisions

### Data collection layer (`src/data.cr`)

Modeled after linPEAS's startup variable pre-computation (`$suids_files`, `$mygroups`, `$sh_usrs`, etc.). The `Data` module provides 19 lazy-cached properties -- expensive commands like `find / -perm -4000` and `ps aux` run once on first access and are cached for the duration of execution. Properties that don't need external commands avoid spawning entirely: hostname via `System.hostname`, kernel version via `/proc/sys/kernel/osrelease`, environment variables via Crystal's `ENV.each`, mount table via `/proc/mounts`, process status via `/proc/self/status`, container detection via filesystem checks. Static file reads use native `File.read` via `read_file()` instead of spawning shell processes.

No disk persistence between runs -- each foothold starts fresh, which is correct behavior since the tool is designed to be re-run per user account context.

### Module isolation

Each of the 15 modules is a standalone function in its own file under `src/modules/`. Modules are pure consumers of the shared layers (constants, output, runner, data, utils) with no cross-module dependencies. Domain-specific checks live in their domain module -- cron writability in `mod_processes`, service writability in `mod_services`, security protection enumeration in `mod_defenses` -- rather than being centralized in a generic module.

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

SUID/SGID findings are cross-referenced against mount flags. A SUID binary on a `nosuid` mount has its set-uid bit ignored by the kernel -- it cannot escalate. mod_suid downgrades these to `info()` and skips GTFOBins analysis. Writable SUID/SGID binaries on nosuid mounts are flagged at `med()` since they become exploitable if the mount is ever reconfigured. Binaries on squashfs mounts (snap, AppImage) are filtered entirely -- squashfs is read-only, the binary can't be replaced, and it runs in the image context.

mod_sysinfo reports mount flag coverage for key paths (`/`, `/tmp`, `/dev/shm`, `/var/tmp`, `/home`, `/opt`, `/srv`) -- where payloads would be dropped and executed. Unmounted `/etc/fstab` entries are flagged as potential remount targets. Credentials embedded in fstab (CIFS `password=`, `credentials=`, `authentication=`) are flagged at `hi()`.

The mount data is also consumed by mod_docker (host mount detection), mod_nfs (active NFS mount listing), and mod_files (SUID-outside-standard-paths respects nosuid mounts for severity consistency with mod_suid).

### Sudo pivot target analysis

When `sudo -l` reveals runas users (e.g., `(scriptmanager) NOPASSWD: ALL`), mod_sudo enumerates directories owned by those users outside system paths. This surfaces the access surface available after pivoting.

For each discovered directory, a top-level scan checks for root-owned files modified within 7 days. A root-owned recent file in a non-root-writable directory is strong evidence of a root cron job or systemd timer writing there -- modify the script the root process executes and you own root. On Bashed, `/scripts/test.txt` (root-owned, modified within the last minute) was the only observable indicator of the hidden root cron job.

Runas user extraction is scoped to `sudo -l` output only (what the current user can actually do), not sudoers files. The directory search is one `find` per pivot user, excluding system paths. The root ownership scan is `Dir.each_child` (top-level only, zero extra spawns) -- deeper analysis happens when sysrift is re-run under the pivoted user.

### Library search path writability

mod_writable parses `/etc/ld.so.conf` and recursively resolves its `include` directives to enumerate all directories in the dynamic linker's library search path. A writable directory in this path enables shared object injection into any dynamically linked SUID binary.

Four attack surfaces are checked: writable include directories (drop a new `.conf`), writable conf files (modify existing path entries), writable library directories (place malicious `.so` files), and writable parent directories of `/etc/ld.so.preload` entries (replace a preloaded library). All file reads and directory checks, no spawns.

## False positive reduction

### Credential scanning

Two-phase design. Shell grep finds candidate files (fast, broad), then Crystal re-matches each line and filters noise before reporting. Sentinel values in config syntax (`ask`, `*`, `none`, `files`, `systemd`), .NET assembly metadata (`PublicKeyToken=`), and delegate template variables are filtered post-match. The value filter extracts from the credential keyword's own `=:` match, not the first one on the line, preventing false drops when an earlier unrelated key-value pair has a sentinel value.

JS/JSON files are excluded from the broad scan -- desktop app bundles dominate the matches with code variable names, not credentials. A narrower JS/JSON pass runs only against `/var/www`, `/srv`, `/opt` where real database credentials live.

Files over 256 KB are skipped before reading, lines over 500 chars skipped during matching. Eliminates minified JS bundles and JSON blobs where `token`/`password` appear in code contexts.

History file matches are deduplicated by content with repeat counts. `File.info?` with nil-safe size check handles files that disappear between grep discovery and size check.

### SUID/SGID noise

- Binaries on `nosuid` mounts downgraded to `info()` -- kernel ignores the set-uid bit
- Binaries on squashfs mounts (snap, AppImage) filtered with summary count -- read-only filesystem, not replaceable
- chrome-sandbox skipped in unusual SUID location check -- no command interface, no GTFOBins entry, no known privesc CVEs
- UID 0 users: `root` filtered, check targets backdoor accounts (`toor`, `admin`, etc.)

### Cron analysis

- `/dev/null` skipped as writable binary target
- Cron target paths validated as regular files via `File.file?` -- world-writable directories are not binaries
- Wildcard injection covers `tar`, `chown`, `chmod` but not `find` (`find`'s `*` is a quoted `-name` argument, not a shell glob)

### Other noise reduction

- Environment variables use word-boundary regex -- `DB_PASSWORD` matches, `OLDPWD` / `XAUTHORITY` do not
- Log credential results grouped by filename with match count and one sample line per file
- Listening ports checked against `INTERESTING_PORTS` map; unmatched listeners listed without editorializing
- Writable service file paths resolved via `File.realpath` and deduplicated (handles Debian symlinks)
- SSH keys: ownership-aware severity. Own keys demoted to `info()`, other users' keys remain `hi()`
- `Data.path_dirs` deduplicates PATH before checking writability

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

### Capability + binary combo detection

Beyond flagging dangerous capabilities generically, mod_capabilities cross-references the specific binary against a `DANGEROUS_CAP_COMBOS` map. `cap_setuid` on an unknown binary is worth noting; `cap_setuid` on python is `os.setuid(0)` -- instant root. The combo map has 43 entries across 11 capabilities, each verified against GTFOBins to confirm the binary can actually leverage the specific capability (unlike linPEAS which maps all GTFOBins-capabilities binaries to cap_setuid/cap_setgid regardless).

Severity is split: `hi()` for combos that yield direct root (setuid(0) via interpreters, kernel module loading, arbitrary file write), `med()` for two-step paths (cap_setfcap granting caps to another binary, cap_setpcap modifying own caps) and packet capture.

### Process capability enumeration

Beyond file capabilities via `getcap`, mod_capabilities enumerates all `/proc/[pid]/status` files for processes with non-zero CapEff or CapAmb. A privileged process with `cap_sys_ptrace` is an injection target regardless of whether file capabilities are set.

Hex capability bitmasks are decoded natively via a `CAP_BITS` constant (41 entries mapping bit positions from `linux/capability.h`). This replaces `capsh --decode` which spawns up to 5 times per flagged process and is absent on minimal containers -- exactly where process capability enumeration matters most.

Filtering: uid=0 processes where CapEff matches CapBnd are skipped -- the default kernel-granted set on bare metal, which would otherwise produce hundreds of noise findings. The filter preserves detection of root processes with unusual grants (CapEff divergent from CapBnd) and all non-root processes with any capabilities. Inside containers where the bounding set is restricted, root processes with capabilities are correctly flagged.

Severity uses `HI_CAPS` -- a Set of 9 capabilities that yield direct root or equivalent without additional steps (`cap_setuid`, `cap_sys_admin`, `cap_sys_ptrace`, `cap_sys_module`, `cap_dac_override`, `cap_dac_read_search`, `cap_sys_rawio`, `cap_bpf`, `cap_setgid`). Remaining dangerous capabilities produce `med()`. Processes with only non-dangerous capabilities report as `info()`.

Three filters demote expected caps to `info()`:

- **Chromium/Electron sandbox** -- `cap_sys_admin` from `clone(CLONE_NEWUSER)` for renderer namespacing. Only demoted when it's the sole dangerous cap on a process matching `CHROMIUM_SANDBOX_NAMES` running as the current user -- anything beyond that still fires normally.
- **SUID helpers** (fusermount3, fusermount) -- inherit full cap set briefly from the SUID bit during mount ops.
- **Known daemon caps** -- `KNOWN_DAEMON_CAPS` maps daemons to their expected caps (e.g., rtkit-daemon gets `cap_dac_read_search` for PulseAudio scheduling). Caps outside the expected set still fire.

### Security protection enumeration

mod_defenses (module 15) reports active defenses on the target. This shapes interpretation of findings from every other module -- a kernel CVE match with ASLR disabled is more actionable than one with full ASLR.

20 checks across mandatory access control (AppArmor, SELinux), address space protections (ASLR, mmap_min_addr), kernel exposure (kptr_restrict, dmesg_restrict, perf_event_paranoid), process isolation (ptrace_scope, seccomp), filesystem hardening (protected_symlinks, protected_hardlinks), namespace and eBPF controls (unprivileged_userns_clone, unprivileged_bpf_disabled), module loading restrictions (modules_disabled, module_sig_enforce), kernel lockdown mode, and legacy protections (grsecurity, PaX).

All procfs/sysfs reads. Seccomp status comes from `Data.proc_status` (shared with mod_docker), gated by `Data.in_container?` to avoid duplicating mod_docker's escape-context seccomp report.

`Data.proc_status` caches `/proc/self/status` and is consumed by three modules: `Data.proc_caps` (Cap lines for mod_capabilities and mod_docker), mod_docker (seccomp/NoNewPrivs in container escape context), and mod_defenses (seccomp in system-level context). `Data.in_container?` caches container detection (Docker, LXC, Kubernetes) and is consumed by mod_docker and mod_defenses.

## Process spawn reduction

linPEAS is bash -- every command is a subprocess. The Crystal port avoids spawning where possible:

- `read_file()` replaces `cat` for all static file reads (`/etc/passwd`, `/etc/shadow`, `/proc` entries, cron files, etc.)
- `Dir.each_child` replaces `ls` for directory enumeration
- `Process.find_executable()` replaces `which` for binary existence checks
- `System.hostname`, `/proc/sys/kernel/osrelease`, `ENV.each` replace their shell equivalents
- Data layer caching ensures commands duplicated across modules (`id`, `ps`, `find -4000`, `/etc/sudoers`) run once
- Config file search uses a single `find` with combined `-o` predicates instead of 12 separate filesystem walks
- History and config file credential scanning uses `read_file()` + in-process regex instead of spawning grep
- `Data.mounts` replaces grep/mount spawns in mod_docker, mod_nfs, and provides mount data to mod_sysinfo and mod_suid
- `Data.proc_status` caches `/proc/self/status` -- Cap lines filtered in-process, seccomp/NoNewPrivs read from cached content
- `Dir.each_child` replaces `ls` + `find -writable` in mod_services init.d enumeration

## Roadmap

### Required for completeness

**Kernel CVE registry expansion.** Currently 3 entries. The registry infrastructure supports adding a CVE by appending a NamedTuple to `KERNEL_CVES` with no control flow changes. Needs population with post-2022 kernel LPEs, all NVD-verified.

### Design decisions open

**SUID deep analysis.** For non-GTFOBins SUID binaries, linPEAS runs `ldd` (writable shared library paths), `readelf -d` (RPATH/RUNPATH to writable locations), and `strings` (relative path calls exploitable via PATH hijacking). Each adds 1-2 spawns per unknown SUID binary. Open question: run on all unknowns, or scope to SUIDs outside `/usr /bin /sbin`? The nosuid mount cross-reference already filters out a class of false positives.

**SGID group-aware escalation context.** Cross-reference SGID binary group ownership against `INTERESTING_GROUPS` to surface multi-hop chains -- SGID `find` with group `disk` = raw filesystem access to `/etc/shadow`. Relevant because sysrift is designed to be re-run per foothold as different users, where each account exposes different group memberships.

**Container runtime expansion.** Currently limited to Docker socket. Should cover containerd, CRI-O, podman sockets, runc CVE-2019-5736 and containerd CVE-2020-15257 version checks, and escape tool detection (`nsenter`, `unshare`, `chroot`, `capsh`). Separately, ambient capability enumeration via `capsh --print` and namespace inode comparison (`/proc/1/ns/*` vs `/proc/self/ns/*`) would strengthen container escape assessment. `Data.proc_status` and `Data.in_container?` are already cached and available.

### Optional

**Kubernetes enumeration** -- service account token permissions, secret/pod/service enumeration, host filesystem mounts, user namespace mappings. Gate behind K8s detection. Heavier scope than other modules due to RBAC-aware logic.

**Cloud metadata harvesting** -- AWS IMDSv1 = instant IAM credential theft across 9 cloud providers via instance metadata APIs. Open question: sysrift currently makes zero network calls; is that worth breaking?

**Firewall rules** -- iptables/nftables/ufw for pivoting assessment and egress mapping.

### Known issues

- mod_network port regex may match wrong field on IPv6 listeners depending on ss column alignment
- mod_processes cron writable binary severity doesn't account for the owning user (www-data cron is med at best, not hi)
- mod_users home directory symlink comparison uses string equality instead of `File.realpath`
- mod_processes cron wildcard regex is rebuilt on every call instead of being a top-level constant
- mod_processes suspicious process location check flags sysrift's own process when deployed to /dev/shm (the recommended location)
- mod_processes cron wildcard regex still matches quoted `*` in tar (e.g., `tar --exclude='*.tmp'`)

### OPSEC

mod_suid embeds `https://gtfobins.github.io/gtfobins/...` in output and mod_docker embeds the Docker socket escape command. Both appear in `strings` output and are matchable by threat intel rules. Not yet decided: strip from binary output, obfuscate at compile time, or accept as operational tradeoff.
