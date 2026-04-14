# Architecture

## Why Crystal

The primary reason is `crystal build --static` -- musl libc target, single binary, zero runtime dependencies. No interpreter, no shared libraries, nothing to install on the target. That's the operational advantage over Bash/Python/Ruby alternatives.

Crystal also enforces types at compile time while reading like Ruby. Union types and nil safety (`String?`, `if x = maybe_nil`) catch bugs before the tool reaches a target. Methods that shell out return `String` or `Array(String)` with explicit empty-string handling on failure, so there's no silent `nil` propagation through the enumeration logic.

On the performance side: compiled native code, value types on the stack, hash-backed `Set` for O(1) membership tests (GTFOBins lookup, group checks), `IO::Memory` for process output capture. All fixed data structures are top-level constants allocated once at program start.

### Why union types and nil safety matter here

Enumeration tools parse a lot of system output that may or may not exist. `/etc/shadow` might not be readable. `sudo -l` might return nothing. `getcap` might not be installed. In a dynamically typed language, a missing value silently becomes `nil` and propagates until something breaks at runtime -- on a target, during an engagement, with no debugger.

Crystal's type system forces you to handle these cases at compile time. `Data.shadow` returns `String` -- if the file isn't readable, it returns `""`, and every consumer handles that explicitly. `Hash#[]?` returns `String?` instead of raising on a missing key, so the compiler won't let you use the value without a nil check. `if m = line.match(regex)` narrows the type inside the block -- you can't accidentally access capture groups on a failed match.

The binary either compiles cleanly or it doesn't. There's no class of "works on my machine but crashes on the target because some edge case returned nil."

### Type safety doesn't defend against logic bugs

`File::Info#owner_id` returns `String`, not a numeric type. `stat.owner_id == 0` compiles cleanly -- Crystal allows `String == Int32` comparisons -- but evaluates to `false` at runtime regardless of the actual UID. This silently broke the SUID root-owner filter for every build until caught by testing against a real report. The fix is `stat.owner_id == "0"`. Valid Crystal, correct syntax, wrong result.

The type system can't help here -- the code is well-typed, it just doesn't do what you think it does. What caught this was knowing what the output should look like and testing against real data. Running on a known target where you already know the answer (a CTF box with a known SUID privesc, a VM with planted test vectors) showed zero SUID findings on a system with obvious ones. That's a logic bug, not a compiler error.

For a project like this, specs aren't strictly necessary -- the feedback loop is short enough that running against a live target catches most issues. But as the codebase grows, they have real value for logic that's easy to get wrong silently: version range comparisons, severity classification, field parsing from system output. The compiler guarantees the code is type-safe Crystal. It doesn't guarantee the code is correct.

## Project structure

```
sysrift.cr              -> entry point, requires, main loop
src/constants.cr        -> colors, GTFOBINS, DANGEROUS_CAPS, INTERESTING_GROUPS, INTERPRETER_LIB_VARS, INTERESTING_PORTS, etc.
src/output.cr           -> Out module, tee/hi/med/info/ok/blank/section helpers
src/runner.cr           -> read_file(), run(), run_lines()
src/data.cr             -> Data module (lazy-cached system data, active_mode flag)
src/menu.cr             -> module_list, print_menu, banner, active_prompt
src/findings.cr         -> Finding struct, Findings collector module
src/utils.cr            -> gtfo_match, decode_caps, dpkg_ver_compare, rpm_ver_compare, list_reports, self_destruct
src/modules/            -> 17 module files (mod_sysinfo.cr through mod_cloud.cr)
```

Files are required in explicit dependency order. Modules use glob require (`require "./src/modules/*"`) since they are all leaf nodes with identical dependency profiles. `src/menu.cr` is required last because `module_list` creates `Proc` literals referencing all `mod_*` functions.

## Design decisions

### Data collection layer (`src/data.cr`)

Modeled after linPEAS's startup variable pre-computation (`$suids_files`, `$mygroups`, `$sh_usrs`, etc.). The `Data` module provides lazy-cached properties -- expensive commands like `find / -perm -4000` and `ps aux` run once on first access and are cached for the duration of execution. Properties that don't need external commands avoid spawning entirely: hostname via `System.hostname`, kernel version via `/proc/sys/kernel/osrelease`, environment variables via Crystal's `ENV.each`, mount table via `/proc/mounts`, process status via `/proc/self/status`, container detection via filesystem checks. Static file reads use native `File.read` via `read_file()` instead of spawning shell processes.

`Data.sudo_l` is the one exception to the `run()` pattern. `sudo -l` hangs indefinitely when stdin is a pipe -- sudo tries to read a password that never arrives, which is the common case on reverse shells. Instead of `/bin/sh`, `Data.sudo_l` spawns sudo directly via `Process.new` with stdin closed (maps to `/dev/null`, so sudo gets EOF on password read and exits immediately). Stdout is read in a fiber with a 5-second `select` timeout covering both the read and the wait. On timeout the process is killed, reaped, and the property returns empty. When credentials are cached or NOPASSWD is set, sudo never reads stdin, so closing it has no effect on those paths.

`Data.ss_output` caches `ss -tulpn` output, consumed by mod_software (internal service detection) and mod_network (listening port enumeration). `Data.sshd_config` caches `/etc/ssh/sshd_config`, consumed by mod_software (directive analysis) and mod_creds (AuthorizedKeysFile path expansion). `Data.resolv_conf` caches `/etc/resolv.conf`, consumed by mod_network (display) and cloud indicator procs in constants.cr (Azure `reddog.microsoft.com` and IBM Cloud `161.26.0.10`/`161.26.0.11` detection). `Data.pkg_version` is a public method that queries dpkg/rpm for a given package name -- used by mod_software for userspace CVE version checks and by mod_docker for runtime CVE checks.

`Data.db_creds` is an append-only array of successful database logins (service, user, host) populated during active credential testing.

`Data.cloud_provider` and `Data.cloud_context` are cached cloud detection results. `detect_cloud` iterates `CLOUD_INDICATORS` (proc-based checks ordered by specificity -- container variants before host variants within each provider family) with DMI sysfs fallback. Detection runs once on first access. The provider string (e.g. `"aws_ecs"`, `"gcp"`, `"azure_app"`) is used by mod_cloud to dispatch to the correct active enumeration handler.

No disk persistence between runs -- each foothold starts fresh. Re-run under each user context.

### Module isolation

Each of the 17 modules is a standalone function in its own file under `src/modules/`. Modules are pure consumers of the shared layers (constants, output, runner, data, utils) with no cross-module dependencies. Domain-specific checks live in their domain module -- cron writability in `mod_processes`, service writability in `mod_services`, security protection enumeration in `mod_defenses` -- rather than being centralized in a generic module. mod_cloud is the only module that imports an additional stdlib (`require "http/client"`) for active IMDS enumeration.

### Active enumeration mode

sysrift is passive by default -- most modules read files, parse /proc, and inspect system state without generating network connections or authentication events. Active enumeration is opt-in via `Data.active_mode?`. Modules with active checks: mod_cloud (IMDS credential harvesting), mod_software (database default credential testing), and mod_processes (process sampling for hidden cron discovery).

`Data.active_mode?` is a boolean class variable (default `false`). Modules gate active checks behind `if Data.active_mode?` -- passive code paths run unconditionally. The module list marks each module with an `active: Bool` field; modules with active checks display `[A]` in the menu.

When the operator selects a module (or combination) that has active checks, an interactive prompt fires before execution: `[p]assive only / [a]ll checks / [c]ancel`. For "Run all", the prompt fires once and lists every active module by name. The boolean resets to `false` after each execution -- never persists across menu selections.

The prompt text uses neutral language ("network connections and authentication events that may appear in system logs") rather than naming detection technologies. Compiled strings stay consistent with the "Linux System Audit" cover.

### Runner design (`src/runner.cr`)

Three functions, all returning empty on error (never crash, never leak output to the terminal):

- `read_file(path)` -- native `File.read` with `File.exists?` + `File::Info.readable?` guards. Used for all static file reads to avoid spawning `/bin/sh` + `cat`.
- `run(cmd)` -- `Process.run("/bin/sh", args: ["-c", cmd])` with `IO::Memory` capture and stderr suppression. Reserved for commands that require shell features or external binaries.
- `run_lines(cmd)` -- splits `run()` output into stripped, non-empty lines.

All command strings passed to `run()` use hardcoded inputs, not filesystem-derived or user-supplied values. Where module logic previously interpolated filesystem paths into shell commands (e.g., grep on discovered files), those have been converted to in-process matching on `read_file()` content. `Data.sudo_l` bypasses `run()` entirely -- it uses `Process.new` with stdin closed and a timeout (see data collection layer above).

### Output system (`src/output.cr`)

All output goes through the `Out` module which tees to both stdout and a log file simultaneously. The log file strips ANSI codes for clean text suitable for exfiltration. Severity helpers (`hi`, `med`, `info`, `ok`) prepend colored tags. Menu and prompt text goes to stdout only (not logged).

### Findings collector (`src/findings.cr`)

Records every `hi()` and `med()` call during module execution. After modules complete, `Findings.summary` prints a severity-sorted digest -- critical findings first, then medium. The collector hooks into the output helpers; modules require no changes. Findings are cleared between menu selections. Duplicate module selection (e.g., `1,1,3`) is deduplicated via `Set(Int32)`.

### Mount data (`Data.mounts`)

`Data.mounts` parses `/proc/mounts` into a sorted array of `NamedTuple(mount: String, fstype: String, opts: Set(String))`, longest mountpoint first. `Data.mount_for(path)` does a longest-prefix lookup to find the governing mount for any file path. `Data.nosuid_mount?(path)` is the convenience wrapper most modules use.

Consumed by mod_suid (nosuid/squashfs filtering), mod_sysinfo (mount flag reporting), mod_docker (host mount detection), mod_nfs (active mount listing), and mod_files (severity consistency with mod_suid). See [DETECTION.md](DETECTION.md) for mount cross-referencing logic and SUID/SGID noise reduction.

### Shared Data properties

`Data.proc_status` caches `/proc/self/status` and is consumed by three modules: `Data.proc_caps` (Cap lines for mod_capabilities and mod_docker), mod_docker (seccomp/NoNewPrivs in escape context, CapAmb for ambient cap analysis), and mod_defenses (seccomp in system-level context). `Data.in_container?` caches container detection via marker files (`/.dockerenv`, `/.containerenv`) and cgroup string matching (docker, lxc, containerd, cri-o, podman, plus K8s secret directory), consumed by mod_docker and mod_defenses.

`Data.runc_pkg_version` and `Data.containerd_pkg_version` query the installed package version via `dpkg-query` or `rpm`, gated behind `Data.distro_family`. One spawn each, cached for the session. mod_docker uses these for runtime CVE version comparison.

## Detection logic

All module-level detection logic, severity classification, false positive reduction, and CVE coverage is documented in [DETECTION.md](DETECTION.md).

## Process spawn reduction

linPEAS is bash -- every command is a subprocess. The Crystal port avoids spawning where possible:

- `read_file()` replaces `cat` for all static file reads (`/etc/passwd`, `/etc/shadow`, `/proc` entries, cron files, etc.)
- `Dir.each_child` replaces `ls` for directory enumeration
- `Process.find_executable()` replaces `which` for binary existence checks
- `System.hostname`, `/proc/sys/kernel/osrelease`, `ENV.each` replace their shell equivalents
- Data layer caching ensures commands duplicated across modules (`id`, `ps`, `find -4000`, `/etc/sudoers`) run once
- Config file search uses a single `find` with combined `-o` predicates instead of 12 separate filesystem walks
- History and config file credential scanning uses `read_file()` + in-process regex instead of spawning grep
- `Data.ss_output` caches `ss -tulpn` for mod_software (internal service detection) and mod_network (listener enumeration) -- one spawn instead of two
- `Data.sshd_config` caches `/etc/ssh/sshd_config` for mod_software (directive analysis) and mod_creds (AuthorizedKeysFile expansion) -- one read instead of two
- `Data.mounts` replaces grep/mount spawns in mod_docker, mod_nfs, and provides mount data to mod_sysinfo and mod_suid
- `Data.proc_status` caches `/proc/self/status` -- Cap lines filtered in-process, seccomp/NoNewPrivs and ambient caps read from cached content
- `Data.runc_pkg_version` / `Data.containerd_pkg_version` cache package manager queries for runtime CVE checks -- one spawn each, gated behind `Data.distro_family`
- Container namespace isolation reads `/proc/1/comm`, `/proc/net/dev`, and hostname directly instead of spawning nsenter or other tools
- `Dir.each_child` replaces `ls` + `find -writable` in mod_services init.d enumeration
- `Data.sudo_l` spawns sudo directly via `Process.new` instead of routing through `/bin/sh` -- also closes stdin to prevent indefinite hangs on non-TTY reverse shells
- `/proc/net/tcp` hex parsing replaces ss/netstat for r-service port detection (512-514) -- kernel exposes TCP socket state directly, no spawn needed
- `aureport --tty` uses streaming `Process.new` with `Redirect::Pipe` instead of `run()` -- output consumed line-by-line with early break, not buffered in full
- `Data.resolv_conf` caches `/etc/resolv.conf` for mod_network and cloud indicator evaluation
- Firewall enumeration reads saved rule files instead of spawning `iptables -L` (requires root)
- Cloud active enumeration uses Crystal stdlib `HTTP::Client` directly (no curl/wget spawns)
- `/proc/modules` + `Dir.glob` on `/lib/modules/` replaces `lsmod` and `modinfo` for kernel module analysis
- Chroot, FD, and environ analysis reads `/proc/[pid]/root`, `fd/`, and `environ` directly instead of spawning `lsof` or `fuser`
- `/dev/` permission scan via `Dir.each_child` + `File.info?` instead of `find /dev`

