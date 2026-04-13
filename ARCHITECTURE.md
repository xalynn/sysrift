# Architecture

## Why Crystal

The primary reason is `crystal build --static` -- musl libc target, single binary, zero runtime dependencies. No interpreter, no shared libraries, nothing to install on the target. That's the operational advantage over Bash/Python/Ruby alternatives.

Crystal also enforces types at compile time while reading like Ruby. Union types and nil safety (`String?`, `if x = maybe_nil`) catch bugs before the tool reaches a target. Methods that shell out return `String` or `Array(String)` with explicit empty-string handling on failure, so there's no silent `nil` propagation through the enumeration logic.

On the performance side: compiled native code, value types on the stack, hash-backed `Set` for O(1) membership tests (GTFOBins lookup, group checks), `IO::Memory` for process output capture. All fixed data structures are top-level constants allocated once at program start.

### Why union types and nil safety matter here

Enumeration tools parse a lot of system output that may or may not exist. `/etc/shadow` might not be readable. `sudo -l` might return nothing. `getcap` might not be installed. In a dynamically typed language, a missing value silently becomes `nil` and propagates until something breaks at runtime -- on a target, during an engagement, with no debugger.

Crystal's type system forces you to handle these cases at compile time. `Data.shadow` returns `String` -- if the file isn't readable, it returns `""`, and every consumer handles that explicitly. `Hash#[]?` returns `String?` instead of raising on a missing key, so the compiler won't let you use the value without a nil check. `if m = line.match(regex)` narrows the type inside the block -- you can't accidentally access capture groups on a failed match.

The practical effect is that the binary either compiles cleanly or it doesn't. There's no class of "works on my machine but crashes on the target because some edge case returned nil." For a tool that needs to run reliably across unknown systems with no opportunity to debug, that tradeoff is worth the stricter syntax.

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
src/data.cr             -> Data module (lazy-cached system data, 30 properties, active_mode flag)
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

`Data.cloud_provider` and `Data.cloud_context` are cached cloud detection results. `detect_cloud` iterates `CLOUD_INDICATORS` (proc-based checks ordered by specificity -- container variants before host variants within each provider family) with DMI sysfs fallback. Detection runs once on first access. The provider string (e.g. `"aws_ecs"`, `"gcp"`, `"azure_app"`) is used by mod_cloud to dispatch to the correct active enumeration handler.

No disk persistence between runs -- each foothold starts fresh, which is correct behavior since the tool is designed to be re-run per user account context.

### Module isolation

Each of the 17 modules is a standalone function in its own file under `src/modules/`. Modules are pure consumers of the shared layers (constants, output, runner, data, utils) with no cross-module dependencies. Domain-specific checks live in their domain module -- cron writability in `mod_processes`, service writability in `mod_services`, security protection enumeration in `mod_defenses` -- rather than being centralized in a generic module. mod_cloud is the only module that imports an additional stdlib (`require "http/client"`) for active IMDS enumeration.

### Active enumeration mode

sysrift is passive by default -- 16 of 17 modules read files, parse /proc, and inspect system state without generating network connections or authentication events. Active enumeration is opt-in via `Data.active_mode?`. mod_cloud is the first module with active checks: IMDS credential harvesting generates HTTP requests to cloud metadata endpoints (169.254.169.254, 169.254.170.2, metadata.google.internal, and provider-specific identity endpoints).

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

Records every `hi()` and `med()` call during module execution. After modules complete, `Findings.summary` prints a severity-sorted digest -- critical findings first, then medium. The collector hooks transparently into the output helpers; modules require no changes. Findings are cleared between menu selections. Duplicate module selection (e.g., `1,1,3`) is deduplicated via `Set(Int32)`.

### Mount options and SUID cross-referencing

`Data.mounts` parses `/proc/mounts` into a sorted array of `NamedTuple(mount: String, fstype: String, opts: Set(String))`, longest mountpoint first. `Data.mount_for(path)` does a longest-prefix lookup to find the governing mount for any file path. `Data.nosuid_mount?(path)` is the convenience wrapper most modules use.

SUID/SGID findings are cross-referenced against mount flags. A SUID binary on a `nosuid` mount has its set-uid bit ignored by the kernel -- it cannot escalate. mod_suid downgrades these to `info()` and skips GTFOBins analysis. Writable SUID/SGID binaries on nosuid mounts are flagged at `med()` since they become exploitable if the mount is ever reconfigured. Binaries on squashfs mounts (snap, AppImage) are filtered entirely -- squashfs is read-only, the binary can't be replaced, and it runs in the image context.

SGID binaries are cross-referenced against `INTERESTING_GROUPS` via a GID-to-name mapping built from `/etc/group`. A SGID binary running as group `shadow` or `disk` is a lateral escalation path regardless of whether GTFOBins has a page for it — the group membership itself grants access. Fires at `med()` independently of the GTFOBins check, so a SGID `find` with group `disk` produces both the group context finding and the GTFOBins match.

### SUID shared library and strings analysis

Non-GTFOBins root-owned SUID binaries outside standard directories (`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/lib`, `/usr/lib64`, `/usr/libexec` and subdirs) get two additional passes when the tools are available:

**Shared library injection** via `readelf -d` (one spawn per binary). Parses both NEEDED entries and RPATH/RUNPATH from the dynamic section in a single pass. NEEDED libraries are resolved against RPATH dirs first, then `LIB_SEARCH_DIRS` (standard multilib and multiarch paths). Writable resolved .so or writable containing directory = hi(). Missing .so with a writable search dir = hi() (plant it). RPATH/RUNPATH pointing to a writable directory = hi(). RPATH/RUNPATH pointing to a non-existent directory with a writable parent = med() (requires mkdir first).

`ldd` was considered and rejected -- on glibc, `ldd` is a shell wrapper that executes the binary's ELF interpreter with `LD_TRACE_LOADED_OBJECTS=1`. For SUID binaries, the dynamic linker detects `AT_SECURE` and refuses to trace, producing no useful output. `readelf -d` is purely static analysis and works regardless of SUID or libc implementation.

**Strings analysis** via `strings` (one spawn per binary). Extracts the first whitespace-delimited token from each line, deduplicates, then checks two classes:

- Absolute paths: writable existing file = hi() (replace it). Missing file with writable parent = hi() (plant it). This catches hardcoded config paths, log paths, or helper binaries the SUID binary reads/writes.
- Relative command names: filtered through `STRINGS_NOISE` (common C symbol names like `free`, `main`, `read`), character class validation, and length minimum. Surviving tokens are resolved via `Process.find_executable` and cross-referenced against writable PATH directories. A writable PATH dir appearing before the resolved binary's directory = hi() (drop a hijacker). PATH position lookup uses a precomputed hash for O(1) access.

The standard directory prefix check limits spawn count to the handful of custom SUID binaries on a typical system -- packaged binaries in `/usr/bin` etc. have clean library dependencies and don't call relative paths.

mod_sysinfo reports mount flag coverage for key paths (`/`, `/tmp`, `/dev/shm`, `/var/tmp`, `/home`, `/opt`, `/srv`) -- where payloads would be dropped and executed. Unmounted `/etc/fstab` entries are flagged as potential remount targets. Credentials embedded in fstab (CIFS `password=`, `credentials=`, `authentication=`) are flagged at `hi()`.

The mount data is also consumed by mod_docker (host mount detection), mod_nfs (active NFS mount listing), and mod_files (SUID-outside-standard-paths respects nosuid mounts for severity consistency with mod_suid).

### Sudo pivot target analysis

When `sudo -l` reveals runas users (e.g., `(scriptmanager) NOPASSWD: ALL`), mod_sudo enumerates directories owned by those users outside system paths. This surfaces the access surface available after pivoting.

For each discovered directory, a top-level scan checks for root-owned files modified within 7 days. A root-owned recent file in a non-root-writable directory is strong evidence of a root cron job or systemd timer writing there -- modify the script the root process executes and you own root. On Bashed, `/scripts/test.txt` (root-owned, modified within the last minute) was the only observable indicator of the hidden root cron job.

Runas user extraction is scoped to `sudo -l` output only (what the current user can actually do), not sudoers files. The directory search is one `find` per pivot user, excluding system paths. The root ownership scan is `Dir.each_child` (top-level only, zero extra spawns) -- deeper analysis happens when sysrift is re-run under the pivoted user.

### Doas and sudo token reuse

mod_sudo also covers doas (OpenBSD's sudo replacement, increasingly common on minimal Linux installs). The key difference from sudo enumeration: `sudo -l` output is already scoped to the current user, but `doas.conf` contains rules for all users. So doas rules are filtered against the current user and `Data.groups` before severity assignment -- a `permit nopass alice as root` is hi() for alice and info() for everyone else. Group identities (`:wheel`, `:staff`) are resolved against the operator's group set. `keepenv` and `persist` are flagged independently -- linPEAS misses both.

Sudo token reuse detection is a combo-based assessment rather than individual findings. The attack (ptrace into a sibling shell holding a cached sudo timestamp, call `create_timestamp()` in its address space) requires four conditions: ptrace_scope=0, gdb present, at least one sibling interactive shell, and evidence of prior sudo use. Each condition alone is low-value noise. Only the combination is actionable -- hi() when all conditions are met, med() when gdb and shells are present but no cached token exists yet, info() or silent otherwise.

### Library search path writability

mod_writable parses `/etc/ld.so.conf` and recursively resolves its `include` directives to enumerate all directories in the dynamic linker's library search path. A writable directory in this path enables shared object injection into any dynamically linked SUID binary.

Four attack surfaces are checked: writable include directories (drop a new `.conf`), writable conf files (modify existing path entries), writable library directories (place malicious `.so` files), and writable parent directories of `/etc/ld.so.preload` entries (replace a preloaded library). All file reads and directory checks, no spawns.

mod_writable also checks `/proc/sys/fs/binfmt_misc/register` writability. A writable register file allows registering a binary format handler with the `credentials` flag, which causes the kernel to run the handler with the credentials of the triggering binary rather than the calling user -- effectively executing arbitrary code as root when a matching binary is run. This is also checked in mod_docker as a container escape surface (`ESCAPE_SURFACES_HI`); the mod_writable check covers the host context.

### D-Bus and PolicyKit enumeration

mod_dbus (module 16) targets the PolicyKit authorization layer rather than D-Bus message routing. The distinction matters: D-Bus `.conf` files in `/etc/dbus-1/system.d/` control which processes can send messages to which services, but PolicyKit is the actual authorization gate for privileged operations. A permissive D-Bus send rule still requires PolicyKit approval before anything dangerous happens.

Three attack surfaces are checked, all via file reads with zero spawns:

**PolicyKit JS rules** in `/etc/polkit-1/rules.d/` and `/usr/share/polkit-1/rules.d/` override the defaults set in `.policy` XML. A rule returning `polkit.Result.YES` bypasses authentication entirely for the matching action. The module parses each `.rules` file for `polkit.Result.YES` and `polkit.Result.AUTH_SELF`, then extracts group gates from the surrounding context (JS rules typically declare `subject.isInGroup()` or `subject.groups.indexOf()` within a few lines of the return). Group gates are cross-referenced against `Data.groups` to determine whether the current user qualifies. Ungated `YES` = hi() (any user, no auth). Group-gated where current user is a member = med() (user already authorized for a privileged action). Other group = info(). `AUTH_SELF` (own password, not admin) = info().

Rules files are processed in sorted order to reflect polkitd's lexical evaluation — `/etc/` rules override `/usr/share/` rules, and within a directory, `49-custom.rules` takes precedence over `50-default.rules`.

**Writable pkexec binaries and D-Bus activation binaries.** The `org.freedesktop.policykit.exec.path` annotation in `.policy` files names the binary that pkexec runs as root. A writable binary at that path is a direct hijack to root execution. D-Bus `.service` files in `/usr/share/dbus-1/system-services/` specify `Exec=` (activation binary) and `User=` (execution context). A writable service file can be modified to set `User=root` regardless of its current value. A writable `Exec=` binary where `User=root` is a direct hijack. `/bin/false` activation stubs are skipped.

**Config directory and file writability** across PolicyKit rules dirs, action dirs, D-Bus policy dirs, and service dirs. A writable directory allows dropping new configs — a single `.rules` file with `return polkit.Result.YES` creates an auth-free root execution path.

Scanning `.policy` XML for `allow_any=yes` / `allow_active=yes` was evaluated and rejected. On a typical desktop, 39 `allow_any=yes` actions (all read-only libvirt operations or self-targeting actions) and 130 `allow_active=yes` actions (standard desktop permissions) produce zero actionable findings. These are intentional package maintainer defaults. The JS rules analysis catches actual misconfigurations — custom or overridden authorization decisions that differ from the shipped defaults.

Crystal's `require "xml"` wraps libxml2 which pulls ICU dependencies with C++ symbols that fail under `--static` musl builds. All XML parsing is regex-based, which is sufficient for extracting the single `policykit.exec.path` annotation value from well-structured PolicyKit XML.

### Internal service detection

mod_software cross-references running processes against `INTERNAL_SERVICES` (8 entries: Gitea, Gogs, GitLab workhorse/puma, Jenkins, Grafana, Vault, Consul) and confirms with `Data.ss_output` listener data. Process name matching uses path delimiter (`/proc_name`) or space delimiter (` proc_name`) to avoid substring false positives -- `vault` shouldn't match a username or argument containing that string. Port matching uses a trailing space (`:3000 `) to prevent prefix collisions (3000 vs 30000). Results are deduplicated by service label since a standard GitLab install runs both `gitlab-workhorse` and `gitlab-puma`.

### Software-specific credential extraction

mod_creds scans known config paths for GitLab and Splunk credential patterns via `scan_app_config` -- a shared helper taking path arrays, a compiled regex, and a label. GitLab paths cover `gitlab.rb` (omnibus config), `gitlab-secrets.json`, and Rails `secrets.yml`/`database.yml`. Splunk paths cover `server.conf`, `web.conf`, `authentication.conf` for both full Splunk and forwarder installs. Splunk `pass4SymmKey` and `sslPassword` values are base64-encoded XOR ciphers crackable with `splunksecrets`, not proper hashes.

Log4j detection scans `/opt`, `/usr/share`, `/var/lib`, `/srv` for `log4j-core-*.jar` files via `find` (one spawn per directory, capped at 10 results). Jar filename version parsed and compared against the 2.17.1 fix threshold (CVE-2021-44228 through CVE-2021-44832).

### AD domain membership

Heuristic requiring 2+ indicators: `/etc/krb5.conf` `default_realm`, `/etc/sssd/sssd.conf` domain sections, nsswitch.conf `sss`/`winbind` tokens (word-boundary regex), AD-specific binaries (`realm`, `adcli`, `winbindd`, `sssd`, `adssod`). The Samba `net` binary was excluded -- too generic, present on non-AD file servers. Domain membership isn't directly exploitable but indicates Kerberos attack surface (keytabs, ticket caches, delegation) that mod_creds already enumerates.

### sshd_config and AuthorizedKeysFile

mod_software parses `/etc/ssh/sshd_config` via `Data.sshd_config` (cached, shared with mod_creds). Directive matching is case-insensitive per OpenSSH spec -- lowercase keys in constant, `directive.downcase` on lookup. Four directives: `PermitRootLogin yes` (med), `PermitEmptyPasswords yes` (hi), `PasswordAuthentication yes` (info), `AllowAgentForwarding yes` (med). Non-standard `AuthorizedKeysFile` paths reported at info().

mod_creds expands `%h` and `%u` tokens in `AuthorizedKeysFile` against `/etc/passwd` entries, then checks writability (hi -- inject SSH key) and readability (info). `Match` blocks are not parsed -- they can override global directives for specific users/addresses, but correct evaluation requires tracking block scope against the current context. The global-only parser catches the common case.

### Cloud environment detection and IMDS enumeration

mod_cloud (module 17) is split into passive detection (always runs) and active metadata harvesting (gated behind `Data.active_mode?`).

Passive detection follows the linPEAS pattern: environment variables and filesystem markers, not DMI/sysfs reads. ECS containers set `ECS_CONTAINER_METADATA_URI_v4`, Lambda sets `AWS_LAMBDA_*`, Azure App Service sets `IDENTITY_ENDPOINT` + `IDENTITY_HEADER` -- these are reliable, zero-cost, and work inside containers where DMI is unavailable. DMI (`/sys/class/dmi/id/sys_vendor`) is a fallback for bare-metal VMs without cloud-init markers. Detection order in `CLOUD_INDICATORS` is critical: container-specific variants (aws_ecs, aws_lambda, gcp_function, azure_app) are checked before host-level variants (aws_ec2, gcp, azure) since a container inside EC2 should identify as ECS, not EC2.

Active enumeration dispatches to per-provider handlers based on `Data.cloud_provider`. All HTTP uses Crystal stdlib `HTTP::Client` via `imds_request` -- a single helper handling method, scheme detection (HTTPS for Azure App Service identity endpoints), 2s timeouts, and `ensure` close to prevent socket leaks in non-cloud environments where every request times out.

The providers fall into two patterns. Most (AWS EC2, Azure VM, DigitalOcean, IBM) use the link-local 169.254.169.254 with provider-specific headers (`X-aws-ec2-metadata-token` for IMDSv2, `Metadata: true` for Azure, `Metadata-Flavor` for GCP/IBM). AWS container services (ECS, CodeBuild) use a separate link-local at 169.254.170.2 for task-level IAM credentials, constructed from `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` -- this is distinct from the host IMDS and is always accessible from within the container. Lambda is the outlier: no IMDS at all, STS credentials are injected directly into environment variables.

IMDSv2 is attempted first on EC2 (PUT for session token); if it fails, unauthenticated IMDSv1 GETs are used. From inside ECS containers, host IMDS reachability is tested but typically blocked by awsvpc's default hop-limit=1. IBM Cloud requires a two-step token exchange (instance identity → IAM token) before any metadata is accessible.

Cloud credential files (`~/.aws/credentials`, `~/.config/gcloud/`, `~/.azure/`) are scanned across all `/etc/passwd` home directories. Cloud CLI tool presence (aws, gcloud, az, doctl) is checked via `Process.find_executable`.

### Firewall rules enumeration

Firewall configuration is enumerated by `check_firewall` in mod_network rather than a standalone module -- firewall state is network context that informs pivoting and egress assessment.

The approach reads saved rule files instead of spawning `iptables -L` (which requires root). `FIREWALL_RULE_PATHS` covers iptables-persistent, legacy, RHEL/CentOS, and nftables paths. UFW and firewalld are detected via their own config files -- UFW's `ufw.conf` for enabled/disabled state and `user.rules` for the actual ruleset, firewalld's `firewalld.conf` for DefaultZone and the corresponding zone XML.

Kernel-level iptables presence is confirmed via `/proc/net/ip_tables_names` (lists loaded table names without requiring root). Output is capped at 40 lines per source via `dump_rules` -- hardened systems with extensive rulesets would otherwise dominate the report.

The fallback distinguishes "iptables tables loaded but no rule files readable" (info -- elevated privileges needed) from "no iptables tables and no firewall configs" (med -- no egress filtering).

### Container escape assessment

mod_docker (module 10) runs in two phases. The first checks runtime sockets and group membership unconditionally -- a Docker socket on the host is just as interesting as one mounted into a container. The second phase runs only inside containers (gated by `Data.in_container?`) and evaluates the escape surface.

Runtime sockets are checked across Docker, containerd, CRI-O, and Podman (rootful path from `RUNTIME_SOCKETS`, rootless path constructed from the current UID). An accessible socket is a direct breakout -- `docker run -v /:/mnt` or the containerd equivalent. Sockets that exist but aren't accessible still indicate the runtime is present.

Privileged container detection decodes CapBnd via `decode_caps` and verifies all 41 defined `CAP_BITS` are present. The earlier substring match on `ffffffff` missed non-aligned representations like `000001ffffffffff` -- the actual bitmask for a full set on current kernels.

Escape surface writability checks are split by severity in constants.cr (`ESCAPE_SURFACES_HI` and `ESCAPE_SURFACES_MED`). The cgroup release_agent check iterates `/sys/fs/cgroup` subdirectories since the agent path varies by subsystem. Ambient capabilities are parsed from the CapAmb line in `Data.proc_status` using the same `decode_caps` path as mod_capabilities -- no capsh dependency.

Namespace isolation uses behavioral heuristics. The obvious approach -- comparing inode numbers between `/proc/1/ns/*` and `/proc/self/ns/*` -- is invalid inside a container because PID 1 is the container's entrypoint, not the host init. Both symlinks resolve to the same container namespace. Instead: PID namespace checks `/proc/1/comm` against `HOST_INIT_NAMES` (systemd, init). NET namespace checks `/proc/net/dev` for physical NIC prefixes via `HOST_NIC_PREFIXES` -- predictable names (enp*, ens*, wlp*) never appear inside a default container namespace, so their presence is definitive `--net=host` evidence. UTS checks whether the hostname matches a 12-char hex container ID pattern.

MAC profile detection reads `/proc/self/attr/current` once. AppArmor profiles are plain names (`docker-default`, `unconfined`); SELinux contexts contain colons (`system_u:system_r:container_t:s0`). The `:` disambiguates which MAC system is active. `unconfined` or `unconfined_t` = med() (missing confinement layer in a container is a misconfiguration, unlike on a host where it's often the default). This runs separately from mod_defenses, which reports host-level MAC posture.

Runtime CVE checks for runc (CVE-2019-5736) and containerd (CVE-2020-15257) use `Data.runc_pkg_version` / `Data.containerd_pkg_version` -- dpkg or rpm queries, one spawn each, cached. CVE-2020-15257 only fires when host networking is confirmed via `host_net_shared?`, since the attack vector (abstract unix socket access to the host shim API) requires a shared network namespace.

The module also enumerates escape-relevant tools (nsenter, unshare, etc.) at info level and runs a soft heuristic on process count and host daemon presence to help characterize the environment.

## False positive reduction

### Credential scanning

Two-phase design. Shell grep finds candidate files (fast, broad), then Crystal re-matches each line and filters noise before reporting. Sentinel values in config syntax (`ask`, `*`, `none`, `files`, `systemd`), .NET assembly metadata (`PublicKeyToken=`), and delegate template variables are filtered post-match. The value filter extracts from the credential keyword's own `=:` match, not the first one on the line, preventing false drops when an earlier unrelated key-value pair has a sentinel value.

JS/JSON files are excluded from the broad scan -- desktop app bundles dominate the matches with code variable names, not credentials. A narrower JS/JSON pass runs only against `/var/www`, `/srv`, `/opt` where real database credentials live.

Files over 256 KB are skipped before reading, lines over 500 chars skipped during matching. Eliminates minified JS bundles and JSON blobs where `token`/`password` appear in code contexts.

History file matches are deduplicated by content with repeat counts. `File.info?` with nil-safe size check handles files that disappear between grep discovery and size check.

### Format-based secret scanning

A second scanning pass in mod_creds targets structured secrets that the keyword-based pattern misses. `SECRET_PATTERNS` contains 7 compiled regex patterns matched by format, not by a preceding keyword: AWS access keys (`AKIA` prefix + 16 uppercase alphanumeric), GCP service account JSON (`"type": "service_account"`), GitHub classic and fine-grained PATs (`ghp_`, `github_pat_` prefixes), GitLab PATs (`glpat-` prefix), Slack tokens (`xox[bpors]-` prefix), and PEM private key headers.

Same two-phase design: `grep -rIilE` with `SECRET_GREP_PRE` finds candidate files, Crystal regexes validate per-line. Same file size (256 KB) and line length (500 char) caps. `SECRET_SCAN_EXTS` extends the config extension set with `.json`, `.sh`, and `.js` so all extensions are covered in a single directory pass -- no second loop for web directories. File content is split once before the pattern loop to avoid redundant allocation. Yield fires once per file regardless of how many patterns match.

The grep pre-filter for GCP requires the JSON quote (`"service_account"` not `service_account`) to avoid false pre-filter hits on Python/Ruby source files with variables named `service_account_name` etc. These would be filtered by the Crystal regex anyway, but tightening the pre-filter reduces unnecessary file reads.

API keys and tokens fire `hi()` -- a confirmed AWS key or GitHub token is immediately exploitable. Private key headers fire `med()` -- may be legitimate system keys in `/etc/ssl/` or standard host keys.

### PAM, cached credentials, and audit logs

Three additional credential hunting strategies that don't use the grep-based two-phase pattern:

**PAM credential extraction** scans `/etc/pam.d/*` and standalone PAM/LDAP config files (`/etc/pam_ldap.conf`, `/etc/ldap.conf`, etc.) for module-specific credential parameters -- `passwd=` (pam_mysql), `bindpw` (pam_ldap/nslcd), `secret=` (pam_radius), `credentials=` (pam_mount). The regex uses equals-only matching to avoid false positives on standard PAM stack lines where `password` appears as a module type keyword. linPEAS greps for `passwd` across all pam.d files, which matches every `password required pam_unix.so` line on the system. Zero spawns.

**Cached credential files** checks readability of Samba TDB databases (`secrets.tdb` for machine account and trust passwords, `passdb.tdb` for local Samba users), Quest/Vintela AD bridge caches and keytabs, SSSD domain caches (`cache_*`), SSSD credential caches (`ccache_*`), SSSD secrets DB (`secrets.ldb` + `.secrets.mkey`), Kerberos ticket caches (`/tmp/krb5cc_*`), and `/etc/security/opasswd` (old password hashes from `pam_pwhistory`). Findings distinguish between hash-based files that need offline cracking and ticket/keytab material that's directly usable for authentication. Readable = hi(). Exists but not readable = info() (confirms domain join or Kerberos presence). Zero spawns.

**TTY audit harvesting** is gated behind auditd process detection -- if auditd isn't running, there's nothing to harvest and no spawn occurs. When active, `aureport --tty` is streamed via `Process.new` with `Redirect::Pipe` so lines are consumed as they arrive without buffering the full output. Only lines referencing `su` or `sudo` sessions are reported -- these contain typed passwords. A raw `/var/log/audit/audit.log` fallback handles systems where aureport isn't installed but the log is readable; it uses `File.open` + `each_line` to avoid loading potentially large audit logs into memory. The fallback only runs if aureport was unavailable or found nothing, preventing duplicate findings from the same data.

### SUID/SGID noise

- Binaries on `nosuid` mounts downgraded to `info()` -- kernel ignores the set-uid bit
- Binaries on squashfs mounts (snap, AppImage) filtered with summary count -- read-only filesystem, not replaceable
- Default install SUIDs (su, sudo, mount, umount, pkexec, newgrp, passwd, chpasswd, crontab) demoted to `med()` -- present on every system, inflate critical count without indicating misconfiguration
- chrome-sandbox skipped in unusual SUID location check -- no command interface, no GTFOBins entry, no known privesc CVEs
- UID 0 users: `root` filtered, check targets backdoor accounts (`toor`, `admin`, etc.)

### Cron analysis

- `/dev/null` skipped as writable binary target
- Cron target paths validated as regular files via `File.file?` -- world-writable directories are not binaries
- Wildcard injection covers `tar`, `chown`, `chmod` but not `find` (`find`'s `*` is a quoted `-name` argument, not a shell glob). Quoted sections (single and double) are stripped before matching to avoid false positives on patterns like `tar --exclude='*.tmp'` where the glob is a flag argument, not a shell-expanded wildcard
- Writable cron target severity accounts for the owning user: `/etc/crontab` and `/etc/cron.d` files have a user field -- root cron targets fire hi(), non-root (e.g., www-data) fire med(). User crontabs and cron script dirs don't have a user field and default to hi()

### Other noise reduction

- Environment variables use word-boundary regex -- `DB_PASSWORD` matches, `OLDPWD` / `XAUTHORITY` do not
- Log credential results grouped by filename with match count and one sample line per file
- Listening ports checked against `INTERESTING_PORTS` map; unmatched listeners listed without editorializing
- Writable service file paths resolved via `File.realpath` and deduplicated (handles Debian symlinks)
- SSH keys: ownership-aware severity. Own keys demoted to `info()`, other users' keys remain `hi()`
- `Data.path_dirs` deduplicates PATH before checking writability
- Screen/tmux session socket checks use `File::Info.writable?`, not `readable?` -- the kernel checks write permission on `connect(2)` to a Unix domain socket, so read permission is irrelevant for attachability
- Suspicious process location check (`/tmp`, `/dev/shm`, `/var/tmp`) filters own PID -- sysrift deployed to `/dev/shm` no longer flags itself

### Interpreter library path hijacking

mod_sysinfo checks `PYTHONPATH`, `RUBYLIB`, `PERL5LIB`, and `NODE_PATH` for writable directories, alongside the existing PATH writability check. The `INTERPRETER_LIB_VARS` constant maps each env var to its interpreter name for output clarity. A writable directory in an interpreter library path means any root cron or sudo rule invoking that interpreter will load attacker-controlled code -- same escalation pattern as `LD_PRELOAD` via `env_keep`, but through interpreter-specific mechanisms that bypass the dynamic linker's `AT_SECURE` protections on SUID binaries. Zero spawns -- `ENV` access and `Dir.exists?` + `File::Info.writable?`.

### Password policy

mod_users parses `/etc/login.defs` for `PASS_MAX_DAYS`, `PASS_MIN_DAYS`, `PASS_WARN_AGE`, and `ENCRYPT_METHOD`. `PASS_MAX_DAYS >= 99999` = med() (no password expiry). `ENCRYPT_METHOD` of `DES` or `MD5` = med() (weak hash algorithm -- crackable if hashes are obtained). Other values reported at info(). Silent skip if the file doesn't exist (containers, minimal installs). Single `read_file` with regex extraction, zero spawns.

## CVE detection

### Kernel CVEs

Kernel version is parsed into numeric components for correct range comparison (string comparison fails: `"5.10" < "5.9"` lexicographically). The patch component strips non-numeric suffixes (`"102-lts"` -> `102`, `"0-100-generic"` -> `0`). Components are parsed once and cached.

Detection uses a data-driven `KERNEL_CVES` registry in `constants.cr`. Each entry is a NamedTuple: `cve`, `name`, `ref`, `severity`, `distro_gate`, `fixed_versions`, `check`. Adding a CVE means appending a tuple -- no control flow changes.

#### Distro backport detection

Upstream kernel version matching alone produces false positives on distro kernels -- security patches are backported without version bumps. linPEAS flags 17 kernel CVEs on a 4.4.0-96 Ubuntu kernel, nearly all noise.

Each CVE entry carries `fixed_versions`: minimum patched package version per distro release, keyed as `"ubuntu_16.04"`, `"rhel_8"`, etc. The installed kernel package version is queried once via `dpkg-query` or `rpm -q` (cached in `Data.kernel_pkg_version`) and compared using Crystal-native dpkg/RPM version comparison (`dpkg_ver_compare`, `rpm_ver_compare` in `utils.cr`). Below the fixed version = vulnerable (full severity). At or above = patched (skip). When no fixed version matches, the upstream version range check fires instead -- downgraded to `med()` with a qualifier on recognized distros, full severity on unknown systems.

Derivative distros resolve to their parent via `/etc/os-release` fields `ID_LIKE` and `UBUNTU_CODENAME`. Mint/Pop/elementary map to Ubuntu LTS via `UBUNTU_CODENAME_MAP`, Rocky/Alma/CentOS map to RHEL major version. Package family detection uses `Process.find_executable("dpkg")` / `Process.find_executable("rpm")` rather than ID parsing -- derivatives inherit the package manager. `UBUNTU_CODENAME_MAP` covers LTS releases only (trusty through noble) -- non-LTS interim releases are rare on servers and match directly via `distro_release`.

The `distro_gate` field restricts a CVE to a specific distro family (e.g. `"ubuntu"` for GameOverlay, which only exists in Ubuntu's custom OverlayFS patches). The consumption loop skips gated entries unless `distro_release` or `distro_base` matches.

15 entries. DirtyCow (CVE-2016-5195), eBPF ALU32 (CVE-2021-3490), Dirty Pipe (CVE-2022-0847), OverlayFS FUSE (CVE-2023-0386), nf_tables OOB (CVE-2023-35001), nf_tables UAF (CVE-2024-1086), GameOverlay (CVE-2023-32629 + CVE-2023-2640), user namespace ID map (CVE-2018-18955), PTRACE_TRACEME (CVE-2019-13272), netfilter setsockopt (CVE-2021-22555), legacy_parse_param (CVE-2022-0185), cgroup release_agent (CVE-2022-0492), cls_route UAF (CVE-2022-2588), nf_tables set UAF (CVE-2022-32250).

CVE-2019-13272 has disjoint NVD ranges across LTS branches (4.4.40-4.4.185, 4.8.16-4.8.x, 4.9.1-4.9.185, 4.10-5.1.17) with per-branch fix points encoded in the check Proc. The nf_tables OOB check has four disjoint NVD ranges with explicit gap exclusions (4.15-4.19 and 5.11-5.15 not affected). CVE-2021-22555 and CVE-2022-2588 have broad upstream ranges where intermediate EOL branches (3.x, 4.5-4.8, 4.10-4.13, etc.) fall through to `else true` -- correct, as these branches were never patched. The GameOverlay entries have no upstream version range -- detection relies entirely on the distro fixed version comparison since the vulnerability is in Ubuntu-specific patches. All upstream ranges NVD-verified, all fixed versions sourced from Debian security tracker, Ubuntu CVE pages, and Red Hat RHSA errata (hydra API). Full provenance in `docs/kernel-cve-verification.md`.

### Userspace CVEs

`USERSPACE_CVES` in constants.cr -- same NamedTuple shape as `KERNEL_CVES` with `binary`, `pkg`, `distro_gate`, `fixed_versions`, and `check` fields. Version obtained from `binary --version` or `Data.pkg_version`. Same two-stage comparison: distro fixed version when available, upstream fallback with qualifier. 4 entries: CVE-2022-31214 (Firejail < 0.9.70), CVE-2024-48990 (needrestart < 3.8), CVE-2023-4911 (Looney Tunables glibc 2.34-2.39), CVE-2023-1326 (apport-cli, Ubuntu-only). All NVD-verified.

### Sudo CVEs

Sudo version is parsed into major, minor, patch, and p-level components to detect:

- **CVE-2019-14287** -- sudo < 1.8.28 (`sudo -u#-1` bypass). NVD verified.
- **CVE-2021-3156 Baron Samedit** -- sudo 1.8.2-1.8.31 and 1.9.0-1.9.5p1 (heap overflow). NVD verified.
- **CVE-2019-18634** -- sudo 1.7.1-1.8.25 with pwfeedback enabled. Version-gated: only flags when both pwfeedback is present and sudo version is vulnerable. NVD verified.
- **CVE-2023-22809** -- sudo 1.9.0-1.9.12p1 (sudoedit bypass via EDITOR env var, arbitrary file write as root). Scoped to 1.9.x only -- sudo 1.8.x is also technically vulnerable but already fires Baron Samedit which is higher impact. Avoids double-reporting on the same binary.

Additionally checks for `env_keep LD_PRELOAD` in both `sudo -l` output and `/etc/sudoers` using per-line matching.

### Polkit CVEs

pkexec version is parsed from `pkexec --version` output (single spawn, shared with PwnKit check):

- **CVE-2021-4034 PwnKit** -- polkit < 0.120 (argv overflow in pkexec -- root). NVD verified.
- **CVE-2021-3560** -- polkit 0.113-0.118 (D-Bus authentication bypass via timing, create privileged user without auth). Distinct mechanism from PwnKit -- 3560 is a race condition in the D-Bus response handling, 4034 is an argv parsing bug. Both use the same version output.

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

`Data.proc_status` caches `/proc/self/status` and is consumed by three modules: `Data.proc_caps` (Cap lines for mod_capabilities and mod_docker), mod_docker (seccomp/NoNewPrivs in escape context, CapAmb for ambient cap analysis), and mod_defenses (seccomp in system-level context). `Data.in_container?` caches container detection via marker files (`/.dockerenv`, `/.containerenv`) and cgroup string matching (docker, lxc, containerd, cri-o, podman, plus K8s secret directory), consumed by mod_docker and mod_defenses.

`Data.runc_pkg_version` and `Data.containerd_pkg_version` query the installed package version via `dpkg-query` or `rpm`, gated behind `Data.distro_family`. One spawn each, cached for the session. mod_docker uses these for runtime CVE version comparison.

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

