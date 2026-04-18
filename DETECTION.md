# Detection Logic

Module-level detection logic, false positive reduction, and CVE coverage. For architecture and data layer design, see [ARCHITECTURE.md](ARCHITECTURE.md). For build instructions, see [README.md](README.md).

## SUID / SGID analysis

### Mount cross-referencing

SUID/SGID findings are cross-referenced against mount flags. A SUID binary on a `nosuid` mount has its set-uid bit ignored by the kernel -- it cannot escalate. mod_suid downgrades these to `info()` and skips GTFOBins analysis. Writable SUID/SGID binaries on nosuid mounts are flagged at `med()` since they become exploitable if the mount is ever reconfigured. Binaries on squashfs mounts (snap, AppImage) are filtered entirely -- squashfs is read-only, the binary can't be replaced, and it runs in the image context.

SGID binaries are cross-referenced against `INTERESTING_GROUPS` via a GID-to-name mapping built from `/etc/group`. A SGID binary running as group `shadow` or `disk` is a lateral escalation path regardless of whether GTFOBins has a page for it -- the group membership itself grants access. Fires at `med()` independently of the GTFOBins check, so a SGID `find` with group `disk` produces both the group context finding and the GTFOBins match.

### Shared library and strings analysis

Non-GTFOBins root-owned SUID binaries outside standard directories (`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/lib`, `/usr/lib64`, `/usr/libexec` and subdirs) get two additional passes when the tools are available:

**Shared library injection** via `readelf -d` (one spawn per binary). Parses both NEEDED entries and RPATH/RUNPATH from the dynamic section in a single pass. NEEDED libraries are resolved against RPATH dirs first, then `LIB_SEARCH_DIRS` (standard multilib and multiarch paths). Writable resolved .so or writable containing directory = hi(). Missing .so with a writable search dir = hi() (plant it). RPATH/RUNPATH pointing to a writable directory = hi(). RPATH/RUNPATH pointing to a non-existent directory with a writable parent = med() (requires mkdir first).

`ldd` was considered and rejected -- on glibc, `ldd` is a shell wrapper that executes the binary's ELF interpreter with `LD_TRACE_LOADED_OBJECTS=1`. For SUID binaries, the dynamic linker detects `AT_SECURE` and refuses to trace, producing no useful output. `readelf -d` is purely static analysis and works regardless of SUID or libc implementation.

**Strings analysis** via `strings` (one spawn per binary). Extracts the first whitespace-delimited token from each line, deduplicates, then checks two classes:

- Absolute paths: writable existing file = hi() (replace it). Missing file with writable parent = hi() (plant it). This catches hardcoded config paths, log paths, or helper binaries the SUID binary reads/writes.
- Relative command names: filtered through `STRINGS_NOISE` (common C symbol names like `free`, `main`, `read`), character class validation, and length minimum. Surviving tokens are resolved via `Process.find_executable` and cross-referenced against writable PATH directories. A writable PATH dir appearing before the resolved binary's directory = hi() (drop a hijacker). PATH position lookup uses a precomputed hash for O(1) access.

The standard directory prefix check limits spawn count to the handful of custom SUID binaries on a typical system -- packaged binaries in `/usr/bin` etc. have clean library dependencies and don't call relative paths.

### Mount flag reporting

mod_sysinfo reports mount flag coverage for key paths (`/`, `/tmp`, `/dev/shm`, `/var/tmp`, `/home`, `/opt`, `/srv`) -- where payloads would be dropped and executed. Unmounted `/etc/fstab` entries are flagged as potential remount targets. Credentials embedded in fstab (CIFS `password=`, `credentials=`, `authentication=`) are flagged at `hi()`.

The mount data is also consumed by mod_docker (host mount detection), mod_nfs (active NFS mount listing), and mod_files (SUID-outside-standard-paths respects nosuid mounts for severity consistency with mod_suid).

## Sudo and privilege delegation

### Pivot target analysis

When `sudo -l` reveals runas users (e.g., `(scriptmanager) NOPASSWD: ALL`), mod_sudo enumerates directories owned by those users outside system paths. This surfaces the access surface available after pivoting.

For each discovered directory, a top-level scan checks for root-owned files modified within 7 days. A root-owned recent file in a non-root-writable directory is strong evidence of a root cron job or systemd timer writing there -- modify the script the root process executes and you own root. On Bashed, `/scripts/test.txt` (root-owned, modified within the last minute) was the only observable indicator of the hidden root cron job.

Runas user extraction is scoped to `sudo -l` output only (what the current user can actually do), not sudoers files. The directory search is one `find` per pivot user, excluding system paths. The root ownership scan is `Dir.each_child` (top-level only, zero extra spawns) -- deeper analysis happens when sysrift is re-run under the pivoted user.

### Doas and sudo token reuse

mod_sudo also covers doas (OpenBSD's sudo replacement, increasingly common on minimal Linux installs). The key difference from sudo enumeration: `sudo -l` output is already scoped to the current user, but `doas.conf` contains rules for all users. So doas rules are filtered against the current user and `Data.groups` before severity assignment -- a `permit nopass alice as root` is hi() for alice and info() for everyone else. Group identities (`:wheel`, `:staff`) are resolved against the operator's group set. `keepenv` and `persist` are flagged independently -- linPEAS misses both.

Sudo token reuse detection is a combo-based assessment rather than individual findings. The attack (ptrace into a sibling shell holding a cached sudo timestamp, call `create_timestamp()` in its address space) requires four conditions: ptrace_scope=0, gdb present, at least one sibling interactive shell, and evidence of prior sudo use. Each condition alone is low-value noise. Only the combination is actionable -- hi() when all conditions are met, med() when gdb and shells are present but no cached token exists yet, info() or silent otherwise.

## Writable file escalation

### Library search path writability

mod_writable parses `/etc/ld.so.conf` and recursively resolves its `include` directives to enumerate all directories in the dynamic linker's library search path. A writable directory in this path enables shared object injection into any dynamically linked SUID binary.

Four attack surfaces are checked: writable include directories (drop a new `.conf`), writable conf files (modify existing path entries), writable library directories (place malicious `.so` files), and writable parent directories of `/etc/ld.so.preload` entries (replace a preloaded library). All file reads and directory checks, no spawns.

mod_writable also checks `/proc/sys/fs/binfmt_misc/register` writability. A writable register file allows registering a binary format handler with the `credentials` flag, which causes the kernel to run the handler with the credentials of the triggering binary rather than the calling user -- effectively executing arbitrary code as root when a matching binary is run. Also checked in mod_docker as a container escape surface (`ESCAPE_SURFACES_HI`); the mod_writable check covers the host context.

### Logrotate abuse (logrotten race condition)

mod_writable parses `/etc/logrotate.conf` and all drop-in files in `/etc/logrotate.d/` to extract log file paths, then cross-references each path against current user writability. logrotate runs as root via cron/timer. When it rotates a log file using the `create` directive, there's a TOCTOU window between the old file being renamed and the new file being created -- an attacker who can write to the log file (or its parent directory) can exploit this race via symlink to achieve arbitrary file writes as root. The `logrotten` tool automates this.

The config parser handles the logrotate block format: paths appear on lines before `{`, directives live inside `{ ... }`. Multiple paths per line and inline `{` (e.g., `/var/log/nginx/*.log {`) are handled. `include` directives outside blocks are skipped (they're logrotate directives pointing to directories, not log paths). `copytruncate` is tracked per block and annotated on findings -- it copies then truncates in place rather than creating a new file, so the symlink race window is different.

Writability is checked on the log file itself (direct race target), on the parent directory (symlink plantable at the log path before rotation creates the new file), and for glob entries (`*.log`) on the containing directory. Severity: writable + logrotate ≤3.18.0 (upstream vulnerable ceiling, per HackTricks / linPEAS) = hi(). Writable + patched version = med() -- still worth noting for config-level issues like the CVE-2016-1247 nginx pattern where the log directory ownership was the root cause, not the logrotate version. Version queried once via `Data.pkg_version("logrotate")`.

### Login shell and MOTD script writability

mod_writable checks two directories where writable scripts lead to code execution on login:

**`/etc/profile.d/`** is sourced by `/etc/profile` on every login shell. Writable `.sh` files execute as the logging-in user. Directory writability checked first (drop a new script), then per-file writability. hi() for both.

**`/etc/update-motd.d/`** scripts are executed by `pam_motd.so` on SSH login. On default Ubuntu, PAM runs these as root -- other configurations may run them as the login user. The binary doesn't parse `/etc/pam.d/sshd` to confirm, so findings note "root on default Ubuntu" rather than asserting root unconditionally. `run-parts` executes all files regardless of extension (unlike profile.d which requires `.sh`), so no extension filter is applied. Files lacking the execute bit are annotated `[not +x]` -- `run-parts` skips non-executable files, but a writable file can be `chmod +x`'d by the operator. Directory writability = hi() (drop new script). File writability = hi(). Zero spawns.

### ACL enumeration

mod_writable runs `getfacl -t -s -R -p` across `/bin /etc /home /opt /root /sbin /tmp /usr` (one spawn) and parses the tabular output in-process. `-s` skips files with only base entries (no extended ACLs). `-p` forces absolute paths -- without it, getfacl prints relative paths during recursive traversal, breaking path-based severity classification.

The parser extracts lowercase `user` and `group` tags from each tabular line (uppercase `USER`/`GROUP` are base owner/group entries, not extended ACLs). Each named entry is cross-referenced against the current username and group set. linPEAS string-matches `$USER` against raw output -- it misses group-based ACL grants entirely (the HTB PermX pattern: setfacl granting group write on `/etc/passwd`).

Write ACL matching current user/groups on privileged targets (`ACL_PRIV_WRITE_TARGETS`: passwd, shadow, sudoers, crontab, environment, profile, bash.bashrc, ld.so.preload, ld.so.conf, plus `/etc/sudoers.d/*`) = hi(). Write ACL matching current identity on any other path = med(). Read ACL on sensitive targets (`ACL_SENSITIVE_READ_TARGETS`: shadow, root SSH keys, root history) = med(). Non-matching entries = info(), capped at 30. hi/med never capped.

Output streamed via `Process.new` pipe with 500KB byte cap (enterprise Samba/AD environments can produce 400KB+). Child reaped via `ensure`. Graceful fallback when `getfacl` not installed.

## D-Bus and PolicyKit

mod_dbus (module 16) targets the PolicyKit authorization layer rather than D-Bus message routing. D-Bus `.conf` files in `/etc/dbus-1/system.d/` control which processes can send messages to which services, but PolicyKit is the actual authorization gate for privileged operations. A permissive D-Bus send rule still requires PolicyKit approval before anything dangerous happens.

All via file reads, zero spawns:

**PolicyKit JS rules** in `/etc/polkit-1/rules.d/` and `/usr/share/polkit-1/rules.d/` override the defaults set in `.policy` XML. A rule returning `polkit.Result.YES` bypasses authentication entirely for the matching action. The module parses each `.rules` file for `polkit.Result.YES` and `polkit.Result.AUTH_SELF`, then extracts group gates from the surrounding context (JS rules typically declare `subject.isInGroup()` or `subject.groups.indexOf()` within a few lines of the return). Group gates are cross-referenced against `Data.groups` to determine whether the current user qualifies. Ungated `YES` = hi() (any user, no auth). Group-gated where current user is a member = med() (user already authorized for a privileged action). Other group = info(). `AUTH_SELF` (own password, not admin) = info().

Rules files are processed in sorted order to reflect polkitd's lexical evaluation -- `/etc/` rules override `/usr/share/` rules, and within a directory, `49-custom.rules` takes precedence over `50-default.rules`.

**Writable pkexec binaries and D-Bus activation binaries.** The `org.freedesktop.policykit.exec.path` annotation in `.policy` files names the binary that pkexec runs as root. A writable binary at that path is a direct hijack to root execution. D-Bus `.service` files in `/usr/share/dbus-1/system-services/` specify `Exec=` (activation binary) and `User=` (execution context). A writable service file can be modified to set `User=root` regardless of its current value. A writable `Exec=` binary where `User=root` is a direct hijack. `/bin/false` activation stubs are skipped.

**Config directory and file writability** across PolicyKit rules dirs, action dirs, D-Bus policy dirs, and service dirs. A writable directory allows dropping new configs -- a single `.rules` file with `return polkit.Result.YES` creates an auth-free root execution path.

Scanning `.policy` XML for `allow_any=yes` / `allow_active=yes` was evaluated and rejected. On a typical desktop, 39 `allow_any=yes` actions (all read-only libvirt operations or self-targeting actions) and 130 `allow_active=yes` actions (standard desktop permissions) produce zero actionable findings. These are intentional package maintainer defaults. The JS rules analysis catches actual misconfigurations -- custom or overridden authorization decisions that differ from the shipped defaults.

Crystal's `require "xml"` wraps libxml2 which pulls ICU dependencies with C++ symbols that fail under `--static` musl builds. All XML parsing is regex-based, which is sufficient for extracting the single `policykit.exec.path` annotation value from well-structured PolicyKit XML.

## Service and software detection

### Internal services

mod_software cross-references running processes against `INTERNAL_SERVICES` (9 entries: Gitea, Gogs, GitLab workhorse/puma, Jenkins, Grafana, Mattermost, Vault, Consul) and confirms with `Data.ss_output` listener data. Process name matching uses path delimiter (`/proc_name`) or space delimiter (` proc_name`) to avoid substring false positives -- `vault` shouldn't match a username or argument containing that string. Port matching uses a trailing space (`:3000 `) to prevent prefix collisions (3000 vs 30000). Results are deduplicated by service label since a standard GitLab install runs both `gitlab-workhorse` and `gitlab-puma`.

### Database services and credential testing

mod_software cross-references `Data.ps_output` against `DB_SERVICES` (mysqld, mariadbd, mysqld_safe, postgres) and confirms with `Data.ss_output` listener data. Root command lines are pre-extracted from ps once before the service loop. Process name matching uses `/proc_name` and ` proc_name` -- same pattern as internal service detection, no trailing space since ps output has no trailing delimiter.

A root-owned database service = med() regardless of active mode. MySQL/MariaDB running as root with valid credentials leads to UDF shared object loading -> root shell. PostgreSQL running as root allows `COPY ... PROGRAM` for command execution. MySQL and MariaDB are differentiated by label but share the wire protocol type for credential testing.

Active credential testing requires all three conditions: service detected in ps, port confirmed listening, client binary found via `Process.find_executable`. `DB_CLIENT_BINS` maps protocol types to candidate binaries (mysql -> [mysql, mariadb], pgsql -> [psql]). Missing client = info() skip.

`test_db_login` spawns the client with all three FDs closed -- only exit status matters. MySQL uses `--connect-timeout=2`, PostgreSQL uses `-w` with `PGPASSWORD` via the `env:` parameter. Each attempt has a 3s timeout via Channel+select; hung clients get SIGKILL. Returns on first successful login (hi()), cached in `Data.db_creds`.

### Software-specific credential extraction

mod_creds scans known config paths for credential patterns via `scan_app_config` -- a shared helper taking path arrays, a compiled regex, and a label. Comments (`#` and `;` prefixes) and blank lines are filtered before regex matching. The file path prints once as a hi() finding with matching lines indented beneath.

GitLab and Splunk paths are checked unconditionally (common enough to justify the stat calls). GitLab paths cover `gitlab.rb` (omnibus config), `gitlab-secrets.json`, and Rails `secrets.yml`/`database.yml`. Splunk paths cover `server.conf`, `web.conf`, `authentication.conf` for both full Splunk and forwarder installs. Splunk `pass4SymmKey` and `sslPassword` values are base64-encoded XOR ciphers crackable with `splunksecrets`, not proper hashes.

Mattermost, Gitea, Grafana, and Jenkins are only checked when the service is confirmed running in `Data.ps_output` or its home directory exists on disk. Mattermost config.json uses JSON `"Key": "Value"` format -- `DataSource` contains the MySQL connection string with embedded password, `SMTPPassword` and salt/encryption keys are separate entries. Gitea app.ini uses standard INI format (`PASSWORD`, `PASSWD`, `SECRET_KEY`, `INTERNAL_TOKEN`, `JWT_SECRET`) with three install paths checked. Grafana grafana.ini (`admin_password`, `password`, `secret_key`, `smtp_password`) relies on the semicolon comment filter to avoid false positives on the hundreds of `;`-prefixed default lines.

Jenkins gets dedicated handling because the attack surface is broader than a single config file. Home directory discovery checks `JENKINS_HOME_DIRS` (`/var/lib/jenkins`, `/opt/jenkins`) and per-user `~/.jenkins` via `Data.home_dirs`. Three opaque secret files are checked for readability: `secrets/master.key` (the AES key that decrypts all stored credentials), `secrets/hudson.util.Secret` (encryption seed), and `secrets/initialAdminPassword` (setup password). XML configs (`credentials.xml`, `config.xml`) are parsed for `<password>`, `<passphrase>`, `<secret>`, `<privateKey>`, `<secretBytes>` elements. Job-level `config.xml` files under `jobs/*/` are walked with a 20-hit cap to catch credential references in build step definitions. When the process is running but no home directory is found, absolute paths from known install locations are checked as a fallback.

linPEAS checks Jenkins (5 file types, recursive build.xml) and Grafana (grafana.ini) but not Mattermost or Gitea. linPEAS checks all paths unconditionally regardless of whether the service is running.

Log4j detection scans `/opt`, `/usr/share`, `/var/lib`, `/srv` for `log4j-core-*.jar` files via `find` (one spawn per directory, capped at 10 results). Jar filename version parsed and compared against the 2.17.1 fix threshold (CVE-2021-44228 through CVE-2021-44832).

### Database credential files

mod_creds scans known config paths for four database services. All pure file reads, zero spawns.

**Redis** checks three standard paths for `requirepass` and `masterauth` directives -- both plaintext passwords. `masterauth` is the replication password, often identical to `requirepass` or reusable for lateral movement. Readable redis.conf without auth directives = info() (Redis present, may use ACL-based auth or no auth at all).

**MySQL/MariaDB** checks system configs (`debian.cnf`, `my.cnf`) plus per-user `~/.my.cnf` and `~/.mylogin.cnf` across all home directories. `debian.cnf` is the primary target -- `debian-sys-maint` has full database access on Debian/Ubuntu installs. The parser tracks `user=` alongside `password=` within INI sections, resetting on `[section]` headers so a `[mysqld]` daemon user doesn't leak into the `[client]` password finding. `.mylogin.cnf` = hi() despite "encryption" -- fixed-key XOR, recoverable with `my_print_defaults`. `CRED_SENTINELS` filters placeholder values.

**PostgreSQL** checks `~/.pgpass` across all home directories. Format is `host:port:db:user:password` with `\:` for literal colons -- parsed via NUL-byte swap before split. Wildcard and empty passwords skipped. Capped at 5 entries per file.

**MongoDB** checks `/etc/mongod.conf` and `/etc/mongodb.conf` for `keyFile` -- the shared key used for replica set authentication. The referenced key file is often world-readable. `[:=]` alternation in `MONGO_CRED_RE` handles both legacy INI and YAML configs.

### Mail spool readability

mod_creds checks `/var/mail` and `/var/spool/mail` via `Dir.each_child`. Ownership compared against current UID: other users' readable mail = hi() (password resets, API keys, internal URLs), own mail = med(). Unreadable files silently skipped -- unreadable mail in the spool is the expected default, not worth reporting.

Readable files streamed via `File.open` + `each_line` (not `read_file`) to handle large mailboxes. First 200 lines scanned against `CRED_PATTERN_RE`, capped at 5 matches per file.

### Browser credential stores

mod_creds checks readability of browser credential stores across `Data.home_dirs`. Zero spawns -- pure `File::Info.readable?` stat checks per profile directory. No content reads.

**Firefox** iterates profile subdirectories under two base paths per home dir: `~/.mozilla/firefox/` (standard) and `~/snap/firefox/common/.mozilla/firefox/` (snap on Ubuntu). Three credential files checked per profile: `logins.json` (modern encrypted password store, JSON format with plaintext site URLs), `signons.sqlite` (legacy pre-Firefox 32 format, same data in SQLite), and `key4.db` (NSS master key database). `signons.sqlite` is only checked when `logins.json` is not readable, preventing double-fire on profiles that have both (upgrade residue). Severity: credential DB + key4.db = hi() (full offline decrypt via firepwd.py), credential DB alone = hi() (site URLs visible, passwords encrypted but extractable if master password is empty), key4.db alone = med() (master key without password entries -- lower immediate value).

**Chrome-family browsers** cover 8 browsers via `BROWSER_CHROME_BASES`: Chrome, Chromium, Brave, Vivaldi, Edge (stable/beta/dev), Opera. All use the same `~/.config/<browser>/` layout with profile subdirectories (`Default`, `Profile 1`, etc.). `Login Data` is the SQLite credential database in each profile. Readable = hi() -- decryptable offline if the user's login keyring is available (or trivially on headless systems where GNOME Keyring stores the key unprotected).

linPEAS comparison: linPEAS dumps entire directory listings per profile (50+ files per Chrome profile including favicons, cache, bookmarks) with uniform red highlighting. No readability gating, no severity differentiation, no per-file targeting. sysrift checks only the credential-bearing files and reports exactly what's exploitable.

### Password manager databases

mod_creds reads `Data.password_vault_files`, the walker's typed set of files matching `WALKER_VAULT_EXTS` (`.kdbx`, `.kdb`, `.psafe3`) across the post-skip-set filesystem. No per-module find spawn; coverage is filesystem-wide rather than scoped to home dirs + a fixed extra-dir list.

Readable database = hi(). These are offline-crackable: hashcat -m 13400 for `.kdbx`, keepass2john for `.kdb`, hashcat -m 5200 for `.psafe3`. Exists but not readable = info() (confirms password manager usage on target).

linPEAS comparison: linPEAS checks `.kdbx` plus KeePass config/ini/enforced files. Config and INI files contain UI preferences, not credentials -- excluded as noise. linPEAS does not detect `.psafe3`. linPEAS also fires on `.kdbx` via its generic `.db`/`.sqlite` scan with no dedup -- sysrift avoids double-fire by scoping to credential-bearing extensions only.

### Exposed .git directories

mod_creds checks for `.git/` directories in web roots and git credential files in home directories. Zero spawns -- pure stat checks and file reads.

`GIT_WEB_ROOTS` (`/var/www`, `/srv`, `/opt`) are walked two levels deep via `Dir.each_child` to catch both `/var/www/site/.git` (direct vhost) and `/var/www/html/app/.git` (Apache/nginx default docroot layout). A `.git/` directory in a web root = hi() -- full source recovery is possible via `git checkout`. When found, `.git/config` is read and scanned for embedded tokens via `GIT_TOKEN_RE` (matches `https://token@host` or `https://user:pass@host` patterns). SSH-style `git@` URLs don't match the regex.

Home directory checks iterate `Data.home_dirs` for `.git-credentials` and `.gitconfig`. Readable `.git-credentials` = hi() with full content dump (plaintext `https://user:token@host` entries, written by `git credential-store`). `.gitconfig` is checked for `helper = store` (med -- confirms `.git-credentials` exists with plaintext content) and for embedded token URLs (hi). `helper = cache` is excluded since it's memory-only with no file artifact.

linPEAS searches the entire filesystem for `.git`, `.github`, `.gitconfig`, `.git-credentials` -- this catches package artifacts in `/usr/share` and `/var/lib` that have no privesc value. linPEAS does not parse `.git/config` for embedded tokens and does not check `.gitconfig` for credential helper configuration. sysrift scopes to web roots and home dirs, and extracts the tokens that linPEAS misses.

### PHP session file enumeration

mod_creds checks readability of PHP session files belonging to other users. Zero spawns.

Five standard session directories are checked: `/tmp`, `/var/tmp`, `/var/lib/php/sessions`, `/var/lib/php5/sessions`, `/var/lib/php7/sessions`. Custom `session.save_path` values from php.ini are not parsed -- the standard paths cover the vast majority of deployments. Files are matched by `sess_*` prefix. Own-UID files are filtered out via `LibC.getuid` since the operator's own sessions have no value. `File.info?` is cached per file for a single stat syscall covering owner_id, size, and type.

Readable other-user session = med() (session hijack material -- the session ID itself may be reusable). Content is scanned against `PHP_SESSION_RE` for credential patterns (`password`, `passwd`, `token`, `auth`, `secret`, `credential` followed by `=`, `|`, or `:`) where the pipe matches PHP's serialized format separator (`password|s:10:"secret1234";`). A credential pattern match upgrades to hi(). A 256KB file size cap prevents reading oversized session dumps, and a 30-file iteration cap bounds runtime on busy PHP servers where thousands of session files may accumulate.

linPEAS dumps all session file content regardless of ownership with no filtering -- on a busy target this produces pages of serialized PHP data. sysrift filters to other-user files, only reports lines with credential patterns, and caps output volume.

### Wifi credentials

mod_creds walks `/etc/NetworkManager/system-connections/` and `/etc/wpa_supplicant/` (both the directory glob for `*.conf` and the singleton `/etc/wpa_supplicant.conf`). These files are root-owned and mode 600 on a healthy system — readability by a non-root process implies misconfiguration (ACL, group widening, or explicit chmod). Zero spawns.

Each readable file is line-scanned to collect SSID(s), an enterprise marker (`[802-1x]` section header or `key_mgmt=WPA-EAP` directive with the `-/_` variation and optional quoting), `psk=` lines, and `password=` lines. `WIFI_PSK_RE` and `WIFI_PASSWORD_RE` match on `keyword\s*=`, which naturally excludes NetworkManager's indirection markers (`psk-flags=0`, `password-flags=1`) because the hyphen is not whitespace. A 256 KB per-file size cap guards against booby-trapped large files.

Severity is dual-emit rather than branched: a file containing both a PSK network and an EAP network in separate `network={}` blocks (wpa_supplicant) fires both findings. WPA-Enterprise with a `password=` line = hi() (Enterprise passwords are often domain credentials used for 802.1x). PSK presence = med() (local wifi access only). Readable with neither = info(). SSID tag (deduplicated, comma-joined) appended to every finding for operator context. Up to 5 matching lines printed red-highlighted per category.

linPEAS greps `psk.*|password.*|ssid.*` with uniform red highlighting, no severity split, and no separation between Enterprise and PSK contexts.

### Terraform state and Terraform Cloud credentials

mod_creds reads `Data.tfstate_files`, the walker's typed set of files matching `WALKER_TFSTATE_EXTS` (`.tfstate`, `.tfstate.backup`) across the post-skip-set filesystem. No per-module find spawn.

Readable tfstate fires hi() with file size. Content is grep'd against `TFSTATE_SECRET_RE`, a broader pattern than linPEAS's `secret.*`: matches `password`, `passwd`, `secret`, `access_key`, `access-key`, `api_key`, `api-key`, `private_key`, `private-key`, `"token"`, `bearer`, `oauth`, and `"sensitive": true`. Intentional false positives: `"type": "aws_iam_access_key"` matches on `access_key` — accepted because knowing which AWS IAM resources exist in state is operational context. Content scan gated by 5 MB file size cap (avoids OOM on bloated state), 10 hits per file, 200 char truncation per line (base64 blobs and long certs truncate cleanly). Stat reads use `Data.stat_safe` for EACCES tolerance.

`credentials.tfrc.json` (Terraform Cloud / Enterprise API token) is checked per home dir as `<home>/.terraform.d/credentials.tfrc.json`. Readable = hi() with full content dump (file is small and contains bearer tokens with full org-level API access).

linPEAS finds `.tfstate` files and greps only `secret.*` — misses password, access_key, api_key, token, private_key, bearer, oauth, and the `"sensitive": true` marker. linPEAS also checks `credentials.tfrc.json` but lists `*.tf` source files which contain variable references, not secrets — sysrift drops the `*.tf` listing as noise.

### Docker registry credentials

mod_creds checks `<home>/.docker/config.json` across `Data.home_dirs`. This file contains base64-encoded `"auth":` strings (username:password for registry push/pull), bearer tokens in `"identitytoken":`, and registry-specific tokens in `"registrytoken":`. `DOCKER_INLINE_CRED_RE` matches any of these key:value pairs with a non-empty string value. Zero spawns.

Readable config with inline creds = hi() with the count of matching entries and up to 10 full match lines (base64 auth values and tokens printed verbatim). Readable config with only `credsStore` or `credHelpers` (external keyring offload — macOS Keychain, Windows Credential Manager, secret-service) = info(). Exists but unreadable = info().

linPEAS lacks this check entirely — the only Docker path it covers is the runtime socket.

### Kubeconfig host-side enumeration

mod_creds checks `KUBECONFIG_ETC_PATHS` (admin.conf, controller-manager.conf, scheduler.conf, kubelet.conf, bootstrap-kubelet.conf under `/etc/kubernetes/`) plus per-home `<home>/.kube/config`. On a K8s control-plane node, a readable `admin.conf` is full cluster-admin; worker nodes hold `kubelet.conf` (node identity). Zero spawns.

Content is scanned line-by-line (not `content.matches?` on whole content — Crystal's PCRE2 `^` anchor matches only string start without the `/m` flag, which would false-negative every real kubeconfig where credential fields appear 10+ lines into the `users:` block). `KUBECONFIG_EMBEDDED_RE` matches `token:`, `client-key-data:`, `client-certificate-data:`, or `password:` at the start of a line with optional leading whitespace. `KUBECONFIG_EXEC_RE` matches `exec:`.

Severity matrix is ownership-aware. `/etc/kubernetes/*` are always treated as system-level (no own annotation). Home-directory kubeconfig ownership is compared via `LibC.getuid` + `File.info?.try(&.owner_id)`:

- Embedded creds, not-own = hi() (someone else's cluster-admin reachable from here)
- Embedded creds, own = med() with `(own)` (the operator's own kubectl config — not escalation, but cluster context is useful)
- Exec plugin, not-own = med() (plugin binary writability is a separate concern noted in the finding message)
- Exec plugin, own = info() with `(own)`
- Cluster-context-only, not-own = med() (file exists, no visible creds, still useful endpoint info)
- Cluster-context-only, own = info() with `(own)`

linPEAS greps structural YAML keys (`server:|cluster:|namespace:|user:|exec:`) with uniform red highlighting — low-signal output with no severity differentiation and no ownership awareness.

### AI coding assistant credentials

mod_creds checks six paths per home dir against per-tool regexes. `AI_CRED_FILES` is an array of `{path, tool, re}` NamedTuples:

- `.codex/auth.json` — `AI_CODEX_RE`: `access_token|refresh_token|id_token|OPENAI_API_KEY|api_key|auth_mode`
- `.claude.json`, `.claude/settings.json`, `.claude/settings.local.json` — `AI_CLAUDE_RE`: `apiKeyHelper|ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN|Authorization|Bearer|"token"|"secret"`
- `.cursor/mcp.json` — `AI_CURSOR_RE`: `Authorization|Bearer|"token"|api_key|"secret"`
- `.gemini/oauth_creds.json` — `AI_GEMINI_RE`: `access_token|refresh_token|oauth|client_secret|GEMINI_API_KEY|GOOGLE_API_KEY`

Match = med() — these tokens pivot into paid AI services and any codebases shared through those services (MCP file access, GitHub repos authorized via OAuth). Up to 5 matching lines per file printed red-highlighted, 200 char truncation. Zero spawns.

`mcpServers` (Claude) and `headers` (Cursor) are deliberately excluded from the alternations. They are feature markers, not credential markers — a `.claude/settings.json` with MCP server config and no inline tokens would match on `mcpServers` alone and fire a spurious "claude credentials" finding. Actual tokens inside MCP configs are still caught via `Bearer`, `Authorization`, `"token"`, or `"secret"`.

linPEAS covers the same paths with similar regexes but includes `mcpServers` and `headers` as match branches, producing false positives on MCP-configured-but-token-free files.

### GPG private key material

mod_creds checks each home in `Data.home_dirs` for two GPG private-key artifacts:

- `~/.gnupg/private-keys-v1.d/` — GnuPG 2.1+ key store. Per-key files have `.key` extension. Presence of any `.key` is the finding. Counted via `Dir.each_child` filtered on `ends_with?(".key")`.
- `~/.gnupg/secring.gpg` — legacy keyring (GnuPG < 2.1). Filtered by non-zero size — an empty `secring.gpg` is a stub from a pre-import installation and not a true private-key artifact.

Severity matches the SSH private-key pattern in the same module:

- Readable + other-owner = `hi()` — direct decryption of pass-store, signed mail, etc.; commit-signing impersonation
- Readable + own-owner = `info()` with `(own)` tag — operator already holds the key in their session; finding is informational for lateral pivot (the key may unlock secrets the current shell context wasn't intended to decrypt)
- Exists + not readable = `info()` with `(not readable)` qualifier
- Directory exists but not traversable (mode 700, other owner) = `info("GPG private key dir exists (not traversable)")` — emitted when stat succeeds but `File::Info.readable?` AND `File::Info.executable?` both fail. Without the explicit guard the previous logic silently dropped this case via the rescue around `Dir.each_child`.

`~/.password-store/` presence (GNU `pass` vault) is detected alongside; when present, every finding for that home appends ` (unlocks pass vault)` as operator pivot context. Pass-store is GPG-encrypted — readable private key on the same home recovers the entire vault.

linPEAS runs `gpg --list-keys` and `gpg --list-secret-keys` (two spawns) plus filename matches for `.pgp`, `.gpg`, `.asc`, `secring.gpg`, `pubring.kbx`, `trustdb.gpg`, `gpg-agent.conf`, `private-keys-v1.d/*.key`, and `.gnupg`. sysrift skips the `gpg --list-secret-keys` spawn deliberately — it touches `~/.gnupg/S.*` agent sockets and may log to `~/.gnupg/log` per `gpg-agent.conf`. sysrift also scopes coverage to private-key material only (the card title is "GPG **private key** enumeration"); encrypted data files (`.pgp`, `.gpg`, `.asc`), public-key databases (`pubring.kbx`), and trust databases (`trustdb.gpg`) are skipped — they're not private-key artifacts and inflate output without enabling escalation. Alternate GPG home paths (`~/.pgp`, `~/.openpgp`, `~/.config/gpg`) are uncommon and currently not checked; tracked as a low-priority KANBAN follow-up.

### Certificates and private key files

mod_creds reads two walker-backed typed sets: `Data.cert_keystore_files` (extension match on `CERT_KEYSTORE_EXTS = .p12 .pfx .jks .keystore`) and `Data.cert_pemkey_files` (extension match on `CERT_TEXT_EXTS = .pem .key`). Coverage is filesystem-wide; walker inode dedup eliminates the need for path-level dedup at the consumer.

`/etc/ssl/certs` is excluded by the consumer (not the walker) for the PEM/key set only — the public CA bundle expansion is 100+ files on Debian/Ubuntu and would drown the section with `info("Readable cert/key (no PRIVATE header)")` for every per-CA `.pem`. Keystores `.p12`/`.pfx`/`.jks`/`.keystore` never ship in CA bundles, so no filter needed there. linPEAS makes the same `/etc/ssl/certs` omission for the same reason.

Two extension classes drive the severity logic:

- **Binary keystores** (`.p12`, `.pfx`, `.jks`, `.keystore`): readability is the finding — these formats have no ASCII header to peek and always carry private-key material by file format. Uniform `hi()` when readable, no ownership demotion. Matches the password-manager-DB pattern: extract and crack the outer passphrase offline regardless of who owns the file. linPEAS does not check `.p12` or `.pfx` — sysrift closes that gap.
- **Text PEM/key** (`.pem`, `.key`): peek the first 512 bytes for `-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----` (`CERT_PRIVATE_KEY_RE`). The non-capturing group is optional — PKCS#8 unencrypted keys (`BEGIN PRIVATE KEY`) match without a prefix. PEM headers always live on line 1 (~30 bytes), so 512 bytes is generous overhead. Match + other-owner = `hi()`; match + own-owner = `info()` with `(own)` tag (ownership check uses `Data.stat_safe` for EACCES tolerance). No header = `info("Readable cert/key (no PRIVATE header)")` — likely public cert or chain.

The peek uses `File.open` + `Bytes.new(CERT_PEEK_BYTES)` + `io.read(buf)` rather than `read_string(CERT_PEEK_BYTES)`. The latter raises `IO::EOFError` for files shorter than the peek size, which is the common case for `.key` files (a typical `id_ed25519` is ~400 bytes). The `Bytes` form returns the actual byte count and `String.new(buf[0, n])` constructs a string from whatever was read.

### EACCES safe-stat helpers

`Data.dir_exists?(path)` and `Data.file_exists?(path)` wrap `File.info?(path)` with `rescue File::Error` and narrow the result on `info.directory?` / `info.file?`. Stdlib `Dir.exists?` and `File.exists?` raise `File::AccessDeniedError` when stat returns EACCES — only ENOENT is swallowed by the `?` variant. The helpers swallow both, treating unreachable paths as "not present" — the operationally correct semantics for an enumeration tool that walks unknown permission topology on a target. `Data.stat_safe(path) : File::Info?` is the same pattern but returns the full `File::Info` for callers that need size, owner_id, or mtime.

The crash surfaces on a non-root caller hitting `Dir.exists?("/root/.jenkins")` in `check_jenkins_creds`: `/root` is mode 700 on standard Debian/Ubuntu, so stat on any child requires the search bit on `/root` itself, which the caller lacks. Same risk applies to `/etc/ssl/private` (mode 710 root:ssl-cert by default), `/etc/ipsec.d/private` on hardened Strongswan installs, and any directory with restrictive parent permissions.

`Data.home_dirs` itself uses the helpers (and the `File::Info.executable?(home)` predicate) to filter out unreachable homes at construction time. Adopted across the credential-hunting helpers in mod_creds, the sudoers and doas helpers in mod_sudo, the home-dir + `.ssh` gates in mod_users (the canonical mode-700 crash site from a non-owner caller), and the logrotate target gates in mod_writable. Remaining unwrapped stdlib calls live under `/etc/*` standard paths, `/proc`, `/sys`, and `/var/log` direct-children — places where the parent dir is canonically world-searchable and EACCES is structurally improbable.

### AD domain membership

Heuristic requiring 2+ indicators: `/etc/krb5.conf` `default_realm`, `/etc/sssd/sssd.conf` domain sections, nsswitch.conf `sss`/`winbind` tokens (word-boundary regex), AD-specific binaries (`realm`, `adcli`, `winbindd`, `sssd`, `adssod`). The Samba `net` binary was excluded -- too generic, present on non-AD file servers. Domain membership isn't directly exploitable but indicates Kerberos attack surface (keytabs, ticket caches, delegation) that mod_creds already enumerates.

### sshd_config and AuthorizedKeysFile

mod_software parses `/etc/ssh/sshd_config` via `Data.sshd_config` (cached, shared with mod_creds). Directive matching is case-insensitive per OpenSSH spec -- lowercase keys in constant, `directive.downcase` on lookup. Four directives: `PermitRootLogin yes` (med), `PermitEmptyPasswords yes` (hi), `PasswordAuthentication yes` (info), `AllowAgentForwarding yes` (med). Non-standard `AuthorizedKeysFile` paths reported at info().

mod_creds expands `%h` and `%u` tokens in `AuthorizedKeysFile` against `/etc/passwd` entries, then checks writability (hi -- inject SSH key) and readability (info). `Match` blocks are not parsed -- they can override global directives for specific users/addresses, but correct evaluation requires tracking block scope against the current context. The global-only parser catches the common case.

### Screen/tmux session hijacking

mod_software scans for other users' attachable screen and tmux sessions. Screen sockets live in `/run/screen/S-<user>/` (and `/var/run/screen/`); tmux sockets live in `/tmp/tmux-<uid>/`. The kernel checks write permission on `connect(2)` to a Unix domain socket, so `File::Info.writable?` is the correct test for attachability -- not `readable?`.

Screen sessions are identified by the `S-` prefix on subdirectories. Tmux sessions require UID-to-username resolution via `/etc/passwd` since the directory name is `tmux-<uid>`. The current user's own sessions are filtered. Root sessions = hi() (attach and execute as root). Other users' sessions = med() (lateral movement).

## Network enumeration

### Cloud environment detection and IMDS

mod_cloud (module 17) is split into passive detection (always runs) and active metadata harvesting (gated behind `Data.active_mode?`).

Passive detection follows the linPEAS pattern: environment variables and filesystem markers, not DMI/sysfs reads. ECS containers set `ECS_CONTAINER_METADATA_URI_v4`, Lambda sets `AWS_LAMBDA_*`, Azure App Service sets `IDENTITY_ENDPOINT` + `IDENTITY_HEADER` -- these are reliable, zero-cost, and work inside containers where DMI is unavailable. DMI (`/sys/class/dmi/id/sys_vendor`) is a fallback for bare-metal VMs without cloud-init markers. Detection order in `CLOUD_INDICATORS` is critical: container-specific variants (aws_ecs, aws_lambda, gcp_function, azure_app) are checked before host-level variants (aws_ec2, gcp, azure) since a container inside EC2 should identify as ECS, not EC2.

Active enumeration dispatches to per-provider handlers based on `Data.cloud_provider`. All HTTP uses Crystal stdlib `HTTP::Client` via `imds_request` -- a single helper handling method, scheme detection (HTTPS for Azure App Service identity endpoints), 2s timeouts, and `ensure` close to prevent socket leaks in non-cloud environments where every request times out.

The providers fall into two patterns. Most (AWS EC2, Azure VM, DigitalOcean, IBM) use the link-local 169.254.169.254 with provider-specific headers (`X-aws-ec2-metadata-token` for IMDSv2, `Metadata: true` for Azure, `Metadata-Flavor` for GCP/IBM). AWS container services (ECS, CodeBuild) use a separate link-local at 169.254.170.2 for task-level IAM credentials, constructed from `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` -- this is distinct from the host IMDS and is always accessible from within the container. Lambda is the outlier: no IMDS at all, STS credentials are injected directly into environment variables.

IMDSv2 is attempted first on EC2 (PUT for session token); if it fails, unauthenticated IMDSv1 GETs are used. From inside ECS containers, host IMDS reachability is tested but typically blocked by awsvpc's default hop-limit=1. IBM Cloud requires a two-step token exchange (instance identity -> IAM token) before any metadata is accessible.

Cloud credential files (`~/.aws/credentials`, `~/.config/gcloud/`, `~/.azure/`) are scanned across all `/etc/passwd` home directories. Cloud CLI tool presence (aws, gcloud, az, doctl) is checked via `Process.find_executable`.

### Firewall rules

Firewall configuration is enumerated by `check_firewall` in mod_network rather than a standalone module -- firewall state is network context that informs pivoting and egress assessment.

The approach reads saved rule files instead of spawning `iptables -L` (which requires root). `FIREWALL_RULE_PATHS` covers iptables-persistent, legacy, RHEL/CentOS, and nftables paths. UFW and firewalld are detected via their own config files -- UFW's `ufw.conf` for enabled/disabled state and `user.rules` for the actual ruleset, firewalld's `firewalld.conf` for DefaultZone and the corresponding zone XML.

Kernel-level iptables presence is confirmed via `/proc/net/ip_tables_names` (lists loaded table names without requiring root). Output is capped at 40 lines per source via `dump_rules` -- hardened systems with extensive rulesets would otherwise dominate the report.

The fallback distinguishes "iptables tables loaded but no rule files readable" (info -- elevated privileges needed) from "no iptables tables and no firewall configs" (med -- no egress filtering).

### Legacy r-commands trust

mod_network checks for rsh/rlogin/rexec trust relationships -- legacy remote access that predates SSH and authenticates by hostname+username without a password. `/etc/hosts.equiv` and `/etc/ssh/shosts.equiv` are read for `+` wildcard entries (trust all hosts) and specific host entries. Per-user `.rhosts` files are scanned across `Data.home_dirs`. Active r-service listeners are detected by parsing `/proc/net/tcp` for ports 512-514 (exec/login/shell) in LISTEN state -- no `ss` or `netstat` spawn needed. inetd and xinetd configs are scanned for enabled rsh/rlogin/rexec service definitions. Wildcard trust (`+` in hosts.equiv) = hi(). Active r-service listeners = med(). Specific host trust and config file presence = info().

## Container escape

mod_docker (module 10) runs in two phases. The first checks runtime sockets and group membership unconditionally -- a Docker socket on the host is just as interesting as one mounted into a container. The second phase runs only inside containers (gated by `Data.in_container?`) and evaluates the escape surface.

Runtime sockets are checked across Docker, containerd, CRI-O, and Podman (rootful path from `RUNTIME_SOCKETS`, rootless path constructed from the current UID). An accessible socket is a direct breakout -- `docker run -v /:/mnt` or the containerd equivalent. Sockets that exist but aren't accessible still indicate the runtime is present.

Privileged container detection parses CapBnd as `UInt64` and checks for a contiguous run of 1-bits from bit 0 — the binary representation must have no `'0'` character and ≥30 bits set. `--privileged` semantics on Linux: the kernel grants every capability it defines, which is always a contiguous bit run from 0 up to the kernel's max cap (~36 on Linux 3.x, ~38 on 4.x, 41 on 5.9+). The contiguous-bits check works across kernel versions; comparing against a fixed set of named caps would miss legacy targets where the kernel defines fewer caps than sysrift's `CAP_BITS` table knows about. Threshold of 30 filters out unprivileged contexts that naturally retain a handful of caps.

Escape surface writability checks are split by severity in constants.cr (`ESCAPE_SURFACES_HI` and `ESCAPE_SURFACES_MED`). The cgroup release_agent check iterates `/sys/fs/cgroup` subdirectories since the agent path varies by subsystem. Ambient capabilities are parsed from the CapAmb line in `Data.proc_status` using the same `decode_caps` path as mod_capabilities -- no capsh dependency.

Namespace isolation uses behavioral heuristics. The obvious approach -- comparing inode numbers between `/proc/1/ns/*` and `/proc/self/ns/*` -- is invalid inside a container because PID 1 is the container's entrypoint, not the host init. Both symlinks resolve to the same container namespace. Instead: PID namespace checks `/proc/1/comm` against `HOST_INIT_NAMES` (systemd, init). NET namespace checks `/proc/net/dev` for physical NIC prefixes via `HOST_NIC_PREFIXES` -- predictable names (enp*, ens*, wlp*) never appear inside a default container namespace, so their presence is definitive `--net=host` evidence. UTS checks whether the hostname matches a 12-char hex container ID pattern.

MAC profile detection reads `/proc/self/attr/current` once. AppArmor profiles are plain names (`docker-default`, `unconfined`); SELinux contexts contain colons (`system_u:system_r:container_t:s0`). The `:` disambiguates which MAC system is active. `unconfined` or `unconfined_t` = med() (missing confinement layer in a container is a misconfiguration, unlike on a host where it's often the default). mod_defenses reports host-level MAC posture separately.

Runtime CVE checks for runc (CVE-2019-5736) and containerd (CVE-2020-15257) use `Data.runc_pkg_version` / `Data.containerd_pkg_version` -- dpkg or rpm queries, one spawn each, cached. CVE-2020-15257 only fires when host networking is confirmed via `host_net_shared?`, since the attack vector (abstract unix socket access to the host shim API) requires a shared network namespace.

The module also enumerates escape-relevant tools (nsenter, unshare, etc.) at info level and runs a soft heuristic on process count and host daemon presence to help characterize the environment.

Host filesystem mounts (non-container filesystems filtered by `CONTAINER_IGNORE_FS`) are checked for writability. A writable host mount is a direct pivot path -- write to the host's crontab, drop a SUID binary, plant an SSH key. Writable = hi(). Read-only = med(). `File::Error` rescue handles the TOCTOU race where a mount disappears between `/proc/mounts` parse and writability check.

User namespace mapping is read from `/proc/self/uid_map`. A mapping of `0 0 4294967295` (or any count > 65535 with both UIDs at 0) means the full host UID range is mapped without remapping -- container processes run as their literal host UIDs. med() for no remapping. info() otherwise.

Container network pivot context surfaces the next hop for the operator. `/proc/net/fib_trie` is parsed for locally-assigned IPs -- the Local table has addresses on `|--` lines preceding their `/32 host LOCAL` leaf, so the parser tracks the last-seen address and emits it when LOCAL follows. `pending_addr` is reset on any `/32` leaf to prevent stale carryover from BROADCAST entries. Loopback (127.x) filtered, remaining addresses classified by RFC1918 range (172.16/12 for Docker bridge/overlay, 10/8 for container networks, 192.168/16 for bridges). `/proc/net/arp` lists adjacent hosts on the container bridge -- in containers, ARP neighbors are almost always sibling containers. `/etc/hosts` is parsed for container-injected entries (Docker and Podman inject linked container entries and the host gateway); loopback filtered via `PIVOT_HOSTS_SKIP`, self-references filtered via hostname match. All info(), all zero spawns. mod_creds annotates SSH private key findings with "(container -- pivot candidate)" when `Data.in_container?` -- keys inside containers often bridge to sibling containers or the host (HTB Ariekei, HTB Ghoul).

When inside a K8s pod (`in_k8s`), the module enumerates the service account token (readability = med, content not dumped to output), pod namespace, and CA cert presence. `kubectl auth can-i --list` is parsed for RBAC permissions using a trailing regex (`\[([^\]]*)\]\s*$`) to extract the verbs column -- positional split is unreliable because intermediate `[]` columns collapse under whitespace splitting. Each verb+resource pair is checked against `K8S_DANGEROUS_RBAC` (20 entries with API group qualifiers for non-core resources like `deployments.apps`, `cronjobs.batch`). Wildcard verbs on `*.*` = hi() (cluster admin equivalent). `kubectl get` enumerates secrets, pods, services, and nodes, each gated by `kubectl auth can-i list` -- the list verb is what `kubectl get` requires, not get. Readable secrets = hi(). kubectl path is resolved once via `Process.find_executable` and passed to both functions; when absent, RBAC reports info() and resource enumeration is skipped entirely.

## NFS

mod_nfs parses `/etc/exports` line-by-line. `no_root_squash` = hi() -- mount the export as root from an attacker-controlled machine, plant a SUID binary, execute on target for instant root. `no_all_squash` = med() -- UID matching allows file access as any local user. `showmount -e` is attempted with a 5-second timeout (prevents hangs when NFS isn't running). Active NFS mounts are pulled from `Data.mounts` filtered by fstype containing `nfs`, reported with mount options.

## Users and groups

**Password policy** from `/etc/login.defs`: `PASS_MAX_DAYS >= 99999` = med() (no expiry). `ENCRYPT_METHOD` of DES or MD5 = med() (weak hash -- crackable if /etc/shadow is obtained). Case-insensitive comparison via `String#compare`. Single `read_file` with regex extraction.

**UID 0 backdoor detection** iterates `/etc/passwd` for non-root users with UID 0. `root` itself is filtered -- the check targets `toor`, `admin`, or any other UID 0 account added as a persistence mechanism. Fires hi().

**Home directory scanning** enumerates `/home/*` for readable directories (med). SSH files in each readable home are severity-split by ownership: own keys = info() (expected), other users' private keys = hi() (credential theft). Ownership comparison uses `File.realpath` on both the current user's `$HOME` and the scanned directory, with `File::Error` rescue fallback for broken symlinks.

## Services

mod_services checks for writable systemd unit files, systemd PATH hijack conditions, and writable init.d scripts.

Systemd units (.service and .timer) are scanned across `/etc/systemd/system`, `/lib/systemd/system`, and `/usr/lib/systemd/system` via `each_systemd_unit` -- a two-level `Dir.each_child` walk that covers top-level files and one subdirectory depth for `.wants/` dirs (zero spawns, replaces `find -writable`). Symlinked subdirectories are skipped to avoid traversal loops; file symlinks are followed via `read_file`. Paths are resolved via `File.realpath` and deduplicated (Debian uses symlinks from `/etc/systemd/system` into `/lib/systemd/system` -- without dedup, the same file fires twice). Writable unit = hi(). File contents tee'd for operator context.

**Systemd PATH hijack.** In the same iteration, ExecStart/ExecStartPre/ExecStartPost directives are parsed. Systemd exec prefixes (`@`, `!`, `+`, `-`) are stripped before checking whether the command starts with `/`. Non-absolute commands are collected and deduped by realpath. Separately, `/proc/1/environ` (PID 1 = systemd/init) is read for the PATH variable. Writable PATH dir + relative ExecStart = hi() (drop a binary in the writable dir, systemd resolves it via PATH on next service restart). Writable PATH dir alone = med(). Falls back gracefully when `/proc/1/environ` is unreadable (requires root or CAP_SYS_PTRACE).

init.d scripts are enumerated via `Dir.each_child("/etc/init.d")`. Writable scripts = hi(). All script names listed at info() regardless of writability for situational awareness.

## Interesting files

**Sensitive config files** read from `Data.sensitive_configs` (walker-backed; basename match against `CONFIG_NAMES` — wp-config.php, database.yml, .env, tomcat-users.xml, etc.). Consumer-side `File::Info.readable?` filter restores grep's `-readable` predicate. **Backup files** (`.bak`, `.backup`, `.old`, `.orig`, `.save`, `.swp`) read from `Data.backup_files`, capped at first 20 — stale backups often contain credentials from before a password rotation. **Root's SSH keys and history** checked directly by path for readability.

**SUID outside standard paths** iterates `Data.suid_files` filtering anything under `/usr`, `/bin`, `/sbin`. `chrome-sandbox` is skipped (no command interface, no known privesc). Nosuid mounts respected via `Data.nosuid_mount?` for severity consistency with mod_suid.

**Log credential scanning** reads `Data.log_files` (walker-backed; path-prefix match against `WALKER_LOG_DIR_PATHS = ["/var/log/", "/var/logs/"]`) and applies `LOG_KEYWORD_RE` (`password|passwd|credential|secret|token`, case-insensitive) per line in-process. NUL-byte check on first 4KB skips compressed rotated archives (.gz/.xz) without shelling out to a decompressor. `ArgumentError` rescue catches Latin-1-encoded logs whose 0x80+ bytes break Crystal's UTF-8 regex requirement. 50 MB per-file size cap, 50 file emission cap. Results: one finding per file with match count + first matching line. **Recently modified files** (last 10 minutes) listed at info() excluding virtual filesystems via `Data.recent_files`.

## False positive reduction

### Credential scanning

Walker emits an extension-based candidate pool (`Data.cred_scan_files`, 15 extensions); mod_creds buckets candidates by (dir, scan-type) in one pass and dispatches per-bucket arrays to `scan_cred_keywords` and `scan_secret_patterns`. Each helper applies content regex per file in-process. Sentinel values in config syntax (`ask`, `*`, `none`, `files`, `systemd`), .NET assembly metadata (`PublicKeyToken=`), and delegate template variables are filtered post-match. The value filter extracts from the credential keyword's own `=:` match, not the first one on the line, preventing false drops when an earlier unrelated key-value pair has a sentinel value.

`CRED_EXT_SET` and `CRED_JS_EXT_SET` partition the keyword scan: generic config extensions (`.conf`, `.ini`, `.env`, `.php`, `.py`, etc.) are scanned in `/etc /var/www /opt /srv /home /root`; `.js`/`.json` are scanned only in `/var/www`, `/srv`, `/opt` where real database credentials live (desktop app bundles in home dirs would dominate matches with code variable names, not credentials).

NUL-byte check on first 4KB of file content skips binary blobs (e.g., `.json` with embedded encoded keys); Crystal's regex engine raises on non-UTF-8 input, so an `ArgumentError` rescue around per-line regex matches catches the rarer Latin-1-encoded text case where no NUL bytes appear but 0x80+ bytes break the UTF-8 requirement.

Files over 256 KB are skipped via `Data.stat_safe(path).try(&.size)` before reading, lines over 500 chars skipped during matching. Eliminates minified JS bundles and JSON blobs where `token`/`password` appear in code contexts.

History file matches are deduplicated by content with repeat counts. Each `(dir, scan-type)` bucket caps at 15 file emissions to bound output volume.

### Format-based secret scanning

mod_creds runs a format-based scan for structured secrets with known prefixes or shapes. `SECRET_PATTERNS` contains 7 compiled regex patterns matched by format, not by a preceding keyword: AWS access keys (`AKIA` prefix + 16 uppercase alphanumeric), GCP service account JSON (`"type": "service_account"`), GitHub classic and fine-grained PATs (`ghp_`, `github_pat_` prefixes), GitLab PATs (`glpat-` prefix), Slack tokens (`xox[bpors]-` prefix), and PEM private key headers.

Same walker-backed pipeline as the keyword scan: `Data.cred_scan_files` provides the candidate pool, `scan_secret_patterns` applies all 7 patterns per file in-process. `SECRET_SCAN_EXT_SET` is the broader 15-extension whitelist (adds `.json`, `.sh`, `.js` to the keyword set) — captures formats where AWS keys and tokens commonly land. Same file size (256 KB) and line length (500 char) caps. File content is split once before the pattern loop to avoid redundant allocation. Yield fires once per file regardless of how many patterns match.

API keys and tokens fire `hi()` -- a confirmed AWS key or GitHub token is immediately exploitable. Private key headers fire `med()` -- may be legitimate system keys in `/etc/ssl/` or standard host keys.

### PAM, cached credentials, and audit logs

Additional credential sources, each with its own parsing strategy:

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
- Writable cron target severity accounts for the owning user: `/etc/crontab` and `/etc/cron.d` files have a user field -- root cron targets fire hi(), non-root (e.g., www-data) fire med(). Cron script dirs (cron.daily etc.) run as root, default to hi(). User crontabs (`crontab -l`) use `root_context: false` -- writable targets still fire but remote command and non-standard path checks are skipped since the entries run as the current user, not root
- Root cron entries matching `CRON_REMOTE_RE` (ssh, scp, sftp, rsync) flagged at med() as redirect/MITM opportunities -- an operator with network position can intercept the connection or redirect it to a controlled host
- Non-writable root cron targets outside `STANDARD_BIN_PREFIXES` flagged at info() -- worth reversing even if not directly exploitable. Gated behind `File::Info.executable?` to filter data file arguments matched by the path regex (e.g., `/var/lib/aptitude/pkgstates` is a regular file, not a binary)

### Non-standard root binary detection

mod_processes iterates `Data.ps_output` (cached `ps aux`) for root processes whose resolved binary path falls outside `STANDARD_BIN_PREFIXES` -- `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/lib`, `/usr/lib64`, `/usr/libexec`, `/etc/init.d`, `/snap`, `/var/lib/snapd`, `/var/lib/flatpak`. Deduped by path (multiple root processes for the same binary = one finding). med() -- the binary runs as root and isn't from a standard package location, making it a target for manual analysis (strings, ltrace, reversing).

This catches the HTB Insane pattern (Smasher, Rope, PlayerTwo, etc.) where the privesc vector is a custom binary that no GTFOBins list will match. linPEAS surfaces a similar signal via "Binary processes permissions" (ownership-based); sysrift uses location-based heuristics (zero spawns, no package manager queries).

Allowlist rationale: `/snap/` and `/var/lib/flatpak/` are read-only squashfs mounts -- not writable, not reversing targets, no known privesc uses a binary under these paths. `/etc/init.d/` scripts are distro-managed.

### Process surface analysis

mod_processes walks `/proc` once per PID:

**Chroot jails.** `/proc/[pid]/root` resolves to the process's root directory. Anything other than `/` means a chroot. Detected jails are cross-referenced against `Data.suid_files` -- a SUID binary visible from inside the jail is a breakout vector (the kernel honors the set-uid bit regardless of the chroot boundary).

**Open file descriptors.** `/proc/[pid]/fd` symlinks are resolved to real paths. Virtual FDs (pipes, sockets, anon_inodes) are dropped by checking the target starts with `/` and isn't under `/dev/` or `/proc/`. The remaining targets are filtered by extension (`SENSITIVE_FD_EXTS` -- .pem, .key, .keytab, .shadow, .p12, etc.) and directory (`SENSITIVE_FD_DIRS` -- /etc/, /root/, /home/, /opt/, /srv/, /var/lib/, /var/run/). Only FDs held by other users pointing to files the current user can't read are reported -- this catches cross-user credential leaks via FD inheritance. `.conf` and `.db` were dropped from the extension set after testing showed excessive noise from system library FDs. Extracted as `scan_open_fds` with a yield block.

**Process environment variables.** `/proc/[pid]/environ` (NUL-delimited) is read for non-root, non-self processes. Keys are matched against `SENSITIVE_ENV_RE`. Deduplicated by `uid:key` -- a `SECRET_TOKEN` set by a service manager would otherwise fire for every forked worker. Values are masked in output (first 8 chars + `...`). The dedup key omits the value so credentials don't persist in the tool's memory.

### Process sampling for hidden cron discovery

mod_processes polls `/proc` for new PIDs over 60 seconds at 100ms intervals when active mode is enabled -- a pspy equivalent using pure /proc reads instead of repeated `ps` spawns.

A baseline PID set is captured before the loop. Each iteration scans `Dir.each_child("/proc")` for numeric entries not in the baseline, reads `/proc/[pid]/cmdline` (NUL bytes -> spaces) and `/proc/[pid]/status` for the UID. Kernel threads (empty or `[bracketed]` cmdline) are filtered. Own PID excluded.

Deduplication keys on `uid:cmdline[0..200]` -- not PID. PIDs recycle over 60 seconds; a PID-keyed hash would silently drop distinct processes reusing a freed PID. linPEAS handles this the same way (`sort | uniq -c` on full process lines). The 200-char prefix cap bounds memory without losing command specificity. UID->username resolution is a hash built once from `Data.passwd` before sampling starts.

Output sorted by first-seen offset. Root = med(), others = info(). Long commands truncated at 200 chars.

100ms is 2x slower than linPEAS's 50ms but still catches sub-second processes. linPEAS spawns `ps` 1210 times; /proc readdir is a single `getdents` per iteration. 60 seconds captures at least one cycle of any 1-minute cron job.

### PATH broken symlink detection

mod_sysinfo checks for two conditions: a dangling symlink as the PATH directory itself (creating the target directory intercepts all lookups in that position), and broken symlinks to individual binaries inside writable PATH dirs (creating the target intercepts calls to that command). The per-binary scan only runs in writable PATH dirs -- stale `/etc/alternatives` entries in `/usr/bin` aren't exploitable and would just generate noise.

### Other noise reduction

- Environment variables use word-boundary regex -- `DB_PASSWORD` matches, `OLDPWD` / `XAUTHORITY` do not
- Log credential results grouped by filename with match count and one sample line per file
- Listening ports checked against `INTERESTING_PORTS` map; unmatched listeners listed without editorializing
- Writable service file paths resolved via `File.realpath` and deduplicated (handles Debian symlinks)
- SSH keys: ownership-aware severity. Own keys demoted to `info()`, other users' keys remain `hi()`. Container pivot annotation added when `Data.in_container?`
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

mod_capabilities cross-references the specific binary against a `DANGEROUS_CAP_COMBOS` map. `cap_setuid` on an unknown binary is worth noting; `cap_setuid` on python is `os.setuid(0)` -- instant root. The combo map has 43 entries across 11 capabilities, each verified against GTFOBins to confirm the binary can actually leverage the specific capability (unlike linPEAS which maps all GTFOBins-capabilities binaries to cap_setuid/cap_setgid regardless).

Severity is split: `hi()` for combos that yield direct root (setuid(0) via interpreters, kernel module loading, arbitrary file write), `med()` for two-step paths (cap_setfcap granting caps to another binary, cap_setpcap modifying own caps) and packet capture.

### Process capability enumeration

mod_capabilities also enumerates all `/proc/[pid]/status` files for processes with non-zero CapEff or CapAmb. A privileged process with `cap_sys_ptrace` is an injection target regardless of whether file capabilities are set.

Hex capability bitmasks are decoded natively via a `CAP_BITS` constant (41 entries mapping bit positions from `linux/capability.h`). This replaces `capsh --decode` which spawns up to 5 times per flagged process and is absent on minimal containers -- exactly where process capability enumeration matters most.

Filtering: uid=0 processes where CapEff matches CapBnd are skipped -- the default kernel-granted set on bare metal, which would otherwise produce hundreds of noise findings. The filter preserves detection of root processes with unusual grants (CapEff divergent from CapBnd) and all non-root processes with any capabilities. Inside containers where the bounding set is restricted, root processes with capabilities are correctly flagged.

Severity uses `HI_CAPS` -- a Set of 9 capabilities that yield direct root or equivalent without additional steps (`cap_setuid`, `cap_sys_admin`, `cap_sys_ptrace`, `cap_sys_module`, `cap_dac_override`, `cap_dac_read_search`, `cap_sys_rawio`, `cap_bpf`, `cap_setgid`). Remaining dangerous capabilities produce `med()`. Processes with only non-dangerous capabilities report as `info()`.

Three filters demote expected caps to `info()`:

- **Chromium/Electron sandbox** -- `cap_sys_admin` from `clone(CLONE_NEWUSER)` for renderer namespacing. Only demoted when it's the sole dangerous cap on a process matching `CHROMIUM_SANDBOX_NAMES` running as the current user -- anything beyond that still fires normally.
- **SUID helpers** (fusermount3, fusermount) -- inherit full cap set briefly from the SUID bit during mount ops.
- **Known daemon caps** -- `KNOWN_DAEMON_CAPS` maps daemons to their expected caps (e.g., rtkit-daemon gets `cap_dac_read_search` for PulseAudio scheduling). Caps outside the expected set still fire.

## Security protections

mod_defenses (module 15) reports active defenses on the target. This shapes interpretation of findings from every other module -- a kernel CVE match with ASLR disabled is more actionable than one with full ASLR.

20 checks across mandatory access control (AppArmor, SELinux), address space protections (ASLR, mmap_min_addr), kernel exposure (kptr_restrict, dmesg_restrict, perf_event_paranoid), process isolation (ptrace_scope, seccomp), filesystem hardening (protected_symlinks, protected_hardlinks), namespace and eBPF controls (unprivileged_userns_clone, unprivileged_bpf_disabled), module loading restrictions (modules_disabled, module_sig_enforce), kernel lockdown mode, and legacy protections (grsecurity, PaX).

All procfs/sysfs reads. Seccomp status comes from `Data.proc_status` (shared with mod_docker), gated by `Data.in_container?` to avoid duplicating mod_docker's escape-context seccomp report.

### Kernel module and /dev/ enumeration

mod_defenses also enumerates loaded kernel modules and device node permissions -- both are indicators of custom attack surface that standard privesc tools miss.

**Kernel module analysis** parses `/proc/modules` and cross-references each loaded module against `.ko` files under `/lib/modules/<krel>/`. The glob covers the full tree -- `kernel/`, `updates/` (DKMS), `extra/`, `misc/` -- because out-of-tree modules like nvidia install to `updates/dkms/` and would be false positives if only `kernel/` were scanned. Module basenames are normalized with `tr("-", "_")` since the kernel uses underscores in `/proc/modules` (`snd_hda_intel`) while `.ko` filenames use hyphens (`snd-hda-intel.ko.zst`). Containers typically lack `/lib/modules/` entirely; when the tree is absent, loaded modules are listed at info() without comparison.

**Permissive /dev/ entries** scans `/dev` and one level into non-standard subdirectories for world-writable or group-writable devices. `STANDARD_DEV_NAMES` and prefix-based filtering (`dev_entry_standard?` -- sd*, vd*, nvme*, tty*, loop*, ram*, dm-*, sr*) exclude standard kernel devices. `STANDARD_DEV_DIRS` skips known subsystem directories (block, bus, char, disk, input, mapper, etc.). Group-writable entries are checked against `Data.groups` via a cached `/etc/group` GID->name map. The scan goes one level deep because custom kernel modules can create devices in subdirectories -- HTB RopeTwo's `/dev/ralloc` was created by a vulnerable LKM and was the userspace entry point to a ring-0 exploit.
