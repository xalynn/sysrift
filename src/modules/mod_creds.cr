def mod_creds : Nil
  section("Credential Hunting")

  tee("#{Y}History files:#{RS}")
  Data.history_files.each do |f|
    next unless File::Info.readable?(f)
    content = read_file(f)
    next if content.empty?
    line_count = content.count('\n').to_s
    med("#{f}  (#{line_count} lines)")
    counts = Hash(String, Int32).new(0)
    content.split("\n").each { |l| counts[l] += 1 if l.matches?(CRED_PATTERN_RE) }
    unless counts.empty?
      hi("  Interesting lines in #{f}:")
      counts.first(20).each do |l, n|
        suffix = n > 1 ? " (x#{n})" : ""
        tee("    #{R}#{l}#{RS}#{suffix}")
      end
    end
  end

  # Bucket walker candidates by (dir, scan-type) in one pass so each
  # scan helper iterates a small per-dir slice instead of the full
  # candidate set.
  cred_prefix_map = {
    "/etc/"     => "/etc",
    "/var/www/" => "/var/www",
    "/opt/"     => "/opt",
    "/srv/"     => "/srv",
    "/home/"    => "/home",
    "/root/"    => "/root",
  }
  js_prefix_map = {
    "/var/www/" => "/var/www",
    "/srv/"     => "/srv",
    "/opt/"     => "/opt",
  }
  cred_buckets   = Hash(String, Array(String)).new { |h, k| h[k] = [] of String }
  js_buckets     = Hash(String, Array(String)).new { |h, k| h[k] = [] of String }
  secret_buckets = Hash(String, Array(String)).new { |h, k| h[k] = [] of String }

  Data.cred_scan_files.each do |path|
    lower = path.downcase
    cred_prefix_map.each do |prefix, dir|
      next unless path.starts_with?(prefix)
      cred_buckets[dir] << path   if CRED_EXT_SET.any?       { |ext| lower.ends_with?(ext) }
      secret_buckets[dir] << path if SECRET_SCAN_EXT_SET.any? { |ext| lower.ends_with?(ext) }
      break
    end
    js_prefix_map.each do |prefix, dir|
      next unless path.starts_with?(prefix)
      js_buckets[dir] << path if CRED_JS_EXT_SET.any? { |ext| lower.ends_with?(ext) }
      break
    end
  end

  blank
  tee("#{Y}Config files with credential patterns:#{RS}")
  # `[]?` rather than `[]` — a missing key means no candidates, not
  # an empty bucket to allocate.
  cred_prefix_map.each_value do |dir|
    if candidates = cred_buckets[dir]?
      scan_cred_keywords(candidates)
    end
  end
  js_prefix_map.each_value do |dir|
    if candidates = js_buckets[dir]?
      scan_cred_keywords(candidates)
    end
  end

  blank
  tee("#{Y}Hardcoded secrets:#{RS}")
  secret_hit = false
  cred_prefix_map.each_value do |dir|
    if candidates = secret_buckets[dir]?
      scan_secret_patterns(candidates) { secret_hit = true }
    end
  end
  ok("No hardcoded secrets found") unless secret_hit

  blank
  tee("#{Y}Password files:#{RS}")
  shadow = Data.shadow
  if shadow.empty?
    ok("/etc/shadow not readable (expected)")
  else
    hi("/etc/shadow is READABLE!")
    shadow.split("\n").each do |line|
      parts = line.split(":")
      hi("  Hash: #{line}") if parts.size >= 2 && !LOCKED_HASH_MARKERS.includes?(parts[1]) && !parts[1].empty?
    end
  end

  Data.passwd.split("\n").each do |line|
    parts = line.split(":")
    hi("/etc/passwd contains hash: #{line}") if parts.size >= 2 && !LOCKED_HASH_MARKERS.includes?(parts[1]) && !parts[1].empty?
  end

  my_uid = LibC.getuid
  pivot = Data.in_container? ? " (container — pivot candidate)" : ""
  Data.ssh_private_keys.each do |k|
    unless File::Info.readable?(k)
      info("Private key (not readable): #{k}")
      next
    end
    if File.info?(k).try(&.owner_id) == my_uid.to_s
      info("Readable private key (own): #{k}#{pivot}")
    else
      hi("Readable private key: #{k}#{pivot}")
    end
  end

  check_nonstandard_authkeys

  Data.netrc_files.each do |f|
    next unless File::Info.readable?(f)
    hi(".netrc (plaintext creds): #{f}")
    tee(read_file(f))
  end

  home = ENV["HOME"]? || "/root"
  ["#{home}/.aws/credentials", "#{home}/.aws/config", "/root/.aws/credentials",
   "#{home}/.config/gcloud/credentials.db", "#{home}/.azure/credentials"].uniq.each do |p|
    if File.exists?(p) && File::Info.readable?(p)
      hi("Cloud creds readable: #{p}")
      tee(read_file(p))
    end
  end

  check_pam
  check_cached_creds
  check_tty_audit
  check_software_creds
  check_db_cred_files
  check_mail_spool
  check_browser_profiles
  check_password_manager_dbs
  check_git_exposure
  check_php_sessions
  check_wifi_creds
  check_terraform_state
  check_docker_registry
  check_kubeconfig
  check_ai_assistant_creds
  check_gpg_private_keys
  check_cert_key_files
end

private def check_pam : Nil
  blank
  tee("#{Y}PAM credential patterns:#{RS}")
  found = false

  if Dir.exists?("/etc/pam.d")
    Dir.each_child("/etc/pam.d") do |name|
      conf = "/etc/pam.d/#{name}"
      next unless File::Info.readable?(conf)
      scan_pam_file(conf) { found = true }
    end
  end

  PAM_CRED_CONFIGS.each do |conf|
    next unless File.exists?(conf) && File::Info.readable?(conf)
    scan_pam_file(conf) { found = true }
  end

  ok("No PAM credential patterns found") unless found
end

private def check_tty_audit : Nil
  blank
  tee("#{Y}TTY audit passwords:#{RS}")
  unless Data.ps_output.matches?(/\bauditd\b/)
    ok("auditd not running")
    return
  end

  found = false

  # TTY keylogger records capture passwords typed during su/sudo
  if Process.find_executable("aureport")
    n = 0
    begin
      ar = Process.new("aureport", args: ["--tty"],
        output: Process::Redirect::Pipe,
        error: Process::Redirect::Close)
      ar.output.each_line do |entry|
        next unless entry.includes?("su ") || entry.includes?("sudo ")
        hi("TTY keystroke capture: #{entry.strip}")
        found = true
        n += 1
        break if n >= 20
      end
      ar.output.close
      ar.wait
    rescue IO::Error | File::Error
    end
  end

  # raw audit log fallback when aureport unavailable or found nothing
  unless found
    auditlog = "/var/log/audit/audit.log"
    if File.exists?(auditlog) && File::Info.readable?(auditlog)
      info("Audit log readable: #{auditlog}")
      n = 0
      begin
        File.open(auditlog) do |fh|
          fh.each_line do |rec|
            next unless rec.includes?("type=TTY")
            next unless rec.includes?("comm=\"su\"") || rec.includes?("comm=\"sudo\"")
            hi("TTY audit record: #{rec.strip}")
            found = true
            n += 1
            break if n >= 20
          end
        end
      rescue IO::Error | File::Error
      end
    end
  end

  ok("No TTY password captures found") unless found
end

# Samba TDB files contain extractable hashes (secretsdump.py, tdbdump).
# Kerberos keytabs and ticket caches are directly usable (pass-the-ticket).
# SSSD caches store domain credential hashes and ticket material.
private def check_cached_creds : Nil
  blank
  tee("#{Y}Cached credentials & tickets:#{RS}")
  found = false

  dbs = %w[
    /var/lib/samba/private/secrets.tdb
    /var/lib/samba/passdb.tdb
    /var/opt/quest/vas/authcache/vas_auth.vdb
    /etc/opt/quest/vas/host.keytab
    /var/lib/sss/secrets/secrets.ldb
    /var/lib/sss/secrets/.secrets.mkey
  ]
  Dir.glob("/var/lib/sss/db/cache_*").each { |p| dbs << p }
  Dir.glob("/var/lib/sss/db/ccache_*").each { |p| dbs << p }
  Dir.glob("/tmp/krb5cc_*").each { |p| dbs << p }

  dbs.each do |db|
    next unless File.exists?(db)
    if File::Info.readable?(db)
      label = if db.ends_with?(".keytab") || db.starts_with?("/tmp/krb5cc_") ||
                  db.ends_with?(".ldb") || db.ends_with?(".mkey") || db.includes?("/ccache_")
                "usable for authentication"
              else
                "offline crackable"
              end
      hi("Readable (#{label}): #{db}")
      found = true
    else
      info("Exists (not readable): #{db}")
    end
  end

  ok("No cached credential files found") unless found

  opasswd = "/etc/security/opasswd"
  if File.exists?(opasswd)
    if File::Info.readable?(opasswd)
      hi("Readable (old password hashes): #{opasswd}")
    else
      info("Exists (not readable): #{opasswd}")
    end
  end
end

# Non-standard AuthorizedKeysFile → writable = inject key, readable = harvest pubkeys
private def check_nonstandard_authkeys : Nil
  content = Data.sshd_config
  return if content.empty?

  content.split("\n").each do |raw_line|
    line = raw_line.strip
    next if line.empty? || line.starts_with?("#")
    next unless line.downcase.starts_with?("authorizedkeysfile") &&
                line.size > 18 && line[18].ascii_whitespace?

    parts = line.split(/\s+/, 2)
    next unless parts.size == 2
    val = parts[1].strip
    next if val == ".ssh/authorized_keys" || val == "%h/.ssh/authorized_keys"

    # Expand %h/%u tokens against home dirs and usernames from /etc/passwd
    val.split(/\s+/).each do |pattern|
      if pattern.includes?("%h") || pattern.includes?("%u")
        Data.passwd.split("\n").each do |pw_line|
          pw = pw_line.split(":")
          next unless pw.size >= 6
          expanded = pattern.gsub("%h", pw[5]).gsub("%u", pw[0])
          check_authkey_path(expanded, pw[0])
        end
      elsif pattern.starts_with?("/")
        check_authkey_path(pattern, nil)
      end
    end
  end
rescue File::Error | IO::Error
end

private def check_authkey_path(path : String, user : String?) : Nil
  return unless File.exists?(path)
  label = user ? " (user: #{user})" : ""
  if File::Info.writable?(path)
    hi("Writable AuthorizedKeysFile: #{path}#{label} — inject SSH key for access")
  elsif File::Info.readable?(path)
    info("Readable non-standard AuthorizedKeysFile: #{path}#{label}")
  end
rescue File::Error
end

private def check_software_creds : Nil
  found = false

  found = scan_app_config(GITLAB_CRED_PATHS, GITLAB_CRED_RE, "GitLab config", found)
  found = scan_app_config(SPLUNK_CRED_PATHS, SPLUNK_CRED_RE, "Splunk config", found,
    note: "obfuscated passwords are crackable (splunksecrets)")

  ps = Data.ps_output

  if ps.includes?("mattermost")
    found = scan_app_config(MATTERMOST_CRED_PATHS, MATTERMOST_CRED_RE, "Mattermost config", found)
  end

  if ps.includes?("gitea")
    found = scan_app_config(GITEA_CRED_PATHS, GITEA_CRED_RE, "Gitea config", found)
  end

  if ps.includes?("grafana-server")
    found = scan_app_config(GRAFANA_CRED_PATHS, GRAFANA_CRED_RE, "Grafana config", found)
  end

  check_jenkins_creds(ps, found)
  scan_log4j
end

private def check_jenkins_creds(ps : String, header_shown : Bool) : Nil
  jenkins_home = nil
  JENKINS_HOME_DIRS.each do |dir|
    if Data.dir_exists?(dir)
      jenkins_home = dir
      break
    end
  end

  # gate the per-home walk on a positive process or system-path signal —
  # otherwise we burn stat calls on every shell user looking for .jenkins
  # on systems that don't run Jenkins
  return unless jenkins_home || ps.includes?("jenkins")

  unless jenkins_home
    Data.home_dirs.each do |home|
      d = "#{home}/.jenkins"
      if Data.dir_exists?(d)
        jenkins_home = d
        break
      end
    end
  end

  shown = header_shown

  if jh = jenkins_home
    JENKINS_SECRET_FILES.each do |rel|
      path = "#{jh}/#{rel}"
      next unless Data.file_exists?(path) && File::Info.readable?(path)
      unless shown
        blank
        tee("#{Y}Software-specific credentials:#{RS}")
        shown = true
      end
      hi("Jenkins secret readable: #{path}")
    end

    shown = scan_app_config(
      JENKINS_CRED_FILES.map { |f| "#{jh}/#{f}" },
      JENKINS_CRED_RE, "Jenkins config", shown)

    jobs_dir = "#{jh}/jobs"
    if Data.dir_exists?(jobs_dir)
      job_hits = 0
      begin
        Dir.each_child(jobs_dir) do |job|
          break if job_hits >= 20
          job_cfg = "#{jobs_dir}/#{job}/config.xml"
          next unless Data.file_exists?(job_cfg) && File::Info.readable?(job_cfg)
          xml = read_file(job_cfg)
          next if xml.empty?
          xml.each_line do |raw|
            line = raw.strip
            next unless line.matches?(JENKINS_CRED_RE)
            unless shown
              blank
              tee("#{Y}Software-specific credentials:#{RS}")
              shown = true
            end
            hi("Jenkins job config: #{job_cfg}")
            tee("    #{R}#{line}#{RS}")
            job_hits += 1
            break
          end
        end
      rescue File::Error
      end
    end
  elsif ps.includes?("jenkins")
    paths = JENKINS_HOME_DIRS.flat_map { |d| JENKINS_CRED_FILES.map { |f| "#{d}/#{f}" } }
    shown = scan_app_config(paths, JENKINS_CRED_RE, "Jenkins config", shown)
  end
end

private def scan_app_config(paths : Array(String), re : Regex, label : String,
                            header_shown : Bool, note : String? = nil) : Bool
  shown = header_shown
  paths.each do |path|
    next unless File.exists?(path) && File::Info.readable?(path)
    content = read_file(path)
    next if content.empty?
    path_shown = false
    content.each_line do |raw|
      line = raw.strip
      next if line.empty? || line.starts_with?("#") || line.starts_with?(";")
      next unless line.matches?(re)
      unless shown
        blank
        tee("#{Y}Software-specific credentials:#{RS}")
        shown = true
      end
      unless path_shown
        msg = note ? "#{label}: #{path} — #{note}" : "#{label}: #{path}"
        hi(msg)
        path_shown = true
      end
      tee("    #{R}#{line}#{RS}")
    end
  end
  shown
end

private def scan_log4j : Nil
  # Walker captures log4j-core-*.jar everywhere; consumer scopes to
  # the historical LOG4J_SCAN_DIRS to avoid noise from developer
  # project trees in home directories.
  Data.log4j_jars.each do |jar|
    next unless LOG4J_SCAN_PREFIXES.any? { |p| jar.starts_with?(p) }
    basename = File.basename(jar)
    next unless m = basename.match(LOG4J_JAR_RE)
    ver = m[1]
    seg = ver.split(".")
    maj = seg[0]?.try(&.to_i) || 0
    mn = seg[1]?.try(&.to_i) || 0
    pat = seg[2]?.try(&.to_i) || 0
    if maj == 2 && (mn < 17 || (mn == 17 && pat < 1))
      hi("Log4j #{ver} (#{jar}) — CVE-2021-44228 Log4Shell + followups, fixed in 2.17.1")
    end
  end
end

private def scan_pam_file(conf : String, &) : Nil
  content = read_file(conf)
  return if content.empty?
  content.each_line do |line|
    rule = line.strip
    next if rule.empty? || rule.starts_with?('#')
    if rule.matches?(PAM_CRED_RE)
      hi("#{conf}: #{rule}")
      yield
    end
  end
end

private def scan_secret_patterns(candidates : Array(String), &) : Nil
  emitted = 0
  candidates.each do |path|
    break if emitted >= 15
    sz = Data.stat_safe(path).try(&.size)
    next unless sz && sz <= 262_144
    raw = read_file(path)
    next if raw.empty?
    # NUL byte = binary file (e.g., .json with embedded key blobs);
    # rescue catches Latin-1 configs whose 0x80+ bytes break the
    # UTF-8 requirement of Crystal's regex engine.
    next if raw[0, 4096].includes?('\0')
    lines = raw.split("\n").select { |line| line.size <= 500 }
    file_hit = false
    begin
      SECRET_PATTERNS.each do |pat|
        hits = lines.select { |line| line.matches?(pat[:re]) }
        next if hits.empty?
        if pat[:severity] == :hi
          hi("#{pat[:name]} in: #{path}")
        else
          med("#{pat[:name]} in: #{path}")
        end
        hits.first(3).each { |line| tee("    #{R}#{line.strip}#{RS}") }
        file_hit = true
      end
    rescue ArgumentError
      next
    end
    if file_hit
      emitted += 1
      yield
    end
  end
end

private def scan_cred_keywords(candidates : Array(String)) : Nil
  emitted = 0
  candidates.each do |path|
    break if emitted >= 15
    sz = Data.stat_safe(path).try(&.size)
    next unless sz && sz <= 262_144
    raw = read_file(path)
    next if raw.empty?
    next if raw[0, 4096].includes?('\0')
    cred_lines = begin
      raw.split("\n").select { |line|
        next false if line.size > 500    # minified JS bundles, not real cred entries
        next false unless hit = line.match(CRED_CAPTURE_RE)
        next false if line.matches?(CRED_NOISE_RE)     # .NET assembly metadata, ImageMagick templates
        next false if CRED_SENTINELS.includes?(hit[2])  # placeholder values (ask, *, none, etc.)
        true
      }
    rescue ArgumentError
      next
    end
    next if cred_lines.empty?
    med("Potential creds in: #{path}")
    cred_lines.first(5).each { |line| tee("    #{Y}#{line}#{RS}") }
    emitted += 1
  end
end

private def check_db_cred_files : Nil
  blank
  tee("#{Y}Database credential files:#{RS}")
  found = false

  REDIS_CRED_PATHS.each do |path|
    next unless File.exists?(path)
    unless File::Info.readable?(path)
      info("Exists (not readable): #{path}")
      next
    end
    content = read_file(path)
    next if content.empty?
    hit = false
    content.each_line do |raw|
      line = raw.strip
      next if line.empty? || line.starts_with?("#")
      if m = line.match(REDIS_CRED_RE)
        hi("Redis #{m[1]}: #{path}")
        tee("    #{R}#{line}#{RS}")
        hit = true
        found = true
      end
    end
    info("Readable (no auth directives): #{path}") unless hit
  end

  mysql_paths = MYSQL_CRED_PATHS.dup
  Data.home_dirs.each do |h|
    p = "#{h}/.my.cnf"
    mysql_paths << p unless mysql_paths.includes?(p)
    lp = "#{h}/.mylogin.cnf"
    mysql_paths << lp unless mysql_paths.includes?(lp)
  end

  mysql_paths.each do |path|
    next unless File.exists?(path)
    unless File::Info.readable?(path)
      info("Exists (not readable): #{path}")
      next
    end
    if path.ends_with?(".mylogin.cnf")
      # encrypted but trivially recoverable — my_print_defaults dumps plaintext
      hi("MySQL encrypted login path: #{path} — decrypt with my_print_defaults or mysql_config_editor")
      found = true
      next
    end
    content = read_file(path)
    next if content.empty?
    hit = false
    db_user = nil
    content.each_line do |raw|
      line = raw.strip
      next if line.empty? || line.starts_with?("#") || line.starts_with?(";")
      db_user = nil if line.starts_with?("[")
      if u = line.match(/^\s*user\s*=\s*(\S+)/)
        db_user = u[1]
      end
      if m = line.match(MYSQL_CRED_RE)
        val = m[1]
        next if CRED_SENTINELS.includes?(val)
        label = db_user ? "MySQL credential (user: #{db_user})" : "MySQL credential"
        hi("#{label}: #{path}")
        tee("    #{R}#{line}#{RS}")
        hit = true
        found = true
      end
    end
    info("Readable (no password): #{path}") unless hit
  end

  pgpass_paths = [] of String
  Data.home_dirs.each { |h| pgpass_paths << "#{h}/.pgpass" }
  pgpass_paths.each do |path|
    next unless File.exists?(path)
    unless File::Info.readable?(path)
      info("Exists (not readable): #{path}")
      next
    end
    content = read_file(path)
    next if content.empty?
    n = 0
    content.each_line do |raw|
      line = raw.strip
      next if line.empty? || line.starts_with?("#")
      # pgpass allows \: as literal colon — swap before split, restore after
      fields = line.gsub("\\:", "\x00").split(":").map(&.gsub("\x00", ":"))
      next unless fields.size >= 5
      pw = fields[4]
      next if pw.empty? || pw == "*"
      hi("PostgreSQL pgpass: #{path} (user: #{fields[3]})")
      found = true
      n += 1
      break if n >= 5
    end
  end

  MONGO_CRED_PATHS.each do |path|
    next unless File.exists?(path)
    unless File::Info.readable?(path)
      info("Exists (not readable): #{path}")
      next
    end
    content = read_file(path)
    next if content.empty?
    hit = false
    content.each_line do |raw|
      line = raw.strip
      next if line.empty? || line.starts_with?("#")
      if line.matches?(MONGO_CRED_RE)
        hi("MongoDB config: #{path}")
        tee("    #{R}#{line}#{RS}")
        hit = true
        found = true
      end
    end
  end

  ok("No database credential files found") unless found
end

private def check_mail_spool : Nil
  blank
  tee("#{Y}Mail spool:#{RS}")
  found = false
  my_uid = LibC.getuid.to_s

  MAIL_SPOOL_DIRS.each do |dir|
    next unless Dir.exists?(dir)
    begin
      Dir.each_child(dir) do |name|
        path = "#{dir}/#{name}"
        info = File.info?(path)
        next unless info
        next if info.directory?
        next unless File::Info.readable?(path)

        found = true
        if info.owner_id == my_uid
          med("Own mail readable: #{path}")
        else
          hi("Other user mail readable: #{path}")
        end

        ln = 0
        hits = 0
        begin
          File.open(path) do |fh|
            fh.each_line do |line|
              ln += 1
              break if ln > 200
              if line.matches?(CRED_PATTERN_RE)
                tee("    #{R}#{line.strip}#{RS}")
                hits += 1
                break if hits >= 5
              end
            end
          end
        rescue IO::Error | File::Error
        end
      end
    rescue File::Error
    end
  end

  ok("No readable mail spool files") unless found
end

private def check_browser_profiles : Nil
  blank
  tee("#{Y}Browser credential stores:#{RS}")
  found = false

  Data.home_dirs.each do |home|
    BROWSER_FIREFOX_BASES.each do |rel|
      ff_base = "#{home}/#{rel}"
      next unless Dir.exists?(ff_base)
      begin
        Dir.each_child(ff_base) do |entry|
          profile_dir = "#{ff_base}/#{entry}"
          next unless File.info?(profile_dir).try(&.directory?)

          logins = "#{profile_dir}/logins.json"
          signons = "#{profile_dir}/signons.sqlite"
          keydb = "#{profile_dir}/key4.db"
          has_logins = File::Info.readable?(logins)
          has_signons = !has_logins && File::Info.readable?(signons)
          has_keydb = File::Info.readable?(keydb)
          cred_db = has_logins || has_signons

          if cred_db && has_keydb
            src = has_logins ? "logins.json" : "signons.sqlite"
            hi("Firefox credentials (#{src} + key4.db): #{profile_dir}")
          elsif cred_db
            path = has_logins ? logins : signons
            hi("Firefox credential DB readable: #{path}")
          elsif has_keydb
            med("Firefox key4.db readable (master key only): #{keydb}")
          else
            next
          end
          found = true
        end
      rescue File::Error
      end
    end

    BROWSER_CHROME_BASES.each do |browser|
      base = "#{home}/#{browser[:base]}"
      next unless Dir.exists?(base)
      begin
        Dir.each_child(base) do |entry|
          profile_dir = "#{base}/#{entry}"
          next unless File.info?(profile_dir).try(&.directory?)
          login_data = "#{profile_dir}/Login Data"
          if File::Info.readable?(login_data)
            hi("#{browser[:name]} credential store: #{login_data}")
            found = true
          end
        end
      rescue File::Error
      end
    end
  end

  ok("No browser credential stores found") unless found
end

private def check_password_manager_dbs : Nil
  blank
  tee("#{Y}Password manager databases:#{RS}")
  found = false

  Data.password_vault_files.each do |path|
    if File::Info.readable?(path)
      hi("Readable: #{path} — extract + crack offline (hashcat -m 13400)")
      found = true
    else
      info("Exists (not readable): #{path}")
    end
  end

  ok("No password manager databases found") unless found
end

private def check_git_exposure : Nil
  blank
  tee("#{Y}Exposed .git directories:#{RS}")
  found = false

  # /var/www/site/.git and /var/www/site/app/.git — two levels covers
  # the common Apache/nginx docroot layouts
  GIT_WEB_ROOTS.each do |root|
    next unless Dir.exists?(root)
    begin
      Dir.each_child(root) do |site|
        site_path = "#{root}/#{site}"
        next unless File.info?(site_path).try(&.directory?)
        found = true if scan_git_dir(site_path)
        begin
          Dir.each_child(site_path) do |app|
            app_path = "#{site_path}/#{app}"
            next unless File.info?(app_path).try(&.directory?)
            found = true if scan_git_dir(app_path)
          end
        rescue File::Error
        end
      end
    rescue File::Error
    end
  end

  Data.home_dirs.each do |home|
    # plaintext credential store — helper=store writes here
    cred_path = "#{home}/.git-credentials"
    if File.exists?(cred_path) && File::Info.readable?(cred_path)
      hi("Readable .git-credentials: #{cred_path}")
      read_file(cred_path).each_line do |raw|
        line = raw.strip
        tee("    #{R}#{line}#{RS}") unless line.empty?
      end
      found = true
    end

    cfg_path = "#{home}/.gitconfig"
    next unless File.exists?(cfg_path) && File::Info.readable?(cfg_path)
    gc = read_file(cfg_path)
    next if gc.empty?
    gc.each_line do |raw|
      line = raw.strip
      if line.matches?(GIT_CRED_HELPER_RE)
        # store helper → .git-credentials contains plaintext
        med("Git credential helper configured: #{cfg_path} — #{line}")
        found = true
      elsif line.matches?(GIT_TOKEN_RE)
        hi("Embedded token in #{cfg_path}")
        tee("    #{R}#{line}#{RS}")
        found = true
      end
    end
  end

  ok("No exposed .git directories or credentials found") unless found
end

private def check_php_sessions : Nil
  blank
  tee("#{Y}PHP session files:#{RS}")
  found = false
  my_uid = LibC.getuid.to_s
  reported = 0

  PHP_SESSION_DIRS.each do |dir|
    next unless Dir.exists?(dir)
    begin
      Dir.each_child(dir) do |name|
        break if reported >= PHP_SESSION_MAX
        next unless name.starts_with?("sess_")
        path = "#{dir}/#{name}"
        stat = File.info?(path)
        next unless stat && stat.file?
        next if stat.owner_id == my_uid
        unless File::Info.readable?(path)
          info("Session file (not readable): #{path}")
          next
        end
        med("Readable session file (owner uid #{stat.owner_id}): #{path}")
        found = true
        reported += 1
        next if stat.size == 0 || stat.size > PHP_SESSION_CAP
        read_file(path).split("\n").each do |raw|
          line = raw.strip
          next if line.empty?
          if line.matches?(PHP_SESSION_RE)
            hi("  Credential pattern in session: #{path}")
            tee("    #{R}#{line}#{RS}")
            break
          end
        end
      end
    rescue File::Error
    end
  end

  ok("No readable PHP session files found") unless found
end

private def check_wifi_creds : Nil
  blank
  tee("#{Y}Wifi credentials:#{RS}")
  found = false

  if Dir.exists?(WIFI_NM_DIR)
    begin
      Dir.each_child(WIFI_NM_DIR) do |name|
        path = "#{WIFI_NM_DIR}/#{name}"
        next unless File.file?(path) && File::Info.readable?(path)
        report_wifi_file(path)
        found = true
      end
    rescue File::Error
    end
  end

  if File.file?(WIFI_WPA_CONF) && File::Info.readable?(WIFI_WPA_CONF)
    report_wifi_file(WIFI_WPA_CONF)
    found = true
  end

  if Dir.exists?(WIFI_WPA_DIR)
    begin
      Dir.each_child(WIFI_WPA_DIR) do |name|
        next unless name.ends_with?(".conf")
        path = "#{WIFI_WPA_DIR}/#{name}"
        next unless File.file?(path) && File::Info.readable?(path)
        report_wifi_file(path)
        found = true
      end
    rescue File::Error
    end
  end

  ok("No readable wifi credential files") unless found
end

private def report_wifi_file(path : String) : Nil
  stat = File.info?(path)
  return unless stat
  if stat.size > WIFI_SIZE_CAP
    info("Wifi config readable (skipped, #{stat.size} bytes > cap): #{path}")
    return
  end
  content = read_file(path)
  return if content.empty?

  ssids = [] of String
  psk_lines = [] of String
  pw_lines = [] of String
  enterprise = false

  content.each_line do |raw|
    line = raw.chomp
    if m = line.match(WIFI_SSID_RE)
      ssids << m[1]
    end
    enterprise = true if line.matches?(WIFI_ENTERPRISE_RE)
    psk_lines << line.strip if line.matches?(WIFI_PSK_RE)
    pw_lines << line.strip if line.matches?(WIFI_PASSWORD_RE)
  end

  ssid_tag = ssids.empty? ? "" : " [SSID: #{ssids.uniq.join(", ")}]"
  reported = false

  if enterprise && !pw_lines.empty?
    hi("WPA-Enterprise creds readable (likely domain): #{path}#{ssid_tag}")
    pw_lines.first(5).each { |l| tee("    #{R}#{l}#{RS}") }
    reported = true
  end

  unless psk_lines.empty?
    med("Wifi PSK readable: #{path}#{ssid_tag}")
    psk_lines.first(5).each { |l| tee("    #{R}#{l}#{RS}") }
    reported = true
  end

  info("Wifi config readable (no inline credential): #{path}#{ssid_tag}") unless reported
end

private def check_terraform_state : Nil
  blank
  tee("#{Y}Terraform state and credentials:#{RS}")
  found = false

  Data.tfstate_files.each do |path|
    stat = Data.stat_safe(path)
    next unless stat && stat.file?
    unless File::Info.readable?(path)
      info("Terraform state exists (not readable): #{path}")
      next
    end
    hi("Terraform state readable: #{path} (#{stat.size} bytes)")
    found = true
    next if stat.size == 0 || stat.size > TFSTATE_SIZE_CAP
    hits = 0
    read_file(path).each_line do |raw|
      break if hits >= TFSTATE_HIT_CAP
      line = raw.strip
      next if line.empty?
      next unless line.matches?(TFSTATE_SECRET_RE)
      line = "#{line[0, TFSTATE_LINE_CAP]}…" if line.size > TFSTATE_LINE_CAP
      tee("    #{R}#{line}#{RS}")
      hits += 1
    end
  end

  Data.home_dirs.each do |home|
    tfrc = "#{home}/#{TFRC_PATH}"
    next unless File.file?(tfrc) && File::Info.readable?(tfrc)
    hi("Terraform Cloud credentials readable: #{tfrc}")
    tee(read_file(tfrc))
    found = true
  end

  ok("No readable terraform state or credentials") unless found
end

private def check_docker_registry : Nil
  blank
  tee("#{Y}Docker registry credentials:#{RS}")
  found = false

  Data.home_dirs.each do |home|
    path = "#{home}/#{DOCKER_CONFIG_PATH}"
    next unless File.file?(path)
    unless File::Info.readable?(path)
      info("Docker config exists (not readable): #{path}")
      next
    end
    content = read_file(path)
    next if content.empty?
    found = true
    matches = content.scan(DOCKER_INLINE_CRED_RE).map(&.[0]).uniq
    if matches.empty?
      info("Docker config readable (no inline creds): #{path}")
    else
      hi("Docker registry creds in #{path} (#{matches.size} entries)")
      matches.first(DOCKER_MATCH_CAP).each { |m| tee("    #{R}#{m}#{RS}") }
    end
  end

  ok("No readable docker registry credentials") unless found
end

private def check_kubeconfig : Nil
  blank
  tee("#{Y}Kubernetes kubeconfig:#{RS}")
  found = false
  my_uid = LibC.getuid.to_s

  paths = [] of {path: String, etc: Bool}
  KUBECONFIG_ETC_PATHS.each { |p| paths << {path: p, etc: true} }
  Data.home_dirs.each { |h| paths << {path: "#{h}/#{KUBECONFIG_HOME_PATH}", etc: false} }

  paths.each do |entry|
    path = entry[:path]
    next unless File.file?(path)
    unless File::Info.readable?(path)
      info("Kubeconfig exists (not readable): #{path}")
      next
    end
    content = read_file(path)
    next if content.empty?
    found = true

    embedded = false
    exec_plugin = false
    content.each_line do |raw|
      line = raw.chomp
      embedded = true if line.matches?(KUBECONFIG_EMBEDDED_RE)
      exec_plugin = true if line.matches?(KUBECONFIG_EXEC_RE)
    end

    label = entry[:etc] ? File.basename(path) : path
    own = !entry[:etc] && File.info?(path).try(&.owner_id) == my_uid
    suffix = own ? " (own)" : ""

    if embedded
      if own
        med("Kubeconfig with embedded credentials: #{label}#{suffix}")
      else
        hi("Kubeconfig with embedded credentials: #{label}")
      end
    elsif exec_plugin
      if own
        info("Kubeconfig with exec plugin: #{label}#{suffix} (check plugin binary writability)")
      else
        med("Kubeconfig with exec plugin: #{label} (check plugin binary writability)")
      end
    else
      if own
        info("Kubeconfig readable: #{label}#{suffix}")
      else
        med("Kubeconfig readable: #{label} (cluster context only)")
      end
    end
  end

  ok("No readable kubeconfig files") unless found
end

private def check_ai_assistant_creds : Nil
  blank
  tee("#{Y}AI coding assistant credentials:#{RS}")
  found = false

  Data.home_dirs.each do |home|
    AI_CRED_FILES.each do |entry|
      path = "#{home}/#{entry[:path]}"
      next unless File.file?(path) && File::Info.readable?(path)
      content = read_file(path)
      next if content.empty?
      re = entry[:re]
      next unless content.matches?(re)
      med("#{entry[:tool]} credentials in #{path}")
      found = true
      shown = 0
      content.each_line do |raw|
        break if shown >= AI_MATCH_CAP
        line = raw.chomp.strip
        next unless line.matches?(re)
        line = "#{line[0, AI_LINE_CAP]}…" if line.size > AI_LINE_CAP
        tee("    #{R}#{line}#{RS}")
        shown += 1
      end
    end
  end

  ok("No AI assistant credential files found") unless found
end

private def check_gpg_private_keys : Nil
  blank
  tee("#{Y}GPG private key material:#{RS}")
  found = false
  my_uid = LibC.getuid.to_s

  Data.home_dirs.each do |home|
    gnupg = "#{home}/#{GPG_DIR}"
    next unless Data.dir_exists?(gnupg)

    pass_note = Data.dir_exists?("#{home}/#{PASS_STORE_DIR}") ? " (unlocks pass vault)" : ""

    privdir = "#{gnupg}/#{GPG_PRIVKEY_SUBDIR}"
    if Data.dir_exists?(privdir)
      # need read+exec to enumerate keys; without exec, every stat under
      # the dir would raise — emit "exists but not traversable" instead
      if File::Info.readable?(privdir) && File::Info.executable?(privdir)
        keys = [] of String
        begin
          Dir.each_child(privdir) do |name|
            keys << name if name.ends_with?(".key")
          end
        rescue File::Error
        end
        unless keys.empty?
          if File.info?(privdir).try(&.owner_id) == my_uid
            info("Readable GPG private key dir (own): #{privdir} — #{keys.size} key(s)#{pass_note}")
          else
            hi("Readable GPG private key dir: #{privdir} — #{keys.size} key(s)#{pass_note}")
          end
          found = true
        end
      else
        info("GPG private key dir exists (not traversable): #{privdir}")
        found = true
      end
    end

    legacy = "#{gnupg}/#{GPG_LEGACY_SECRING}"
    if Data.file_exists?(legacy) && (File.info?(legacy).try(&.size) || 0_u64) > 0
      owner_own = File.info?(legacy).try(&.owner_id) == my_uid
      own_suffix = owner_own ? " (own)" : ""
      if File::Info.readable?(legacy)
        if owner_own
          info("Readable legacy GPG secring#{own_suffix}: #{legacy}#{pass_note}")
        else
          hi("Readable legacy GPG secring: #{legacy}#{pass_note}")
        end
      else
        info("Legacy GPG secring (not readable): #{legacy}")
      end
      found = true
    end
  end

  ok("No GPG private key material found") unless found
end

private def check_cert_key_files : Nil
  blank
  tee("#{Y}Certificates and private keys:#{RS}")
  found = false
  my_uid = LibC.getuid.to_s

  Data.cert_keystore_files.each do |path|
    if File::Info.readable?(path)
      hi("Readable keystore: #{path} — extract with keytool/openssl, crack offline")
    else
      info("Keystore exists (not readable): #{path}")
    end
    found = true
  end

  # /etc/ssl/certs is the public CA bundle — 100+ .pem files that
  # would drown the section. Skip for PEM/key, not keystores (CA
  # bundles never carry .p12/.pfx/.jks).
  Data.cert_pemkey_files.each do |path|
    next if path.starts_with?("/etc/ssl/certs/")
    unless File::Info.readable?(path)
      info("Cert/key exists (not readable): #{path}")
      found = true
      next
    end
    head = ""
    begin
      File.open(path) do |io|
        buf = Bytes.new(CERT_PEEK_BYTES)
        n = io.read(buf)
        head = String.new(buf[0, n])
      end
    rescue File::Error
      next
    end
    if head.matches?(CERT_PRIVATE_KEY_RE)
      if Data.stat_safe(path).try(&.owner_id) == my_uid
        info("Readable private key (own): #{path}")
      else
        hi("Readable private key: #{path}")
      end
    else
      info("Readable cert/key (no PRIVATE header): #{path}")
    end
    found = true
  end

  ok("No readable certificates or private keys found") unless found
end

private def scan_git_dir(dir : String) : Bool
  git_dir = "#{dir}/.git"
  return false unless Dir.exists?(git_dir)
  hi("Exposed .git directory: #{git_dir} — full source recovery possible")
  config = "#{git_dir}/config"
  if File.exists?(config) && File::Info.readable?(config)
    read_file(config).each_line do |raw|
      line = raw.strip
      if line.matches?(GIT_TOKEN_RE)
        hi("  Embedded token in #{config}")
        tee("    #{R}#{line}#{RS}")
      end
    end
  end
  true
end
