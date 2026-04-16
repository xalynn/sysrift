def mod_creds : Nil
  section("Credential Hunting")

  tee("#{Y}History files:#{RS}")
  run_lines("find /home /root /tmp /var -name '.*history' -readable 2>/dev/null").uniq.each do |f|
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

  blank
  tee("#{Y}Config files with credential patterns:#{RS}")
  %w[/etc /var/www /opt /srv /home /root].each do |d|
    next unless Dir.exists?(d)
    grep_cred_files(d, CRED_EXTS)
  end

  CRED_JS_DIRS.each do |d|
    next unless Dir.exists?(d)
    grep_cred_files(d, CRED_JS_EXTS)
  end

  blank
  tee("#{Y}Hardcoded secrets:#{RS}")
  secret_hit = false
  %w[/etc /var/www /opt /srv /home /root].each do |d|
    next unless Dir.exists?(d)
    scan_secret_patterns(d, SECRET_SCAN_EXTS) { secret_hit = true }
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
  run_lines("find /home /root /etc/ssh /tmp /opt /var /mnt \\( -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' -o -name 'id_dsa' \\) 2>/dev/null").uniq.each do |k|
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

  run_lines("find /home /root /tmp /opt /var /mnt -name '.netrc' -readable 2>/dev/null").each do |f|
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

  scan_log4j
end

private def scan_app_config(paths : Array(String), re : Regex, label : String,
                            header_shown : Bool, note : String? = nil) : Bool
  shown = header_shown
  paths.each do |path|
    next unless File.exists?(path) && File::Info.readable?(path)
    content = read_file(path)
    next if content.empty?
    content.each_line do |raw|
      line = raw.strip
      next if line.empty? || line.starts_with?("#")
      next unless line.matches?(re)
      unless shown
        blank
        tee("#{Y}Software-specific credentials:#{RS}")
        shown = true
      end
      msg = note ? "#{label}: #{path} — #{note}" : "#{label}: #{path}"
      hi(msg)
      tee("    #{R}#{line}#{RS}")
    end
  end
  shown
end

private def scan_log4j : Nil
  LOG4J_SCAN_DIRS.each do |dir|
    next unless Dir.exists?(dir)
    run_lines("find #{dir} -name 'log4j-core-*.jar' -type f 2>/dev/null | head -10").each do |jar|
      basename = File.basename(jar)
      if m = basename.match(LOG4J_JAR_RE)
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

private def scan_secret_patterns(dir : String, exts : String, &) : Nil
  run_lines("grep -rIilE '#{SECRET_GREP_PRE}' #{dir} #{exts} 2>/dev/null | head -15").each do |path|
    next unless (sz = File.info?(path).try(&.size)) && sz <= 262_144
    raw = read_file(path)
    next if raw.empty?
    lines = raw.split("\n").select { |l| l.size <= 500 }
    file_hit = false
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
    yield if file_hit
  end
end

private def grep_cred_files(dir : String, exts : String) : Nil
  run_lines("grep -rIilE '#{CRED_PATTERN}' #{dir} #{exts} 2>/dev/null | head -15").each do |path|
    next unless (sz = File.info?(path).try(&.size)) && sz <= 262_144
    raw = read_file(path)
    next if raw.empty?
    cred_lines = raw.split("\n").select { |line|
      next false if line.size > 500    # minified JS lines, not real cred entries
      next false unless hit = line.match(CRED_CAPTURE_RE)
      next false if line.matches?(CRED_NOISE_RE)     # .NET assembly metadata, ImageMagick templates
      next false if CRED_SENTINELS.includes?(hit[2])  # placeholder values (ask, *, none, etc.)
      true
    }
    next if cred_lines.empty?
    med("Potential creds in: #{path}")
    cred_lines.first(5).each { |line| tee("    #{Y}#{line}#{RS}") }
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

  search_roots = Data.home_dirs + PASSMGR_EXTRA_DIRS

  search_roots.each do |root|
    next unless Dir.exists?(root)
    scan_vault_files(root) { found = true }
    begin
      Dir.each_child(root) do |child|
        sub = "#{root}/#{child}"
        next unless File.directory?(sub)
        scan_vault_files(sub) { found = true }
      end
    rescue File::Error
    end
  end

  ok("No password manager databases found") unless found
end

private def scan_vault_files(dir : String, &) : Nil
  Dir.each_child(dir) do |name|
    lower = name.downcase
    next unless PASSMGR_EXTENSIONS.any? { |ext| lower.ends_with?(ext) }
    path = "#{dir}/#{name}"
    next unless File.file?(path)
    if File::Info.readable?(path)
      hi("Readable: #{path} — extract + crack offline (hashcat -m 13400)")
      yield
    else
      info("Exists (not readable): #{path}")
    end
  end
rescue File::Error
end
