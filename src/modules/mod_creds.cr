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
  run_lines("find /home /root /etc/ssh /tmp /opt /var /mnt \\( -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' -o -name 'id_dsa' \\) 2>/dev/null").uniq.each do |k|
    unless File::Info.readable?(k)
      info("Private key (not readable): #{k}")
      next
    end
    if File.info?(k).try(&.owner_id) == my_uid.to_s
      info("Readable private key (own): #{k}")
    else
      hi("Readable private key: #{k}")
    end
  end

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
