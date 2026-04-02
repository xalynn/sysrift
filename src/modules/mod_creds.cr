def mod_creds : Nil
  section("Credential Hunting")

  tee("#{Y}History files:#{RS}")
  run_lines("find /home /root /tmp /var -name '.*history' -readable 2>/dev/null").uniq.each do |f|
    content = read_file(f)
    next if content.empty?
    line_count = content.count('\n').to_s
    med("#{f}  (#{line_count} lines)")
    hits = content.split("\n").select { |l| l.matches?(/pass|secret|token|key|ssh|mysql|psql|curl.*-u|wget.*--user/i) }
    unless hits.empty?
      hi("  Interesting lines in #{f}:")
      hits.first(20).each { |l| tee("    #{R}#{l}#{RS}") }
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
end

private def grep_cred_files(dir : String, exts : String) : Nil
  run_lines("grep -rIilE '#{CRED_PATTERN}' #{dir} #{exts} 2>/dev/null | head -15").each do |path|
    next if File.size(path) > 262_144  # skip bulk files (minified JS, JSON blobs)
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
