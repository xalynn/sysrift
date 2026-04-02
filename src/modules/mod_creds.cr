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
    run_lines("grep -rIilE '#{CRED_PATTERN}' #{d} #{CRED_EXTS} 2>/dev/null | head -15").each do |f|
      med("Potential creds in: #{f}")
      content = read_file(f)
      next if content.empty?
      content.split("\n").select { |l| l.matches?(CRED_PATTERN_RE) }.first(5).each do |l|
        tee("    #{Y}#{l}#{RS}")
      end
    end
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

  run_lines("find /home /root /etc/ssh /tmp /opt /var /mnt \\( -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' -o -name 'id_dsa' \\) 2>/dev/null").uniq.each do |k|
    File::Info.readable?(k) ? hi("Readable private key: #{k}") : info("Private key (not readable): #{k}")
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
