def mod_files : Nil
  section("Interesting Files")

  tee("#{Y}Known sensitive config files:#{RS}")
  Data.sensitive_configs.each do |f|
    next unless File::Info.readable?(f)
    med("Found: #{f}")
  end

  blank
  tee("#{Y}Backup files:#{RS}")
  Data.backup_files.first(20).each { |f| med("Backup: #{f}") }

  blank
  tee("#{Y}Sensitive files readable by current user:#{RS}")
  %w[/root/.bash_history /root/.ssh/id_rsa /root/.ssh/id_ed25519].each do |f|
    hi("Readable: #{f}") if File.exists?(f) && File::Info.readable?(f)
  end

  blank
  tee("#{Y}SUID binaries outside standard paths:#{RS}")
  Data.suid_files.each do |f|
    next if f.starts_with?("/usr") || f.starts_with?("/bin") || f.starts_with?("/sbin")
    next if File.basename(f) == "chrome-sandbox"
    if Data.nosuid_mount?(f)
      info("  #{f} (unusual location, but on nosuid mount)")
    else
      hi("Unusual SUID location: #{f}")
    end
  end

  blank
  tee("#{Y}Sensitive content in logs:#{RS}")
  emitted = 0
  Data.log_files.each do |path|
    break if emitted >= 50
    next unless File::Info.readable?(path)
    sz = Data.stat_safe(path).try(&.size)
    next unless sz && sz <= LOG_SCAN_SIZE_CAP
    raw = read_file(path)
    next if raw.empty?
    # NUL byte in early bytes = binary file, including compressed
    # rotated archives (.gz/.xz). Rescue handles the rarer Latin-1
    # log case where no NUL bytes appear but high-bit chars break
    # Crystal's UTF-8 regex requirement.
    next if raw[0, 4096].includes?('\0')
    matches = begin
      raw.split("\n").select { |line| line.matches?(LOG_KEYWORD_RE) }
    rescue ArgumentError
      next
    end
    next if matches.empty?
    med("Log hit (#{matches.size} match#{"es" if matches.size > 1}): #{path}")
    tee("  #{matches.first}")
    emitted += 1
  end

  blank
  tee("#{Y}Recently modified files (last 10 min, excl /proc /sys /dev /run):#{RS}")
  Data.recent_files.each { |f| info("  #{f}") }
end
