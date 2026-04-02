def mod_files : Nil
  section("Interesting Files")

  tee("#{Y}Known sensitive config files:#{RS}")
  run_lines("find /etc /home /root /opt /srv /var /tmp /mnt \\( #{CONFIG_PREDICATES} \\) -readable 2>/dev/null").each do |f|
    med("Found: #{f}")
  end

  blank
  tee("#{Y}Backup files:#{RS}")
  run_lines(
    "find /etc /home /root /opt /srv /var /tmp /mnt -type f " \
    "\\( -name '*.bak' -o -name '*.backup' -o -name '*.old' " \
    "-o -name '*.orig' -o -name '*.save' -o -name '*.swp' \\) " \
    "2>/dev/null | head -20"
  ).each { |f| med("Backup: #{f}") }

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
  log_hits = run("grep -rIiE '(password|passwd|credential|secret|token)' /var/log/ 2>/dev/null | grep -v Binary | head -50")
  unless log_hits.empty?
    grouped = Hash(String, Array(String)).new { |h, k| h[k] = [] of String }
    log_hits.split("\n").each do |l|
      next if l.empty?
      if idx = l.index(':')
        file = l[0...idx]
        grouped[file] << l
      end
    end
    grouped.each do |file, lines|
      med("Log hit (#{lines.size} match#{"es" if lines.size > 1}): #{file}")
      tee("  #{lines.first}")
    end
  end

  blank
  tee("#{Y}Recently modified files (last 10 min, excl /proc /sys /dev /run):#{RS}")
  run_lines("find / -mmin -10 -type f 2>/dev/null | grep -vE '^/(proc|sys|dev|run)' | head -20").each do |f|
    info("  #{f}")
  end
end
