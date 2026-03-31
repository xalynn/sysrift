def mod_processes : Nil
  section("Processes, Cron & Timers")

  tee("#{Y}Root processes with writable binaries:#{RS}")
  run_lines("ps -eo user=,pid=,cmd= 2>/dev/null").each do |line|
    parts = line.split(limit: 3)
    next unless parts.size == 3 && parts[0] == "root"
    bin = parts[2].split[0]? || next
    next unless bin.starts_with?("/") && File.exists?(bin) && File::Info.writable?(bin)
    hi("Root process (pid #{parts[1]}): writable binary #{bin}")
  end

  blank
  tee(Data.ps_output)

  blank
  tee("#{Y}Crontab (current user):#{RS}")
  cron = run("crontab -l 2>/dev/null")
  if !cron.empty? && !cron.downcase.includes?("no crontab")
    med("Crontab entries found:")
    tee(cron)
    scan_cron_entries(cron)
  else
    info("No crontab for current user")
  end

  blank
  tee("#{Y}System cron jobs:#{RS}")
  crontab = read_file("/etc/crontab")
  unless crontab.empty?
    tee(crontab)
    scan_cron_entries(crontab)
  end

  CRON_DIRS.each do |d|
    next unless Dir.exists?(d)
    hi("Writable cron dir: #{d}") if File::Info.writable?(d)
    Dir.each_child(d) do |fname|
      fp = "#{d}/#{fname}"
      hi("Writable cron file: #{fp}") if File::Info.writable?(fp)
      content = read_file(fp)
      unless content.empty?
        med("Cron file: #{fp}")
        tee(content)
        scan_cron_entries(content)
      end
    end
  end

  timers = run("systemctl list-timers --all 2>/dev/null")
  unless timers.empty?
    blank
    tee(timers)
  end

  blank
  tee("#{Y}Processes running from /tmp /dev/shm /var/tmp:#{RS}")
  unusual = Data.ps_output.split("\n").select { |l|
    l.includes?("/tmp/") || l.includes?("/dev/shm") || l.includes?("/var/tmp")
  }
  if unusual.empty?
    ok("No processes from tmp/shm")
  else
    hi("Suspicious process locations:")
    unusual.each { |l| tee(l) }
  end
end

private def scan_cron_entries(content : String) : Nil
  content.split("\n").each do |line|
    next if line.starts_with?("#") || line.strip.empty?
    next if line.matches?(/^\s*\w+=/) # skip cron variable assignments (SHELL=, PATH=, etc.)
    if line.matches?(/\b(tar|chown|chmod|find)\b.*\*/)
      hi("  Wildcard injection vector: #{line.strip}")
    end
    if m = line.match(/\/\S+/)
      bin = m[0].split(/[;\|&><]/).first
      if File.exists?(bin) && File::Info.writable?(bin)
        hi("  Writable cron target binary: #{bin}")
      end
    end
  end
end
