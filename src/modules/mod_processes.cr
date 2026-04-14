def mod_processes : Nil
  section("Processes, Cron & Timers")

  tee("#{Y}Root processes with writable binaries:#{RS}")
  ps = Data.ps_output
  custom_bins = Set(String).new
  ps.split("\n").skip(1).each do |line|
    cols = line.split(limit: 11)
    next unless cols.size == 11 && cols[0] == "root"
    bin = cols[10].split[0]? || next
    next unless bin.starts_with?("/")
    if File.exists?(bin) && File::Info.writable?(bin)
      hi("Root process (pid #{cols[1]}): writable binary #{bin}")
    end
    unless STANDARD_BIN_PREFIXES.any? { |p| bin.starts_with?(p) }
      custom_bins << bin
    end
  end

  unless custom_bins.empty?
    blank
    tee("#{Y}Root processes with non-standard binary paths:#{RS}")
    custom_bins.each { |bin| med("Non-standard root binary: #{bin}") }
  end

  blank
  tee(ps)

  blank
  tee("#{Y}Crontab (current user):#{RS}")
  cron = run("crontab -l 2>/dev/null")
  if !cron.empty? && !cron.downcase.includes?("no crontab")
    med("Crontab entries found:")
    tee(cron)
    scan_cron_entries(cron, root_context: false)
  else
    info("No crontab for current user")
  end

  blank
  tee("#{Y}System cron jobs:#{RS}")
  crontab = read_file("/etc/crontab")
  unless crontab.empty?
    tee(crontab)
    scan_cron_entries(crontab, has_user_field: true)
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
        scan_cron_entries(content, has_user_field: d == "/etc/cron.d")
      end
    end
  end

  timers = run("systemctl list-timers --all 2>/dev/null")
  unless timers.empty?
    blank
    tee(timers)
  end

  blank
  check_proc_surfaces

  blank
  sample_processes

  blank
  tee("#{Y}Processes running from /tmp /dev/shm /var/tmp:#{RS}")
  own_pid = Process.pid.to_s
  unusual = ps.split("\n").select { |l|
    next false unless l.includes?("/tmp/") || l.includes?("/dev/shm") || l.includes?("/var/tmp")
    cols = l.split(limit: 3)
    cols.size >= 2 && cols[1] != own_pid
  }
  if unusual.empty?
    ok("No processes from tmp/shm")
  else
    hi("Suspicious process locations:")
    unusual.each { |l| tee(l) }
  end
end

private def check_proc_surfaces : Nil
  tee("#{Y}Process surface analysis:#{RS}")
  own_pid = Process.pid.to_s
  my_uid  = LibC.getuid.to_s
  suid_set = Data.suid_files.to_set
  reported_env = Set(String).new
  found = false

  pids = [] of String
  Dir.each_child("/proc") do |entry|
    pids << entry if entry.each_char.all?(&.ascii_number?) && entry != own_pid
  end
  pids.sort_by! { |p| p.to_i }

  pids.each do |pid|
    status = read_file("/proc/#{pid}/status")
    next if status.empty?

    pname = ""
    uid = ""
    status.each_line do |sl|
      if sl.starts_with?("Name:\t")
        pname = sl[6..].strip
      elsif sl.starts_with?("Uid:\t")
        uid = sl[5..].strip.split.first? || ""
      end
    end

    root_link = File.readlink("/proc/#{pid}/root") rescue nil
    if root_link && root_link != "/"
      med("Chroot jail: pid=#{pid} (#{pname}) root=#{root_link}")
      found = true
      suid_set.each do |sp|
        med("  SUID reachable inside chroot: #{sp}") if File.exists?("#{root_link}#{sp}")
      end
    end

    scan_open_fds(pid, pname, uid, my_uid) { found = true }

    if uid != "0" && uid != my_uid
      environ = read_file("/proc/#{pid}/environ")
      unless environ.empty?
        environ.split('\0').each do |var|
          next if var.empty?
          eq = var.index('=') || next
          key = var[0...eq]
          next if BENIGN_ENV_NAMES.includes?(key)
          next unless key.matches?(SENSITIVE_ENV_RE)
          next if reported_env.includes?("#{uid}:#{key}")
          reported_env << "#{uid}:#{key}"
          val = var[(eq + 1)..]
          masked = val.size > 8 ? "#{val[0, 8]}..." : val
          med("pid=#{pid} (#{pname}) uid=#{uid} env: #{key}=#{masked}")
          found = true
        end
      end
    end
  end

  ok("No sensitive FDs, chroot jails, or leaked env credentials found") unless found
end

private def scan_open_fds(pid : String, pname : String, uid : String, my_uid : String, &) : Nil
  fd_dir = "/proc/#{pid}/fd"
  return unless Dir.exists?(fd_dir)
  Dir.each_child(fd_dir) do |fd_num|
    target = File.readlink("#{fd_dir}/#{fd_num}") rescue next
    next if target[0]? != '/' || target.starts_with?("/dev/") || target.starts_with?("/proc/")
    ext = File.extname(target).downcase
    next unless SENSITIVE_FD_EXTS.includes?(ext)
    next unless SENSITIVE_FD_DIRS.any? { |d| target.starts_with?(d) }
    next if uid == my_uid
    unless File.exists?(target) && File::Info.readable?(target)
      info("pid=#{pid} (#{pname}) uid=#{uid} holds FD to unreadable: #{target}")
      yield
    end
  end
rescue IO::Error | File::Error
end

private def sample_processes : Nil
  tee("#{Y}Process sampling (hidden cron discovery):#{RS}")
  unless Data.active_mode?
    info("Process sampling available — run in active mode for hidden cron discovery (#{PROC_SAMPLE_DURATION.total_seconds.to_i}s observation window)")
    return
  end

  uid_names = build_uid_map
  own_pid = Process.pid
  known_pids = Set(String).new
  Dir.each_child("/proc") do |pid_str|
    known_pids << pid_str if pid_str.each_char.all?(&.ascii_number?)
  end

  seen = Set(String).new
  discovered = [] of NamedTuple(uid: String, user: String, cmdline: String, offset: Int32)
  iterations = (PROC_SAMPLE_DURATION.total_milliseconds / PROC_SAMPLE_INTERVAL.total_milliseconds).to_i

  info("  Sampling /proc for #{PROC_SAMPLE_DURATION.total_seconds.to_i}s at #{PROC_SAMPLE_INTERVAL.total_milliseconds.to_i}ms intervals...")

  iterations.times do |tick|
    Dir.each_child("/proc") do |pid_str|
      next unless pid_str.each_char.all?(&.ascii_number?)
      next if known_pids.includes?(pid_str)
      next if pid_str.to_i == own_pid

      raw = read_file("/proc/#{pid_str}/cmdline")
      next if raw.empty?
      cmdline = raw.gsub('\0', ' ').strip
      next if cmdline.empty? || cmdline.starts_with?("[")

      status = read_file("/proc/#{pid_str}/status")
      uid = ""
      status.each_line do |line|
        if line.starts_with?("Uid:\t")
          uid = line[5..].strip.split.first? || ""
          break
        end
      end

      dedup_key = "#{uid}:#{cmdline[0, PROC_CMDLINE_DISPLAY_MAX]}"
      next unless seen.add?(dedup_key)

      elapsed = (tick.to_f * PROC_SAMPLE_INTERVAL.total_seconds).to_i
      discovered << {uid: uid, user: uid_names[uid]? || "uid:#{uid}", cmdline: cmdline, offset: elapsed}
    end

    sleep(PROC_SAMPLE_INTERVAL)
  end

  if discovered.empty?
    ok("  No new processes observed during #{PROC_SAMPLE_DURATION.total_seconds.to_i}s window")
    return
  end

  tee("  #{discovered.size} unique new process(es) observed:")
  discovered.sort_by { |p| p[:offset] }.each do |proc|
    display = proc[:cmdline].size > PROC_CMDLINE_DISPLAY_MAX ? "#{proc[:cmdline][0, PROC_CMDLINE_DISPLAY_MAX]}..." : proc[:cmdline]
    msg = "  +#{proc[:offset]}s [#{proc[:user]}] #{display}"
    proc[:uid] == "0" ? med(msg) : info(msg)
  end
rescue IO::Error | File::Error
end

private def build_uid_map : Hash(String, String)
  map = {} of String => String
  Data.passwd.split("\n").each do |pw_line|
    fields = pw_line.split(":")
    map[fields[2]] = fields[0] if fields.size >= 3
  end
  map
end

private def scan_cron_entries(content : String, has_user_field = false, root_context = true) : Nil
  content.split("\n").each do |line|
    next if line.starts_with?("#") || line.strip.empty?
    next if line.matches?(/^\s*\w+=/)
    stripped = line.gsub(/'[^']*'|"[^"]*"/, "")
    if stripped.matches?(CRON_WILDCARD_RE)
      hi("  Wildcard injection vector: #{line.strip}")
    end

    user = root_context ? "root" : ""
    if has_user_field
      fields = line.strip.split
      user = fields[5]? || "root"
    end

    if stripped.matches?(CRON_REMOTE_RE) && user == "root"
      med("  Root cron runs remote command (redirect/MITM opportunity): #{line.strip}")
    end

    if m = line.match(/\/\S+/)
      bin = m[0].split(/[;\|&><]/).first
      next if bin == "/dev/null"
      if File.file?(bin) && File::Info.writable?(bin)
        if user == "root"
          hi("  Writable cron target binary (#{user}): #{bin}")
        else
          med("  Writable cron target binary (#{user}): #{bin}")
        end
      elsif File.file?(bin) && File::Info.executable?(bin) && user == "root" &&
            !STANDARD_BIN_PREFIXES.any? { |p| bin.starts_with?(p) }
        info("  Non-standard root cron target (review/reverse): #{bin}")
      end
    end
  end
end
