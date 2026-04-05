def mod_sudo : Nil
  section("Sudo Rights")
  seen = Set(String).new

  sudo_l = Data.sudo_l
  if sudo_l.empty?
    info("sudo -l returned nothing (no rights, or requires password without a tty)")
  else
    tee(sudo_l)
    blank
    sudo_l.split("\n").each do |line|
      if line.downcase.includes?("nopasswd")
        key = "nopasswd:#{line.strip}"
        hi("NOPASSWD entry: #{line.strip}") if seen.add?(key)
      end
      line.scan(/\/\S+/).each do |m|
        name = File.basename(m[0]).downcase
        if GTFOBINS.includes?(name)
          hi("GTFOBins binary in sudo rule: #{m[0]}") if seen.add?("gtfo:#{m[0]}")
        end
      end
    end
    scan_sudoers_rules(sudo_l, "sudo -l", seen)
    enumerate_pivot_targets(sudo_l)
  end

  blank
  sudo_ver = run("sudo --version 2>/dev/null | head -1")
  sv_maj = sv_mn = sv_pat = sv_plevel = 0
  sv_parsed = false
  unless sudo_ver.empty?
    info("Sudo version: #{sudo_ver}")
    if m = sudo_ver.match(/(\d+)\.(\d+)(?:\.(\d+))?(?:p(\d+))?/)
      sv_maj    = m[1].to_i
      sv_mn     = m[2].to_i
      sv_pat    = m[3]?.try(&.to_i) || 0
      sv_plevel = m[4]?.try(&.to_i) || 0
      sv_parsed = true
      if sv_maj == 1 && sv_mn == 8 && sv_pat < 2
        hi("sudo #{sudo_ver} → CVE-2019-14287 (sudo -u#-1 bypass)")
      elsif sv_maj == 1 && sv_mn == 8 && sv_pat >= 2 && sv_pat < 28
        hi("sudo #{sudo_ver} → CVE-2019-14287 (sudo -u#-1) and CVE-2021-3156 Baron Samedit")
      elsif sv_maj == 1 && sv_mn == 8 && sv_pat >= 28 && sv_pat < 32
        hi("sudo #{sudo_ver} → CVE-2021-3156 Baron Samedit heap overflow → root")
      elsif sv_maj == 1 && sv_mn == 9 && (sv_pat < 5 || (sv_pat == 5 && sv_plevel < 2))
        hi("sudo #{sudo_ver} → CVE-2021-3156 Baron Samedit heap overflow → root")
      end
    end
  end

  blank
  sudoers = Data.sudoers
  unless sudoers.empty?
    hi("/etc/sudoers is readable!")
    tee(sudoers)
    audit_sudoers_file(sudoers, "/etc/sudoers", sv_parsed, sv_maj, sv_mn, sv_pat, seen)
  end

  blank
  enumerate_sudoers_d(sv_parsed, sv_maj, sv_mn, sv_pat, seen)

  blank
  tee("#{Y}Doas:#{RS}")
  check_doas

  blank
  tee("#{Y}Sudo token reuse:#{RS}")
  check_sudo_tokens
end

# Single-pass scan for env_keep vectors, !env_reset, NOPASSWD, and GTFOBins in sudoers content
private def scan_sudoers_rules(content : String, source : String, seen : Set(String)) : Nil
  content.split("\n").each do |line|
    stripped = line.strip
    next if stripped.starts_with?("#") || stripped.empty?

    if m = stripped.match(/env_keep\s*\+?=\s*(.+)/)
      values = m[1].tr("\"", " ").split
      DANGEROUS_ENV_KEEP.each do |var, desc|
        if values.includes?(var)
          hi("#{source} env_keep includes #{var} → #{desc}") if seen.add?("envkeep:#{var}")
        end
      end
    end

    if stripped.starts_with?("!env_reset")
      hi("#{source}: !env_reset → all caller env vars passed to root context") if seen.add?("envreset")
    end

    if stripped.downcase.includes?("nopasswd")
      hi("NOPASSWD entry in #{source}: #{stripped}") if seen.add?("nopasswd:#{stripped}")
    end

    line.scan(/\/\S+/).each do |m|
      bin = File.basename(m[0]).downcase
      if GTFOBINS.includes?(bin)
        hi("GTFOBins binary in #{source}: #{m[0]}") if seen.add?("gtfo:#{m[0]}")
      end
    end
  end
end

private def audit_sudoers_file(content : String, source : String,
                               sv_parsed : Bool, sv_maj : Int32, sv_mn : Int32, sv_pat : Int32,
                               seen : Set(String)) : Nil
  if content.includes?("pwfeedback")
    if sv_parsed
      if sv_maj == 1 && ((sv_mn == 7 && sv_pat >= 1) || (sv_mn == 8 && sv_pat < 26))
        hi("pwfeedback + sudo < 1.8.26 → CVE-2019-18634 buffer overflow")
      else
        info("pwfeedback enabled (not vulnerable — sudo >= 1.8.26)")
      end
    else
      med("pwfeedback in #{source} — could not parse sudo version, check CVE-2019-18634 manually")
    end
  end
  scan_sudoers_rules(content, source, seen)
end

private def enumerate_sudoers_d(sv_parsed : Bool, sv_maj : Int32, sv_mn : Int32, sv_pat : Int32,
                                seen : Set(String)) : Nil
  dir = "/etc/sudoers.d"
  return unless Dir.exists?(dir)

  if File::Info.writable?(dir)
    hi("/etc/sudoers.d/ is writable → create new sudoers drop-in for root!")
  end

  # sudo #includedir skips files with '.' in name or '~' suffix
  Dir.each_child(dir) do |name|
    next if name.includes?('.') || name.ends_with?('~')
    path = "#{dir}/#{name}"
    next unless File.file?(path)

    if File::Info.writable?(path)
      hi("Writable sudoers drop-in: #{path} → modify for root!")
    end

    content = read_file(path)
    next if content.empty?
    info("Readable sudoers drop-in: #{path}")
    tee(content)
    audit_sudoers_file(content, path, sv_parsed, sv_maj, sv_mn, sv_pat, seen)
  end
rescue File::Error | IO::Error
end

private def enumerate_pivot_targets(sudo_l : String) : Nil
  current_user = ENV["USER"]? || ""
  skip = Set{"root", "ALL", current_user}
  pivot_users = Set(String).new

  sudo_l.split("\n").each do |line|
    if m = line.match(/\(([a-zA-Z0-9._-]+)/)
      user = m[1]
      pivot_users << user unless skip.includes?(user)
    end
  end

  return if pivot_users.empty?

  blank
  tee("#{Y}Pivot target directory analysis:#{RS}")
  now = Time.local
  pivot_users.each do |user|
    dirs = run_lines("find / -user #{user} -type d " \
      "-not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' " \
      "-not -path '/run/*' -not -path '/usr/*' -not -path '/lib/*' " \
      "-not -path '/lib64/*' -not -path '/boot/*' -not -path '/sbin/*' " \
      "-not -path '/bin/*' -not -path '/snap/*' 2>/dev/null")
    next if dirs.empty?
    med("Directories owned by #{user} (sudo pivot target):")
    dirs.each do |d|
      tee("  #{d}")
      begin
        Dir.each_child(d) do |name|
          path = "#{d}/#{name}"
          next unless stat = File.info?(path)
          next unless stat.owner_id == "0"
          age = now - stat.modification_time
          if age.total_seconds > 0 && age.total_days < 7
            hi("  Root-owned recent file: #{path} (modified #{format_age(age)} ago)")
          end
        end
      rescue File::Error | IO::Error
      end
    end
  end
end

private def format_age(span : Time::Span) : String
  if span.total_days >= 1
    "#{span.total_days.to_i}d"
  elsif span.total_hours >= 1
    "#{span.total_hours.to_i}h"
  else
    "#{span.total_minutes.to_i}m"
  end
end

private def check_doas : Nil
  doas_bin = Process.find_executable("doas")
  unless doas_bin
    tee("doas not found")
    return
  end

  info("doas binary: #{doas_bin}")
  if stat = File.info?(doas_bin)
    info("  SUID: #{stat.flags.set_user?}  owner: #{stat.owner_id}")
  end

  me = ENV["USER"]? || ""
  my_groups = Data.groups
  have_conf = false

  %w[/etc/doas.conf /usr/local/etc/doas.conf].each do |conf|
    next unless File.exists?(conf)
    have_conf = true

    # writable conf = write your own permit rule
    parent = File.dirname(conf)
    if parent != "/etc" && Dir.exists?(parent) && File::Info.writable?(parent)
      hi("Writable directory containing #{conf} → replace doas.conf")
    end
    hi("Writable: #{conf} → inject permit nopass rule") if File::Info.writable?(conf)

    raw = read_file(conf)
    next if raw.empty?
    info("Readable: #{conf}")

    raw.split("\n").each do |rule|
      rule = rule.strip
      next if rule.empty? || rule.starts_with?("#") || !rule.starts_with?("permit")
      words = rule.split
      next if words.size < 2

      # walk past option keywords to reach identity
      pos = 1
      rule_opts = [] of String
      while pos < words.size && DOAS_OPTIONS.includes?(words[pos])
        rule_opts << words[pos]
        pos += 1
      end
      next if pos >= words.size
      who = words[pos]

      # "as target" defaults to root when omitted
      runas = "root"
      if pos + 2 < words.size && words[pos + 1] == "as"
        runas = words[pos + 2]
      end

      # only flag rules the current user can actually invoke
      ours = who.starts_with?(":") ? my_groups.includes?(who.lchop(":")) : who == me

      if rule_opts.includes?("nopass")
        if runas == "root"
          ours ? hi("doas: nopass #{who} as root → immediate root") :
                 info("doas: nopass #{who} as root (not current user)")
        else
          ours ? med("doas: nopass #{who} as #{runas} → lateral pivot") :
                 info("doas: nopass #{who} as #{runas} (not current user)")
        end
      end

      # keepenv preserves LD_PRELOAD through the privilege boundary
      if rule_opts.includes?("keepenv") && runas == "root" && ours
        hi("doas: keepenv as root for #{who} → LD_PRELOAD injection")
      end

      if rule_opts.includes?("persist") && ours
        med("doas: persist for #{who} → cached credential reuse window")
      end
    end
  end

  tee("No doas.conf found") unless have_conf
rescue File::Error | IO::Error
end

private def check_sudo_tokens : Nil
  ts_dir = %w[/var/run/sudo/ts /run/sudo/ts].find { |d| Dir.exists?(d) }
  unless ts_dir
    tee("No sudo token directory found")
    return
  end

  # writable timestamp dir = forge tokens without ptrace
  hi("#{ts_dir} is writable → forge sudo timestamps directly") if File::Info.writable?(ts_dir)

  me = ENV["USER"]? || ""
  ts_file = "#{ts_dir}/#{me}"
  have_token = File.exists?(ts_file)

  if have_token && File::Info.writable?(ts_file)
    hi("User sudo token file writable: #{ts_file}")
  elsif have_token
    info("Sudo token file exists: #{ts_file}")
  end

  # ptrace token injection: gdb attaches to a sibling shell that holds a valid
  # sudo timestamp, then calls create_timestamp() in the target's address space
  ptrace = read_file("/proc/sys/kernel/yama/ptrace_scope").to_i? || -1
  gdb = !!Process.find_executable("gdb")
  prior_sudo = have_token || File.exists?("#{ENV["HOME"]?}/.sudo_as_admin_successful")

  # count sibling shells owned by us — injection targets
  shell_names = INTERACTIVE_SHELLS.map { |sh| File.basename(sh) }.to_set
  pid = Process.pid.to_s
  siblings = 0
  Data.ps_output.split("\n").skip(1).each do |entry|
    col = entry.split(limit: 11)
    next unless col.size >= 11 && col[0] == me && col[1] != pid
    bin = File.basename(col[10].split.first? || "")
    siblings += 1 if shell_names.includes?(bin)
  end

  if ptrace < 0
    info("ptrace_scope unreadable — cannot assess token injection")
  elsif ptrace == 0
    if gdb && siblings > 0 && prior_sudo
      hi("Sudo token injection viable: ptrace=0, gdb present, #{siblings} sibling shell(s), " \
         "#{have_token ? "active token" : ".sudo_as_admin_successful"}")
    elsif gdb && siblings > 0
      med("Sudo token injection possible: ptrace=0, gdb present, #{siblings} sibling shell(s) " \
          "(no cached token yet)")
    elsif gdb
      info("ptrace=0 + gdb present but no sibling shells for injection")
    else
      info("ptrace=0 (unprotected) but gdb not available")
    end
  else
    info("ptrace_scope=#{ptrace} — token injection blocked")
  end
rescue File::Error | IO::Error
end
