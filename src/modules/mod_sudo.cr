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
