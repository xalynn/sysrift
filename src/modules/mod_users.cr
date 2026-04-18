def mod_users : Nil
  section("Users & Groups")

  info("Current: #{Data.id_info}")

  login_defs = read_file("/etc/login.defs")
  unless login_defs.empty?
    blank
    tee("#{Y}Password policy (/etc/login.defs):#{RS}")
    max_days = login_defs.match(/^\s*PASS_MAX_DAYS\s+(\S+)/m).try &.[1]
    min_days = login_defs.match(/^\s*PASS_MIN_DAYS\s+(\S+)/m).try &.[1]
    warn_age = login_defs.match(/^\s*PASS_WARN_AGE\s+(\S+)/m).try &.[1]
    encrypt  = login_defs.match(/^\s*ENCRYPT_METHOD\s+(\S+)/m).try &.[1]

    if max_days
      max_i = max_days.to_i? || 0
      if max_i >= 99999
        med("  PASS_MAX_DAYS=#{max_days}  ← no password expiry")
      else
        info("  PASS_MAX_DAYS=#{max_days}")
      end
    end
    info("  PASS_MIN_DAYS=#{min_days}") if min_days
    info("  PASS_WARN_AGE=#{warn_age}") if warn_age
    if encrypt
      if encrypt.compare("DES", case_insensitive: true) == 0 || encrypt.compare("MD5", case_insensitive: true) == 0
        med("  ENCRYPT_METHOD=#{encrypt}  ← weak hash algorithm")
      else
        info("  ENCRYPT_METHOD=#{encrypt}")
      end
    end
  end

  blank
  tee("#{Y}Users with interactive shells:#{RS}")
  Data.passwd.split("\n").each do |line|
    parts = line.split(":")
    next if parts.size < 7
    uid   = parts[2].to_i? || -1
    shell = parts[6]
    if uid == 0 && parts[0] != "root"
      hi("UID 0 user: #{line}")
    elsif INTERACTIVE_SHELLS.includes?(shell)
      med("Shell user: #{line}")
    end
  end

  blank
  tee("#{Y}Non-empty groups:#{RS}")
  read_file("/etc/group").split("\n").each do |line|
    parts = line.split(":")
    info("  #{line}") if parts.size >= 4 && !parts[3].empty?
  end

  blank
  tee("#{Y}Last logins:#{RS}")
  tee(run("last 2>/dev/null | head -20"))

  tee("#{Y}Currently logged in:#{RS}")
  tee(run("who 2>/dev/null || w 2>/dev/null"))

  blank
  tee("#{Y}Readable home directories:#{RS}")
  my_home = ENV["HOME"]?
  resolved_home = if my_home
    begin; File.realpath(my_home); rescue File::Error; my_home; end
  end
  if Dir.exists?("/home")
    Dir.each_child("/home") do |entry|
      d = "/home/#{entry}"
      next unless Data.dir_exists?(d) && File::Info.readable?(d)
      med("Readable: #{d}")
      resolved_d = begin; File.realpath(d); rescue File::Error; d; end
      is_own = resolved_home != nil && resolved_d == resolved_home
      ssh_dir = "#{d}/.ssh"
      if Data.dir_exists?(ssh_dir)
        Dir.each_child(ssh_dir) do |f|
          fp = "#{ssh_dir}/#{f}"
          next unless File::Info.readable?(fp)
          if is_own
            info("  Readable SSH file: #{fp}") if f.starts_with?("id_") && !f.ends_with?(".pub")
          else
            hi("  Readable SSH file: #{fp}")
          end
        end
      end
    end
  end
end
