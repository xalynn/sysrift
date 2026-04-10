def mod_users : Nil
  section("Users & Groups")

  info("Current: #{Data.id_info}")

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
      next unless Dir.exists?(d) && File::Info.readable?(d)
      med("Readable: #{d}")
      resolved_d = begin; File.realpath(d); rescue File::Error; d; end
      is_own = resolved_home != nil && resolved_d == resolved_home
      ssh_dir = "#{d}/.ssh"
      if Dir.exists?(ssh_dir)
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
