def mod_services : Nil
  section("Services")

  tee("#{Y}Running services:#{RS}")
  svc = run("systemctl list-units --type=service --state=running 2>/dev/null | head -40")
  if svc.empty?
    tee(run("service --status-all 2>/dev/null | grep '+' | head -30"))
  else
    tee(svc)
  end

  blank
  tee("#{Y}Enabled services:#{RS}")
  enabled = run("systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -40")
  tee(enabled) unless enabled.empty?

  blank
  tee("#{Y}Writable service files:#{RS}")
  seen_units = Set(String).new
  hijackable = [] of {String, String}
  seen_directives = Set(String).new

  %w[/etc/systemd/system /lib/systemd/system /usr/lib/systemd/system].each do |d|
    next unless Dir.exists?(d)
    each_systemd_unit(d) do |fp|
      body = read_file(fp)
      real = File.realpath(fp) rescue fp

      if File::Info.writable?(fp) && seen_units.add?(real)
        hi("Writable: #{fp}")
        tee(body) unless body.empty?
      end

      next if body.empty?
      body.each_line do |line|
        directive = line.strip
        next unless directive.starts_with?("ExecStart=") || directive.starts_with?("ExecStartPre=") || directive.starts_with?("ExecStartPost=")
        cmd = directive.split("=", 2).last.lstrip("@!+-")
        next if cmd.empty? || cmd.starts_with?("/")
        if seen_directives.add?("#{real}:#{directive}")
          hijackable << {fp, directive}
        end
      end
    end
  end

  blank
  check_systemd_path_hijack(hijackable)

  blank
  tee("#{Y}init.d scripts:#{RS}")
  if Dir.exists?("/etc/init.d")
    scripts = [] of String
    Dir.each_child("/etc/init.d") do |name|
      fp = "/etc/init.d/#{name}"
      hi("Writable init.d script: #{fp}") if File::Info.writable?(fp)
      scripts << name
    end
    info("Scripts: #{scripts.join(", ")}") unless scripts.empty?
  end
end

private def check_systemd_path_hijack(hijackable : Array({String, String})) : Nil
  tee("#{Y}Systemd PATH hijack check:#{RS}")
  environ = read_file("/proc/1/environ")
  if environ.empty?
    info("Cannot read /proc/1/environ — skipping systemd PATH check")
    return
  end

  path_val = nil
  environ.split('\0').each do |var|
    if var.starts_with?("PATH=")
      path_val = var[5..]
      break
    end
  end

  unless path_val
    info("No PATH in /proc/1/environ")
    return
  end

  writable_dirs = [] of String
  path_val.split(":").each do |dir|
    next if dir.empty?
    writable_dirs << dir if Dir.exists?(dir) && File::Info.writable?(dir)
  end

  if writable_dirs.empty?
    ok("Systemd PATH: no writable directories")
    return
  end

  writable_dirs.each { |d| med("Writable directory in systemd PATH: #{d}") }

  if hijackable.empty?
    info("No service units with relative ExecStart found")
  else
    hijackable.each do |unit, directive|
      hi("PATH hijack: #{unit} — #{directive}")
    end
  end
rescue IO::Error | File::Error
end

private def each_systemd_unit(dir : String, &block : String ->) : Nil
  Dir.each_child(dir) do |name|
    fp = "#{dir}/#{name}"
    if File.directory?(fp) && !File.symlink?(fp)
      Dir.each_child(fp) do |child|
        cfp = "#{fp}/#{child}"
        yield cfp if child.ends_with?(".service") || child.ends_with?(".timer")
      end
    elsif name.ends_with?(".service") || name.ends_with?(".timer")
      yield fp
    end
  end
rescue IO::Error | File::Error
end
