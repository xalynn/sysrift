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
  seen_services = Set(String).new
  %w[/etc/systemd/system /lib/systemd/system /usr/lib/systemd/system].each do |d|
    next unless Dir.exists?(d)
    run_lines("find '#{d}' -writable -name '*.service' 2>/dev/null").each do |f|
      real = begin
        File.realpath(f)
      rescue File::Error
        f
      end
      next if seen_services.includes?(real)
      seen_services << real
      hi("Writable: #{f}")
      tee(read_file(f))
    end
  end

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
