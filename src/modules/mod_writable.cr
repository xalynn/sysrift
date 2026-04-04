def mod_writable : Nil
  section("Writable Files & Directories")

  tee("#{Y}High-value writable files:#{RS}")
  %w[/etc/passwd /etc/shadow /etc/sudoers /etc/hosts /etc/crontab /etc/environment
     /etc/profile /etc/bash.bashrc /etc/ld.so.conf /etc/ld.so.preload /etc/sysctl.conf].each do |t|
    hi("Writable: #{t}") if File.exists?(t) && File::Info.writable?(t)
  end

  blank
  check_ld_paths

  blank
  tee("#{Y}World-writable directories (excl /tmp /proc /dev /run /sys):#{RS}")
  ww = run_lines("find / -maxdepth 6 -type d -perm -0002 2>/dev/null | grep -vE '^/(tmp|proc|dev|run|sys)'")
  ww.first(30).each { |d| med("World-writable: #{d}") }
  ok("No interesting world-writable directories") if ww.empty?
end

private def check_ld_paths : Nil
  tee("#{Y}Library search path writability (ld.so.conf):#{RS}")
  lib_dirs = Set(String).new
  conf_files = ["/etc/ld.so.conf"]

  raw = read_file("/etc/ld.so.conf")
  raw.split("\n").each do |line|
    stripped = line.strip
    next if stripped.empty? || stripped.starts_with?("#")
    if stripped.starts_with?("include ")
      glob = stripped.lchop("include ").strip
      inc_dir = File.dirname(glob)
      if Dir.exists?(inc_dir) && File::Info.writable?(inc_dir)
        hi("Writable ld config dir: #{inc_dir} → drop new .conf to inject library path")
      end
      Dir.glob(glob).each { |f| conf_files << f }
    else
      lib_dirs << stripped if stripped.starts_with?("/")
    end
  end

  conf_files.skip(1).each do |cf|
    if File::Info.writable?(cf)
      hi("Writable ld config: #{cf} → inject library search path")
    end
    content = read_file(cf)
    content.split("\n").each do |line|
      stripped = line.strip
      next if stripped.empty? || stripped.starts_with?("#")
      lib_dirs << stripped if stripped.starts_with?("/")
    end
  end

  vuln = false
  lib_dirs.each do |d|
    next unless Dir.exists?(d)
    if File::Info.writable?(d)
      hi("Writable library path: #{d} → shared object injection into SUID binaries")
      vuln = true
    end
  end

  preload = read_file("/etc/ld.so.preload")
  unless preload.empty?
    preload.split("\n").each do |line|
      so_path = line.strip
      next if so_path.empty? || so_path.starts_with?("#")
      parent = File.dirname(so_path)
      if Dir.exists?(parent) && File::Info.writable?(parent)
        hi("Writable parent of ld.so.preload entry: #{parent} (#{so_path}) → replace preloaded library")
        vuln = true
      end
    end
  end

  ok("No writable library search paths") unless vuln
end
