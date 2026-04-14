def mod_writable : Nil
  section("Writable Files & Directories")

  tee("#{Y}High-value writable files:#{RS}")
  %w[/etc/passwd /etc/shadow /etc/sudoers /etc/hosts /etc/crontab /etc/environment
     /etc/profile /etc/bash.bashrc /etc/ld.so.conf /etc/ld.so.preload /etc/sysctl.conf].each do |t|
    hi("Writable: #{t}") if File.exists?(t) && File::Info.writable?(t)
  end

  # credentials flag on a registered handler runs it as the triggering binary's owner
  if File.exists?("/proc/sys/fs/binfmt_misc/register") && File::Info.writable?("/proc/sys/fs/binfmt_misc/register")
    hi("Writable: /proc/sys/fs/binfmt_misc/register → credential handler for root exec")
  end

  blank
  check_ld_paths

  blank
  check_profile_d

  blank
  check_logrotate

  blank
  tee("#{Y}World-writable directories (excl /tmp /proc /dev /run /sys):#{RS}")
  ww = run_lines("find / -maxdepth 6 -type d -perm -0002 " \
    "-not -path '/tmp' -not -path '/tmp/*' " \
    "-not -path '/proc' -not -path '/proc/*' " \
    "-not -path '/dev' -not -path '/dev/*' " \
    "-not -path '/run' -not -path '/run/*' " \
    "-not -path '/sys' -not -path '/sys/*' 2>/dev/null")
  ww.first(30).each { |d| med("World-writable: #{d}") }
  ok("No interesting world-writable directories") if ww.empty?
end

private def check_profile_d : Nil
  dir = "/etc/profile.d"
  return unless Dir.exists?(dir)

  tee("#{Y}Login shell initialization (/etc/profile.d/):#{RS}")

  # sourced by /etc/profile on every login shell — runs as the logging-in user
  dir_writable = File::Info.writable?(dir)
  hi("Writable: #{dir}/ → drop .sh script, runs on next login") if dir_writable

  hit = false
  Dir.each_child(dir) do |name|
    next unless name.ends_with?(".sh")
    path = "#{dir}/#{name}"
    next unless File.file?(path) && File::Info.writable?(path)
    hi("Writable: #{path} → executes as next login user")
    hit = true
  end

  ok("No writable profile.d scripts") unless hit || dir_writable
rescue File::Error | IO::Error
end

private def check_logrotate : Nil
  tee("#{Y}Logrotate abuse (logrotten race condition):#{RS}")

  pkg_ver = Data.pkg_version("logrotate")
  unless pkg_ver
    info("logrotate not installed (or version not queryable)")
    return
  end

  upstream = pkg_ver.sub(/^\d+:/, "").split("-").first
  m = upstream.match(/(\d+)\.(\d+)\.?(\d+)?/)
  unless m
    info("logrotate installed (#{pkg_ver}) — version not parseable")
    return
  end

  maj, mn, pat = m[1].to_i, m[2].to_i, (m[3]?.try(&.to_i) || 0)
  vulnerable = {maj, mn, pat} <= LOGROTATE_VULN_MAX
  info("logrotate #{pkg_ver}#{vulnerable ? " (vulnerable to logrotten race)" : ""}")

  log_paths = Set(String).new
  copy_truncate_paths = Set(String).new

  raw = read_file(LOGROTATE_CONF)
  parse_logrotate_paths(raw, log_paths, copy_truncate_paths) unless raw.empty?

  if Dir.exists?(LOGROTATE_DROP_DIR)
    Dir.each_child(LOGROTATE_DROP_DIR) do |name|
      body = read_file("#{LOGROTATE_DROP_DIR}/#{name}")
      parse_logrotate_paths(body, log_paths, copy_truncate_paths) unless body.empty?
    end
  end

  if log_paths.empty?
    ok("No log paths found in logrotate configs")
    return
  end

  hits = 0
  log_paths.each do |path|
    ct = copy_truncate_paths.includes?(path) ? " [copytruncate]" : ""

    # glob entries — check the directory itself
    if path.includes?("*") || path.includes?("?")
      dir = File.dirname(path)
      next unless Dir.exists?(dir) && File::Info.writable?(dir)
      if vulnerable
        hi("Writable log directory: #{dir} (config: #{path})#{ct} → logrotten race → root file write")
      else
        med("Writable log directory: #{dir} (config: #{path})#{ct}")
      end
      hits += 1
      next
    end

    # concrete file path
    if File.exists?(path) && File::Info.writable?(path)
      if vulnerable
        hi("Writable log file: #{path}#{ct} → logrotten race → root file write")
      else
        med("Writable log file: #{path}#{ct}")
      end
      hits += 1
    else
      parent = File.dirname(path)
      if Dir.exists?(parent) && File::Info.writable?(parent)
        if vulnerable
          hi("Writable log parent dir: #{parent} (#{path})#{ct} → symlink race → root file write")
        else
          med("Writable log parent dir: #{parent} (#{path})#{ct}")
        end
        hits += 1
      end
    end
  end

  ok("No writable log files in logrotate configs") if hits == 0
rescue File::Error | IO::Error
end

# Logrotate config parser — extracts log file paths and tracks copytruncate blocks.
# Format: paths appear before `{`, directives inside `{ ... }`.
private def parse_logrotate_paths(content : String, paths : Set(String), ct_paths : Set(String)) : Nil
  pending = [] of String
  in_block = false
  is_copytruncate = false

  content.split("\n").each do |raw|
    line = raw.strip
    next if line.empty? || line.starts_with?("#")

    if line.includes?("{")
      in_block = true
      is_copytruncate = false
      # paths can share a line with `{` — strip it and check for paths
      pre = line.split("{").first.strip
      unless pre.empty?
        pre.split(/\s+/).each { |p| pending << p if p.starts_with?("/") }
      end
      next
    end

    if line.includes?("}")
      if is_copytruncate
        pending.each { |p| ct_paths << p }
      end
      pending.each { |p| paths << p }
      pending.clear
      in_block = false
      is_copytruncate = false
      next
    end

    if in_block
      is_copytruncate = true if line == "copytruncate"
      # `include` directives inside blocks are not standard — skip
      next
    end

    # outside a block — lines are log file paths (possibly multiple per line)
    # skip logrotate directives that take a path argument
    next if line.starts_with?("include ")

    line.split(/\s+/).each do |token|
      pending << token if token.starts_with?("/")
    end
  end
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
