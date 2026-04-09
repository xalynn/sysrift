def mod_suid : Nil
  section("SUID / SGID Binaries")

  info("Searching filesystem for SUID/SGID binaries...")
  suids  = Data.suid_files
  sguids = Data.sgid_files

  if suids.empty? && sguids.empty?
    ok("No SUID/SGID binaries found (or insufficient read permissions)")
    return
  end

  hits = 0
  squashfs_skipped = 0
  nonstandard_suids = [] of String
  tee("#{Y}SUID binaries:#{RS}")
  suids.each do |path|
    if m = Data.mount_for(path)
      if m[:fstype] == "squashfs"
        squashfs_skipped += 1
        next
      end
    end
    stat = File.info?(path)
    next unless stat
    root_owned = stat.owner_id == "0"
    unless root_owned
      info("  #{path} (owner uid=#{stat.owner_id}, not root)")
      next
    end
    if Data.nosuid_mount?(path)
      if File::Info.writable?(path)
        med("Writable root SUID on nosuid mount: #{path} → exploitable if remounted")
      else
        info("  #{path} (on nosuid mount — SUID bit ineffective)")
      end
      next
    end
    if File::Info.writable?(path)
      hi("Writable root SUID binary: #{path} → replace for root")
    end
    if name = gtfo_match(path)
      if DEFAULT_SUID_BINS.includes?(name)
        med("#{path}  ← GTFOBins (default install): https://gtfobins.github.io/gtfobins/#{name}/")
      else
        hi("#{path}  ← GTFOBins: https://gtfobins.github.io/gtfobins/#{name}/")
      end
      hits += 1
    else
      info("  #{path}")
      unless STANDARD_SUID_PREFIXES.any? { |pfx| path.starts_with?(pfx) }
        nonstandard_suids << path
      end
    end
  end

  unless sguids.empty?
    blank
    tee("#{Y}SGID binaries:#{RS}")
    gid_map = Hash(String, String).new
    read_file("/etc/group").split("\n").each do |entry|
      fields = entry.split(":")
      gid_map[fields[2]] = fields[0] if fields.size >= 3
    end
    sguids.each do |path|
      if m = Data.mount_for(path)
        if m[:fstype] == "squashfs"
          squashfs_skipped += 1
          next
        end
      end
      stat = File.info?(path)
      next unless stat
      if Data.nosuid_mount?(path)
        if File::Info.writable?(path)
          med("Writable SGID on nosuid mount: #{path} → exploitable if remounted")
        else
          info("  #{path} (on nosuid mount — SGID bit ineffective)")
        end
        next
      end
      if File::Info.writable?(path)
        hi("Writable SGID binary: #{path} → replace for group escalation")
      end
      if grp = gid_map[stat.group_id]?
        if desc = INTERESTING_GROUPS[grp]?
          med("#{path}  ← SGID group=#{grp} (#{desc})")
        end
      end
      if name = gtfo_match(path)
        hi("#{path}  ← GTFOBins SGID match")
        hits += 1
      else
        info("  #{path}")
      end
    end
  end

  info("#{squashfs_skipped} SUID/SGID binaries on squashfs mounts filtered") if squashfs_skipped > 0

  info("#{hits} GTFOBins match(es) found") if hits > 0

  check_suid_shared_libs(nonstandard_suids)
  check_suid_strings(nonstandard_suids)
end

private def check_suid_shared_libs(candidates : Array(String)) : Nil
  return if candidates.empty?
  return unless Process.find_executable("readelf")

  blank
  tee("#{Y}Shared library injection analysis (#{candidates.size} non-standard SUID):#{RS}")

  findings = 0
  candidates.each do |bin|
    io = IO::Memory.new
    Process.run("readelf", args: ["-d", bin], output: io, error: Process::Redirect::Close)

    rpath_dirs = [] of String
    needed = [] of String
    io.to_s.split("\n").each do |line|
      if line.includes?("NEEDED")
        if m = line.match(/\[(.+)\]/)
          needed << m[1]
        end
      elsif line.includes?("RPATH") || line.includes?("RUNPATH")
        if m = line.match(/\[(.+)\]/)
          m[1].split(":").each { |d| s = d.strip; rpath_dirs << s unless s.empty? }
        end
      end
    end

    rpath_dirs.each do |rdir|
      if Dir.exists?(rdir)
        if File::Info.writable?(rdir)
          hi("#{bin}: writable RPATH/RUNPATH #{rdir} → place .so for root")
          findings += 1
        end
      else
        parent = File.dirname(rdir)
        if Dir.exists?(parent) && File::Info.writable?(parent)
          med("#{bin}: RPATH/RUNPATH #{rdir} does not exist, parent writable → mkdir + place .so")
          findings += 1
        end
      end
    end

    # ld.so resolves NEEDED against RPATH first, then standard dirs
    search = rpath_dirs + LIB_SEARCH_DIRS
    needed.each do |soname|
      found_at = search.find { |dir| File.exists?(File.join(dir, soname)) }
      if found_at
        full = File.join(found_at, soname)
        if File::Info.writable?(full)
          hi("#{bin}: writable .so #{full} → replace for root")
          findings += 1
        elsif File::Info.writable?(found_at)
          hi("#{bin}: .so dir writable #{found_at} → replace #{soname} for root")
          findings += 1
        end
      else
        # missing dep — any writable search dir lets us plant it
        if plant_dir = search.find { |dir| Dir.exists?(dir) && File::Info.writable?(dir) }
          hi("#{bin}: #{soname} not found, writable search dir #{plant_dir} → plant for root")
          findings += 1
        end
      end
    end
  end

  if findings == 0
    ok("No shared library injection vectors found")
  else
    info("#{findings} shared library injection vector(s) found")
  end
end

private def check_suid_strings(candidates : Array(String)) : Nil
  return if candidates.empty?
  return unless Process.find_executable("strings")

  writable_path_dirs = Data.path_dirs.select { |d| Dir.exists?(d) && File::Info.writable?(d) }
  path_pos = Hash(String, Int32).new
  Data.path_dirs.each_with_index { |d, i| path_pos[d] = i }

  blank
  tee("#{Y}SUID strings analysis (#{candidates.size} non-standard SUID):#{RS}")

  findings = 0
  candidates.each do |bin|
    io = IO::Memory.new
    status = Process.run("strings", args: [bin], output: io, error: Process::Redirect::Close)
    next unless status.success?

    seen = Set(String).new
    io.to_s.split("\n").each do |line|
      token = line.strip.split.first?
      next unless token && token.size >= 3
      next unless seen.add?(token)

      if token.starts_with?("/")
        if File.exists?(token) && File::Info.writable?(token)
          hi("#{bin}: calls writable path #{token} → replace for root")
          findings += 1
        elsif !File.exists?(token)
          parent = File.dirname(token)
          if Dir.exists?(parent) && File::Info.writable?(parent)
            hi("#{bin}: calls missing path #{token}, parent writable → plant for root")
            findings += 1
          end
        end
        next
      end

      # relative name — filter non-command strings before PATH resolution
      next if token.includes?(".") || token.includes?("(") || token.includes?("=")
      next if token[0] == '-' || token[0] == '_'
      next if STRINGS_NOISE.includes?(token.downcase)
      next unless SUID_CMD_RE.matches?(token)
      next if writable_path_dirs.empty?

      if actual = Process.find_executable(token)
        actual_dir = File.dirname(actual)
        ri = path_pos[actual_dir]?
        next unless ri
        if writable_path_dirs.any? { |wd| (wi = path_pos[wd]?) && wi < ri }
          hi("#{bin}: calls relative \"#{token}\" → writable PATH dir before #{actual}")
          findings += 1
        end
      end
    end
  end

  if findings == 0
    ok("No SUID strings hijack vectors found")
  else
    info("#{findings} SUID strings hijack vector(s) found")
  end
end
