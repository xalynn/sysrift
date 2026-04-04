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
end
