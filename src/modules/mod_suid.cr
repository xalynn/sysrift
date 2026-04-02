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
  tee("#{Y}SUID binaries:#{RS}")
  suids.each do |path|
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
      hi("#{path}  ← GTFOBins: https://gtfobins.github.io/gtfobins/#{name}/")
      hits += 1
    else
      info("  #{path}")
    end
  end

  unless sguids.empty?
    blank
    tee("#{Y}SGID binaries:#{RS}")
    sguids.each do |path|
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
      if name = gtfo_match(path)
        hi("#{path}  ← GTFOBins SGID match")
        hits += 1
      else
        info("  #{path}")
      end
    end
  end

  info("#{hits} GTFOBins match(es) found") if hits > 0
end
