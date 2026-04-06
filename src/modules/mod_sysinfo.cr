def mod_sysinfo : Nil
  section("System Information")

  info("Hostname : #{W}#{Data.hostname}#{RS}")
  info("Identity : #{W}#{Data.id_info}#{RS}")

  hi("Already running as root!") if Data.id_info.includes?("uid=0")

  INTERESTING_GROUPS.each do |grp, note|
    med("Interesting group: #{note}") if Data.groups.includes?(grp)
  end

  info("Kernel   : #{W}#{Data.uname_full}#{RS}")
  maj, mn, pat = Data.kernel_major, Data.kernel_minor, Data.kernel_patch
  distro_rel  = Data.distro_release
  distro_base = Data.distro_base
  pkg_ver     = Data.kernel_pkg_version
  pkg_family  = Data.distro_family

  KERNEL_CVES.each do |cve|
    floors = cve[:distro_floors]
    floor = distro_rel ? floors[distro_rel]? : nil
    floor ||= distro_base ? floors[distro_base]? : nil

    if floor && pkg_ver && pkg_family
      # Distro floor available — authoritative comparison
      cmp = case pkg_family
            when "dpkg" then dpkg_ver_compare(pkg_ver, floor)
            when "rpm"  then rpm_ver_compare(pkg_ver, floor)
            else             nil
            end
      if cmp && cmp < 0
        msg = "Kernel #{Data.kernel} (#{pkg_ver}) → #{cve[:name]} (#{cve[:cve]})"
        cve[:severity] == :hi ? hi(msg) : med(msg)
      end
    elsif cve[:check].call(maj, mn, pat)
      # Upstream version match — qualify if on a known distro without floor data
      msg = "Kernel #{Data.kernel} → check #{cve[:name]} (#{cve[:cve]})"
      if distro_rel
        msg += " [upstream match on #{distro_rel} — distro patch status unverified]"
        med(msg)
      else
        cve[:severity] == :hi ? hi(msg) : med(msg)
      end
    end
  end

  info("OS:\n#{Data.os_release}")

  blank
  info("Interesting environment variables:")
  Data.env_output.split("\n").each do |line|
    key = line.split("=")[0]? || ""
    key_lower = key.downcase
    if !BENIGN_ENV_NAMES.includes?(key) && SENSITIVE_ENV_RE.matches?(key)
      hi("  #{line}")
    elsif INFO_ENV_KEYS.any? { |x| key_lower.includes?(x) }
      info("  #{line}")
    end
  end

  info("PATH: #{(ENV["PATH"]? || "")}")
  Data.path_dirs.each do |p|
    hi("Writable PATH dir: #{p}  ← PATH hijacking possible") if Dir.exists?(p) && File::Info.writable?(p)
  end

  blank
  mounts = Data.mounts
  unless mounts.empty?
    tee("#{Y}Mount options:#{RS}")
    MOUNT_CHECK_PATHS.each do |path|
      if m = Data.mount_for(path)
        absent = %w[nosuid noexec nodev].reject { |flag| m[:opts].includes?(flag) }
        if absent.empty?
          ok("  #{path} on #{m[:mount]} (#{m[:fstype]}) — nosuid,noexec,nodev all set")
        else
          info("  #{path} on #{m[:mount]} (#{m[:fstype]}) — missing: #{absent.join(", ")}")
        end
      end
    end

    fstab = read_file("/etc/fstab")
    unless fstab.empty?
      mounted_points = mounts.map { |m| m[:mount] }.to_set
      fstab.split("\n").each do |line|
        next if line.starts_with?("#") || line.strip.empty?
        if line.matches?(/(password|passwd|credentials?|secret|token|auth(?:entication)?)[=:]/i)
          hi("Credentials in /etc/fstab: #{line.strip}")
        end
        fields = line.split
        next unless fields.size >= 4
        mp = fields[1]
        next if mp == "none" || mp == "swap" || fields[2] == "swap"
        unless mounted_points.includes?(mp)
          med("Unmounted fstab entry: #{fields[0]} → #{mp} (#{fields[2]}) — may be mountable")
        end
      end
    end
  end
end
