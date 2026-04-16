def mod_capabilities : Nil
  section("File Capabilities")

  tee("#{Y}Files with capabilities:#{RS}")
  caps = run("getcap -r / 2>/dev/null")
  if caps.empty?
    info("getcap returned nothing (not installed or no capabilities set)")
  else
    caps.split("\n").each do |line|
      next if line.empty?

      # " =ep" or "=ep" at start of caps field means ALL caps granted.
      # "cap_foo=ep" is a single cap — handled by the DANGEROUS_CAPS loop.
      if line.matches?(/\s=ep\b/)
        hi("#{line}  ← full capability set (all caps)")
        next
      end

      # Normalize binary name for combo lookup — same logic as gtfo_match
      bin_raw = if path = line.split.first?
                  File.basename(path).downcase
                end
      bin_base = bin_raw.try(&.gsub(/[\d.]+$/, ""))

      flagged = false
      line_lower = line.downcase
      DANGEROUS_CAPS.each do |cap, desc|
        next unless line_lower.matches?(DANGEROUS_CAP_RE[cap])

        combo_hit = false
        if name = bin_raw
          if combos = DANGEROUS_CAP_COMBOS[cap]?
            base = bin_base
            if combo = combos.find { |c| c[:bin] == name || (base && c[:bin] == base) }
              if combo[:severity] == :hi
                hi("#{line}  ← #{cap} + #{name}: #{combo[:desc]}")
              else
                med("#{line}  ← #{cap} + #{name}: #{combo[:desc]}")
              end
              combo_hit = true
            end
          end
        end

        hi("#{line}  ← #{desc}") unless combo_hit
        flagged = true
        break
      end
      info(line) unless flagged
    end
  end

  blank
  tee("#{Y}Current process capabilities:#{RS}")
  tee(Data.proc_caps)

  blank
  tee("#{Y}Processes with capabilities:#{RS}")
  own_pid = Process.pid.to_s
  my_uid  = LibC.getuid.to_s
  actionable = 0
  pids = [] of String
  Dir.each_child("/proc") do |entry|
    pids << entry if entry.each_char.all?(&.ascii_number?) && entry != own_pid
  end
  pids.sort_by! { |p| p.to_i }
  pids.each do |entry|
    status = read_file("/proc/#{entry}/status")
    next if status.empty?

    cap_eff_hex = ""
    cap_amb_hex = ""
    cap_inh_hex = ""
    cap_prm_hex = ""
    cap_bnd_hex = ""
    proc_name = ""
    proc_uid = ""

    status.each_line do |line|
      if line.starts_with?("CapEff:\t")
        cap_eff_hex = line[8..].strip
      elsif line.starts_with?("CapAmb:\t")
        cap_amb_hex = line[8..].strip
      elsif line.starts_with?("CapInh:\t")
        cap_inh_hex = line[8..].strip
      elsif line.starts_with?("CapPrm:\t")
        cap_prm_hex = line[8..].strip
      elsif line.starts_with?("CapBnd:\t")
        cap_bnd_hex = line[8..].strip
      elsif line.starts_with?("Name:\t")
        proc_name = line[6..].strip
      elsif line.starts_with?("Uid:\t")
        proc_uid = line[5..].strip.split.first? || ""
      end
    end

    eff_zero = cap_eff_hex.empty? || cap_eff_hex == "0000000000000000"
    amb_zero = cap_amb_hex.empty? || cap_amb_hex == "0000000000000000"
    next if eff_zero && amb_zero

    # uid=0 with CapEff==CapBnd is the default kernel grant — skip unless
    # inside a container where CapBnd is restricted
    next if proc_uid == "0" && cap_eff_hex == cap_bnd_hex

    eff_caps = decode_caps(cap_eff_hex)
    amb_caps = decode_caps(cap_amb_hex)

    dangerous_eff = eff_caps.select { |c| DANGEROUS_CAPS.has_key?(c) }
    dangerous_amb = amb_caps.select { |c| DANGEROUS_CAPS.has_key?(c) }
    all_dangerous = dangerous_eff | dangerous_amb

    if all_dangerous.empty?
      info("pid=#{entry} (#{proc_name}) uid=#{proc_uid}  CapEff=#{cap_eff_hex}")
    else
      # cap_sys_admin from clone(CLONE_NEWUSER) — every Chromium/Electron
      # process gets this for sandboxing, not exploitable
      if proc_uid == my_uid &&
         all_dangerous.size == 1 && all_dangerous[0] == "cap_sys_admin" &&
         CHROMIUM_SANDBOX_NAMES.includes?(proc_name)
        info("pid=#{entry} (#{proc_name}) uid=#{proc_uid}  cap_sys_admin (sandbox)")
        next
      end

      if SUID_HELPER_NAMES.includes?(proc_name)
        info("pid=#{entry} (#{proc_name}) uid=#{proc_uid}  #{all_dangerous.join(", ")}")
        next
      end

      if expected = KNOWN_DAEMON_CAPS[proc_name]?
        if all_dangerous.all? { |c| expected.includes?(c) }
          info("pid=#{entry} (#{proc_name}) uid=#{proc_uid}  #{all_dangerous.join(", ")}")
          next
        end
      end

      has_hi = all_dangerous.any? { |c| HI_CAPS.includes?(c) }
      label = if all_dangerous.size == DANGEROUS_CAPS.size
                "full dangerous set (#{all_dangerous.size} caps)"
              else
                all_dangerous.join(", ")
              end

      if has_hi
        hi("pid=#{entry} (#{proc_name}) uid=#{proc_uid}  #{label}")
      else
        med("pid=#{entry} (#{proc_name}) uid=#{proc_uid}  #{label}")
      end

      tee("    CapEff: #{cap_eff_hex}")
      tee("    CapAmb: #{cap_amb_hex}") unless amb_zero
      tee("    CapPrm: #{cap_prm_hex}")
      tee("    CapBnd: #{cap_bnd_hex}")
      tee("    CapInh: #{cap_inh_hex}")
      actionable += 1
    end
  end
  info("No processes with non-zero CapEff or CapAmb (besides self)") if actionable == 0
end
