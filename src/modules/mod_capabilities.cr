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
        next unless line_lower.includes?(cap)

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
      med(line) unless flagged
    end
  end

  blank
  tee("#{Y}Current process capabilities:#{RS}")
  tee(Data.proc_caps)
end
