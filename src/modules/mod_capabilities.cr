def mod_capabilities : Nil
  section("File Capabilities")

  tee("#{Y}Files with capabilities:#{RS}")
  caps = run("getcap -r / 2>/dev/null")
  if caps.empty?
    info("getcap returned nothing (not installed or no capabilities set)")
  else
    caps.split("\n").each do |line|
      if line.includes?("=ep")
        hi("#{line}  ← full capability set (all caps)")
        next
      end
      flagged = false
      line_lower = line.downcase
      DANGEROUS_CAPS.each do |cap, desc|
        if line_lower.includes?(cap)
          hi("#{line}  ← #{desc}")
          flagged = true
          break
        end
      end
      med(line) unless flagged
    end
  end

  blank
  tee("#{Y}Current process capabilities:#{RS}")
  tee(Data.proc_caps)
end
