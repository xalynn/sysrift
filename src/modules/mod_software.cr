def mod_software : Nil
  section("Installed Software & Versions")

  tee("#{Y}Compilers / interpreters:#{RS}")
  %w[gcc cc g++ make python python2 python3 perl ruby php node nodejs java go].each do |t|
    if path = Process.find_executable(t)
      ver = run("#{t} --version 2>&1 | head -1")
      info("  #{path} → #{ver}")
    end
  end

  blank
  tee("#{Y}Useful transfer / pivot tools present:#{RS}")
  %w[wget curl nc ncat netcat socat ssh scp rsync screen tmux git docker kubectl tcpdump nmap strace].each do |t|
    if path = Process.find_executable(t)
      info("  #{path}")
    end
  end

  blank
  tee("#{Y}Package manager counts:#{RS}")
  dpkg = run("dpkg -l 2>/dev/null | wc -l")
  info("  dpkg packages: #{dpkg}") unless dpkg.empty?
  rpm = run("rpm -qa 2>/dev/null | wc -l")
  info("  rpm packages:  #{rpm}") unless rpm.empty?

  blank
  tee("#{Y}Web servers:#{RS}")
  %w[apache2 httpd nginx lighttpd].each do |svc|
    if Process.find_executable(svc)
      ver = run("#{svc} -v 2>&1 | head -1")
      med("  #{svc}: #{ver}") unless ver.empty?
    end
  end

  blank
  check_internal_services

  blank
  tee("#{Y}Known vulnerable software:#{RS}")

  # screen < 4.5.1 → CVE-2017-5618
  sv = run("screen --version 2>/dev/null | head -1")
  unless sv.empty?
    info("  screen: #{sv}")
    if m = sv.match(/(\d+)\.(\d+)\.(\d+)/)
      maj, mn, patch = m[1].to_i, m[2].to_i, m[3].to_i
      hi("  screen #{sv} → CVE-2017-5618 (setuid screen LPE)") if {maj, mn, patch} < {4, 5, 1}
    end
  end

  # Exim
  exim = run("exim --version 2>/dev/null | head -1 || exim4 --version 2>/dev/null | head -1")
  med("  Exim: #{exim} — check for known LPE CVEs") unless exim.empty?

  # pkexec PwnKit (CVE-2021-4034) — numeric comparison
  pk = run("pkexec --version 2>/dev/null | head -1")
  unless pk.empty?
    med("  pkexec: #{pk}")
    if m = pk.match(/(\d+)\.(\d+)/)
      pk_maj = m[1].to_i
      pk_mn  = m[2].to_i
      if pk_maj == 0 && pk_mn < 120
        hi("  pkexec → CVE-2021-4034 PwnKit → root!")
      end
      if pk_maj == 0 && pk_mn >= 113 && pk_mn <= 118
        hi("  polkit #{pk_maj}.#{pk_mn} → CVE-2021-3560 auth bypass via D-Bus timing → root!")
      end
    end
  end

  check_userspace_cves
  check_ad_membership
  check_sshd_config

  blank
  check_sessions
end

# Match running processes against known self-hosted services, confirm with ss listener data
private def check_internal_services : Nil
  tee("#{Y}Internal services (lateral movement targets):#{RS}")
  ss_lines = Data.ss_output.split("\n")
  ps = Data.ps_output
  seen = Set(String).new
  hits = 0

  INTERNAL_SERVICES.each do |proc_name, svc|
    next unless ps.includes?("/#{proc_name}") || ps.includes?(" #{proc_name}")
    next unless seen.add?(svc[:label])
    port_line = ss_lines.find { |l| l.includes?(":#{svc[:port]} ") && l.includes?("LISTEN") }
    if port_line
      med("#{svc[:label]} detected (process: #{proc_name}, listening on :#{svc[:port]}) — check for credential reuse / lateral movement")
    else
      med("#{svc[:label]} process detected (#{proc_name}) — port not confirmed on :#{svc[:port]}, check manually")
    end
    hits += 1
  end

  ok("No high-value internal services detected") if hits == 0
rescue File::Error | IO::Error
end

# Userspace CVEs — binary --version or distro package version comparison
private def check_userspace_cves : Nil
  distro_rel  = Data.distro_release
  distro_base = Data.distro_base
  pkg_family  = Data.distro_family
  hits = 0

  USERSPACE_CVES.each do |cve|
    if gate = cve[:distro_gate]
      next unless distro_rel.try(&.starts_with?(gate)) || distro_base.try(&.starts_with?(gate))
    end

    ver_str = nil
    maj = mn = pat = 0

    if bin = cve[:binary]
      next unless Process.find_executable(bin)
      raw = run("#{bin} --version 2>&1 | head -1")
      next if raw.empty?
      if m = raw.match(/(\d+)\.(\d+)\.?(\d+)?/)
        maj, mn = m[1].to_i, m[2].to_i
        pat = m[3]?.try(&.to_i) || 0
        ver_str = raw
      end
    else
      pkg_ver = Data.pkg_version(cve[:pkg])
      next unless pkg_ver
      upstream = pkg_ver.sub(/^\d+:/, "").split("-").first
      if m = upstream.match(/(\d+)\.(\d+)\.?(\d+)?/)
        maj, mn = m[1].to_i, m[2].to_i
        pat = m[3]?.try(&.to_i) || 0
        ver_str = pkg_ver
      end
    end

    next unless ver_str

    fixed = cve[:fixed_versions]
    fix_ver = distro_rel ? fixed[distro_rel]? : nil
    fix_ver ||= distro_base ? fixed[distro_base]? : nil

    # pkg_ver is nil when binary path was taken — guard short-circuits to upstream fallback
    if fix_ver && pkg_family && pkg_ver
      cmp = case pkg_family
            when "dpkg" then dpkg_ver_compare(pkg_ver, fix_ver)
            when "rpm"  then rpm_ver_compare(pkg_ver, fix_ver)
            else             nil
            end
      if cmp && cmp < 0
        if hits == 0
          blank
          tee("#{Y}Userspace software CVEs:#{RS}")
        end
        msg = "#{cve[:name]} (#{cve[:cve]}) — installed: #{ver_str}"
        cve[:severity] == :hi ? hi(msg) : med(msg)
        hits += 1
        next
      else
        next # patched per distro
      end
    end

    # Upstream fallback
    if cve[:check].call(maj, mn, pat)
      if hits == 0
        blank
        tee("#{Y}Userspace software CVEs:#{RS}")
      end
      msg = "check #{cve[:name]} (#{cve[:cve]}) — installed: #{ver_str}"
      if distro_rel
        msg += " [upstream match on #{distro_rel} — distro patch status unverified]"
        med(msg)
      else
        cve[:severity] == :hi ? hi(msg) : med(msg)
      end
      hits += 1
    end
  end
rescue File::Error | IO::Error
end

# Heuristic AD domain membership detection — 2+ indicators required to reduce FP
private def check_ad_membership : Nil
  indicators = 0
  realm_name = nil

  AD_DOMAIN_CONFIGS.each do |path, pattern|
    content = read_file(path)
    next if content.empty?
    if m = content.match(pattern)
      realm_name ||= m[1]?
      indicators += 1
    end
  end

  nsswitch = read_file("/etc/nsswitch.conf")
  unless nsswitch.empty?
    AD_NSSWITCH_TOKENS.each do |token|
      if nsswitch.matches?(/\b#{token}\b/)
        indicators += 1
        break
      end
    end
  end

  AD_DOMAIN_BINARIES.each do |bin|
    if Process.find_executable(bin)
      indicators += 1
      break
    end
  end

  if indicators >= 2
    blank
    msg = "Host appears domain-joined"
    msg += " (realm: #{realm_name})" if realm_name
    msg += " — not directly exploitable, but Kerberos attack surface present (keytabs, ticket caches, delegation)"
    med(msg)
  end
rescue File::Error | IO::Error
end

# sshd_config directives — case-insensitive per OpenSSH spec
private def check_sshd_config : Nil
  content = Data.sshd_config
  return if content.empty?

  blank
  tee("#{Y}SSH server config (#{SSHD_CONFIG_PATH}):#{RS}")
  hits = 0

  content.split("\n").each do |raw_line|
    line = raw_line.strip
    next if line.empty? || line.starts_with?("#")

    parts = line.split(/\s+/, 2)
    next unless parts.size == 2
    directive = parts[0]
    value = parts[1].downcase.strip

    if spec = SSHD_DIRECTIVES[directive.downcase]?
      if spec[:bad].includes?(value)
        msg = "#{directive} #{parts[1].strip} — #{spec[:desc]}"
        case spec[:severity]
        when :hi   then hi(msg)
        when :med  then med(msg)
        when :info then info(msg)
        end
        hits += 1
      end
    end

    if directive.compare("AuthorizedKeysFile", case_insensitive: true) == 0
      raw_val = parts[1].strip
      unless raw_val == ".ssh/authorized_keys" || raw_val == "%h/.ssh/authorized_keys"
        info("Non-standard AuthorizedKeysFile: #{raw_val}")
        hits += 1
      end
    end
  end

  ok("sshd_config — no risky directives found") if hits == 0
rescue File::Error | IO::Error
end

private def check_sessions : Nil
  me = ENV["USER"]? || ""
  hits = 0

  # screen stores sockets in /run/screen/S-<user>/ — connect(2) requires write on the socket
  %w[/run/screen /var/run/screen].each do |base|
    next unless Dir.exists?(base)
    Dir.each_child(base) do |entry|
      next unless entry.starts_with?("S-")
      who = entry.lchop("S-")
      next if who == me
      sock_dir = "#{base}/#{entry}"
      next unless File.directory?(sock_dir)
      Dir.each_child(sock_dir) do |name|
        path = "#{sock_dir}/#{name}"
        next unless File.exists?(path) && File::Info.writable?(path)
        tee("#{Y}Attachable screen/tmux sessions (other users):#{RS}") if hits == 0
        hits += 1
        who == "root" ? hi("Root screen session: #{path}") : med("Screen session (#{who}): #{path}")
      end
    rescue File::Error | IO::Error
    end
  rescue File::Error | IO::Error
  end

  # tmux sockets live in /tmp/tmux-<uid>/ — resolve uid to name for severity split
  tmux_dirs = Dir.glob("/tmp/tmux-*")
  unless tmux_dirs.empty?
    uid_name = {} of String => String
    Data.passwd.split("\n").each do |entry|
      pw = entry.split(":")
      uid_name[pw[2]] = pw[0] if pw.size >= 4
    end

    tmux_dirs.each do |sock_dir|
      next unless File.directory?(sock_dir)
      uid = File.basename(sock_dir).lchop("tmux-")
      who = uid_name[uid]? || "uid:#{uid}"
      next if who == me
      Dir.each_child(sock_dir) do |name|
        path = "#{sock_dir}/#{name}"
        next unless File.exists?(path) && File::Info.writable?(path)
        tee("#{Y}Attachable screen/tmux sessions (other users):#{RS}") if hits == 0
        hits += 1
        uid == "0" ? hi("Root tmux session: #{path}") : med("Tmux session (#{who}): #{path}")
      end
    rescue File::Error | IO::Error
    end
  end

  tee("No attachable screen/tmux sessions from other users") if hits == 0
rescue File::Error | IO::Error
end
