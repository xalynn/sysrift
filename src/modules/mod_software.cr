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
    end
  end
end
