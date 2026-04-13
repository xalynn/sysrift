def mod_network : Nil
  section("Network Information")

  tee("#{Y}Interfaces:#{RS}")
  tee(run("ip addr 2>/dev/null || ifconfig -a 2>/dev/null"))

  blank
  tee("#{Y}Routes:#{RS}")
  tee(run("ip route 2>/dev/null || route -n 2>/dev/null"))

  blank
  tee("#{Y}Listening ports:#{RS}")
  Data.ss_output.split("\n").each do |line|
    next if line.empty? || line.matches?(/^(State|Proto|Netid)/)
    # extract port from addr:port or *:port patterns in ss/netstat output
    port = line.match(/:(\d+)\s/)
    if port && (note = INTERESTING_PORTS[port[1]]?)
      med("  #{line}  ← #{note}")
    else
      info("  #{line}")
    end
  end

  blank
  tee("#{Y}/etc/hosts:#{RS}")
  tee(read_file("/etc/hosts"))

  blank
  tee("#{Y}ARP cache:#{RS}")
  tee(run("arp -a 2>/dev/null || ip neigh 2>/dev/null"))
  tee("#{Y}Active connections:#{RS}")
  tee(run("ss -tp 2>/dev/null || netstat -tp 2>/dev/null"))
  med("IP forwarding enabled — potential pivot point") if read_file("/proc/sys/net/ipv4/ip_forward") == "1"
  tee(read_file("/etc/resolv.conf"))

  check_rcommands
end

private def check_rcommands : Nil
  blank
  tee("#{Y}Legacy r-commands trust:#{RS}")
  found = false

  # hosts.equiv grants passwordless rlogin/rsh to listed hosts
  %w[/etc/hosts.equiv /etc/shosts.equiv].each do |equiv|
    next unless File.exists?(equiv)
    content = read_file(equiv)
    if content.empty?
      info("#{equiv} exists (empty)")
      next
    end
    has_wildcard = content.each_line.any? { |l| r = l.strip; !r.empty? && !r.starts_with?('#') && r.matches?(/(?:^|\s)\+(?:\s|$)/) }
    if has_wildcard
      hi("#{equiv}: wildcard '+' trust (passwordless access from any host)")
    else
      med("#{equiv} exists with trust entries")
    end
    found = true
  end

  # .rhosts = per-user trust file, same format as hosts.equiv
  %w[/root].concat(
    Dir.glob("/home/*").select { |d| File.directory?(d) }
  ).each do |homedir|
    rhosts = "#{homedir}/.rhosts"
    next unless File.exists?(rhosts)
    content = read_file(rhosts)
    if content.empty?
      info("#{rhosts} exists (empty)")
      next
    end
    has_wildcard = content.each_line.any? { |l| r = l.strip; !r.empty? && !r.starts_with?('#') && r.matches?(/(?:^|\s)\+(?:\s|$)/) }
    if has_wildcard
      hi("#{rhosts}: wildcard '+' trust#{homedir == "/root" ? " (root — immediate access)" : ""}")
    else
      med("#{rhosts} exists with trust entries")
    end
    found = true
  end

  # rsh=514, rlogin=513, rexec=512 — /proc/net/tcp has hex port + state
  tcp = read_file("/proc/net/tcp")
  unless tcp.empty?
    tcp.each_line do |entry|
      cols = entry.strip.split
      next unless cols.size >= 4 && cols[3] == "0A" # 0A = LISTEN
      port_hex = cols[1].split(":").last?
      if port_hex && (port = RSERVICE_PORTS[port_hex]?)
        med("r-service listening on port #{port}")
        found = true
      end
    end
  end

  # inetd — service name is always the first field
  inetd = read_file("/etc/inetd.conf")
  unless inetd.empty?
    inetd.each_line do |entry|
      row = entry.strip
      next if row.empty? || row.starts_with?('#')
      svc = row.split.first?
      if svc && svc.matches?(RSERVICE_RE)
        med("/etc/inetd.conf: #{row}")
        found = true
      end
    end
  end

  if Dir.exists?("/etc/xinetd.d")
    Dir.each_child("/etc/xinetd.d") do |name|
      conf = "/etc/xinetd.d/#{name}"
      next unless File::Info.readable?(conf)
      body = read_file(conf)
      next unless body.matches?(/^\s*service\s+(rsh|rlogin|rexec|shell|login|exec)\b/mi)
      next if body.matches?(/^\s*disable\s*=\s*yes\b/mi)
      med("xinetd r-service enabled: #{conf}")
      found = true
    end
  end

  ok("No legacy r-commands trust found") unless found
end
