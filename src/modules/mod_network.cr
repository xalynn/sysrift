def mod_network : Nil
  section("Network Information")

  tee("#{Y}Interfaces:#{RS}")
  tee(run("ip addr 2>/dev/null || ifconfig -a 2>/dev/null"))

  blank
  tee("#{Y}Routes:#{RS}")
  tee(run("ip route 2>/dev/null || route -n 2>/dev/null"))

  blank
  tee("#{Y}Listening ports:#{RS}")
  run("ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null").split("\n").each do |line|
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
end
