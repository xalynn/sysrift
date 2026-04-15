def mod_docker : Nil
  section("Container / Docker")

  in_docker = File.exists?("/.dockerenv")
  cgroup    = read_file("/proc/1/cgroup")
  cg_lower  = cgroup.downcase
  in_lxc    = cg_lower.includes?("lxc")
  in_k8s    = Dir.exists?("/run/secrets/kubernetes.io") ||
              File.exists?("/var/run/secrets/kubernetes.io/serviceaccount/token")
  in_podman = File.exists?("/.containerenv")

  med("Inside a Docker container (/.dockerenv present)") if in_docker
  med("Inside an LXC container (cgroup detection)") if in_lxc
  med("Inside a Kubernetes pod") if in_k8s
  med("Inside a Podman container (/.containerenv present)") if in_podman
  if !in_docker && !in_lxc && cg_lower.includes?("containerd")
    med("Inside a containerd-managed container (cgroup detection)")
  end
  if !in_docker && !in_lxc && cg_lower.includes?("cri-o")
    med("Inside a CRI-O container (cgroup detection)")
  end
  info("Does not appear to be inside a container") unless Data.in_container?

  blank
  check_runtime_sockets
  check_runtime_groups

  if Data.in_container?
    blank
    check_escape_surfaces
    blank
    check_container_caps
    blank
    check_namespace_isolation
    blank
    check_container_mac
    blank
    check_host_mounts
    blank
    check_runtime_cves
    blank
    check_escape_tools
    blank
    check_process_heuristic
    blank
    check_pivot_networks
    blank
    check_pivot_arp
    blank
    check_pivot_hosts
    blank
    check_uid_map

    if in_k8s
      blank
      check_k8s_sa
      kubectl = Process.find_executable("kubectl")
      blank
      check_k8s_rbac(kubectl)
      blank
      check_k8s_resources(kubectl)
    end
  end
end

private def check_runtime_sockets : Nil
  tee("#{Y}Container runtime sockets:#{RS}")
  hits = 0

  RUNTIME_SOCKETS.each do |sock, runtime|
    next unless File.exists?(sock)
    if File::Info.readable?(sock) && File::Info.writable?(sock)
      hi("#{runtime} socket #{sock} is accessible!")
      hits += 1
    else
      med("#{runtime} socket exists at #{sock} but not accessible by current user")
      hits += 1
    end
  end

  # podman rootless: /run/user/<uid>/podman/podman.sock
  uid = LibC.getuid.to_s
  rootless_sock = "/run/user/#{uid}/podman/podman.sock"
  if File.exists?(rootless_sock)
    if File::Info.readable?(rootless_sock) && File::Info.writable?(rootless_sock)
      hi("Podman rootless socket #{rootless_sock} is accessible!")
      hits += 1
    else
      med("Podman rootless socket exists at #{rootless_sock} but not accessible")
      hits += 1
    end
  end

  info("No container runtime sockets found") if hits == 0
end

private def check_runtime_groups : Nil
  hi("In docker group → root via socket") if Data.groups.includes?("docker")
  hi("In lxd/lxc group → container image escape to root") if Data.groups.includes?("lxd") || Data.groups.includes?("lxc")
end

private def check_escape_surfaces : Nil
  tee("#{Y}Container escape checks:#{RS}")
  info("Capabilities:\n#{Data.proc_caps}")
  cap_bnd_hex = ""
  Data.proc_caps.each_line do |line|
    if line.starts_with?("CapBnd:\t")
      cap_bnd_hex = line[8..].strip
      break
    end
  end
  unless cap_bnd_hex.empty?
    bnd_set = decode_caps(cap_bnd_hex).to_set
    all_defined = CAP_BITS.values
    if all_defined.all? { |c| bnd_set.includes?(c) }
      hi("Full capability bounding set (#{bnd_set.size}/#{all_defined.size} defined caps) → --privileged container")
      hi("  Escape: mount host disk → write crontab or drop SUID binary")
    end
  end
  blank
  tee("#{Y}Escape surfaces (procfs/sysfs writability):#{RS}")

  if Dir.exists?("/sys/fs/cgroup")
    begin
      Dir.each_child("/sys/fs/cgroup") do |sub|
        ra = "/sys/fs/cgroup/#{sub}/release_agent"
        next unless File.exists?(ra)
        if File::Info.writable?(ra)
          hi("Writable release_agent: #{ra} → container escape via cgroup notify_on_release")
        else
          med("release_agent exists: #{ra} (not writable)")
        end
      end
    rescue File::Error | IO::Error
    end
  end

  ESCAPE_SURFACES_HI.each do |path, desc|
    if File.exists?(path) && File::Info.writable?(path)
      hi("Writable: #{path} → #{desc}")
    end
  end

  ESCAPE_SURFACES_MED.each do |path, desc|
    if File.exists?(path) && File::Info.writable?(path)
      med("Writable: #{path} → #{desc}")
    end
  end

  pstatus = Data.proc_status
  unless pstatus.empty?
    if m = pstatus.match(/^Seccomp:\s*(\d+)/m)
      case m[1]
      when "0" then hi("Seccomp disabled → no syscall filtering, all escape techniques viable")
      when "1" then info("Seccomp: strict mode")
      when "2" then info("Seccomp: filter mode")
      end
    end
    if m = pstatus.match(/^NoNewPrivs:\s*(\d+)/m)
      if m[1] == "0"
        med("NoNewPrivs disabled → SUID/capabilities honored on exec")
      else
        info("NoNewPrivs enabled (SUID/capabilities blocked on exec)")
      end
    end
  end
end

private def check_container_caps : Nil
  tee("#{Y}Ambient capabilities:#{RS}")
  pstatus = Data.proc_status
  cap_amb_hex = ""
  pstatus.each_line do |line|
    if line.starts_with?("CapAmb:\t")
      cap_amb_hex = line[8..].strip
      break
    end
  end

  if cap_amb_hex.empty? || cap_amb_hex == "0000000000000000"
    info("No ambient capabilities set")
    return
  end

  amb_caps = decode_caps(cap_amb_hex)
  if amb_caps.empty?
    info("No ambient capabilities set")
    return
  end

  dangerous = amb_caps.select { |c| DANGEROUS_CAPS.has_key?(c) }
  if dangerous.empty?
    info("Ambient caps (non-dangerous): #{amb_caps.join(", ")}")
    return
  end

  has_hi = dangerous.any? { |c| HI_CAPS.includes?(c) }
  label = dangerous.join(", ")
  if has_hi
    hi("Ambient capabilities: #{label}")
  else
    med("Ambient capabilities: #{label}")
  end
  info("  CapAmb: #{cap_amb_hex}")
end

private def check_namespace_isolation : Nil
  tee("#{Y}Namespace isolation:#{RS}")
  shared = [] of String

  # PID namespace: if PID 1 is a host init, we see the host process tree
  init_comm = read_file("/proc/1/comm").strip
  if HOST_INIT_NAMES.includes?(init_comm)
    shared << "pid"
    med("PID namespace shared with host (PID 1 is #{init_comm})")
  else
    info("PID namespace isolated (PID 1: #{init_comm.empty? ? "unreadable" : init_comm})")
  end

  # NET namespace: host networking exposes physical NICs and bridges
  ifaces = parse_net_ifaces
  if host_net_shared?(ifaces)
    shared << "net"
    med("NET namespace shared with host (#{ifaces.size} interfaces: #{ifaces.first(6).join(", ")})")
  else
    info("NET namespace isolated (#{ifaces.join(", ")})")
  end

  # UTS namespace: hostname matching container ID pattern = isolated
  hostname = Data.hostname
  if hostname.size == 12 && hostname.each_char.all? { |c| c.ascii_number? || ('a' <= c <= 'f') }
    info("UTS namespace isolated (hostname is container ID: #{hostname})")
  else
    info("UTS hostname: #{hostname}")
  end

  if shared.empty?
    info("No shared host namespaces detected")
  end
end

private def check_container_mac : Nil
  tee("#{Y}Container MAC profile:#{RS}")

  # /proc/self/attr/current holds either:
  #   AppArmor profile name (e.g. "docker-default", "unconfined")
  #   SELinux context (e.g. "system_u:system_r:container_t:s0")
  # Distinguish by format: SELinux contexts contain ':'
  raw = read_file("/proc/self/attr/current").strip
  raw = raw.strip("\x00").strip
  label = raw.split(" ").first? || ""

  if label.empty?
    info("No AppArmor or SELinux profile detected")
    return
  end

  if label.includes?(":")
    # SELinux context
    if label.includes?("unconfined_t")
      med("SELinux: unconfined_t (no mandatory access control)")
    elsif label.includes?("container_t") || label.includes?("svirt_lxc_net_t")
      info("SELinux: #{label} (standard container confinement)")
    else
      info("SELinux: #{label}")
    end
  else
    # AppArmor profile
    case label
    when "unconfined"
      med("AppArmor: unconfined (no mandatory access control)")
    when "docker-default"
      info("AppArmor: docker-default (standard Docker confinement)")
    else
      info("AppArmor: #{label}")
    end
  end
end

private def check_host_mounts : Nil
  tee("#{Y}Host mounts:#{RS}")
  host_mounts = Data.mounts.reject { |m| CONTAINER_IGNORE_FS.includes?(m[:fstype]) }
  if host_mounts.empty?
    info("No host filesystem mounts detected")
    return
  end

  host_mounts.each do |m|
    begin
      if File::Info.writable?(m[:mount])
        hi("Writable host mount: #{m[:mount]} (#{m[:fstype]}) → write crontab, drop SUID, plant SSH key")
      else
        med("Host mount: #{m[:mount]} (#{m[:fstype]})")
      end
    rescue File::Error
      med("Host mount: #{m[:mount]} (#{m[:fstype]})")
    end
  end
end

private def check_runtime_cves : Nil
  tee("#{Y}Container runtime CVEs:#{RS}")
  hits = 0
  pkg_family = Data.distro_family

  # CVE-2019-5736: runc < 1.0.0-rc6
  if runc_ver = Data.runc_pkg_version
    if pkg_family
      cmp = case pkg_family
            when "dpkg" then dpkg_ver_compare(runc_ver, "1.0.0~rc6")
            when "rpm"  then rpm_ver_compare(runc_ver, "1.0.0-0.rc6")
            else             nil
            end
      if cmp && cmp < 0
        hi("runc #{runc_ver} → CVE-2019-5736 (container escape via /proc/self/exe overwrite)")
        hits += 1
      else
        info("runc #{runc_ver} (not vulnerable to CVE-2019-5736)")
      end
    else
      info("runc #{runc_ver} (no package manager for version comparison)")
    end
  end

  # CVE-2020-15257: containerd < 1.3.9 or < 1.4.3, requires host networking
  if ctrd_ver = Data.containerd_pkg_version
    # only flag if host networking confirmed via shared net namespace
    net_shared = host_net_shared?(parse_net_ifaces)
    if net_shared && pkg_family
      vulnerable = containerd_15257_vulnerable?(ctrd_ver, pkg_family)
      if vulnerable
        hi("containerd #{ctrd_ver} + host networking → CVE-2020-15257 (host access via abstract unix sockets)")
        hits += 1
      else
        info("containerd #{ctrd_ver} (not vulnerable to CVE-2020-15257)")
      end
    elsif !net_shared
      info("containerd #{ctrd_ver} (CVE-2020-15257 requires host networking — not shared)")
    end
  end

  info("No container runtime CVEs detected") if hits == 0
end

private def check_escape_tools : Nil
  tee("#{Y}Escape-relevant tools:#{RS}")
  found = [] of String
  CONTAINER_ESCAPE_TOOLS.each do |tool|
    if path = Process.find_executable(tool)
      found << "#{tool} (#{path})"
    end
  end
  if found.empty?
    info("No escape-relevant tools found in PATH")
  else
    found.each { |t| info("  #{t}") }
  end
end

private def check_process_heuristic : Nil
  tee("#{Y}Container environment indicators:#{RS}")
  pids = 0
  Dir.each_child("/proc") do |entry|
    pids += 1 if entry.each_char.all?(&.ascii_number?)
  end
  info("Process count: #{pids}")

  present = [] of String
  Data.ps_output.split("\n").skip(1).each do |line|
    cols = line.split(limit: 11)
    next unless cols.size == 11
    bin = File.basename(cols[10].split.first? || "")
    present << bin if HOST_DAEMON_NAMES.includes?(bin) && !present.includes?(bin)
  end

  if present.empty? && pids < 50
    info("Low process count (#{pids}) with no host daemons — consistent with container")
  elsif present.size >= 3
    info("Host-like daemon presence (#{present.join(", ")}) — may not be fully containerized")
  end
rescue File::Error | IO::Error
end

# CVE-2020-15257: containerd < 1.3.9 (1.3.x branch) or < 1.4.3 (1.4.x branch)
private def containerd_15257_vulnerable?(ver : String, family : String) : Bool
  cmp = family == "dpkg" ? ->dpkg_ver_compare(String, String) : ->rpm_ver_compare(String, String)
  if cmp.call(ver, "1.4.0") < 0
    cmp.call(ver, "1.3.9") < 0
  else
    cmp.call(ver, "1.4.3") < 0
  end
end

private def parse_net_ifaces : Array(String)
  read_file("/proc/net/dev").split("\n").skip(2)
    .map { |l| l.split(":").first?.try(&.strip) }.compact.reject(&.empty?)
end

# Heuristic: is the network namespace shared with the host?
# Default container namespace has lo + eth0. Physical NIC names (systemd
# predictable naming, legacy em*, wireless) never appear in a container
# namespace — they're a definitive --net=host signal.
private def host_net_shared?(ifaces : Array(String)) : Bool
  ifaces.any? { |i| HOST_NIC_PREFIXES.any? { |pfx| i.starts_with?(pfx) } }
end

# fib_trie LOCAL table: address on |-- line precedes its /32 leaf
private def check_pivot_networks : Nil
  tee("#{Y}Container network interfaces:#{RS}")
  trie = read_file("/proc/net/fib_trie")
  if trie.empty?
    info("Cannot read /proc/net/fib_trie")
    return
  end

  local_ips = [] of String
  pending_addr = ""
  trie.split("\n").each do |entry|
    node = entry.strip
    if node.starts_with?("|--")
      pending_addr = node[3..].strip
    elsif node.starts_with?("/32")
      if node.includes?("host LOCAL") && !pending_addr.empty?
        local_ips << pending_addr unless pending_addr.starts_with?("127.")
      end
      pending_addr = ""
    end
  end

  if local_ips.empty?
    info("No non-loopback local addresses found")
    return
  end

  local_ips.uniq.each do |ip|
    octets = ip.split(".")
    next unless octets.size == 4
    a = octets[0].to_i?
    b = octets[1].to_i?
    next unless a && b

    net = case
          when a == 172 && b >= 16 && b <= 31
            "RFC1918 172.16/12 — likely Docker bridge or overlay"
          when a == 10
            "RFC1918 10/8 — likely container/overlay network"
          when a == 192 && b == 168
            "RFC1918 192.168/16 — possible bridge network"
          else
            "non-RFC1918"
          end
    info("Local address: #{ip} (#{net})")
  end
end

# /proc/net/arp: on a container bridge, neighbors are sibling containers
private def check_pivot_arp : Nil
  tee("#{Y}ARP neighbors (pivot candidates):#{RS}")
  arp = read_file("/proc/net/arp")
  if arp.empty?
    info("Cannot read /proc/net/arp")
    return
  end

  found = false
  arp.split("\n").skip(1).each do |entry|
    fields = entry.split
    next unless fields.size >= 6
    addr  = fields[0]
    hwaddr = fields[3]
    dev    = fields[5]
    next if dev == "lo" || hwaddr == "00:00:00:00:00:00"
    info("  #{addr} on #{dev}")
    found = true
  end

  info("No ARP neighbors found") unless found
end

# Docker/Podman inject linked container entries and the host gateway
private def check_pivot_hosts : Nil
  tee("#{Y}Container /etc/hosts entries:#{RS}")
  hosts = read_file("/etc/hosts")
  if hosts.empty?
    info("Cannot read /etc/hosts")
    return
  end

  found = false
  hosts.split("\n").each do |entry|
    row = entry.strip
    next if row.empty? || row.starts_with?("#")
    fields = row.split
    next unless fields.size >= 2
    addr = fields[0]
    next if PIVOT_HOSTS_SKIP.includes?(addr)
    names = fields[1..]
    next if names.includes?(Data.hostname)
    info("  #{addr} → #{names.join(", ")}")
    found = true
  end

  info("No non-loopback /etc/hosts entries") unless found
end

private def check_k8s_sa : Nil
  tee("#{Y}Kubernetes service account:#{RS}")

  ns = read_file(K8S_SA_NAMESPACE_PATH)
  info("Pod namespace: #{ns.empty? ? "unknown" : ns}")

  if File.exists?(K8S_SA_TOKEN_PATH) && File::Info.readable?(K8S_SA_TOKEN_PATH)
    med("Service account token readable at #{K8S_SA_TOKEN_PATH}")
  elsif File.exists?(K8S_SA_TOKEN_PATH)
    info("Service account token exists but not readable")
  else
    info("No service account token found")
    return
  end

  if File.exists?(K8S_SA_CA_PATH) && File::Info.readable?(K8S_SA_CA_PATH)
    info("CA cert present at #{K8S_SA_CA_PATH}")
  end
end

private def check_k8s_rbac(kubectl : String?) : Nil
  tee("#{Y}Kubernetes RBAC permissions:#{RS}")

  unless kubectl
    info("kubectl not in PATH — cannot enumerate RBAC")
    return
  end

  listing = run("kubectl auth can-i --list 2>/dev/null")
  if listing.empty?
    info("kubectl auth can-i returned empty (no API access or RBAC denied)")
    return
  end

  escalation = [] of String
  listing.split("\n").each do |row|
    next if row.starts_with?("Resources")
    resource = row.split.first?
    next unless resource
    verb_match = row.match(/\[([^\]]*)\]\s*$/)
    next unless verb_match
    verbs = verb_match[1].split

    if verbs.includes?("*")
      if resource == "*.*" || resource == "*"
        hi("RBAC: wildcard verbs on all resources → cluster admin equivalent")
        return
      end
      escalation << "* #{resource}"
      next
    end

    verbs.each do |verb|
      key = "#{verb} #{resource}"
      escalation << key if K8S_DANGEROUS_RBAC.includes?(key)
    end
  end

  if escalation.empty?
    info("No dangerous RBAC permissions detected")
    tee(listing)
  else
    hi("Dangerous RBAC permissions:")
    escalation.each { |perm| tee("  #{perm}") }
    blank
    info("Full RBAC listing:")
    tee(listing)
  end
end

private def check_k8s_resources(kubectl : String?) : Nil
  return unless kubectl

  tee("#{Y}Kubernetes resource enumeration:#{RS}")

  K8S_ENUM_RESOURCES.each do |resource|
    can = run("kubectl auth can-i list #{resource} 2>/dev/null").strip
    next unless can == "yes"

    result = run("kubectl get #{resource} 2>/dev/null")
    next if result.empty?

    if resource == "secrets"
      hi("Readable K8s secrets:")
    else
      info("K8s #{resource}:")
    end
    tee(result)
    blank
  end
end

private def check_uid_map : Nil
  tee("#{Y}User namespace mapping:#{RS}")

  mapping = read_file("/proc/self/uid_map")
  if mapping.empty?
    info("Cannot read /proc/self/uid_map")
    return
  end

  # "0 0 4294967295" = full host UID range, no remapping
  mapping.split("\n").each do |entry|
    fields = entry.split
    next unless fields.size >= 3
    uid_range = fields[2].to_u64?
    if fields[0] == "0" && fields[1] == "0" && uid_range && uid_range > 65535
      med("User namespace not remapped (#{mapping.strip}) — container UIDs map directly to host")
      return
    end
  end

  info("User namespace mapping: #{mapping.strip}")
end
