# Lazy-cached system data — run once, read from Data.*
module Data
  @@active_mode : Bool = false

  def self.active_mode? : Bool
    @@active_mode
  end

  def self.active_mode=(val : Bool) : Nil
    @@active_mode = val
  end

  # ── Safe filesystem predicates ────────────────────────────
  # Stdlib Dir.exists? / File.exists? raise File::AccessDeniedError
  # when stat() returns EACCES (parent dir not searchable). On a
  # target system with restrictive permissions, every unguarded
  # stat is a crash site. These helpers swallow File::Error so
  # callers can treat unreachable paths as "not present" — the
  # operationally correct semantics for an enumeration tool.

  def self.dir_exists?(path : String) : Bool
    info = File.info?(path)
    !info.nil? && info.directory?
  rescue File::Error
    false
  end

  def self.file_exists?(path : String) : Bool
    info = File.info?(path)
    !info.nil? && info.file?
  rescue File::Error
    false
  end

  @@id_info    : String? = nil
  @@passwd     : String? = nil
  @@shadow     : String? = nil
  @@sudoers    : String? = nil
  @@sudo_l     : String? = nil
  @@suid_files : Array(String)? = nil
  @@sgid_files : Array(String)? = nil
  @@env_output : String? = nil
  @@proc_status : String? = nil
  @@proc_caps   : String? = nil
  @@kernel       : String? = nil
  @@kernel_parts : {Int32, Int32, Int32}? = nil
  @@uname_full   : String? = nil
  @@hostname   : String? = nil
  @@os_release : String? = nil
  @@distro_family     : String? = nil
  @@distro_release    : String? = nil
  @@distro_base       : String? = nil
  @@kernel_pkg_version : String? = nil
  @@distro_family_checked : Bool = false
  @@distro_parsed : Bool = false
  @@kernel_pkg_version_checked : Bool = false
  @@groups     : Set(String)? = nil
  @@gid_map    : Hash(String, String)? = nil
  @@home_dirs  : Array(String)? = nil
  @@path_dirs  : Array(String)? = nil
  @@ps_output  : String? = nil
  @@ss_output  : String? = nil
  @@sshd_config : String? = nil
  @@mounts     : Array(NamedTuple(mount: String, fstype: String, opts: Set(String)))? = nil
  @@cloud_provider : String?  = nil
  @@cloud_context  : String?  = nil
  @@cloud_detected : Bool     = false
  @@resolv_conf    : String?  = nil
  @@db_creds       : Array(NamedTuple(service: String, user: String, host: String)) = [] of NamedTuple(service: String, user: String, host: String)

  # ── Identity ──────────────────────────────────────────────

  def self.id_info : String
    @@id_info ||= run("id")
  end

  def self.groups : Set(String)
    @@groups ||= begin
      set = Set(String).new
      id_info.scan(/\(([^)]+)\)/) { |m| set << m[1] }
      set
    end
  end

  def self.gid_map : Hash(String, String)
    @@gid_map ||= begin
      map = Hash(String, String).new
      raw = read_file("/etc/group")
      raw.each_line do |entry|
        fields = entry.split(":")
        map[fields[2]] = fields[0] if fields.size >= 3
      end
      map
    end
  end

  # ── System ────────────────────────────────────────────────

  def self.hostname : String
    @@hostname ||= System.hostname
  end

  def self.kernel : String
    @@kernel ||= begin
      rel = read_file("/proc/sys/kernel/osrelease")
      rel.empty? ? run("uname -r") : rel
    end
  end

  private def self.parse_kernel : {Int32, Int32, Int32}
    parts = kernel.split(".")
    major = parts[0]?.try(&.to_i?) || 0
    minor = parts[1]?.try(&.to_i?) || 0
    patch = parts[2]?.try { |s| s.split(/[^0-9]/, 2).first?.try(&.to_i?) } || 0
    {major, minor, patch}
  end

  def self.kernel_parts : {Int32, Int32, Int32}
    @@kernel_parts ||= parse_kernel
  end

  def self.kernel_major : Int32
    kernel_parts[0]
  end

  def self.kernel_minor : Int32
    kernel_parts[1]
  end

  def self.kernel_patch : Int32
    kernel_parts[2]
  end

  def self.uname_full : String
    @@uname_full ||= run("uname -a")
  end

  def self.os_release : String
    parse_distro_info
    @@os_release || ""
  end

  # "dpkg", "rpm", or nil — detected via executable presence
  def self.distro_family : String?
    unless @@distro_family_checked
      @@distro_family_checked = true
      @@distro_family = if Process.find_executable("dpkg")
                           "dpkg"
                         elsif Process.find_executable("rpm")
                           "rpm"
                         end
    end
    @@distro_family
  end

  private def self.parse_distro_info : Nil
    return if @@distro_parsed
    @@distro_parsed = true
    raw = read_file("/etc/os-release")
    if raw.empty?
      @@os_release = read_file("/etc/issue").split("\n").first(3).join("\n")
      return
    end
    lines = raw.split("\n")
    @@os_release = lines.first(3).join("\n")

    id = nil
    ver = nil
    id_like = nil
    ubuntu_codename = nil
    lines.each do |line|
      field = line.strip
      if field.starts_with?("ID=")
        id = field[3..].tr("\"", "")
      elsif field.starts_with?("VERSION_ID=")
        ver = field[11..].tr("\"", "")
      elsif field.starts_with?("ID_LIKE=")
        id_like = field[8..].tr("\"", "")
      elsif field.starts_with?("UBUNTU_CODENAME=")
        ubuntu_codename = field[16..].tr("\"", "")
      end
    end

    @@distro_release = if id && ver
                         "#{id}_#{ver}"
                       elsif id
                         id
                       end

    # Derivative distros share kernel packages with their parent
    if id_like
      likes = id_like.split
      if likes.includes?("ubuntu") && ubuntu_codename
        if base_ver = UBUNTU_CODENAME_MAP[ubuntu_codename]?
          @@distro_base = "ubuntu_#{base_ver}"
        end
      elsif likes.includes?("rhel") && ver
        @@distro_base = "rhel_#{ver.split(".").first}"
      elsif likes.includes?("debian") && ver
        @@distro_base = "debian_#{ver.split(".").first}"
      end
    end
  end

  # "linuxmint_22.3", "ubuntu_22.04", "debian_11", "rhel_8", etc.
  def self.distro_release : String?
    parse_distro_info
    @@distro_release
  end

  # Parent distro for derivatives: "ubuntu_24.04" for Mint 22, "rhel_8" for Rocky 8
  # nil if the distro IS the base (ubuntu, debian, rhel) or unknown
  def self.distro_base : String?
    parse_distro_info
    @@distro_base
  end

  # Installed kernel package version string — one spawn, cached
  def self.kernel_pkg_version : String?
    unless @@kernel_pkg_version_checked
      @@kernel_pkg_version_checked = true
      @@kernel_pkg_version = begin
        case distro_family
        when "dpkg"
          io = IO::Memory.new
          status = Process.run("dpkg-query",
            args: ["-W", "-f=${Version}", "linux-image-#{kernel}"],
            output: io, error: Process::Redirect::Close)
          raw = io.to_s.strip
          status.success? && !raw.empty? ? raw : nil
        when "rpm"
          io = IO::Memory.new
          status = Process.run("rpm",
            args: ["-q", "--queryformat", "%{VERSION}-%{RELEASE}", "kernel-#{kernel}"],
            output: io, error: Process::Redirect::Close)
          raw = io.to_s.strip
          status.success? ? raw.presence : nil
        end
      rescue IO::Error
        nil
      end
    end
    @@kernel_pkg_version
  end

  def self.path_dirs : Array(String)
    @@path_dirs ||= (ENV["PATH"]? || "").split(":").reject(&.empty?).uniq
  end

  def self.env_output : String
    @@env_output ||= String.build { |io| ENV.each { |k, v| io << k << "=" << v << "\n" } }.strip
  end

  def self.ps_output : String
    @@ps_output ||= run("ps aux 2>/dev/null")
  end

  def self.ss_output : String
    @@ss_output ||= run("ss -tulpn 2>/dev/null")
  end

  def self.sshd_config : String
    @@sshd_config ||= read_file("/etc/ssh/sshd_config")
  end

  def self.resolv_conf : String
    @@resolv_conf ||= read_file("/etc/resolv.conf")
  end

  def self.db_creds : Array(NamedTuple(service: String, user: String, host: String))
    @@db_creds
  end

  def self.add_db_cred(service : String, user : String, host : String) : Nil
    @@db_creds << {service: service, user: user, host: host}
  end

  # ── Cloud detection ─────────────────────────────────────

  private def self.detect_cloud : Nil
    return if @@cloud_detected
    @@cloud_detected = true
    CLOUD_INDICATORS.each do |ind|
      if ind[:check].call
        @@cloud_provider = ind[:provider]
        @@cloud_context  = ind[:label]
        return
      end
    end
    # DMI fallback for bare-metal VMs without cloud-init markers
    vendor = read_file("/sys/class/dmi/id/sys_vendor").downcase
    if vendor.includes?("amazon")
      @@cloud_provider = "aws_ec2"
      @@cloud_context  = "AWS EC2 instance (DMI)"
    elsif vendor.includes?("google")
      @@cloud_provider = "gcp"
      @@cloud_context  = "GCP VM instance (DMI)"
    elsif vendor.includes?("microsoft")
      @@cloud_provider = "azure"
      @@cloud_context  = "Azure VM (DMI)"
    elsif vendor.includes?("digitalocean")
      @@cloud_provider = "do"
      @@cloud_context  = "DigitalOcean Droplet (DMI)"
    end
  end

  def self.cloud_provider : String?
    detect_cloud
    @@cloud_provider
  end

  def self.cloud_context : String?
    detect_cloud
    @@cloud_context
  end

  # ── Mounts ───────────────────────────────────────────────

  def self.mounts : Array(NamedTuple(mount: String, fstype: String, opts: Set(String)))
    @@mounts ||= begin
      raw = read_file("/proc/mounts")
      entries = [] of NamedTuple(mount: String, fstype: String, opts: Set(String))
      raw.split("\n").each do |line|
        fields = line.split
        next unless fields.size >= 4
        mp = fields[1].gsub(/\\([0-7]{3})/) { |_, m| m[1].to_i(8).chr.to_s }
        entries << {mount: mp, fstype: fields[2], opts: Set.new(fields[3].split(","))}
      end
      entries.sort_by { |e| -e[:mount].size }
    end
  end

  def self.mount_for(path : String) : NamedTuple(mount: String, fstype: String, opts: Set(String))?
    mounts.find { |e| path.starts_with?(e[:mount] == "/" ? "/" : e[:mount] + "/") || path == e[:mount] }
  end

  def self.nosuid_mount?(path : String) : Bool
    if m = mount_for(path)
      m[:opts].includes?("nosuid")
    else
      false
    end
  end

  # ── File contents (read once) ─────────────────────────────

  def self.passwd : String
    @@passwd ||= read_file("/etc/passwd")
  end

  def self.home_dirs : Array(String)
    @@home_dirs ||= begin
      dirs = Array(String).new
      passwd.each_line do |line|
        fields = line.split(":")
        next unless fields.size >= 7
        shell = fields[6]
        next if shell.ends_with?("nologin") || shell.ends_with?("/false") || shell.ends_with?("/sync")
        home = fields[5]
        # exec bit on a directory == search permission; without it, every
        # downstream stat under this home raises File::AccessDeniedError
        dirs << home if !home.empty? && dir_exists?(home) && File::Info.executable?(home)
      end
      if !dirs.includes?("/root") && dir_exists?("/root") && File::Info.executable?("/root")
        dirs << "/root"
      end
      dirs.uniq!
      dirs
    end
  end

  def self.shadow : String
    @@shadow ||= read_file("/etc/shadow")
  end

  def self.sudoers : String
    @@sudoers ||= read_file("/etc/sudoers")
  end

  def self.sudo_l : String
    @@sudo_l ||= begin
      child = Process.new("sudo", args: ["-l"],
        input: Process::Redirect::Close,
        output: Process::Redirect::Pipe,
        error: Process::Redirect::Close)

      stdout = Channel(String).new
      reaped = Channel(Process::Status).new
      spawn { stdout.send(child.output.gets_to_end) }
      spawn { reaped.send(child.wait) }

      select
      when raw = stdout.receive
        reaped.receive
        raw.strip
      when timeout(5.seconds)
        child.terminate(graceful: false)
        reaped.receive
        ""
      end
    rescue IO::Error | File::Error
      ""
    end
  end

  # ── Expensive filesystem scans ────────────────────────────

  def self.suid_files : Array(String)
    @@suid_files ||= run_lines("find / -perm -4000 -type f 2>/dev/null")
  end

  def self.sgid_files : Array(String)
    @@sgid_files ||= run_lines("find / -perm -2000 -type f 2>/dev/null")
  end

  # ── Process status ───────────────────────────────────────

  def self.proc_status : String
    @@proc_status ||= read_file("/proc/self/status")
  end

  def self.proc_caps : String
    @@proc_caps ||= proc_status.split("\n").select(&.starts_with?("Cap")).join("\n")
  end

  # ── Container detection ─────────────────────────────────

  @@in_container : Bool? = nil

  def self.in_container? : Bool
    @@in_container ||= begin
      File.exists?("/.dockerenv") ||
        File.exists?("/.containerenv") ||
        begin
          cgroup = read_file("/proc/1/cgroup").downcase
          cgroup.includes?("lxc") ||
            cgroup.includes?("docker") ||
            cgroup.includes?("containerd") ||
            cgroup.includes?("cri-o") ||
            cgroup.includes?("podman")
        end ||
        Dir.exists?("/run/secrets/kubernetes.io") ||
        File.exists?("/var/run/secrets/kubernetes.io/serviceaccount/token")
    end
  end

  # ── Container runtime package versions ──────────────────

  @@runc_pkg_version : String? = nil
  @@runc_pkg_checked : Bool = false
  @@containerd_pkg_version : String? = nil
  @@containerd_pkg_checked : Bool = false

  def self.runc_pkg_version : String?
    unless @@runc_pkg_checked
      @@runc_pkg_checked = true
      @@runc_pkg_version = pkg_version("runc")
    end
    @@runc_pkg_version
  end

  def self.containerd_pkg_version : String?
    unless @@containerd_pkg_checked
      @@containerd_pkg_checked = true
      @@containerd_pkg_version = pkg_version("containerd")
    end
    @@containerd_pkg_version
  end

  def self.pkg_version(name : String) : String?
    case distro_family
    when "dpkg"
      io = IO::Memory.new
      status = Process.run("dpkg-query",
        args: ["-W", "-f=${Version}", name],
        output: io, error: Process::Redirect::Close)
      raw = io.to_s.strip
      status.success? && !raw.empty? ? raw : nil
    when "rpm"
      io = IO::Memory.new
      status = Process.run("rpm",
        args: ["-q", "--queryformat", "%{VERSION}-%{RELEASE}", name],
        output: io, error: Process::Redirect::Close)
      raw = io.to_s.strip
      status.success? ? raw.presence : nil
    end
  rescue IO::Error
    nil
  end
end
