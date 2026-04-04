# Lazy-cached system data — run once, read from Data.*
module Data
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
  @@groups     : Set(String)? = nil
  @@path_dirs  : Array(String)? = nil
  @@ps_output  : String? = nil
  @@mounts     : Array(NamedTuple(mount: String, fstype: String, opts: Set(String)))? = nil

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
    @@os_release ||= begin
      raw = read_file("/etc/os-release")
      raw = read_file("/etc/issue") if raw.empty?
      raw.split("\n").first(3).join("\n")
    end
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
        read_file("/proc/1/cgroup").downcase.includes?("lxc") ||
        Dir.exists?("/run/secrets/kubernetes.io") ||
        File.exists?("/var/run/secrets/kubernetes.io/serviceaccount/token")
    end
  end
end
