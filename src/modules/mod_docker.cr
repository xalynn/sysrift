def mod_docker : Nil
  section("Container / Docker")

  in_docker = File.exists?("/.dockerenv")
  cgroup    = read_file("/proc/1/cgroup")
  in_lxc    = cgroup.downcase.includes?("lxc")
  in_k8s    = Dir.exists?("/run/secrets/kubernetes.io") ||
              File.exists?("/var/run/secrets/kubernetes.io/serviceaccount/token")

  med("Inside a Docker container (/.dockerenv present)") if in_docker
  med("Inside an LXC container (cgroup detection)") if in_lxc
  med("Inside a Kubernetes pod") if in_k8s
  info("Does not appear to be inside a container") unless in_docker || in_lxc || in_k8s

  blank
  sock = "/var/run/docker.sock"
  if File.exists?(sock)
    if File::Info.readable?(sock) && File::Info.writable?(sock)
      hi("Docker socket #{sock} is accessible!")
      hi("  → docker run -v /:/mnt --rm -it alpine chroot /mnt sh")
    else
      med("Docker socket exists at #{sock} but not accessible by current user")
    end
  end

  hi("In docker group → docker run -v /:/mnt --rm -it alpine chroot /mnt sh") if Data.groups.includes?("docker")
  hi("In lxd/lxc group → container image escape to root") if Data.groups.includes?("lxd") || Data.groups.includes?("lxc")

  if in_docker || in_lxc || in_k8s
    blank
    tee("#{Y}Container escape checks:#{RS}")
    info("Capabilities:\n#{Data.proc_caps}")
    cap_bnd_lower = Data.proc_caps.downcase
    if cap_bnd_lower.includes?("ffffffffffffffff")
      hi("Full capability set (64-bit) → likely --privileged container")
      hi("  Escape: mount host disk → write crontab or drop SUID binary")
    elsif cap_bnd_lower.includes?("ffffffff")
      med("Possible full capability set (32-bit match) → verify --privileged")
    end
    blank
    tee("#{Y}Escape surfaces (procfs/sysfs writability):#{RS}")

    # release_agent — iterate cgroup subsystem dirs
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

    {
      "/proc/sys/kernel/core_pattern"       => "overwrite → host code execution on crash",
      "/proc/sys/fs/binfmt_misc/register"   => "register handler → host code execution on binary exec",
      "/sys/kernel/uevent_helper"           => "overwrite → host code execution on device event",
    }.each do |path, desc|
      if File.exists?(path) && File::Info.writable?(path)
        hi("Writable: #{path} → #{desc}")
      end
    end

    {
      "/proc/sys/kernel/modprobe"    => "overwrite modprobe path → code execution on unknown module load",
      "/proc/sysrq-trigger"          => "trigger host kernel actions (DoS)",
      "/proc/sys/vm/panic_on_oom"    => "force host kernel panic on OOM (DoS)",
      "/proc/sys/fs/suid_dumpable"   => "enable core dumps from SUID binaries (info leak)",
    }.each do |path, desc|
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

    host_mounts = Data.mounts.reject { |m| CONTAINER_IGNORE_FS.includes?(m[:fstype]) }
    unless host_mounts.empty?
      med("Host mounts visible inside container:")
      host_mounts.each { |m| tee("  #{m[:mount]} (#{m[:fstype]})") }
    end
  end
end
