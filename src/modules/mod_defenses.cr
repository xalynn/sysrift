def mod_defenses : Nil
  section("Security Protections")

  # ── Mandatory access control ──────────────────────────────

  aa_enabled = read_file("/sys/module/apparmor/parameters/enabled").strip
  if aa_enabled == "Y"
    profile_lines = read_file("/sys/kernel/security/apparmor/profiles").split("\n")
    enforce  = profile_lines.count(&.includes?("enforce"))
    complain = profile_lines.count(&.includes?("complain"))
    if enforce > 0
      ok("AppArmor: #{enforce} enforcing, #{complain} complain")
    else
      med("AppArmor loaded but no profiles enforcing (#{complain} complain)")
    end
    current = read_file("/proc/self/attr/current").strip
    info("  Current profile: #{current}") unless current.empty?
  elsif aa_enabled == "N"
    med("AppArmor: compiled into kernel but disabled")
  end

  se_config = read_file("/etc/selinux/config")
  unless se_config.empty?
    enforce_val = read_file("/sys/fs/selinux/enforce").strip
    case enforce_val
    when "1" then ok("SELinux: enforcing")
    when "0" then med("SELinux: permissive (logs but does not block)")
    else
      if se_config.match(/^\s*SELINUX\s*=\s*disabled/mi)
        med("SELinux: disabled")
      else
        info("SELinux: config present, enforcement unknown")
      end
    end
  end

  # ── Address space ─────────────────────────────────────────

  aslr = read_file("/proc/sys/kernel/randomize_va_space").strip
  case aslr
  when "0" then hi("ASLR disabled → kernel exploits reliable, ret2libc viable")
  when "1" then med("ASLR partial (shared libraries only, stack not randomized)")
  when "2" then ok("ASLR: full")
  end

  mmap = read_file("/proc/sys/vm/mmap_min_addr").strip
  if mmap == "0"
    med("mmap_min_addr=0 → NULL pointer dereference exploits viable")
  elsif !mmap.empty?
    info("mmap_min_addr=#{mmap}")
  end

  # ── Kernel exposure ───────────────────────────────────────

  sysctl_check("/proc/sys/kernel/kptr_restrict", "kptr_restrict",
    bad: "0", bad_sev: :med,
    bad_desc: "kernel symbol addresses exposed → useful for exploit development",
    good_desc: "kernel pointers restricted")

  sysctl_check("/proc/sys/kernel/dmesg_restrict", "dmesg_restrict",
    bad: "0", bad_sev: :med,
    bad_desc: "kernel log readable by unprivileged users → address leaks",
    good_desc: "kernel log restricted to root")

  perf = read_file("/proc/sys/kernel/perf_event_paranoid").strip
  if v = perf.to_i?
    if v <= 1
      med("perf_event_paranoid=#{v} → unprivileged perf access, kernel address leak via side channels")
    else
      info("perf_event_paranoid=#{v}")
    end
  end

  # ── Process isolation ─────────────────────────────────────

  sysctl_check("/proc/sys/kernel/yama/ptrace_scope", "ptrace_scope",
    bad: "0", bad_sev: :med,
    bad_desc: "any process can ptrace any other owned process → credential extraction, injection",
    good_desc: "ptrace restricted")

  # mod_docker reports seccomp in container escape context — skip here to avoid duplication
  unless Data.in_container?
    pstatus = Data.proc_status
    if m = pstatus.match(/^Seccomp:\s*(\d+)/m)
      case m[1]
      when "0" then med("Seccomp: disabled for current process")
      when "1" then info("Seccomp: strict mode")
      when "2" then info("Seccomp: filter mode")
      end
    end
  end

  sysctl_check("/proc/sys/fs/protected_symlinks", "protected_symlinks",
    bad: "0", bad_sev: :med,
    bad_desc: "symlink following unrestricted → symlink race attacks in world-writable dirs",
    good_desc: "symlink following restricted")

  sysctl_check("/proc/sys/fs/protected_hardlinks", "protected_hardlinks",
    bad: "0", bad_sev: :med,
    bad_desc: "hardlink creation unrestricted → hardlink attack to privileged files",
    good_desc: "hardlink creation restricted")

  userns = read_file("/proc/sys/kernel/unprivileged_userns_clone").strip
  if userns == "1"
    info("unprivileged_userns_clone=1 (user namespaces available to unprivileged users)")
  elsif userns == "0"
    info("unprivileged_userns_clone=0 (user namespaces restricted)")
  end

  sysctl_check("/proc/sys/kernel/unprivileged_bpf_disabled", "unprivileged_bpf_disabled",
    bad: "0", bad_sev: :med,
    bad_desc: "unprivileged eBPF enabled → kernel memory read/write via verifier bugs",
    good_desc: "unprivileged eBPF disabled")

  mod_disabled = read_file("/proc/sys/kernel/modules_disabled").strip
  sig_enforce  = read_file("/proc/sys/kernel/module_sig_enforce").strip
  if sig_enforce.empty?
    sig_enforce = read_file("/sys/module/module/parameters/sig_enforce").strip
  end

  if mod_disabled == "0" && (sig_enforce == "0" || sig_enforce == "N" || sig_enforce.empty?)
    med("Kernel modules loadable without signature enforcement")
  elsif mod_disabled == "0"
    info("modules_disabled=0, module_sig_enforce=#{sig_enforce}")
  elsif mod_disabled == "1"
    ok("Kernel module loading disabled")
  end

  # ── Loaded kernel modules ─────────────────────────────────
  check_kernel_modules

  # ── Permissive /dev/ entries ─────────────────────────────
  check_dev_permissions

  lockdown = read_file("/sys/kernel/security/lockdown").strip
  unless lockdown.empty?
    if m = lockdown.match(/\[([^\]]+)\]/)
      mode = m[1]
      case mode
      when "none"            then hi("Kernel lockdown: none → kernel memory and module access unrestricted")
      when "integrity"       then ok("Kernel lockdown: integrity")
      when "confidentiality" then ok("Kernel lockdown: confidentiality")
      else                        info("Kernel lockdown: #{mode}")
      end
    else
      info("Kernel lockdown: #{lockdown}")
    end
  end

  if Data.kernel.includes?("-grsec")
    info("grsecurity kernel detected")
  end
  if Process.find_executable("paxctl") || Process.find_executable("paxctl-ng")
    info("PaX control binary found")
  end
end

private def check_kernel_modules : Nil
  raw = read_file("/proc/modules")
  return if raw.empty?

  krel = Data.kernel
  mod_base = "/lib/modules/#{krel}"
  standard = Set(String).new
  if Dir.exists?(mod_base)
    Dir.glob("#{mod_base}/**/*.ko*") do |path|
      name = File.basename(path).sub(/\.ko(\.\w+)?$/, "").tr("-", "_")
      standard << name
    end
  end

  count = 0
  raw.each_line do |line|
    fields = line.split
    next if fields.size < 3
    name    = fields[0]
    size    = fields[1]
    refcnt  = fields[2]
    deps    = fields.size > 3 ? fields[3].rstrip(",") : "-"

    next if standard.includes?(name)
    if standard.empty?
        info("Loaded module: #{name} (size=#{size} refcnt=#{refcnt} deps=#{deps})")
    else
      med("Non-standard kernel module: #{name} (size=#{size} refcnt=#{refcnt} deps=#{deps})")
    end
    count += 1
  end
  if count == 0 && !standard.empty?
    ok("All loaded modules found in #{mod_base}")
  end
end

private def check_dev_permissions : Nil
  return unless Dir.exists?("/dev")

  my_groups = Data.groups
  gid_map = Hash(String, String).new
  read_file("/etc/group").each_line do |gl|
    f = gl.split(":")
    gid_map[f[2]] = f[0] if f.size >= 3
  end

  found = false
  flag_dev = ->(fp : String) do
    fi = File.info?(fp, follow_symlinks: false)
    return unless fi
    mode = fi.permissions.value
    if (mode & 0o002) != 0
      med("World-writable /dev/ entry: #{fp} (#{sprintf("%04o", mode)})")
      found = true
    elsif (mode & 0o020) != 0
      if gn = gid_map[fi.group_id.to_s]?
        if my_groups.includes?(gn)
          med("Group-writable /dev/ entry: #{fp} (#{sprintf("%04o", mode)}, group=#{gn})")
          found = true
        end
      end
    end
  end

  Dir.each_child("/dev") do |entry|
    next if dev_entry_standard?(entry)
    fp = "/dev/#{entry}"
    if File.directory?(fp)
      next if STANDARD_DEV_DIRS.includes?(entry)
      begin
        Dir.each_child(fp) { |child| flag_dev.call("#{fp}/#{child}") }
      rescue IO::Error | File::Error
      end
    else
      flag_dev.call(fp)
    end
  end
  ok("No permissive non-standard /dev/ entries") unless found
rescue IO::Error | File::Error
end

private def dev_entry_standard?(name : String) : Bool
  return true if STANDARD_DEV_NAMES.includes?(name)
  name.starts_with?("loop") || name.starts_with?("ram") ||
    name.starts_with?("dm-") || name.starts_with?("tty") ||
    name.starts_with?("vcsa") || name.starts_with?("vcs") ||
    name.starts_with?("sd") || name.starts_with?("vd") ||
    name.starts_with?("nvme") || name.starts_with?("sr")
end

# Reads a sysctl procfs/sysfs value and reports based on bad/good threshold.
# Silently skips if the file doesn't exist or is empty.
private def sysctl_check(path : String, name : String, *,
                          bad : String, bad_sev : Symbol,
                          bad_desc : String, good_desc : String) : Nil
  val = read_file(path).strip
  return if val.empty?
  if val == bad
    if bad_sev == :hi
      hi("#{name}=#{val} → #{bad_desc}")
    else
      med("#{name}=#{val} → #{bad_desc}")
    end
  else
    info("#{name}=#{val} (#{good_desc})")
  end
end
