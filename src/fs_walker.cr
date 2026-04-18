# Single-pass filesystem walker. One descent from /, one stat per
# entry, all predicates evaluated inline. Skip set is the only depth
# defense; result caps bound output. Consumers read typed sets via
# Data.* accessors.
module FsWalker
  RESULT_KEYS = [
    :suid, :sgid,
    :world_writable_dirs, :world_writable_files,
    :backup_files, :recent_files,
    :ssh_keys, :netrc_files, :history_files,
    :sensitive_configs,
    :password_vaults, :tfstate_files,
    :cert_keystores, :cert_pemkeys,
    :log4j_jars,
    :cred_scan_files, :log_files,
    :path_sh_scripts, :path_broken_symlinks,
    :weak_kernel_modules,
  ]

  alias Aliases = Hash(String, Array(String))
  alias RunResult = NamedTuple(results: Hash(Symbol, Array(String)), aliases: Aliases)

  private class State
    property results : Hash(Symbol, Array(String))
    property visited : Set({UInt64, UInt64})
    property sym_targets : Aliases
    property skip_mounts : Set(String)
    property counter : Int32
    property aborted : Bool

    def initialize
      @results = Hash(Symbol, Array(String)).new
      RESULT_KEYS.each { |k| @results[k] = [] of String }
      @visited = Set({UInt64, UInt64}).new
      @sym_targets = Aliases.new
      @skip_mounts = build_skip_mount_set
      @counter = 0
      @aborted = false
    end

    private def build_skip_mount_set : Set(String)
      set = Set(String).new
      Data.mounts.each do |m|
        set << m[:mount] if WALKER_SKIP_FSTYPES.includes?(m[:fstype])
      end
      set
    end
  end

  # Result paths are real filesystem paths. Symlink reachability lives
  # separately in the alias map (target → [incoming symlinks]) so
  # consumers can format their own output without parsing path strings.
  def self.run : RunResult
    state = State.new
    started = Time.instant
    done = Channel(Nil).new(1)
    spawn run_status_line(started, done)

    begin
      walk_dir("/", state)
      walk_path_subwalk(state)
      walk_modules_subwalk(state)
    ensure
      done.send(nil)
      finalize_status_line(started, state)
    end

    {results: state.results, aliases: state.sym_targets}
  end

  # In-place updating row via \r — TTY only, so piped output stays clean.
  private def self.run_status_line(started : Time::Instant, done : Channel(Nil)) : Nil
    unless STDOUT.tty?
      done.receive
      return
    end
    STDOUT.print "[*] Walking filesystem... 0.0s"
    STDOUT.flush
    loop do
      select
      when done.receive
        break
      when timeout(WALKER_STATUS_INTERVAL.seconds)
        STDOUT.print "\r[*] Walking filesystem... #{started.elapsed.total_seconds.round(1)}s"
        STDOUT.flush
      end
    end
  end

  private def self.finalize_status_line(started : Time::Instant, state : State) : Nil
    elapsed = started.elapsed.total_seconds
    if STDOUT.tty?
      STDOUT.print "\r" + (" " * 60) + "\r"
    end
    suffix = state.aborted ? " (aborted at WALKER_MAX_ENTRIES cap)" : ""
    Out.write("#{G}[+]#{RS} Filesystem walk complete in #{elapsed.round(1)}s (#{state.counter} entries)#{suffix}")
  end

  private def self.walk_dir(path : String, state : State) : Nil
    return if state.aborted
    begin
      Dir.each_child(path) do |name|
        return if state.aborted
        child = path == "/" ? "/#{name}" : "#{path}/#{name}"
        visit_entry(child, name, state)
      end
    rescue File::Error | IO::Error
    end
  end

  private def self.visit_entry(path : String, name : String, state : State) : Nil
    state.counter += 1
    if state.counter >= WALKER_MAX_ENTRIES
      state.aborted = true
      return
    end
    # Yield periodically so the status fiber can redraw.
    Fiber.yield if state.counter % 1024 == 0

    # File::Info doesn't expose st_dev / st_ino — only same_file?(other)
    # — so call lstat directly and wrap the same struct via File::Info.new
    # for the predicate API. One syscall, raw inode pair for dedup.
    stat = uninitialized LibC::Stat
    return unless LibC.lstat(path, pointerof(stat)) == 0

    inode_key = {stat.st_dev.to_u64, stat.st_ino.to_u64}
    return unless state.visited.add?(inode_key)

    info = File::Info.new(stat)

    case info.type
    when .symlink?
      handle_symlink(path, state)
    when .directory?
      return if skip_dir?(path, name, state)
      evaluate_dir(path, info, state)
      walk_dir(path, state)
    when .file?
      evaluate_file(path, name, info, state)
    end
  end

  # Target inside the walk → record in the alias map (Data.symlink_aliases).
  # Target outside (broken, pseudo-fs, skipped subtree) → drop. Broken
  # symlinks in PATH have their own typed set via the PATH sub-walk.
  private def self.handle_symlink(path : String, state : State) : Nil
    target = begin
      File.realpath(path)
    rescue File::Error | IO::Error
      return
    end
    return unless symlink_target_inside_walk?(target, state)
    if aliases = state.sym_targets[target]?
      aliases << path
    else
      state.sym_targets[target] = [path]
    end
  end

  private def self.symlink_target_inside_walk?(target : String, state : State) : Bool
    return false if WALKER_SKIP_PATHS.any? { |p| target == p || target.starts_with?(p + "/") }
    return false if state.skip_mounts.any? { |m| target == m || target.starts_with?(m + "/") }
    true
  end

  private def self.skip_dir?(path : String, name : String, state : State) : Bool
    return true if WALKER_SKIP_BASENAMES.includes?(name)
    return true if WALKER_SKIP_PATHS.any? { |p| path == p }
    return true if state.skip_mounts.includes?(path)
    false
  end

  private def self.evaluate_dir(path : String, info : File::Info, state : State) : Nil
    if info.permissions.other_write?
      append_capped(state.results[:world_writable_dirs], path, WALKER_CAP_WORLD_WRITABLE_DIRS)
    end
  end

  private def self.evaluate_file(path : String, name : String, info : File::Info, state : State) : Nil
    perms = info.permissions
    flags = info.flags

    state.results[:suid] << path if flags.set_user?
    state.results[:sgid] << path if flags.set_group?

    if perms.other_write?
      append_capped(state.results[:world_writable_files], path, WALKER_CAP_WORLD_WRITABLE_FILES)
    end

    # Lower bound on age guards against future mtimes from clock skew.
    age_minutes = (Time.utc - info.modification_time).total_minutes
    if age_minutes >= 0 && age_minutes <= WALKER_RECENT_MINUTES
      append_capped(state.results[:recent_files], path, WALKER_CAP_RECENT_FILES)
    end

    lower = name.downcase
    if WALKER_BACKUP_EXTS.any? { |ext| lower.ends_with?(ext) }
      append_capped(state.results[:backup_files], path, WALKER_CAP_BACKUP_FILES)
    end

    if WALKER_SSH_KEY_NAMES.includes?(name)
      append_capped(state.results[:ssh_keys], path, WALKER_CAP_CRED_FILES_PER_CAT)
    elsif name == WALKER_NETRC_NAME
      append_capped(state.results[:netrc_files], path, WALKER_CAP_CRED_FILES_PER_CAT)
    elsif WALKER_HISTORY_RE.matches?(name)
      append_capped(state.results[:history_files], path, WALKER_CAP_CRED_FILES_PER_CAT)
    elsif WALKER_SENSITIVE_CONFIG_NAMES.includes?(name)
      append_capped(state.results[:sensitive_configs], path, WALKER_CAP_CRED_FILES_PER_CAT)
    end

    if WALKER_VAULT_EXTS.any? { |ext| lower.ends_with?(ext) }
      append_capped(state.results[:password_vaults], path, WALKER_CAP_CRED_FILES_PER_CAT)
    elsif WALKER_TFSTATE_EXTS.any? { |ext| lower.ends_with?(ext) }
      append_capped(state.results[:tfstate_files], path, WALKER_CAP_CRED_FILES_PER_CAT)
    elsif CERT_KEYSTORE_EXTS.any? { |ext| lower.ends_with?(ext) }
      append_capped(state.results[:cert_keystores], path, WALKER_CAP_CRED_FILES_PER_CAT)
    elsif CERT_TEXT_EXTS.any? { |ext| lower.ends_with?(ext) }
      append_capped(state.results[:cert_pemkeys], path, WALKER_CAP_CRED_FILES_PER_CAT)
    end

    if WALKER_LOG4J_RE.matches?(name)
      append_capped(state.results[:log4j_jars], path, WALKER_CAP_CRED_FILES_PER_CAT)
    end

    # Candidate set for in-process content-pattern scan (cred regex,
    # API key signatures). Independent of the buckets above — a file
    # may legitimately appear in both sensitive_configs (basename) and
    # cred_scan_files (extension class).
    if WALKER_CRED_SCAN_EXTS.any? { |ext| lower.ends_with?(ext) }
      append_capped(state.results[:cred_scan_files], path, WALKER_CAP_CRED_SCAN_FILES)
    end

    # Candidate set for in-process log credential-pattern scan.
    # Path-prefix predicate (not extension): /var/log holds files of
    # all extensions including extension-less rotated archives.
    if WALKER_LOG_DIR_PATHS.any? { |p| path.starts_with?(p) }
      append_capped(state.results[:log_files], path, WALKER_CAP_LOG_FILES)
    end
  end

  private def self.append_capped(arr : Array(String), path : String, cap : Int32) : Nil
    arr << path if arr.size < cap
  end

  # PATH dirs to depth 2 — surfaces .sh scripts (replaceable hijack
  # target) and broken symlinks (writable parent + missing target =
  # plant window).
  private def self.walk_path_subwalk(state : State) : Nil
    Data.path_dirs.each do |dir|
      next unless Data.dir_exists?(dir)
      walk_path_dir(dir, state, 0)
    end
  end

  private def self.walk_path_dir(path : String, state : State, depth : Int32) : Nil
    return if depth > WALKER_PATH_SUBWALK_DEPTH
    begin
      Dir.each_child(path) do |name|
        child = "#{path}/#{name}"
        info = begin
          File.info?(child, follow_symlinks: false)
        rescue File::Error
          nil
        end
        next unless info

        if info.type.symlink?
          target_exists = begin
            target = File.realpath(child)
            File.exists?(target)
          rescue File::Error | IO::Error
            false
          end
          unless target_exists
            append_capped(state.results[:path_broken_symlinks], child, WALKER_CAP_CRED_FILES_PER_CAT)
          end
        elsif info.type.file? && name.downcase.ends_with?(".sh")
          append_capped(state.results[:path_sh_scripts], child, WALKER_CAP_CRED_FILES_PER_CAT)
        elsif info.type.directory?
          walk_path_dir(child, state, depth + 1)
        end
      end
    rescue File::Error | IO::Error
    end
  end

  # /lib/modules to depth 8 — non-root-owned .ko files give an LKM
  # rootkit window via insmod under sufficient capabilities.
  private def self.walk_modules_subwalk(state : State) : Nil
    root = "/lib/modules"
    return unless Data.dir_exists?(root)
    walk_modules_dir(root, state, 0)
  end

  private def self.walk_modules_dir(path : String, state : State, depth : Int32) : Nil
    return if depth > WALKER_MODULES_SUBWALK_DEPTH
    begin
      Dir.each_child(path) do |name|
        child = "#{path}/#{name}"
        info = begin
          File.info?(child, follow_symlinks: false)
        rescue File::Error
          nil
        end
        next unless info
        if info.type.directory?
          walk_modules_dir(child, state, depth + 1)
        elsif info.type.file? && name.ends_with?(".ko") && info.owner_id != "0"
          append_capped(state.results[:weak_kernel_modules], child, WALKER_CAP_CRED_FILES_PER_CAT)
        end
      end
    rescue File::Error | IO::Error
    end
  end

end
