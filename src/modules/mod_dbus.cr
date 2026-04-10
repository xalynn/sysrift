def mod_dbus : Nil
  section("D-Bus / PolicyKit")

  scan_polkit_rules
  blank
  scan_pkexec_and_service_binaries
  blank
  scan_dbus_polkit_writability
end

private def list_dir(dir : String) : Array(String)?
  return nil unless Dir.exists?(dir)
  Dir.children(dir)
rescue File::Error
  nil
end

private def scan_polkit_rules : Nil
  tee("#{Y}PolicyKit rules (Result.YES / AUTH_SELF):#{RS}")
  hits = 0
  user_groups = Data.groups

  POLKIT_RULES_DIRS.each do |dir|
    names = list_dir(dir)
    next unless names
    names.sort.each do |name|
      next unless name.ends_with?(".rules")
      content = read_file("#{dir}/#{name}")
      next if content.empty?

      lines = content.split("\n")
      lines.each_with_index do |line, idx|
        next unless rm = line.match(POLKIT_RESULT_RE)
        result = rm[1]

        # JS rules declare group checks within a few lines of the return statement
        ctx_start = {idx - 5, 0}.max
        ctx = lines[ctx_start..idx].join("\n")

        gated_groups = Set(String).new
        ctx.scan(POLKIT_GROUP_RE) { |m| gated_groups << (m[1]? || m[2]).to_s }

        action = ""
        if am = ctx.match(POLKIT_ACTION_EXACT_RE)
          action = am[1]
        elsif am = ctx.match(POLKIT_ACTION_MATCH_RE)
          action = "#{am[1]}*"
        end

        tag = "#{name}:#{idx + 1}"
        tag += " action=#{action}" unless action.empty?

        if result == "YES"
          if gated_groups.empty?
            hi("#{tag} → Result.YES (ungated, no group check)")
          elsif gated_groups.any? { |g| user_groups.includes?(g) }
            ours = gated_groups.select { |g| user_groups.includes?(g) }
            med("#{tag} → Result.YES (gated: #{gated_groups.join(", ")} — you are in: #{ours.join(", ")})")
          else
            info("#{tag} → Result.YES (gated: #{gated_groups.join(", ")})")
          end
        else
          info("#{tag} → Result.AUTH_SELF (own password, not admin)")
        end
        hits += 1
      end
    end
  end
  info("No PolicyKit rules with Result.YES or AUTH_SELF found") if hits == 0
end

private def scan_pkexec_and_service_binaries : Nil
  tee("#{Y}Writable pkexec / D-Bus activation binaries:#{RS}")
  hits = 0

  POLKIT_ACTION_DIRS.each do |dir|
    names = list_dir(dir)
    next unless names
    names.each do |name|
      next unless name.ends_with?(".policy")
      content = read_file("#{dir}/#{name}")
      next if content.empty?

      content.scan(/policykit\.exec\.path">\s*([^<]+)/) do |m|
        bin = m[1].strip
        next if bin.empty?
        if File.exists?(bin) && File::Info.writable?(bin)
          hi("Writable pkexec binary: #{bin} (#{name})")
          hits += 1
        end
      end
    end
  end

  DBUS_SERVICE_DIRS.each do |dir|
    names = list_dir(dir)
    next unless names
    names.each do |name|
      next unless name.ends_with?(".service")
      svc_path = "#{dir}/#{name}"
      content = read_file(svc_path)
      next if content.empty?

      exec_bin = ""
      run_as = ""
      content.split("\n").each do |line|
        if line.starts_with?("Exec=")
          exec_bin = line[5..].strip.split(/\s/, 2)[0]
        elsif line.starts_with?("User=")
          run_as = line[5..].strip
        end
      end
      if File::Info.writable?(svc_path)
        hi("Writable D-Bus service file: #{svc_path} — can set User=root")
        hits += 1
      end
      next if exec_bin.empty? || exec_bin == "/bin/false"
      next unless run_as == "root"

      if File.exists?(exec_bin) && File::Info.writable?(exec_bin)
        hi("Writable D-Bus service binary: #{exec_bin} (User=root, #{name})")
        hits += 1
      end
    end
  end
  info("No writable pkexec or D-Bus activation binaries found") if hits == 0
end

private def scan_dbus_polkit_writability : Nil
  tee("#{Y}PolicyKit / D-Bus config writability:#{RS}")
  hits = 0

  DBUS_POLKIT_WRITABLE_DIRS.each do |dir|
    next unless Dir.exists?(dir)

    if File::Info.writable?(dir)
      hi("Writable directory: #{dir} — can drop new config")
      hits += 1
    end

    begin
      Dir.each_child(dir) do |name|
        fp = "#{dir}/#{name}"
        next unless File.file?(fp)
        next if name.ends_with?(".service") && DBUS_SERVICE_DIRS.any? { |sd| dir == sd }
        if File::Info.writable?(fp)
          hi("Writable config: #{fp}")
          hits += 1
        end
      end
    rescue File::Error
    end
  end
  info("No writable PolicyKit or D-Bus config paths found") if hits == 0
end
