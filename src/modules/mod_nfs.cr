def mod_nfs : Nil
  section("NFS Shares")

  exports = read_file("/etc/exports")
  if exports.empty?
    info("/etc/exports not found or not readable")
  else
    tee("#{Y}/etc/exports:#{RS}")
    exports.split("\n").each do |line|
      next if line.starts_with?("#") || line.strip.empty?
      if line.includes?("no_root_squash")
        hi("#{line}  ← no_root_squash → mount as root, plant SUID binary")
      elsif line.includes?("no_all_squash")
        med("#{line}  ← no_all_squash")
      else
        info("  #{line}")
      end
    end
  end

  blank
  # timeout prevents hang when NFS is not running (common on most targets)
  showmount = run("timeout 5 showmount -e localhost 2>/dev/null || timeout 5 showmount -e 127.0.0.1 2>/dev/null")
  unless showmount.empty?
    med("NFS exports via showmount:")
    tee(showmount)
  end

  nfs_mounts = Data.mounts.select { |m| m[:fstype].includes?("nfs") }
  if nfs_mounts.empty?
    info("No active NFS mounts")
  else
    med("Active NFS mounts:")
    nfs_mounts.each { |m| tee("  #{m[:mount]} (#{m[:fstype]}) #{m[:opts].to_a.sort.join(",")}") }
  end
end
