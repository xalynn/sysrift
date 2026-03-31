def mod_writable : Nil
  section("Writable Files & Directories")

  tee("#{Y}High-value writable files:#{RS}")
  %w[/etc/passwd /etc/shadow /etc/sudoers /etc/hosts /etc/crontab /etc/environment
     /etc/profile /etc/bash.bashrc /etc/ld.so.conf /etc/ld.so.preload /etc/sysctl.conf].each do |t|
    hi("Writable: #{t}") if File.exists?(t) && File::Info.writable?(t)
  end

  blank
  tee("#{Y}World-writable directories (excl /tmp /proc /dev /run /sys):#{RS}")
  ww = run_lines("find / -maxdepth 6 -type d -perm -0002 2>/dev/null | grep -vE '^/(tmp|proc|dev|run|sys)'")
  ww.first(30).each { |d| med("World-writable: #{d}") }
  ok("No interesting world-writable directories") if ww.empty?
end
