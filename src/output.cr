module Out
  @@log      : File?   = nil
  @@log_path : String  = ""

  def self.init(user : String, ts : String) : String
    path = "/dev/shm/audit-report_#{user}_#{ts}.txt"
    @@log = File.open(path, "w")
    @@log_path = path
    path
  rescue IO::Error | File::Error
    @@log_path = ""
    ""
  end

  def self.log_path : String
    @@log_path
  end

  def self.write(msg : String)
    STDOUT.puts msg
    if log = @@log
      log.puts msg.gsub(ANSI_RE, "")
      log.flush
    end
  end

  def self.prompt(msg : String)
    STDOUT.print msg
  end

  def self.close
    @@log.try &.close
  end
end

# Output helpers
def tee(msg : String);  Out.write(msg); end
def hi(msg : String);   Findings.add(:hi, msg);  Out.write("#{R}[!]#{RS} #{msg}"); end
def med(msg : String);  Findings.add(:med, msg); Out.write("#{Y}[+]#{RS} #{msg}"); end
def info(msg : String); Out.write("#{B}[-]#{RS} #{msg}"); end
def ok(msg : String);   Out.write("#{G}[ok]#{RS} #{msg}"); end
def blank;              Out.write(""); end

def section(title : String)
  Findings.current_module = title
  Out.write("")
  Out.write(SEPARATOR)
  Out.write("#{M}  #{title}#{RS}")
  Out.write(SEPARATOR)
  Out.write("")
end
