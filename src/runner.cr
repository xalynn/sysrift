def read_file(path : String) : String
  return "" unless File.exists?(path) && File::Info.readable?(path)
  File.read(path).strip
rescue IO::Error | File::Error
  ""
end

def run(cmd : String) : String
  io = IO::Memory.new
  Process.run("/bin/sh", args: ["-c", cmd], output: io, error: Process::Redirect::Close)
  io.to_s.strip
rescue IO::Error | File::Error
  ""
end

def run_lines(cmd : String) : Array(String)
  out = run(cmd)
  return [] of String if out.empty?
  out.split("\n").map(&.strip).reject(&.empty?)
end
