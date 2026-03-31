struct Finding
  getter severity : Symbol
  getter mod_name : String
  getter message  : String

  def initialize(@severity, @mod_name, @message)
  end
end

module Findings
  @@entries      = [] of Finding
  @@current_mod  = ""

  def self.current_module=(name : String)
    @@current_mod = name
  end

  def self.add(severity : Symbol, message : String)
    @@entries << Finding.new(severity, @@current_mod, message)
  end

  def self.clear
    @@entries.clear
    @@current_mod = ""
  end

  def self.summary
    Out.write("")
    Out.write(SEPARATOR)
    Out.write("#{M}  Findings Summary#{RS}")
    Out.write(SEPARATOR)
    Out.write("")

    if @@entries.empty?
      Out.write("#{G}[ok]#{RS} No critical or medium findings.")
      return
    end

    critical, medium = @@entries.partition { |f| f.severity == :hi }

    Out.write("  #{R}#{critical.size} critical#{RS}, #{Y}#{medium.size} medium#{RS}")
    Out.write("")

    critical.each do |f|
      Out.write("#{R}[!]#{RS} #{f.message}  #{C}[#{f.mod_name}]#{RS}")
    end
    medium.each do |f|
      Out.write("#{Y}[+]#{RS} #{f.message}  #{C}[#{f.mod_name}]#{RS}")
    end
  end
end
