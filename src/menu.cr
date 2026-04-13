def banner
  puts "#{C}"
  puts "  ███████╗██╗   ██╗███████╗██████╗ ██╗███████╗████████╗"
  puts "  ██╔════╝╚██╗ ██╔╝██╔════╝██╔══██╗██║██╔════╝╚══██╔══╝"
  puts "  ███████╗ ╚████╔╝ ███████╗██████╔╝██║█████╗     ██║   "
  puts "  ╚════██║  ╚██╔╝  ╚════██║██╔══██╗██║██╔══╝     ██║   "
  puts "  ███████║   ██║   ███████║██║  ██║██║██║        ██║   "
  puts "  ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   "
  puts "  #{W}Linux System Audit  |  v0.3.0#{RS}"
  puts ""
end

def print_menu(mods : Array(NamedTuple(name: String, active: Bool, action: Proc(Nil))), log_path : String)
  puts "\n#{MENU_RULE}"
  puts "#{C}   sysrift  —  Linux System Audit#{RS}"
  puts "#{C}   Log → #{log_path.empty? ? "stdout only" : log_path}#{RS}"
  puts MENU_RULE
  mods.each_with_index do |mod, i|
    suffix = mod[:active] ? " #{Y}[A]#{RS}" : ""
    puts "  #{W}#{(i + 1).to_s.rjust(2)}.#{RS}  #{mod[:name]}#{suffix}"
  end
  puts ""
  puts "  #{W} 0.#{RS}  Run ALL modules"
  puts "  #{W} r.#{RS}  List report files in /dev/shm"
  puts "  #{W} x.#{RS}  Self-destruct binary (keeps reports)"
  puts "  #{W} q.#{RS}  Quit"
  puts MENU_RULE
  puts "#{B}  Tip: comma-separate to run multiple  e.g. 1,3,5#{RS}"
end

def active_prompt(mod_names : Array(String)) : Symbol
  puts "\n#{Y}Warning: the following modules include active checks that"
  puts "generate additional network connections and authentication"
  puts "events that may appear in system logs:#{RS}"
  mod_names.each { |n| puts "  #{W}•#{RS} #{n}" }
  puts ""
  puts "  #{W}[p]#{RS}assive only   #{W}[a]#{RS}ll checks   #{W}[c]#{RS}ancel"
  Out.prompt("#{W}> #{RS}")
  input = gets
  return :cancel if input.nil?
  case input.chomp.strip.downcase
  when "a" then :active
  when "p" then :passive
  else          :cancel
  end
end

def module_list : Array(NamedTuple(name: String, active: Bool, action: Proc(Nil)))
  [
    {name: "System Information",       active: false, action: ->{ mod_sysinfo }},
    {name: "SUID / SGID Binaries",     active: false, action: ->{ mod_suid }},
    {name: "Sudo Rights",              active: false, action: ->{ mod_sudo }},
    {name: "Credential Hunting",       active: false, action: ->{ mod_creds }},
    {name: "Writable Files & Dirs",    active: false, action: ->{ mod_writable }},
    {name: "Network Information",      active: false, action: ->{ mod_network }},
    {name: "Processes, Cron & Timers", active: false, action: ->{ mod_processes }},
    {name: "File Capabilities",        active: false, action: ->{ mod_capabilities }},
    {name: "NFS Shares",               active: false, action: ->{ mod_nfs }},
    {name: "Container / Docker",       active: false, action: ->{ mod_docker }},
    {name: "Installed Software",       active: false, action: ->{ mod_software }},
    {name: "Users & Groups",           active: false, action: ->{ mod_users }},
    {name: "Services",                 active: false, action: ->{ mod_services }},
    {name: "Interesting Files",        active: false, action: ->{ mod_files }},
    {name: "Security Protections",     active: false, action: ->{ mod_defenses }},
    {name: "D-Bus / PolicyKit",        active: false, action: ->{ mod_dbus }},
    {name: "Cloud Environment",        active: true,  action: ->{ mod_cloud }},
  ] of NamedTuple(name: String, active: Bool, action: Proc(Nil))
end
