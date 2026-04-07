def banner
  puts "#{C}"
  puts "  ███████╗██╗   ██╗███████╗██████╗ ██╗███████╗████████╗"
  puts "  ██╔════╝╚██╗ ██╔╝██╔════╝██╔══██╗██║██╔════╝╚══██╔══╝"
  puts "  ███████╗ ╚████╔╝ ███████╗██████╔╝██║█████╗     ██║   "
  puts "  ╚════██║  ╚██╔╝  ╚════██║██╔══██╗██║██╔══╝     ██║   "
  puts "  ███████║   ██║   ███████║██║  ██║██║██║        ██║   "
  puts "  ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   "
  puts "  #{W}Linux System Audit  |  v0.2.0#{RS}"
  puts ""
end

def print_menu(mods : Array(NamedTuple(name: String, action: Proc(Nil))), log_path : String)
  puts "\n#{MENU_RULE}"
  puts "#{C}   sysrift  —  Linux System Audit#{RS}"
  puts "#{C}   Log → #{log_path.empty? ? "stdout only" : log_path}#{RS}"
  puts MENU_RULE
  mods.each_with_index do |mod, i|
    puts "  #{W}#{(i + 1).to_s.rjust(2)}.#{RS}  #{mod[:name]}"
  end
  puts ""
  puts "  #{W} 0.#{RS}  Run ALL modules"
  puts "  #{W} r.#{RS}  List report files in /dev/shm"
  puts "  #{W} x.#{RS}  Self-destruct binary (keeps reports)"
  puts "  #{W} q.#{RS}  Quit"
  puts MENU_RULE
  puts "#{B}  Tip: comma-separate to run multiple  e.g. 1,3,5#{RS}"
end

def module_list : Array(NamedTuple(name: String, action: Proc(Nil)))
  [
    {name: "System Information",       action: ->{ mod_sysinfo }},
    {name: "SUID / SGID Binaries",     action: ->{ mod_suid }},
    {name: "Sudo Rights",              action: ->{ mod_sudo }},
    {name: "Credential Hunting",       action: ->{ mod_creds }},
    {name: "Writable Files & Dirs",    action: ->{ mod_writable }},
    {name: "Network Information",      action: ->{ mod_network }},
    {name: "Processes, Cron & Timers", action: ->{ mod_processes }},
    {name: "File Capabilities",        action: ->{ mod_capabilities }},
    {name: "NFS Shares",               action: ->{ mod_nfs }},
    {name: "Container / Docker",       action: ->{ mod_docker }},
    {name: "Installed Software",       action: ->{ mod_software }},
    {name: "Users & Groups",           action: ->{ mod_users }},
    {name: "Services",                 action: ->{ mod_services }},
    {name: "Interesting Files",        action: ->{ mod_files }},
    {name: "Security Protections",    action: ->{ mod_defenses }},
  ] of NamedTuple(name: String, action: Proc(Nil))
end
