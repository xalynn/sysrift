#!/usr/bin/env crystal

require "./src/constants"
require "./src/output"
require "./src/findings"
require "./src/runner"
require "./src/data"
require "./src/utils"
require "./src/modules/*"
require "./src/menu"

STDOUT.sync = true

banner

user     = ENV["USER"]? || ENV["LOGNAME"]? || run("whoami")
ts       = Time.local.to_s("%Y%m%d_%H%M%S")
log_path = Out.init(user, ts)

if log_path.empty?
  puts "#{Y}[+] Could not create log in /dev/shm — stdout only.#{RS}"
else
  puts "#{G}[ok] Session log: #{log_path}#{RS}"
end

mods = module_list

loop do
  print_menu(mods, log_path)
  Out.prompt("\n#{W}> #{RS}")

  input = gets
  break if input.nil?
  choice = input.chomp.strip.downcase

  case choice
  when "q", "quit", "exit"
    puts "#{Y}Exiting.#{RS}"
    Out.close
    break
  when "x"
    self_destruct
    Out.close
    break
  when "r"
    list_reports
  when "0"
    active_names = mods.select(&.[:active]).map(&.[:name])
    unless active_names.empty?
      case active_prompt(active_names)
      when :active  then Data.active_mode = true
      when :passive then Data.active_mode = false
      when :cancel  then next
      end
    end
    t_start = Time.instant
    mods.each { |m| m[:action].call }
    elapsed = Time.instant.duration_since(t_start)
    Data.active_mode = false
    Findings.summary
    Findings.clear
    tee("\n#{G}All modules complete.#{RS} (elapsed: #{elapsed.total_seconds.round(1)}s)")
    Out.prompt("#{B}Press Enter to return to menu...#{RS}")
    gets
  else
    selected = [] of NamedTuple(name: String, active: Bool, action: Proc(Nil))
    seen = Set(Int32).new
    choice.split(",").each do |part|
      if idx = part.strip.to_i?
        if idx >= 1 && idx <= mods.size
          if seen.add?(idx)
            selected << mods[idx - 1]
          end
        else
          puts "#{R}Invalid option: #{idx}#{RS}"
        end
      end
    end
    if selected.empty?
      puts "#{R}No valid selection. Enter a number from the menu.#{RS}"
    else
      active_names = selected.select(&.[:active]).map(&.[:name])
      unless active_names.empty?
        case active_prompt(active_names)
        when :active  then Data.active_mode = true
        when :passive then Data.active_mode = false
        when :cancel  then next
        end
      end
      selected.each { |m| m[:action].call }
      Data.active_mode = false
      Findings.summary
      Findings.clear
      puts "\n#{G}Done.#{RS}"
      Out.prompt("#{B}Press Enter to return to menu...#{RS}")
      gets
    end
  end
end
