require 'socket'
require 'ipaddress'
require 'net/http'
require 'terminal-table'

def get_interfaces
    addr_infos = Socket.getifaddrs;nil
    int_to_use = []
    addr_infos.each do |addr_info|
        if addr_info.addr && addr_info.broadaddr
            if addr_info.addr.ipv4? && addr_info.addr.ip_address !~ /\A127/
                int_to_use << addr_info
            end
        end
    end;nil
    return int_to_use
end

def clear_screen
    Gem.win_platform? ? (system "cls") : (system "clear")
end

def scan_ips(sel_intf)
    ips = IPAddress::IPv4.parse_classful(sel_intf.addr.ip_address)
    p_ips = 0
    r_data = []
    ips.hosts[0..19].each do |ip|
        
        # puts "Processing --> #{ip.to_s}"
        `ping #{ip.to_s} -c 1`
        arp_res = `arp -a`
        arp_res_lines = arp_res.gsub(/\r\n?/, "\n")
        arp_res_lines.each_line do |line|
            if !line.include?("incomplete") && line.include?(ip.to_s) 
                r_data << {
                    :ip => ip.to_s,
                    :mac => line.split('at')[1].split('on')[0].delete(' '),
                    :vendor => ''
                }
            end
        end

        p_ips += 1
        progress = "=" * (((p_ips/ips.hosts[0..19].size.to_f) * 100 ) / 5) unless p_ips < 5
        printf("\rProcessing: [%-20s] %d%%", progress, ((p_ips/ips.hosts[0..19].size.to_f) * 100 ).round(2))
        
    end
    return r_data
end

def get_interface_sel(ifs)
    puts
    ifs.each_with_index do |intf,idx|
        puts "#{idx}> #{intf.name} (#{intf.addr.ip_address})"
    end
    puts
    puts "Please choose one interface to proceed"
    sel_intf = gets.chomp.to_i
    if ifs[sel_intf]
        return ifs[sel_intf]
    else
        puts "Invalid Selection"
        return false
    end
end

def get_vendor_info(r_data)
    r_data.each do |r|
        vendor = Net::HTTP.get('api.macvendors.com', "/#{r[:mac]}/") rescue nil
        if !vendor.include?("errors")
            r[:vendor] = vendor
        end
    end
    return r_data
end

def print_result(r_data_updated)
    puts
    table = Terminal::Table.new do |t|
        t << ['IP','MAC','Vendor']
        t << :separator
        r_data_updated.each do |i|
            t.add_row [i[:ip], i[:mac],i[:vendor]]
        end
    end
    puts table
end

def print_banner
    puts <<-'EOF'
------------------------------------------------------------------------
  _____                          ____                _       _         
 / ____|                        |  _ \              | |     | |        
| (___     ___    __ _   _ __   | |_) |  _   _    __| |   __| |  _   _ 
 \___ \   / __|  / _` | | '_ \  |  _ <  | | | |  / _` |  / _` | | | | |
 ____) | | (__  | (_| | | | | | | |_) | | |_| | | (_| | | (_| | | |_| |
|_____/   \___|  \__,_| |_| |_| |____/   \__,_|  \__,_|  \__,_|  \__, |
                                                                  __/ |
                                                                 |___/ 
- Team Gooseberry Security (https://gooseberrysec.com)
------------------------------------------------------------------------
    EOF
end


ifs = get_interfaces
if ifs.size > 0
    clear_screen
    print_banner
    sel_intf = get_interface_sel(ifs)
    if sel_intf
        puts 
        puts """
---------------------------
Interface Details

Name : #{sel_intf.name}
IP : #{sel_intf.addr.ip_address}
Broadcast : #{sel_intf.broadaddr.ip_address}
Netmask : #{sel_intf.netmask.ip_address}
---------------------------
        """
        puts
        puts "Scanning In Progres..."
        r_data = scan_ips(sel_intf)
        r_data_updated = get_vendor_info(r_data)
        print_result(r_data_updated)
    end
else
    puts "No Compatible Interface Available"
end
