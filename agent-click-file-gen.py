#!/usr/bin/python

# This script creates a .click file which can then be run using the click modular router.
# http://read.cs.ucla.edu/click/click
# https://github.com/kohler/click
#
# it requires that you have installed the OdinAgent module within your click installation
# https://github.com/Wi5/odin-wi5-agent/tree/master/src
#
# it also requires that you have patched the ath9k driver. This is the only driver supported currently
# About the driver patch see:
# https://github.com/Wi5/odin-wi5/tree/master/odin-patch-driver-ath9k

import sys

if (len(sys.argv) != 10):
    print 'Usage:'
    print ''
    print '%s <AP_CHANNEL> <QUEUE_SIZE> <MAC_ADDR_AP> <ODIN_MASTER_IP> <ODIN_MASTER_PORT> <DEBUGFS_FILE> <SSIDAGENT> <ODIN_AGENT_IP> <DEBUG_LEVEL>' %(sys.argv[0])
    print ''
    print 'AP_CHANNEL: it must be the same where mon0 of the AP is placed. To avoid problems at init time, it MUST be the same channel specified in the /etc/config/wireless file of the AP'
    print 'QUEUE_SIZE: you can use the size 50'
    print 'MAC_ADDR_AP: the MAC of the wireless interface mon0 of the AP. e.g. 74-F0-6E-20-D4-74'
    print 'ODIN_MASTER_IP is the IP of the openflow controller where Odin master is running'
    print 'ODIN_MASTER_PORT should be 2819 by default'
    print 'DEBUGFS_FILE is the path of the bssid_extra file created by the ath9k patch'	
    print '             it can be /sys/kernel/debug/ieee80211/phy0/ath9k/bssid_extra'
    print 'SSIDAGENT is the name of the SSID of this Odin agent'
    print 'ODIN_AGENT_IP is the IP address of the AP where this script is running (the IP used for communicating with the controller)'
    print 'DEBUG_LEVEL: "0" no info displayed; "1" only basic info displayed; "2" all the info displayed'
    print ''
    print 'Example:'
    print '$ python %s X 50 XX:XX:XX:XX:XX:XX 192.168.1.X 2819 /sys/kernel/debug/ieee80211/phy0/ath9k/bssid_extra odin-unizar 192.168.1.Y L > agent.click' %(sys.argv[0])
    print ''
    print 'and then run the .click file you have generated'
    print 'click$ ./bin/click agent.click'
    sys.exit(0)

# Read the arguments
AP_CHANNEL = sys.argv[1]
QUEUE_SIZE = sys.argv[2]
AP_UNIQUE_BSSID = sys.argv[3]		# MAC address of the wlan0 interface of the router where Click runs (in monitor mode). It seems it does not matter.
ODIN_MASTER_IP = sys.argv[4]
ODIN_MASTER_PORT = sys.argv[5]
DEBUGFS_FILE = sys.argv[6]
SSIDAGENT = sys.argv[7]
DEFAULT_GW = sys.argv[8]			#the IP address of the Access Point.
AP_UNIQUE_IP = sys.argv[8]			# IP address of the wlan0 interface of the router where Click runs (in monitor mode). It seems it does not matter.
DEBUG_LEVEL = int(sys.argv[9])

# Set the value of some constants
NETWORK_INTERFACE_NAMES = "mon"		# beginning of the network interface names in monitor mode. e.g. mon
TAP_INTERFACE_NAME = "ap"			# name of the TAP device that Click will create in the 
STA_IP = "192.168.1.11"				# IP address of the STA in the LVAP tuple. It only works for a single client without DHCP
STA_MAC = "74:F0:6D:20:D4:74"		# MAC address of the STA in the LVAP tuple. It only works for a single client without DHCP
RATE = "108"						# e.g. if it is 108, this means 108*500kbps = 54Mbps

print '''
// This is the scheme:
//
//            TAP interface 'ap' in the machine that runs Click
//             | ^
// from host   | |   to host
//             v |
//            click
//             | ^
// to device   | |   to device 
//             V |
//            'mon0' interface in the machine that runs Click. Must be in monitor mode
//
'''

#print '''
#// call OdinAgent::configure to create and configure an Odin agent:
#odinagent::OdinAgent(HWADDR %s, RT rates, CHANNEL %s, DEFAULT_GW %s, DEBUGFS %s, SSIDAGENT %s)
#''' % (AP_UNIQUE_BSSID, AP_CHANNEL, DEFAULT_GW, DEBUGFS_FILE, SSIDAGENT )

print '''
// call OdinAgent::configure to create and configure an Odin agent:
odinagent::OdinAgent(HWADDR %s, RT rates, CHANNEL %s, DEFAULT_GW %s, DEBUGFS %s)
''' % (AP_UNIQUE_BSSID, AP_CHANNEL, DEFAULT_GW, DEBUGFS_FILE )

print '''
// send a ping to odinsocket every 2 seconds
TimedSource(2, "ping\n")->  odinsocket::Socket(UDP, %s, %s, CLIENT true)
''' % (ODIN_MASTER_IP, ODIN_MASTER_PORT)

# Create ControlSocket and ChatterSocket, which are Click's remote control elements.
#http://piotrjurkiewicz.pl/files/bsc-dissertation.pdf
#
# Controlsocket: Communication with the Click application at user level is provided by a 
#TCP/IP based protocol. The user declares it in a configuration file, just like any 
#other element. However, ControlSocket does not process packets itself, so it is not 
#connected with other elements. 
# ControlSocket opens a socket and starts listening for connections.
#When a connection is opened, the server responds by stating its protocol version
#number. After that client can send commands to the Click router. The "server"
#(that is, the ControlSocket element) speaks a relatively simple line-based protocol.
#Commands sent to the server are single lines of text; they consist of words separated
#by spaces
#
# ChatterSocket opens a chatter socket that allows clients to receive copies 
#of router chatter traffic. The "server" (that is, the ChatterSocket element) 
#simply echoes any messages generated by the router configuration to any 
#existing clients.
print '''
// output 3 of odinagent goes to odinsocket
odinagent[3] -> odinsocket
rates :: AvailableRates(DEFAULT 24 36 48 108);	// wifi rates in multiples of 500kbps
control :: ControlSocket("TCP", 6777);
chatter :: ChatterSocket("TCP", 6778);
'''

print '''
// ----------------Packets going down (AP to STA)
// I don't want the ARP requests from the AP to the stations to go to the network device
//so click is in the middle and answers the ARP to the host on behalf of the station
//'ap' is a Linux tap device which is instantiated by Click in the machine.
//FromHost reads packets from 'ap'
// The arp responder configuration here doesnt matter, odinagent.cc sets it according to clients
FromHost(%s, HEADROOM 50)
  -> fhcl :: Classifier(12/0806 20/0001, -)
				// 12 means the 12th byte of the eth frame (i.e. ethertype)
				// 0806 is the ARP ethertype, http://en.wikipedia.org/wiki/EtherType
				// 20 means the 20th byte of the eth frame, i.e. the 6th byte of the ARP packet: 
				// "Operation". It specifies the operation the sender is performing: 1 for request, 2 for reply.''' % (TAP_INTERFACE_NAME)

if (DEBUG_LEVEL > 0):
    print '''  -> ARPPrint("[Click] ARP request from host to resolve STA's ARP")'''

print '''  -> fh_arpr :: ARPResponder(%s %s) 	// looking for an STA's ARP: Resolve STA's ARP''' % (STA_IP, STA_MAC)

if (DEBUG_LEVEL > 0):
    print '''  -> ARPPrint("[Click] Resolving client's ARP by myself")'''

print '''  -> ToHost(%s)''' % (TAP_INTERFACE_NAME)

print '''
// Anything from host that is not an ARP request goes to the input 1 of Odin Agent
fhcl[1]'''

if (DEBUG_LEVEL > 1):
    print '''  -> Print("[Click] Non-ARP request from host goes to Odin agent port 1")'''

print '''  -> [1]odinagent
'''

print '''// Not looking for an STA's ARP? Then let it pass.
fh_arpr[1]'''

if (DEBUG_LEVEL > 0):
    print '''  -> Print("[Click] ARP request to another STA goes to Odin agent port 1")'''

print '''  -> [1]odinagent'''

print '''
// create a queue and connect it to SetTXRate-RadiotapEncap and send it to the network interface
q :: Queue(%s)
  -> SetTXRate (%s)	// e.g. if it is 108, this means 54Mbps=108*500kbps
  -> RadiotapEncap()
  -> to_dev :: ToDevice (%s0);
''' % (QUEUE_SIZE, RATE, NETWORK_INTERFACE_NAMES )

print '''
odinagent[2]
  -> q
'''

print '''
// ----------------Packets coming up (from the STA to the AP) go to the input 0 of the Odin Agent
from_dev :: FromDevice(%s0, HEADROOM 50)
  -> RadiotapDecap()
  -> ExtraDecap()
  -> phyerr_filter :: FilterPhyErr()
  -> tx_filter :: FilterTX()
  -> dupe :: WifiDupeFilter()	// Filters out duplicate 802.11 packets based on their sequence number
								// click/elements/wifi/wifidupefilter.hh
  -> [0]odinagent
''' % ( NETWORK_INTERFACE_NAMES )

print '''
odinagent[0]
  -> q
''' 

print '''
// Data frames
// The arp responder configuration here does not matter, odinagent.cc sets it according to clients
odinagent[1]
  -> decap :: WifiDecap()	// Turns 802.11 packets into ethernet packets. click/elements/wifi/wifidecap.hh
  -> RXStats				// Track RSSI for each ethernet source.
							// Accumulate RSSI, noise for each ethernet source you hear a packet from.
							// click/elements/wifi/rxstats.hh
  -> arp_c :: Classifier(12/0806 20/0001, -)
				// 12 means the 12th byte of the eth frame (i.e. ethertype)
				// 0806 is the ARP ethertype, http://en.wikipedia.org/wiki/EtherType
				// 20 means the 20th byte of the eth frame, i.e. the 6th byte of the ARP packet: 
				// "Operation". It specifies the operation the sender is performing: 1 for request'''

if (DEBUG_LEVEL > 0):
    print '''  -> Print("[Click] ARP request from the STA") //debug level 1''' 

print '''  -> arp_resp::ARPResponder (%s %s) // ARP fast path for STA
									// the STA is asking for the MAC address of the AP
									// add the IP of the AP and the BSSID of the LVAP corresponding to this STA''' % ( AP_UNIQUE_IP, AP_UNIQUE_BSSID )

if (DEBUG_LEVEL > 0):
    print '''  -> Print("[Click] ARP fast path for STA: the STA is asking for the MAC address of the AP")'''

print '''  -> [1]odinagent''' 
# it seems that AP_UNIQUE_IP and AP_UNIQUE_BSSID do not matter

print '''
// Non ARP packets. Re-write MAC address to
// reflect datapath or learning switch will drop it
arp_c[1]'''

if (DEBUG_LEVEL > 1):
    print '''  -> Print("[Click] Non-ARP packet in arp_c classifier")''' 

print '''  -> ToHost(%s)''' % ( TAP_INTERFACE_NAME )

print '''
// Click is receiving an ARP request from a STA different from its own STAs
// I have to forward the ARP request to the host without modification
// ARP Fast path fail. Re-write MAC address (without modification)
// to reflect datapath or learning switch will drop it
arp_resp[1]'''

if (DEBUG_LEVEL > 0):
    print '''  -> Print("[Click] ARP Fast path fail")''' 

print '''  -> ToHost(%s)''' % ( TAP_INTERFACE_NAME )
