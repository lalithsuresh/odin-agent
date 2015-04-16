#!/usr/bin/python

# This script creates a .click file which can then be run using the click router.
# it requires that you have installed the OdinAgent within your click installation
#
# run this (for example):
# $ python agent-click-file-gen.py 6 50 00-1B-B1-F2-EF-Fe 127.0.0.1 5658 > agent.click
#
# and then run the .click file you have generated:
# click$ ./bin/click agent.click


import sys

if (len(sys.argv) != 6):
    print 'Usage:'
    print '%s <AP_CHANNEL> <QUEUE_SIZE> <HW_ADDR> <ODIN_MASTER_IP> <ODIN_MASTER_PORT>' %(sys.argv[0])
    sys.exit(0)

AP_UNIQUE_IP = "172.17.2.53"			#172.17.0.0 are private IP addresses
MASK = "24"
seq = (AP_UNIQUE_IP,"/",MASK)
AP_UNIQUE_IP_WITH_MASK = ''.join(seq)	# join the AP_UNIQUE_IP and the mask
AP_UNIQUE_BSSID = "00-1B-B1-F2-EF-Fe"
AP_CHANNEL = sys.argv[1]
QUEUE_SIZE = sys.argv[2]
HW_ADDR = sys.argv[3]
ODIN_MASTER_IP = sys.argv[4]
ODIN_MASTER_PORT = sys.argv[5]
DEFAULT_CLIENT_MAC = "e8-39-df-4c-7c-ee"
NETWORK_INTERFACE_NAMES = "wlan"				#beginning of the network interface names. e.g. wlan
STA_IP = "172.17.2.51"
STA_MAC = "e8:39:df:4c:7c:e3"


print '''
// This is the scheme:
//
//            host (the AP)
//             | ^
// from host   v |   to host
//            click
//             | ^
// to device   v |   to device
//            device
//

// call OdinAgent::configure to create and configure an Odin agent:
odinagent::OdinAgent(%s, RT rates, CHANNEL %s, DEFAULT_GW 172.17.2.53, DEBUGFS 2)
''' % (HW_ADDR, AP_CHANNEL)

print '''
// send a ping to odinsocket every 2 seconds ??
TimedSource(2, "ping\n")->  odinsocket::Socket(UDP, %s, %s, CLIENT true)
''' % (ODIN_MASTER_IP, ODIN_MASTER_PORT)


print '''
// output 3 of odinagent goes to odinsocket
odinagent[3] -> odinsocket

rates :: AvailableRates(DEFAULT 24 36 48 108);	// wifi rates

control :: ControlSocket("TCP", 6777);
chatter :: ChatterSocket("TCP", 6778);

// ----------------Packets going down (AP to STA)
// I don't want the ARP requests from the AP to the stations to go to the network device
//so click is in the middle and answers the ARP to the host on behalf of the station
FromHost(ap, HEADROOM 50)
  -> fhcl :: Classifier(12/0806 20/0001, -)
				// 12 means the 12th byte of the eth frame (i.e. ethertype)
				// 0806 is the ARP ethertype, http://en.wikipedia.org/wiki/EtherType
				// 20 means the 20th byte of the eth frame, i.e. the 6th byte of the ARP packet: 
				// "Operation". It specifies the operation the sender is performing: 1 for request, 2 for reply.
  -> fh_arpr :: ARPResponder(%s %s) 	// looking for an STA's ARP: Resolve STA's ARP
  -> ARPPrint("Resolving client's ARP by myself")
  -> ToHost(ap)
''' % (STA_IP, STA_MAC)

print '''
// Anything from host that is not an ARP request goes to the input 1 of Odin Agent
fhcl[1]
  -> [1]odinagent
'''

print '''
// Not looking for an STA's ARP? Then let it pass.
fh_arpr[1]
  -> [1]odinagent
'''

print '''
// create a queue and connect it to SetTXRate-RadiotapEncap and send it to the network interface
q :: Queue(%s)
  -> SetTXRate (108)
  -> RadiotapEncap()
  -> to_dev :: ToDevice (%s0);
''' % (QUEUE_SIZE, NETWORK_INTERFACE_NAMES )

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
odinagent[1]
  -> decap :: WifiDecap()	// Turns 802.11 packets into ethernet packets. click/elements/wifi/wifidecap.hh
  -> RXStats				// Track RSSI for each ethernet source.
							// Accumulate RSSI, noise for each ethernet source you hear a packet from.
							// click/elements/wifi/rxstats.hh
  -> arp_c :: Classifier(12/0806 20/0001, -)
				// 12 means the 12th byte of the eth frame (i.e. ethertype)
				// 0806 is the ARP ethertype, http://en.wikipedia.org/wiki/EtherType
				// 20 means the 20th byte of the eth frame, i.e. the 6th byte of the ARP packet: 
				// "Operation". It specifies the operation the sender is performing: 1 for request
  -> arp_resp::ARPResponder (%s %s) // ARP fast path for STA
									// the STA is asking for the MAC address of the AP
									// add the IP and the BSSID of the Agent
  -> [1]odinagent
''' % ( AP_UNIQUE_IP, AP_UNIQUE_BSSID )

print '''
// Non ARP packets. Re-write MAC address to
// reflect datapath or learning switch will drop it
arp_c[1]
  -> ToHost(ap)
'''

print '''
// Click is receiving an ARP request from a STA different from his own STA
// I have to forward the ARP request to the host without modification
// ARP Fast path fail. Re-write MAC address (without modification)
// to reflect datapath or learning switch will drop it
arp_resp[1]
  -> ToHost(ap)
'''
