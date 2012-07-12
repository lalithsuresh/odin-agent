import sys

if (len(sys.argv) != 6):
    print 'Usage:'
    print 'ap-gen.py <AP_CHANNEL> <QUEUE_SIZE> <HW_ADDR> <ODIN_MASTER_IP> <ODIN_MASTER_PORT>'
    sys.exit(0)

AP_UNIQUE_IP_WITH_MASK = "172.17.2.53/24"
AP_UNIQUE_BSSID = "00-1B-B1-F2-EF-Fe"
AP_CHANNEL = sys.argv[1]
QUEUE_SIZE = sys.argv[2]
HW_ADDR = sys.argv[3]
ODIN_MASTER_IP = sys.argv[4]
ODIN_MASTER_PORT = sys.argv[5]
DEFAULT_CLIENT_MAC = "e8-39-df-4c-7c-ee"

print '''
odinagent::OdinAgent(%s, RT rates, CHANNEL %s, DEFAULT_GW 172.17.2.53)
TimedSource(2, "ping\n")->  odinsocket::Socket(UDP, %s, %s, CLIENT true)
''' % (HW_ADDR, AP_CHANNEL, ODIN_MASTER_IP, ODIN_MASTER_PORT)


print '''

odinagent[3] -> odinsocket

rates :: AvailableRates(DEFAULT 24 36 48 108);

control :: ControlSocket("TCP", 6777);
chatter :: ChatterSocket("TCP", 6778);

// ----------------Packets going down
FromHost(ap, HEADROOM 50)
  -> fhcl :: Classifier(12/0806 20/0001, -)
  -> fh_arpr :: ARPResponder(172.17.2.51 e8:39:df:4c:7c:e3) // Resolve STA's ARP
  -> ARPPrint("Resolving client's ARP by myself")
  -> ToHost(ap)
'''

print '''

q :: Queue(%s)
  -> SetTXRate (108)
  -> RadiotapEncap()
  -> to_dev :: ToDevice (mon0);

// Anything from host that isn't an ARP request
fhcl[1]
  -> [1]odinagent

''' % (QUEUE_SIZE)


print '''
// Not looking for an STA's ARP? Then let it pass.
fh_arpr[1]
  -> [1]odinagent

odinagent[2]
  -> q

// ----------------Packets going down


// ----------------Packets coming up
from_dev :: FromDevice(mon0, HEADROOM 50)
  -> RadiotapDecap()
  -> ExtraDecap()
  -> phyerr_filter :: FilterPhyErr()
  -> tx_filter :: FilterTX()
  -> dupe :: WifiDupeFilter()
  -> [0]odinagent

odinagent[0]
  -> q

// Data frames
odinagent[1]
  -> decap :: WifiDecap()
  -> RXStats
  -> arp_c :: Classifier(12/0806 20/0001, -)
  -> arp_resp::ARPResponder (172.17.2.53 00-1B-B1-F2-EF-F1) // ARP fast path for STA
  -> [1]odinagent


// ARP Fast path fail. Re-write MAC address
// to reflect datapath or learning switch will drop it
arp_resp[1]
  -> ToHost(ap)


// Non ARP packets. Re-write MAC address to
// reflect datapath or learning switch will drop it
arp_c[1]
  -> ToHost(ap)
'''
