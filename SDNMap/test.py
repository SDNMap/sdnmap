__author__ = 'mininet'

from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.dhcp import *
from scapy.layers.dns import *
from tools import tools
from struct import pack
import binascii

#a=rdpcap("/home/stefan/Desktop/GREPacket.pcap")
#a[0].show2()
#print(hexdump(a[0])[23:25])
#a[0].show2()

ipsrc="10.0.0.222"
portsrc=36753

ether = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
ip = IP(src=ipsrc, dst="10.0.0.2")
icmp = ICMP(type = 8, code = 0)
pkt = ether/ip/icmp
sendp(pkt, verbose=0)
time.sleep(2)

ether1 = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
arp1 = ARP(op="is-at", hwsrc="00:00:00:00:00:01", hwdst="00:00:00:00:00:02", psrc=ipsrc, pdst="10.0.0.2")
arppkt = ether1/arp1
sendp(arppkt , verbose=0)

eth=Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
ip=IP(src=ipsrc, dst="10.0.0.2")
tcp=TCP(sport=portsrc, dport=80, flags="S",seq=1000)
tcpsyn=eth/ip/tcp
synack=srp1(tcpsyn, verbose=0)

my_ack = synack.seq + 1

eth=Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
ip=IP(src=ipsrc, dst="10.0.0.2")
tcp=TCP(sport=portsrc, dport=80, flags="A", seq=1001, ack=my_ack)
tcpack=eth/ip/tcp
sendp(tcpack, verbose=0)

http="GET /index.lighttpd.html HTTP/1.1\r\nHost: 10.0.0.2\r\n\r\n"
eth=Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
ip=IP(src=ipsrc, dst="10.0.0.2")
tcp=TCP(sport=portsrc, dport=80, flags="PA", seq=1001, ack=my_ack)
tcphttp=eth/ip/tcp/http
sendp(tcphttp, verbose=0)



httpget=eth/ip/tcp/http
#sendp(httpget, verbose=0)





'''

from map_net import map_net
map_net = map_net("10.0.0.1","00:00:00:00:00:01")
map_net.mapHostsARP(24)

ether = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
ip = IP(src="10.0.0.1", dst="10.0.0.2")
#icmp = ICMP(type = 5, code = 1, gw="10.0.0.5")
icmp2 = ICMP(type = 0, code = 0)
ip2 = IP(src="10.0.0.2", dst="10.3.3.3")
#udp = UDP(sport=64346,dport=53)
tcp = TCP(sport=1284, dport=22)
pkt = ether/ip/icmp2
#sendp(pkt)

ether1 = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:03")
arp1 = ARP(op="is-at", hwsrc="00:00:00:00:00:02", hwdst="00:00:00:00:00:03", psrc="10.0.0.1", pdst="10.0.0.3")
arppkt = ether1/arp1
#sendp(arppkt)


ether1 = Ether(src="00:00:00:01:01:01", dst="00:00:00:03:03:01")
ether2 = Ether(src="00:00:00:00:00:02", dst="00:00:00:00:00:01")
ip3 = IP(src="10.1.1.1", dst="10.3.3.1")
ip4 = IP(src="10.0.0.2", dst="10.0.0.1")
icmp2 = ICMP(type = 8, code = 0)
pkt2 = ether2/ip4/icmp2
sendp(pkt2)

ether = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:03")
ip = IP(dst="66.96.149.1")
udp = UDP(sport=64346,dport=36548)
pkt = ip/udp
#send(pkt)
#rpkt = srp1(pkt)

#rpkt.show2()
#pkt2.show2()
#sendp(pkt2)

#pkt.show2()

'''
#OF Packet
'''
a=rdpcap("/home/stefan/Desktop/OFPacket1.pcap")
#a[0].show2()
#print(hexdump(a[0])[23:25])
a[0].show2()

newRaw=""
if a[0].haslayer(Raw):
    #a[0][Raw][25:27] = 01
    p = str(a[0][Raw]).encode('hex')
    print(p)
    arr = list(p)
    arr[31] = '3'
    p = "".join(arr)
    print(p)
    dp = p.decode('hex')
    newRaw = dp

ether = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
#ip = IP(src="10.0.0.1", dst="10.0.0.2")
ip = IP(src="10.0.0.1", dst="10.0.0.2", proto=a[0][IP].proto, flags=a[0][IP].flags, chksum=a[0][IP].chksum, frag=a[0][IP].frag)
tcp = TCP(sport=a[0][TCP].sport, dport=a[0][TCP].dport, dataofs=a[0][TCP].dataofs, reserved=a[0][TCP].reserved, flags=a[0][TCP].flags, window=a[0][TCP].window, chksum=a[0][TCP].chksum,
          urgptr=a[0][TCP].urgptr, options=a[0][TCP].options)
raw = newRaw
newPkt = ether/ip/tcp/raw

#seq=a[0][TCP].seq, ack=a[0][TCP].ack,
newPkt.show()
sendp(newPkt)
'''

