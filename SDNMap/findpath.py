__author__ = 'mininet'

from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.dhcp import *
from scapy.layers.dns import *
from tools import tools
from memory import memory
from hostmap import hostmap
import time

class findpath(object):

    def __init__(self,ip,mac):
        self.myip=ip
        self.mymac=mac
        self.tools=tools()
        self.mem=memory()
        self.hostmap=hostmap()

    def probehost(self,probeIP):
        responseTimeout=2

        for key in self.hostmap.arpCache.keys():
            for node in self.hostmap.arpCache.get(key):
                if probeIP==node.ip:
                    dstnode = node
                    srcIP=key
                    break

        for node in self.hostmap.arpCache.get(self.myip):
            if srcIP==node.ip:
                srcnode = node

        print(srcnode.ip + " can reach " + dstnode.ip)

        #craft packet to reach probeIP
        hw_src = srcnode.mac
        hw_dst = dstnode.mac
        ip_src = srcnode.ip
        ip_dst = dstnode.ip

        #send ping request
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst, id=120)
        icmp = ICMP(type = 0, code = 0)

        raw=str(self.tools.encodeIP(ip_src))+"#"+str(self.tools.encodeMAC(hw_src))+"#"+str(self.tools.encodeIP(self.myip))+"#"+str(self.tools.encodeMAC(self.mymac))+"#"
        i=1
        while len(raw) < 56:
            raw=raw+str(i)
            i=i+1
            if i==10:
                i=1
        icmp_pkt = ether/ip/icmp/raw
        #self.tools.encodeMAC(self.mymac)+
        sendp(icmp_pkt, verbose=0)

        time.sleep(responseTimeout)
        if ip_dst in self.mem.seenIPs:
            print("SDN rules do not check for ingress port")
        else:
            print("Assuming that SDN rules check for ingress port")
            #self.ruleconstructor.createMatchRule(None,None,self.myip,ip_dst,None)

