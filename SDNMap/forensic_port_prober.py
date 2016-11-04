__author__ = 'mininet'

from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.dhcp import *
from scapy.layers.dns import *
from tools import tools
from memory import memory
from ruleconstructor import ruleconstructor
import time
from Target import Target
from network import network

class forensic_port_prober(object):

    def __init__(self,ip,mac):
        self.myip=ip
        self.mymac=mac
        self.tools=tools()
        self.mem=memory()
        self.ruleconstructor=ruleconstructor()
        self.recv_target=None
        self.sent_target=None
        self.network=network()
        #print("TCP Prober initialized at... " + str(self.myip) + " - " + str(self.mymac))

    #determine ports that are enforced for TCP packets
    def checkTCPPorts (self,probeIP,probeMAC,responseTimeout,probePorts):
        #use correct mac and IP
        hw_src = self.mymac
        hw_dst = probeMAC
        ip_src = self.myip
        ip_dst = probeIP

        count=0
        reachableSrcPorts=[]
        reachableDstPorts=[]
        for srcPort in probePorts:
            for dstPort in probePorts:
                ether = Ether(src=hw_src, dst=hw_dst)
                ip = IP(src=ip_src, dst=ip_dst)
                tcp_syn=TCP(sport=srcPort, dport=dstPort, flags="S")

                print("Probing " + str(ip_dst) + " - " + str(hw_dst) + " with TCP source port " + str(srcPort) + " and destination port " + str(dstPort))

                tcp_pkt=ether/ip/tcp_syn
                ans,unans=srp(tcp_pkt, verbose=0, timeout=responseTimeout)
                if len(ans)!=0:
                    print("Replied!")
                    reachableSrcPorts.append(srcPort)
                    reachableDstPorts.append(dstPort)
                else:
                    print("No reply received!")

        for srcPort in probePorts:
            for dstPort in probePorts:
                ether = Ether(src=hw_src, dst=hw_dst)
                ip_src = self.tools.getDiffIP(self.myip)
                ip = IP(src=ip_src, dst=ip_dst)
                tcp_syn=TCP(sport=srcPort, dport=dstPort, flags="S")

                print("Probing " + str(ip_dst) + " - " + str(hw_dst) + " with spoofed IP source and TCP source port " + str(srcPort) + " and destination port " + str(dstPort))

                tcp_pkt=ether/ip/tcp_syn
                sendp(tcp_pkt, verbose=0)
                time.sleep(responseTimeout)

                if self.mem.getARPIPReq().has_key(ip_src):
                    print("Received ARP request for " + str(ip_src))
                    if srcPort not in reachableSrcPorts or dstPort not in reachableDstPorts:
                        reachableSrcPorts.append(srcPort)
                        reachableDstPorts.append(dstPort)
                    self.mem.getARPIPReq().clear()
                else:
                    print("No reply received!")


        return [reachableSrcPorts,reachableDstPorts]

    #determine ports that are enforced for UDP packets
    def checkUDPPorts (self,probeIP,probeMAC,responseTimeout,probePorts):
        #use correct mac and IP
        hw_src = self.mymac
        hw_dst = probeMAC
        ip_src = self.myip
        ip_dst = probeIP

        count=0
        reachableSrcPorts=[]
        reachableDstPorts=[]

        del self.mem.getrecvICMP_PNR()[:]
        for srcPort in probePorts:
            for dstPort in probePorts:
                ether = Ether(src=hw_src, dst=hw_dst)
                ip = IP(src=ip_src, dst=ip_dst)
                udp = UDP(sport=srcPort, dport=dstPort)
                pkt = ether/ip/udp
                sendp(pkt, verbose=0)
                time.sleep(responseTimeout)

                print("Probing " + str(ip_dst) + " - " + str(hw_dst) + " with UDP source port " + str(srcPort) + " and destination port " + str(dstPort))

                if len(self.mem.getrecvICMP_PNR())!=0:
                    print("Replied at port " + str(dstPort) + "!")
                    reachableSrcPorts.append(srcPort)
                    reachableDstPorts.append(dstPort)
                    del self.mem.getrecvICMP_PNR()[:]
                else:
                    print("No reply received!")

        for srcPort in probePorts:
            for dstPort in probePorts:
                ether = Ether(src=hw_src, dst=hw_dst)
                ip_src = self.tools.getDiffIP(self.myip)
                ip = IP(src=ip_src, dst=ip_dst)
                udp = UDP(sport=srcPort, dport=dstPort)
                pkt = ether/ip/udp
                sendp(pkt, verbose=0)
                time.sleep(responseTimeout)

                print("Probing " + str(ip_dst) + " - " + str(hw_dst) + " with spoofed IP source and UDP source port " + str(srcPort) + " and destination port " + str(dstPort))

                if self.mem.getARPIPReq().has_key(ip_src):
                    print("Received ARP request for " + str(ip_src))
                    if srcPort not in reachableSrcPorts or dstPort not in reachableDstPorts:
                        reachableSrcPorts.append(srcPort)
                        reachableDstPorts.append(dstPort)
                    self.mem.getARPIPReq().clear()
                else:
                    print("No reply received!")

        return [reachableSrcPorts,reachableDstPorts]


    def spoofARP(self,spoofIP,spoofMAC,dstMAC,dstIP):
        print("Spoof ARP cache at " + str(dstIP) + " from " + str(spoofIP) + " to " + str(spoofMAC))
        ether1 = Ether(src=self.mymac, dst=dstMAC)
        arp1 = ARP(op="is-at", hwsrc=spoofMAC, hwdst=dstMAC, psrc=spoofIP, pdst=dstIP)
        arppkt = ether1/arp1
        return arppkt

    def determinePorts(self,probeIP,probeMAC,probePorts):

        responseTimeout=2

        print("------- Test which TCP ports, using ports " + str(probePorts) + ", are checked --------")
        reachableSrcPorts_tcp,reachableDstPorts_tcp=self.checkTCPPorts(probeIP,probeMAC,responseTimeout,probePorts)
        print("-------------------------------------------")
        print("------- Test which UDP ports, using ports " + str(probePorts) + ", are checked --------")
        reachableSrcPorts_udp,reachableDstPorts_udp=self.checkUDPPorts(probeIP,probeMAC,responseTimeout,probePorts)
        print("-------------------------------------------")


        return [reachableSrcPorts_tcp,reachableDstPorts_tcp,reachableSrcPorts_udp,reachableDstPorts_udp]
