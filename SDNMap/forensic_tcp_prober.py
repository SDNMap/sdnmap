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

class forensic_tcp_prober(object):

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

    #determine of OF controller follows a reactive approach
    def checkReActive(self,probeIP,probeMAC,responseTimeout,probeSrcPort,probeDstPort):
        #use correct mac and IP
        hw_src = self.mymac
        hw_dst = probeMAC
        ip_src = self.myip
        ip_dst = probeIP

        reactive=False

        #send ping request
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        tcp_syn=TCP(sport=probeSrcPort, dport=probeDstPort, flags="S")

        tcp_pkt=ether/ip/tcp_syn

        count=0
        probeTimes=[]
        #print("Check if host at " + str(ip_dst) + " - " + str(hw_dst) + " is reachable with src addresses " + str(ip_src) + " - " + str(hw_src) + " from port " + str(probeSrcPort) + " to port " + str(probeDstPort))
        while count < 2:
            ans,unans=srp(tcp_pkt, verbose=0, timeout=10)
            if len(ans)!=0:
                rx = ans[0][1]
                tx = ans[0][0]
                delta = rx.time-tx.sent_time
                probeTimes.append(delta)
                count+=1
            else:
                break

        if len(probeTimes)!=0:
            routingOption1=1
            #print("Host at " + str(ip_dst) + " - " + str(hw_dst) + " is reachable with src addresses " + str(ip_src) + " - " + str(hw_src))

            if probeTimes[0]>5:
                reactiveTimeout=probeTimes[0]
            else:
                reactiveTimeout=5
            #factor = probeTimes[0]/probeTimes[1]
            #if factor>10:
            #    print("Probe response times indicate a reactive approach (delay difference factor " + str(int(factor)) + " > 10)")
            #else:
            #    print("Proactive approach is assumed based on probing response times (difference factor " + str(int(factor)) + " < 10)")
        else:
            #print("Host at " + str(ip_dst) + " - " + str(hw_dst) + " is not reachable with src addresses " + str(ip_src) + " - " + str(hw_src))
            reactiveTimeout=5
            routingOption1=0


        #use fake src mac and src IP addresses
        hw_src = self.tools.randMAC(self.mymac)
        hw_dst = probeMAC
        ip_src = self.tools.getDiffIP(self.myip)
        ip_dst = probeIP
        #print("Check if host at " + str(ip_dst) + " - " + str(hw_dst) + " is reachable with src addresses " + str( ip_src) + " - " + str(hw_src) + " from port " + str(probeSrcPort) + " to port " + str(probeDstPort))

        #send TCP packet with SYN flag
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        tcp_syn=TCP(sport=probeSrcPort, dport=probeDstPort, flags="S")

        tcp_pkt=ether/ip/tcp_syn
        sendp(tcp_pkt, verbose=0)

        #send ARP reply spoof message
        arppkt = self.spoofARPInv(ip_src,self.mymac,probeMAC,probeIP)
        sendp(arppkt, verbose=0)
        time.sleep(reactiveTimeout)

        if self.mem.getSeenTCP_Pktsself().has_key(ip_src):
            #print("Reply to fake src addresses received, learning approach assumed")
            self.mem.getSeenTCP_Pktsself().clear()
            reactive=True
        else:
            #print("Static approach is assumed since no response for fake addresses received")
            eactive=False

        return reactive,routingOption1

    def checkReachability(self,probeIP,probeMAC,probeSrcPort,probeDstPort):

        #use correct mac and IP
        hw_src = self.mymac
        hw_dst = probeMAC
        ip_src = self.myip
        ip_dst = probeIP
        print("Check if host at " + str(ip_dst) + " - " + str(hw_dst) + " is reachable with src addresses " + str( ip_src) + " - " + str(hw_src) + " from port " + str(probeSrcPort) + " to port " + str(probeDstPort))

        #send ping request
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        tcp_syn=TCP(sport=probeSrcPort, dport=probeDstPort, flags="S")

        tcp_pkt=ether/ip/tcp_syn
        ack_pkt=srp1(tcp_pkt, verbose=0)

        if ack_pkt!=None:
            print("Host is reachable!")
            routingOption=1
        else:
            routingOption=0

        self.mem.getSeenTCP_Pktsself().clear()
        return routingOption

    def spoofARP(self,spoofIP,spoofMAC,dstMAC,dstIP):
        print("Spoof ARP cache at " + str(dstIP) + " from " + str(spoofIP) + " to " + str(spoofMAC))
        ether1 = Ether(src=self.mymac, dst=dstMAC)
        arp1 = ARP(op="is-at", hwsrc=spoofMAC, hwdst=dstMAC, psrc=spoofIP, pdst=dstIP)
        arppkt = ether1/arp1
        return arppkt

    def spoofARPInv(self,spoofIP,spoofMAC,dstMAC,dstIP):
        #print("Spoof ARP cache at " + str(dstIP) + " from " + str(spoofIP) + " to " + str(spoofMAC))
        ether1 = Ether(src=self.mymac, dst=dstMAC)
        arp1 = ARP(op="is-at", hwsrc=spoofMAC, hwdst=dstMAC, psrc=spoofIP, pdst=dstIP)
        arppkt = ether1/arp1
        return arppkt

    def checkL3RoutingSrcDst(self,probeIP,probeMAC,responseTimeout,probeSrcPort,probeDstPort):
        #use correct MAC but wrong src IP
        hw_src = self.mymac
        hw_dst = probeMAC
        ip_src = self.tools.getDiffIP(self.myip)
        ip_dst = probeIP
        print("Check if host at " + str(ip_dst) + " - " + str(hw_dst) + " is reachable with src addresses " + str( ip_src) + " - " + str(hw_src) + " from port " + str(probeSrcPort) + " to port " + str(probeDstPort))

        #send ping request
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        tcp_syn=TCP(sport=probeSrcPort, dport=probeDstPort, flags="S")

        tcp_pkt=ether/ip/tcp_syn
        sendp(tcp_pkt, verbose=0)
        time.sleep(responseTimeout)

        srcIP=1
        dstIP=1

        if self.mem.getSeenTCP_Pktsself().has_key(ip_src):
            print("Response to fake IP src received!")
            srcIP=0
            self.mem.getSeenTCP_Pktsself().clear()

        if self.mem.getARPIPReq().has_key(ip_src):
            print("ARP req for fake IP src received!")
            srcIP=0
            self.mem.getSeenTCP_Pktsself().clear()

        #spoof arp entry
        arppkt = self.spoofARP(ip_src,hw_src,probeMAC,probeIP)
        sendp(arppkt, verbose=0)
        #print("Spoof ARP cache")
        time.sleep(responseTimeout)

        #send ping request
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        tcp_syn=TCP(sport=probeSrcPort, dport=probeDstPort, flags="S")

        print("Check if host at " + str(ip_dst) + " - " + str(hw_dst) + " is reachable from " + str( ip_src) + " - " + str(hw_src) + " from port " + str(probeSrcPort) + " to port " + str(probeDstPort))

        tcp_pkt=ether/ip/tcp_syn
        sendp(tcp_pkt, verbose=0)
        time.sleep(responseTimeout)

        if self.mem.getSeenTCP_Pktsself().has_key(ip_src):
            print("Response to fake IP src and dst received!")
            dstIP=0
            self.mem.getSeenTCP_Pktsself().clear()

        self.mem.getSeenTCP_Pktsself().clear()
        return [srcIP,dstIP]

    def checkL2RoutingSrcDst(self,probeIP,probeMAC,responseTimeout,probeSrcPort,probeDstPort):
        #use correct IP but wrong MAC
        hw_src = self.tools.randMAC(self.mymac)
        hw_dst = probeMAC
        ip_src = self.myip
        ip_dst = probeIP
        print("Check if host at " + str(ip_dst) + " - " + str(hw_dst) + " is reachable with src addresses " + str(ip_src) + " - " + str(hw_src) + " from port " + str(probeSrcPort) + " to port " + str(probeDstPort))

        #send ping request
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        tcp_syn=TCP(sport=probeSrcPort, dport=probeDstPort, flags="S")

        tcp_pkt=ether/ip/tcp_syn
        sendp(tcp_pkt, verbose=0)
        time.sleep(responseTimeout)

        srcMac=1
        dstMac=1

        if self.mem.getSeenTCP_Pktsself().has_key(ip_src):
            print("Response to fake src MAC received!")
            self.mem.getSeenTCP_Pktsself().clear()
            srcMac=0

        #spoof arp entry of us on target host
        arppkt = self.spoofARP(self.myip,hw_src,probeMAC,probeIP)
        sendp(arppkt, verbose=0)
        #print("Spoof ARP cache")
        time.sleep(1)

        #send ping packet again with correct MAC src address and see if response comes back
        hw_src = self.mymac
        ether = Ether(src=hw_src, dst=hw_dst)

        tcp_pkt=ether/ip/tcp_syn
        sendp(tcp_pkt, verbose=0)
        print("Check if host at " + str(ip_dst) + " - " + str(hw_dst) + " is reachable from " + str( ip_src) + " - " + str(hw_src) + " from port " + str(probeSrcPort) + " to port " + str(probeDstPort))
        time.sleep(responseTimeout)

        if self.mem.getSeenTCP_Pktsself().has_key(ip_src):
            print("Response to fake src and dst MAC received!")
            self.mem.getSeenTCP_Pktsself().clear()
            dstMac=0

        #restore our arp entry
        arppkt = self.spoofARP(self.myip,self.mymac,probeMAC,probeIP)
        sendp(arppkt, verbose=0)
        self.mem.getSeenTCP_Pktsself().clear()

        return [srcMac,dstMac]

    def determineTCPProtocol(self,probeIP,probeMAC,responseTimeout):
        hw_src = self.mymac
        hw_dst = probeMAC
        ip_src = self.myip
        ip_dst = probeIP

        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        tcp_syn=TCP(sport=1500, dport=80, flags="S")
        tcp_pkt=ether/ip/tcp_syn

        tcp_pkt.show2()
        ack_pkt=srp1(tcp_pkt, verbose=0)
        ack_pkt.show2()


    def determineTCPRouting(self,probeIP,probeMAC,probeSrcPort,probeDstPort):
        responseTimeout=2

        #print("------- Check SDN approach --------")
        reactive,routingOption1=self.checkReActive(probeIP,probeMAC,responseTimeout,probeSrcPort,probeDstPort)
        #print("-------------------------------------------")
        #routingOption1 = self.checkReachability(probeIP,probeMAC,probePort)
        print("------- Check if layer 3 routing is used --------")
        [srcIP,dstIP] = self.checkL3RoutingSrcDst(probeIP,probeMAC,responseTimeout,probeSrcPort,probeDstPort)
        print("-------------------------------------------")
        print("------- Check if layer 2 routing is used --------")
        [srcMac,dstMac] = self.checkL2RoutingSrcDst(probeIP,probeMAC,responseTimeout,probeSrcPort,probeDstPort)
        print("-------------------------------------------")

        ip_src=self.myip
        ip_dst=probeIP
        hw_src=self.mymac
        hw_dst=probeMAC

        if routingOption1==0 and reactive==True:
            #if srcMac==0 and dstMac==0 and srcIP==0 and dstIP==0:
                #print("SDN controller does not enforce any L2 or L3 address fields on this path!")

            if srcMac==1 and dstMac==0 and srcIP==0 and dstIP==0:
                hw_src=None

            if srcMac==0 and dstMac==1 and srcIP==0 and dstIP==0:
                hw_dst=None

            if srcMac==1 and dstMac==1 and srcIP==0 and dstIP==0:
                hw_src=None
                hw_dst=None

            if srcMac==0 and dstMac==0 and srcIP==1 and dstIP==0:
                ip_src=None

            if srcMac==1 and dstMac==0 and srcIP==1 and dstIP==0:
                hw_src=None
                ip_src=None

            if srcMac==0 and dstMac==1 and srcIP==1 and dstIP==0:
                hw_dst=None
                ip_src=None

            if srcMac==1 and dstMac==1 and srcIP==1 and dstIP==0:
                hw_src=None
                hw_dst=None
                ip_src=None

            if srcMac==0 and dstMac==0 and srcIP==0 and dstIP==1:
                ip_dst=None

            if srcMac==1 and dstMac==0 and srcIP==0 and dstIP==1:
                hw_src=None
                ip_dst=None

            if srcMac==0 and dstMac==1 and srcIP==0 and dstIP==1:
                hw_dst=None
                ip_dst=None

            if srcMac==1 and dstMac==1 and srcIP==0 and dstIP==1:
                hw_src=None
                hw_dst=None
                ip_dst=None

            if srcMac==0 and dstMac==0 and srcIP==1 and dstIP==1:
                ip_src=None
                ip_dst=None

            if srcMac==1 and dstMac==0 and srcIP==1 and dstIP==1:
                hw_src=None
                ip_src=None
                ip_dst=None

            if srcMac==0 and dstMac==1 and srcIP==1 and dstIP==1:
                hw_dst=None
                ip_src=None
                ip_dst=None

            if srcMac==1 and dstMac==1 and srcIP==1 and dstIP==1:
                hw_src=None
                hw_dst=None
                ip_src=None
                ip_dst=None
        else:
            if srcMac==0:
                hw_src=None

            if dstMac==0:
                hw_dst=None

            if srcIP==0:
                ip_src=None

            if dstIP==0:
                ip_dst=None

            #if srcMac==0 and dstMac==0 and srcIP==0 and dstIP==0:
                #print("SDN controller does not enforce any L2 or L3 address fields on this path!")

        '''
        if routingOption1==1:
            self.ruleconstructor.createMatchRule(hw_src,hw_dst,ip_src,ip_dst,None)
        else:
            print("Destination not reachable!")
        '''
        return [ip_src,ip_dst,hw_src,hw_dst,routingOption1,reactive]
