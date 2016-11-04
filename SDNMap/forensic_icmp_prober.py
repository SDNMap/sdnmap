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

class forensic_icmp_prober(object):

    def __init__(self,ip,mac):
        self.myip=ip
        self.mymac=mac
        self.tools=tools()
        self.mem=memory()
        self.ruleconstructor=ruleconstructor()
        self.recv_target=None
        self.sent_target=None
        self.network=network()
        #print("ICMP Prober initialized at... " + str(self.myip) + " - " + str(self.mymac))

    #determine of OF controller follows a reactive approach
    def checkReActive(self,probeIP,probeMAC,responseTimeout):
        #use correct mac and IP
        hw_src = self.mymac
        hw_dst = probeMAC
        ip_src = self.myip
        ip_dst = probeIP

        reactive=False
        routingOption1=0

        #send ping request
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        icmp = ICMP(type = 8, code = 0)

        icmp_pkt = ether/ip/icmp

        count=0
        probeTimes=[]
        #print("Check if host at " + str(ip_dst) + " - " + str(hw_dst) + " is reachable with src addresses " + str(ip_src) + " - " + str(hw_src))
        while count < 2:
            ans,unans=srp(icmp_pkt, verbose=0, timeout=10)
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

        #send ping request
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        icmp = ICMP(type = 8, code = 0)
        raw=self.tools.createTimeNonce(None,56)
        nonce=int(str(raw).split("#")[1],10)
        #nonce will be stored in memory if it was received

        icmp_pkt = ether/ip/icmp/raw
        #print("Check if host at " + str(ip_dst) + " - " + str(hw_dst) + " is reachable with src addresses " + str(ip_src) + " - " + str(hw_src))
        sendp(icmp_pkt, verbose=0)
        time.sleep(responseTimeout)

        #send ARP reply spoof message
        arppkt = self.spoofARPInv(ip_src,self.mymac,hw_dst,ip_dst)
        sendp(arppkt, verbose=0)
        time.sleep(reactiveTimeout)

        #send ping request
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        icmp = ICMP(type = 8, code = 0)
        raw=self.tools.createTimeNonce(None,56)
        nonce=int(str(raw).split("#")[1],10)
        #nonce will be stored in memory if it was received

        icmp_pkt = ether/ip/icmp/raw
        #print("Check if host at " + str(ip_dst) + " - " + str(hw_dst) + " is reachable with src addresses " + str(ip_src) + " - " + str(hw_src))
        sendp(icmp_pkt, verbose=0)
        time.sleep(responseTimeout)

        if self.mem.getNonces().has_key(nonce):
            #print("Reply to fake src addresses received, learning approach assumed!")
            self.mem.getNonces().clear()
            reactive=True
        else:
            #print("Static approach is assumed since no response for fake addresses received")
            reactive=False

        return reactive,routingOption1

    def checkReachability(self,probeIP,probeMAC,responseTimeout):

        #use correct mac and IP
        hw_src = self.mymac
        hw_dst = probeMAC
        ip_src = self.myip
        ip_dst = probeIP
        print("Check if host at " + str(ip_dst) + " - " + str(hw_dst) + " is reachable from " + str(ip_src) + " - " + str(hw_src))

        #send ping request
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        icmp = ICMP(type = 8, code = 0)

        #raw=self.tools.createICMPPayload(self.myip,56)
        raw=self.tools.createTimeNonce(None,56)
        nonce=int(str(raw).split("#")[1],10)
        #nonce will be stored in memory if it was received

        icmp_pkt = ether/ip/icmp/raw

        #include raw payload with encoded arp table
        #print("Send icmp packet to " + str(ip_dst) + " to check reachability")
        print("Sent nonce " + str(nonce))
        sendp(icmp_pkt, verbose=0)
        time.sleep(responseTimeout)

        if self.mem.getNonces().has_key(nonce):
            self.recv_target = self.mem.getNonces().get(nonce)
            self.sent_target = Target(nonce,ip_src,hw_src,ip_dst,hw_dst)
            #print(hw_src + "/" + target.src_mac + " - " + hw_dst + "/" + target.dst_mac + " - " + ip_src + "/" + target.src_ip + " - " + ip_dst + "/" + target.dst_ip)
            print("Host is reachable!")
            routingOption=1
            self.mem.getNonces().clear()
        else:
            routingOption=0
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

    def checkL3RoutingSrcDst(self,probeIP,probeMAC,responseTimeout):
        #use correct MAC but wrong src IP
        hw_src = self.mymac
        hw_dst = probeMAC
        ip_src = self.tools.getDiffIP(self.myip)
        ip_dst = probeIP
        print("Check if host at " + str(ip_dst) + " - " + str(hw_dst) + " is reachable with src addresses " + str(ip_src) + " - " + str(hw_src))

        #send ping request
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        icmp = ICMP(type = 8, code = 0)

        raw=self.tools.createTimeNonce(None,56)
        nonce=int(str(raw).split("#")[1],10)
        #nonce will be stored in memory if it was received

        icmp_pkt = ether/ip/icmp/raw
        sendp(icmp_pkt, verbose=0)
        time.sleep(responseTimeout)

        srcIP=1
        dstIP=1

        if self.mem.getARPIPReq().has_key(ip_src):
            print("ARP req for fake IP src received!")
            srcIP=0

        #spoof arp entry
        arppkt = self.spoofARP(ip_src,hw_src,probeMAC,probeIP)
        sendp(arppkt, verbose=0)
        time.sleep(responseTimeout)

        #send ping request
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        icmp = ICMP(type = 8, code = 0)

        raw=self.tools.createTimeNonce(None,56)
        nonce=int(str(raw).split("#")[1],10)
        #nonce will be stored in memory if it was received

        icmp_pkt = ether/ip/icmp/raw
        print("Check if host at " + str(ip_dst) + " - " + str(hw_dst) + " is reachable with src addresses " + str(ip_src) + " - " + str(hw_src))
        sendp(icmp_pkt, verbose=0)
        time.sleep(responseTimeout)

        if self.mem.getNonces().has_key(nonce):
            print("Response to fake IP src and dst received!")
            dstIP=0
            self.mem.getNonces().clear()

        return [srcIP,dstIP]

    def checkL2RoutingSrcDst(self,probeIP,probeMAC,responseTimeout):
        #use correct IP but wrong MAC
        hw_src = self.tools.randMAC(self.mymac)
        hw_dst = probeMAC
        ip_src = self.myip
        ip_dst = probeIP

        #send ping request
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        icmp = ICMP(type = 8, code = 0)

        raw=self.tools.createTimeNonce(None,56)
        nonce=int(str(raw).split("#")[1],10)
        #nonce will be stored in memory if it was received

        icmp_pkt = ether/ip/icmp/raw
        print("Check if host at " + str(ip_dst) + " - " + str(hw_dst) + " is reachable with src addresses " + str(ip_src) + " - " + str(hw_src))
        sendp(icmp_pkt, verbose=0)
        time.sleep(responseTimeout)

        srcMac=1
        dstMac=1

        if self.mem.getNonces().has_key(nonce):
            print("Response to fake src MAC received!")
            srcMac=0
            self.mem.getNonces().clear()

        #spoof arp entry of us on target host
        arppkt = self.spoofARP(self.myip,hw_src,probeMAC,probeIP)
        sendp(arppkt, verbose=0)
        time.sleep(responseTimeout)

        #send ping packet again with correct MAC src address and see if response comes back
        hw_src = self.mymac
        ether = Ether(src=hw_src, dst=hw_dst)

        raw=self.tools.createTimeNonce(None,56)
        nonce=int(str(raw).split("#")[1],10)
        #nonce will be stored in memory if it was received

        icmp_pkt = ether/ip/icmp/raw

        print("Check if host at " + str(ip_dst) + " - " + str(hw_dst) + " is reachable with src addresses " + str(ip_src) + " - " + str(hw_src))
        sendp(icmp_pkt, verbose=0)
        time.sleep(responseTimeout)

        if self.mem.getNonces().has_key(nonce):
            print("Response to fake src and dst MAC received!")
            dstMac=0
            self.mem.getNonces().clear()

        #restore our arp entry
        arppkt = self.spoofARP(self.myip,self.mymac,probeMAC,probeIP)
        sendp(arppkt, verbose=0)
        self.mem.getNonces().clear()
        return [srcMac,dstMac]


    def determineRouting(self,probeIP,probeMAC):
        responseTimeout=2

        #print("------- Check SDN approach --------")
        reactive,routingOption1=self.checkReActive(probeIP,probeMAC,responseTimeout)
        #print("-------------------------------------------")
        #routingOption1 = self.checkReachability(probeIP,probeMAC,probePort)
        print("------- Check if layer 3 routing is used --------")
        [srcIP,dstIP] = self.checkL3RoutingSrcDst(probeIP,probeMAC,responseTimeout)
        print("-------------------------------------------")
        print("------- Check if layer 2 routing is used --------")
        [srcMac,dstMac] = self.checkL2RoutingSrcDst(probeIP,probeMAC,responseTimeout)
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
            print(self.ruleconstructor.ruleMatch("",hw_src,hw_dst,ip_src,ip_dst,None))
        else:
            print("Destination not reachable!")
        '''
        return [ip_src,ip_dst,hw_src,hw_dst,routingOption1,reactive]
