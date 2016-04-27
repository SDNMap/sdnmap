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

class forensic_protocol_prober(object):

    def __init__(self,ip,mac):
        self.myip=ip
        self.mymac=mac
        self.tools=tools()
        self.mem=memory()
        self.network=network()
        self.replyTimeout=20
        #print("Protocol Prober initialized at... " + str(self.myip) + " - " + str(self.mymac))

    #check if host is reachable with TCP
    def checkTCP(self,probeIP,probeMAC,srcPort,dstPort):
        #use correct mac and IP
        hw_src = self.mymac
        hw_dst = probeMAC
        ip_src = self.myip
        ip_dst = probeIP
        print("Check if host at " + str(ip_dst) + " - " + str(hw_dst) + " is reachable with src addresses " + str( ip_src) + " - " + str(hw_src) + " with TCP on src port " + str(srcPort) + " and dst port " + str(dstPort))

        #rSrcP = random.randint(61000,65000)
        #rDstP = random.randint(36000,37000)
        rSrcP = srcPort
        rDstP = dstPort

        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        tcp_syn=TCP(sport=rSrcP, dport=rDstP, flags="S")

        tcp_pkt=ether/ip/tcp_syn
        ack_pkt=srp1(tcp_pkt, verbose=0, timeout=self.replyTimeout)

        if ack_pkt!=None:
            print("Host is reachable via TCP!")
            return 1
        else:
            return 0

    #check if host is reachable with ICMP
    def checkICMP(self,probeIP,probeMAC):
        #use correct mac and IP
        hw_src = self.mymac
        hw_dst = probeMAC
        ip_src = self.myip
        ip_dst = probeIP
        print("Check if host at " + str(ip_dst) + " - " + str(hw_dst) + " is reachable with src addresses " + str( ip_src) + " - " + str(hw_src) + " with ICMP")

        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        icmp = ICMP(type = 8, code = 0)

        icmp_pkt = ether/ip/icmp
        icmp_reply=srp1(icmp_pkt, verbose=0, timeout=self.replyTimeout)

        if icmp_reply!=None:
            print("Host is reachable via ICMP!")
            return 1
        else:
            return 0

    #check if host is reachable with UDP
    def checkUDP(self,probeIP,probeMAC,srcPort,dstPort):
        #use correct mac and IP
        hw_src = self.mymac
        hw_dst = probeMAC
        ip_src = self.myip
        ip_dst = probeIP
        print("Check if host at " + str(ip_dst) + " - " + str(hw_dst) + " is reachable with src addresses " + str( ip_src) + " - " + str(hw_src) + " with UDP on src port " + str(srcPort) + " and dst port " + str(dstPort))

        #send UDP packet to trigger an ICMP port unreachable error
        #rSrcP = random.randint(61000,65000)
        #rDstP = random.randint(36000,37000)
        rSrcP = srcPort
        rDstP = dstPort

        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        udp = UDP(sport=rSrcP,dport=rDstP)
        pkt = ether/ip/udp
        sendp(pkt, verbose=0)

        check=0
        while len(self.mem.getrecvICMP_PNR())==0 and check<self.replyTimeout:
            check+=1
            time.sleep(1)

        #ICMP redirect has to be received as stated in RFC 1122
        if len(self.mem.getrecvICMP_PNR())!=0:
            pkt = self.mem.getrecvICMP_PNR().pop(0)
            recv_srcIP = pkt[0][ICMP][1].src
            recv_dstIP = pkt[0][ICMP][1].dst
            del self.mem.getrecvICMP_PNR()[:]
            self.mem.getRecvICMPReplies().clear()
            print("Host is reachable via UDP!")
            return 1
        else:
            rSrcP = random.randint(61000,65000)
            rDstP = random.randint(36000,37000)
            print("Check if host at " + str(ip_dst) + " - " + str(hw_dst) + " is reachable with src addresses " + str( ip_src) + " - " + str(hw_src) + " with UDP on src port " + str(srcPort) + " and dst port " + str(dstPort))

            #send UDP packet to trigger an ICMP port unreachable error

            ether = Ether(src=hw_src, dst=hw_dst)
            ip = IP(src=ip_src, dst=ip_dst)
            udp = UDP(sport=rSrcP,dport=rDstP)
            pkt = ether/ip/udp
            sendp(pkt, verbose=0)

            if len(self.mem.getrecvICMP_PNR())!=0:
                pkt = self.mem.getrecvICMP_PNR().pop(0)
                recv_srcIP = pkt[0][ICMP][1].src
                recv_dstIP = pkt[0][ICMP][1].dst
                del self.mem.getrecvICMP_PNR()[:]
                self.mem.getRecvICMPReplies().clear()
                print("Host is reachable via UDP!")
                return 1

        return 0


    def determineProtocol(self,probeIP,probeMAC,srcPort,dstPort):
        print("------- Check with TCP --------")
        tcp=self.checkTCP(probeIP,probeMAC,srcPort,dstPort)
        print("-------------------------------------------")
        print("------- Check with ICMP -------")
        icmp=self.checkICMP(probeIP,probeMAC)
        print("-------------------------------------------")
        print("------- Check with UDP --------")
        udp=self.checkUDP(probeIP,probeMAC,srcPort,dstPort)
        print("-------------------------------------------\n")

        print("Accepted protocols: ")
        if tcp==1:
            print("TCP")
        if icmp==1:
            print("ICMP")
        if udp==1:
            print("UDP")
        if tcp==0 and icmp==0 and udp==0:
            print("none!")

        print("")
        print("")

        return [tcp,icmp,udp]