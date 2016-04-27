
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
import random

class reconstr_actions(object):

    def __init__(self,ip,mac):
        self.myip=ip
        self.mymac=mac
        self.tools=tools()
        self.mem=memory()
        self.ruleconstructor=ruleconstructor()


    def reconstrAction(self,tIP,tMAC,probePorts):
        cnt=0
        if len(probePorts)==0:
            while(len(self.mem.getrecvICMP_PNR())==0 and cnt<5):
                #send UDP packet to trigger an ICMP port unreachable error
                rSrcP = random.randint(61000,65000)
                rDstP = random.randint(36000,37000)
                print("Sending UDP packet to port " + str(rDstP) + " at " + str(tIP) + " / " + str(tMAC))

                ether = Ether(src=self.mymac, dst=tMAC)
                ip = IP(src=self.myip, dst=tIP)
                udp = UDP(sport=rSrcP,dport=rDstP)
                pkt = ether/ip/udp
                sendp(pkt, verbose=0)
                cnt+=1
                time.sleep(2)

                recv_srcIP=self.myip
                recv_dstIP=tIP

                #ICMP redirect has to be received as stated in RFC 1122
                if len(self.mem.getrecvICMP_PNR())!=0:
                    print("Received ICMP Port Unreachable message")
                    pkt = self.mem.getrecvICMP_PNR().pop(0)
                    recv_srcIP = pkt[0][ICMP][1].src
                    recv_dstIP = pkt[0][ICMP][1].dst
                    del self.mem.getrecvICMP_PNR()[:]
                    cnt=5
                    #pkt.show2()

        else:
            found=0
            for srcPort in probePorts:
                for dstPort in probePorts:
                    if found==0:
                        #send UDP packet to trigger an ICMP port unreachable error
                        rSrcP = srcPort
                        rDstP = dstPort
                        print("Sending UDP packet to port " + str(rDstP) + " at " + str(tIP) + " / " + str(tMAC))

                        ether = Ether(src=self.mymac, dst=tMAC)
                        ip = IP(src=self.myip, dst=tIP)
                        udp = UDP(sport=rSrcP,dport=rDstP)
                        pkt = ether/ip/udp
                        sendp(pkt, verbose=0)
                        cnt+=1
                        time.sleep(2)

                        recv_srcIP=self.myip
                        recv_dstIP=tIP

                        #ICMP redirect has to be received as stated in RFC 1122
                        if len(self.mem.getrecvICMP_PNR())!=0:
                            print("Received ICMP Port Unreachable message")
                            pkt = self.mem.getrecvICMP_PNR().pop(0)
                            recv_srcIP = pkt[0][ICMP][1].src
                            recv_dstIP = pkt[0][ICMP][1].dst
                            del self.mem.getrecvICMP_PNR()[:]
                            found=1
                            #pkt.show2()


        #print("orgi src " + str(self.myip) + " recv src " + str(recv_srcIP))
        #print("orgi dst " + str(tIP) + " recv dst " + str(recv_dstIP))

        if str(tIP)==str(recv_dstIP) and str(self.myip)==str(recv_srcIP):
            print("IP addresses are not rewritten")
        else:
            if str(self.myip)!=str(recv_srcIP):
                print("IP src " + str(self.myip) + " is rewritten to " + str(recv_srcIP))

            if str(tIP)!=str(recv_dstIP):
                print("IP dst " + str(tIP) + " is rewritten to " + str(recv_dstIP))
        print("")

        return [self.myip,recv_srcIP,tIP,recv_dstIP]