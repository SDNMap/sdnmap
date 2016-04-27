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

class prober(object):

    def __init__(self,ip,mac):
        self.myip=ip
        self.mymac=mac
        self.tools=tools()
        self.mem=memory()
        self.ruleconstructor=ruleconstructor()
        self.recv_target=None
        self.sent_target=None
        self.network=network()
        print("Prober initialized at... " + str(self.myip) + " - " + str(self.mymac))


    def checkReachability(self,probeIP,probeMAC,responseTimeout,routingOption):
        #use correct mac and IP
        hw_src = self.mymac
        hw_dst = probeMAC
        ip_src = self.myip
        ip_dst = probeIP

        #hw_src = self.network.nodesF[1].mac
        #hw_dst = self.network.nodesF[3].mac
        #ip_src = self.network.nodesF[1].ip
        #ip_dst = self.network.nodesF[3].ip


        #send ping request
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        icmp = ICMP(type = 8, code = 0)

        #raw=self.tools.createICMPPayload(self.myip,56)
        #option 1
        raw=self.tools.createNonce(None,1,self.myip,self.mymac,"0.0.0.0","00:00:00:00:00:00",56)
        nonce=int(str(raw).split("#")[1],10)
        #nonce will be stored in memory if it was received

        icmp_pkt = ether/ip/icmp/raw
        icmp_pkt.show2()

        #include raw payload with encoded arp table

        print("Send icmp packet to " + str(ip_dst) + " to check reachability")
        sendp(icmp_pkt, verbose=0)
        time.sleep(responseTimeout)

        if self.mem.getNonces().has_key(nonce):
            self.recv_target = self.mem.getNonces().get(nonce)
            self.sent_target = Target(nonce,ip_src,hw_src,ip_dst,hw_dst)
            #print(hw_src + "/" + target.src_mac + " - " + hw_dst + "/" + target.dst_mac + " - " + ip_src + "/" + target.src_ip + " - " + ip_dst + "/" + target.dst_ip)
            print("Assuming l2 and/or l3 routing and input port")
            routingOption=1
            self.mem.getNonces().pop(nonce)
        else:
            print("")
        return routingOption

    def checkL3Routing(self,probeIP,probeMAC,responseTimeout,routingOption):
        #use correct MAC but wrong IP
        hw_src = self.mymac
        hw_dst = probeMAC
        ip_src = self.tools.randIP(self.myip)
        ip_dst = self.tools.randIP(self.myip)
        #ip_dst = self.network.nodesF[3].ip
        #ip_src = self.network.nodesF[1].ip

        #send ping request
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        icmp = ICMP(type = 8, code = 0)

        #option 2
        raw=self.tools.createNonce(None,2,self.myip,self.mymac,"0.0.0.0","00:00:00:00:00:00",56)
        nonce=int(str(raw).split("#")[1],10)
        #nonce will be stored in memory if it was received

        icmp_pkt = ether/ip/icmp/raw

        print("Send icmp packet to " + str(ip_dst) + " to check L2 routing")
        sendp(icmp_pkt, verbose=0)
        time.sleep(responseTimeout)

        if self.mem.getNonces().has_key(nonce):
            #self.recv_target = self.mem.getNonces().get(nonce)
            #self.sent_target = Target(nonce,ip_src,hw_src,ip_dst,hw_dst)
            #print(hw_src + "/" + target.src_mac + " - " + hw_dst + "/" + target.dst_mac + " - " + ip_src + "/" + target.src_ip + " - " +ip_dst + "/" + target.dst_ip)
            print("Response to fake IP received, L2 routing can be assumed")
            routingOption=2
            self.mem.getNonces().pop(nonce)

        else:
            print("")
        return routingOption

    def checkL2Routing(self,probeIP,probeMAC,responseTimeout,routingOption):
        #use correct IP but wrong MAC
        hw_src = self.tools.randMAC(self.mymac)
        hw_dst = self.tools.randMAC(self.mymac)
        ip_src = self.myip
        ip_dst = probeIP
        #hw_src = self.network.nodesF[1].mac
        #hw_dst = self.network.nodesF[3].mac

        #send ping request
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        icmp = ICMP(type = 8, code = 0)

        #option 3
        raw=self.tools.createNonce(None,3,self.myip,self.mymac,"0.0.0.0","00:00:00:00:00:00",56)
        nonce=int(str(raw).split("#")[1],10)
        #nonce will be stored in memory if it was received

        icmp_pkt = ether/ip/icmp/raw

        print("Send icmp packet to " + str(ip_dst) + " to check L3 routing")
        sendp(icmp_pkt, verbose=0)
        time.sleep(responseTimeout)

        if self.mem.getNonces().has_key(nonce):
            #self.recv_target = self.mem.getNonces().get(nonce)
            #self.sent_target = Target(nonce,ip_src,hw_src,ip_dst,hw_dst)
            #print(hw_src + "/" + target.src_mac + " - " + hw_dst + "/" + target.dst_mac + " - " + ip_src + "/" + target.src_ip + " - " +ip_dst + "/" + target.dst_ip)
            print("Response to fake MAC received, L3 routing can be assumed")
            routingOption=3
            self.mem.getNonces().pop(nonce)

        else:
            print("")
        return routingOption

    def checkDSTRouting(self,probeIP,probeMAC,responseTimeout,routingOption):
        #use correct IP but wrong MAC
        hw_src = self.tools.randMAC(self.mymac)
        hw_dst = probeMAC
        ip_src = self.tools.randIP(self.myip)
        ip_dst = probeIP

        #hw_src = self.network.nodesF[1].mac
        #ip_src = self.network.nodesF[1].ip

        #send ping request
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        icmp = ICMP(type = 8, code = 0)

        #option 4
        raw=self.tools.createNonce(None,4,self.myip,self.mymac,"0.0.0.0","00:00:00:00:00:00",56)
        nonce=int(str(raw).split("#")[1],10)
        #nonce will be stored in memory if it was received

        icmp_pkt = ether/ip/icmp/raw

        print("Send icmp packet to " + str(ip_dst) + " to check DST routing")
        sendp(icmp_pkt, verbose=0)
        time.sleep(responseTimeout)

        if self.mem.getNonces().has_key(nonce):
            #self.recv_target = self.mem.getNonces().get(nonce)
            #self.sent_target = Target(nonce,ip_src,hw_src,ip_dst,hw_dst)
            #print(hw_src + "/" + target.src_mac + " - " + hw_dst + "/" + target.dst_mac + " - " + ip_src + "/" + target.src_ip + " - " +ip_dst + "/" + target.dst_ip)
            print("Response to fake src MAC and src IP received, DST routing can be assumed")
            routingOption=4
            self.mem.getNonces().pop(nonce)

        else:
            print("")
        return routingOption

    def checkL2DSTRouting(self,probeIP,probeMAC,responseTimeout,routingOption):
        #use correct dst IP but wrong MACs
        hw_src = self.tools.randMAC(self.mymac)
        hw_dst = self.tools.randMAC(self.mymac)
        ip_src = self.tools.randIP(self.myip)
        ip_dst = probeIP

        #send ping request
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        icmp = ICMP(type = 8, code = 0)

        #option 6
        raw=self.tools.createNonce(None,6,self.myip,self.mymac,"0.0.0.0","00:00:00:00:00:00",56)
        nonce=int(str(raw).split("#")[1],10)
        #nonce will be stored in memory if it was received

        icmp_pkt = ether/ip/icmp/raw

        print("Send icmp packet to " + str(ip_dst) + " to check L2 DST routing")
        sendp(icmp_pkt, verbose=0)
        time.sleep(responseTimeout)

        if self.mem.getNonces().has_key(nonce):
            #self.recv_target = self.mem.getNonces().get(nonce)
            #self.sent_target = Target(nonce,ip_src,hw_src,ip_dst,hw_dst)
            #print(hw_src + "/" + target.src_mac + " - " + hw_dst + "/" + target.dst_mac + " - " + ip_src + "/" + target.src_ip + " - " +ip_dst + "/" + target.dst_ip)
            print("Response to fake MACs and src IP received, L3 IP DST routing can be assumed")
            routingOption=6
            self.mem.getNonces().pop(nonce)

        else:
            print("")
        return routingOption

    def checkL3DSTRouting(self,probeIP,probeMAC,responseTimeout,routingOption):
        #use correct dst MAC but wrong IPs
        hw_src = self.tools.randMAC(self.mymac)
        hw_dst = probeMAC
        ip_src = self.tools.randIP(self.myip)
        ip_dst = self.tools.randIP(self.myip)

        #send ping request
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        icmp = ICMP(type = 8, code = 0)

        #option 5
        raw=self.tools.createNonce(None,5,self.myip,self.mymac,"0.0.0.0","00:00:00:00:00:00",56)
        nonce=int(str(raw).split("#")[1],10)
        #nonce will be stored in memory if it was received

        icmp_pkt = ether/ip/icmp/raw

        print("Send icmp packet to " + str(ip_dst) + " to check L3 DST routing")
        sendp(icmp_pkt, verbose=0)
        time.sleep(responseTimeout)

        if self.mem.getNonces().has_key(nonce):
            #self.recv_target = self.mem.getNonces().get(nonce)
            #self.sent_target = Target(nonce,ip_src,hw_src,ip_dst,hw_dst)
            #print(hw_src + "/" + target.src_mac + " - " + hw_dst + "/" + target.dst_mac + " - " + ip_src + "/" + target.src_ip + " - " +ip_dst + "/" + target.dst_ip)
            print("Response to fake IPs and src MAC received, L2 MAC DST routing can be assumed")
            routingOption=5
            self.mem.getNonces().pop(nonce)

        else:
            print("")
        return routingOption


    def determineRouting(self,probeIP,probeMAC):

        # 1=l2+l3, 2=l2, 3=l3
        routingOption=0

        responseTimeout=2

        routingOption = self.checkReachability(probeIP,probeMAC,responseTimeout,routingOption)
        routingOption = self.checkL3Routing(probeIP,probeMAC,responseTimeout,routingOption)
        routingOption = self.checkL2Routing(probeIP,probeMAC,responseTimeout,routingOption)

        ip_src=self.myip
        ip_dst=probeIP
        hw_src=self.mymac
        hw_dst=probeMAC

        if routingOption==1:
            routingOption = self.checkDSTRouting(probeIP,probeMAC,responseTimeout,routingOption)
            if routingOption==4:
                hw_src=None
                ip_src=None

        elif routingOption==2:
            routingOption = self.checkL3DSTRouting(probeIP,probeMAC,responseTimeout,routingOption)
            ip_dst=None
            ip_src=None
            if routingOption==5:
                hw_src=None

        elif routingOption==3:
            routingOption = self.checkL2DSTRouting(probeIP,probeMAC,responseTimeout,routingOption)
            hw_src=None
            hw_dst=None
            if routingOption==6:
                ip_src=None

        if routingOption!=0:
            self.ruleconstructor.createMatchRule(hw_src,hw_dst,ip_src,ip_dst,None)
        else:
            print("Destination not reachable!")

        if self.recv_target!=None and self.sent_target!=None:
            self.ruleconstructor.createActionRule(self.recv_target,self.sent_target)

        '''
        #determine which fields of a packet are used to route ping packets,
        #if we know which ones are used and which are not used, we can use these fields in pings
        #to secretly transport information between nodes

        if routingOption==1:
            #use correct IP

            #decide about nounce, use id
            id=11

            #hw_src = self.tools.randMAC(self.mymac)
            hw_src = self.tools.nounceMAC(self.mymac,id)
            hw_dst = probeMAC
            ip_src = self.tools.nounceIP(self.myip,id)
            ip_dst = probeIP

            #send ping request
            ether = Ether(src=hw_src, dst=hw_dst)
            ip = IP(src=ip_src, dst=ip_dst, id=id)
            icmp = ICMP(type = 8, code = 0)
            icmp_pkt = ether/ip/icmp

            sendp(icmp_pkt, verbose=0)
            time.sleep(responseTimeout)

            if ip_src in self.mem.seenIPs and hw_src in self.mem.seenMacs:
                self.mem.seenIPs.remove(ip_src)
                self.mem.seenMacs.remove(hw_src)
                print("Rule checks for MAC and IP dst addresses")
                self.ruleconstructor.createMatchRule(None,hw_dst,None,ip_dst,None)
            else:
                print("Rule checks for src and dst addresses")
                self.ruleconstructor.createMatchRule(self.mymac,hw_dst,self.myip,ip_dst,None)

        elif routingOption==2:
            #use correct IP

            ip_src = self.tools.randIP(self.myip)
            ip_dst = self.tools.randIP(self.myip)
            #get first non null number of IP address and use as nounce
            nounce = ip_src.split(".")
            for n in nounce:
                intn = self.tools.keyFormula(n,10)
                if intn!=0:
                    break

            hw_src = self.tools.nounceMAC(self.mymac,intn)
            hw_dst = probeMAC

            #send ping request
            ether = Ether(src=hw_src, dst=hw_dst)
            ip = IP(src=ip_src, dst=ip_dst, id=9)
            icmp = ICMP(type = 8, code = 0)
            icmp_pkt = ether/ip/icmp

            sendp(icmp_pkt, verbose=0)
            time.sleep(responseTimeout)

            if ip_src in self.mem.seenIPs:
                self.mem.seenIPs.remove(ip_src)
                print("Rule checks only for dst MAC")
                self.ruleconstructor.createMatchRule(None,hw_dst,None,None,None)
            else:
                print("Rule checks for src and dst MACs")
                self.ruleconstructor.createMatchRule(self.mymac,hw_dst,None,None,None)

        elif routingOption==3:
            #use correct IP
            hw_src = self.tools.randMAC(self.mymac)
            hw_dst = self.tools.randMAC(self.mymac)

            #get first non null number of mac address and use as nounce
            nounce = hw_src.split(":")
            for n in nounce:
                intn = self.tools.keyFormula(n,16)
                if intn!=0:
                    break
            #print("Nounce " + str(intn))
            #print("Nounce IP " + self.tools.nounceIP(self.myip,intn))

            ip_src = self.tools.nounceIP(self.myip,intn)  #adjust IP address in a way that it is different but receiver can reconstruct the known one
            ip_dst = probeIP

            #send ping request
            ether = Ether(src=hw_src, dst=hw_dst)
            ip = IP(src=ip_src, dst=ip_dst, id=7)
            icmp = ICMP(type = 8, code = 0)
            icmp_pkt = ether/ip/icmp

            sendp(icmp_pkt, verbose=0)
            time.sleep(responseTimeout)

            if hw_src in self.mem.seenMacs:
                self.mem.seenMacs.remove(hw_src)
                print("Rule checks only for dst IP")
                self.ruleconstructor.createMatchRule(None,None,None,ip_dst,None)
            else:
                print("Rule checks for src and dst IP")
                self.ruleconstructor.createMatchRule(None,None,self.myip,ip_dst,None)

            '''