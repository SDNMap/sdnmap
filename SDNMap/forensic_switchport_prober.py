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
import copy
from network_map import network_map

class forensic_switchport_prober(object):

    def __init__(self,ip,mac):
        self.myip=ip
        self.mymac=mac
        self.tools=tools()
        self.mem=memory()
        self.ruleconstructor=ruleconstructor()
        self.recv_target=None
        self.sent_target=None
        self.network=network()
        self.network_map=network_map(ip,mac)
        #print("SwitchPort Prober initialized at... " + str(self.myip) + " - " + str(self.mymac))

    #evaluate if ingress port in used as a matching rule
    def checkForIngressPort(self,probeIP1,probeMAC1,probeIP2,probeMAC2,responseTimeout):
        self.mem.getARPIPReq().clear()
        hw_src = probeMAC1
        hw_dst = probeMAC2
        ip_src = probeIP1
        ip_dst = probeIP2

        #send out ping frequest
        #listen for ARP requests
        print("Sending Ping request from " + str(ip_src) + " / " + str(hw_src) + " to " + str(ip_dst) + " / " + str(hw_dst))
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        icmp = ICMP(type = 8, code = 0)
        icmp_pkt = ether/ip/icmp
        sendp(icmp_pkt, verbose=0)
        time.sleep(responseTimeout+5)

        portCheck=1

        #check if an ARP request was received
        if self.mem.getARPIPReq().has_key(probeIP1):
            portCheck=0
            print("Received ARP request for " + str(probeIP1) + " --> ingress port is not checked")
            return portCheck

        #spoof ARP table
        arp_spoof = self.spoofARP(ip_src,self.mymac,hw_dst,ip_dst)
        sendp(arp_spoof, verbose=0)
        time.sleep(responseTimeout)

        #In RFC 1122 http://www.ietf.org/rfc/rfc1122.txt it is specified at 2.3.2.1 (2) that to validate and ARP cache entry a unicast poll is sent to the specified address and if after N successive polls
        #(N is typically 2) no reply message is received, the ARP cache entry will be deleted
        #The timeout for ARP cache entries is typically 60 seconds as specified in RFC 5227
        timeout=65
        print("Waiting for " + str(timeout) + " seconds to make ARP entries timeout at " + str(ip_dst))
        time.sleep(timeout)

        #send out ping frequest
        #listen for ARP requests
        print("Sending Ping request from " + str(ip_src) + " / " + str(hw_src) + " to " + str(ip_dst) + " / " + str(hw_dst))
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        icmp = ICMP(type = 8, code = 0)
        icmp_pkt = ether/ip/icmp
        sendp(icmp_pkt, verbose=0)
        time.sleep(responseTimeout+5)

        #check if an ARP request was received
        if self.mem.getARPIPReq().has_key(probeIP1):
            portCheck=0
            print("Received ARP request for " + str(probeIP1) + " --> ingress port is not checked")
            return portCheck

        if portCheck==1:
            print("The performed probing tests suggest that flow rules are matching for a hosts ingress port")

        return portCheck


    def spoofARP(self,spoofIP,spoofMAC,dstMAC,dstIP):
        print("Spoof ARP cache at " + str(dstIP) + " from " + str(spoofIP) + " to " + str(spoofMAC))
        ether1 = Ether(src=spoofMAC, dst=dstMAC)
        arp1 = ARP(op="is-at", hwsrc=spoofMAC, hwdst=dstMAC, psrc=spoofIP, pdst=dstIP)
        arppkt = ether1/arp1
        return arppkt

    def ingressPortCheckL3(self):
        responseTimeout=2

        print("--- Search for 2 hosts we can connect to and which also can connect to each other ---")
        print("")
        hosts = self.network_map.getNeighbor()

        #find 2 IP address we can connect to and which also can connect to each other
        portCheckIP1=None
        portCheckMAC1=None
        portCheckIP2=None
        portCheckMAC2=None

        for key in hosts.keys():
            if portCheckIP2==None:
                probeIP = key
                probeMAC = hosts[key].mac
                portCheckIP1 = probeIP
                portCheckMAC1 = probeMAC

                addr = self.network_map.getNeighbor_Neighbor(key)

                for nextIP in hosts.keys():
                    if key!=nextIP and portCheckIP2==None:
                        for neighbor in addr:
                            if nextIP==neighbor.ip:
                                portCheckIP2 = nextIP
                                portCheckMAC2 = hosts[nextIP].mac
                                break

        if portCheckIP2!=None:
            print("Using " + str(portCheckIP1) + " - " + str(portCheckMAC1) + " and " + str(portCheckIP2) + " - " + str(portCheckMAC2) + " to evaluate switch port check")
            portCheck=self.checkForIngressPort(portCheckIP1,portCheckMAC1,portCheckIP2,portCheckMAC2,responseTimeout)
        else:
            portCheck = 1
            print("No hosts found that match the requirement!")

        return portCheck


    def ingressPortCheckL2(self):
        hosts = self.network_map.getNeighbor()

        if len(hosts)<=1:
            return -1
        print("Selecting two hosts to use for probing...")
        port_check=1
        responseTimeout=2
        for srckey in hosts.keys():
            ip_src = srckey
            hw_src = hosts[srckey].mac
            for dstkey in hosts.keys():
                ip_dst = dstkey
                hw_dst = hosts[dstkey].mac

                if ip_src!=ip_dst:
                    port_check=self.checkForIngressPort(ip_src,hw_src,ip_dst,hw_dst,responseTimeout)
                    if port_check==0:
                        return port_check
        return port_check


    def ingressPortCheckL2_Old(self):
        hosts = self.network_map.getNeighbor()

        cacheTimeout=65

        for srckey in hosts.keys():
            ip_src = srckey
            hw_src = hosts[srckey].mac
            for dstkey in hosts.keys():
                ip_dst = dstkey
                hw_dst = hosts[dstkey].mac

                if ip_src!=ip_dst:
                    print("Sending Ping request from " + str(ip_src) + " / " + str(hw_src) + " to " + str(ip_dst) + " / " + str(hw_dst))
                    #send ping request
                    ether = Ether(src=hw_src, dst=hw_dst)
                    ip = IP(src=ip_src, dst=ip_dst)
                    icmp = ICMP(type = 8, code = 0)

                    icmp_pkt = ether/ip/icmp
                    sendp(icmp_pkt, verbose=0)

                    #--> if ARP broadcast received --> port is not checked
                    if self.mem.getARPIPReq().has_key(ip_src):
                        print("ARP request received from " + str(ip_src) + " --> ingress port is not checked")
                        self.mem.getARPIPReq().clear()
                        return 0

                    print("Waiting " + str(cacheTimeout) + " seconds until ARP entry for " + str(ip_src) + " times out at " + str(ip_dst))
                    time.sleep(cacheTimeout)

                    spoof_arp = self.spoofARP(ip_src,self.mymac,hw_dst,ip_dst)
                    sendp(spoof_arp, verbose=0)
                    print("Waiting " + str(cacheTimeout) + " seconds until ARP entry for " + str(ip_src) + " times out at " + str(ip_dst))
                    time.sleep(cacheTimeout)

                    print("Sending Ping request from " + str(ip_src) + " / " + str(hw_src) + " to " + str(ip_dst) + " / " + str(hw_dst))
                    #send ping request
                    ether = Ether(src=hw_src, dst=hw_dst)
                    ip = IP(src=ip_src, dst=ip_dst)
                    icmp = ICMP(type = 8, code = 0)

                    icmp_pkt = ether/ip/icmp
                    sendp(icmp_pkt, verbose=0)

                    #--> if ARP assertion received --> port is not checked
                    if self.mem.getARPIPReq().has_key(ip_src):
                        print("ARP request received from " + str(ip_src) + " --> ingress port is not checked")
                        self.mem.getARPIPReq().clear()
                        return 0

                    print("Waiting " + str(cacheTimeout) + " seconds until ARP entry for " + str(ip_src) + " times out at " + str(ip_dst))
                    time.sleep(cacheTimeout)

                    print("Sending Ping request from " + str(ip_src) + " / " + str(hw_src) + " to " + str(ip_dst) + " / " + str(hw_dst))
                    #send ping request
                    ether = Ether(src=hw_src, dst=hw_dst)
                    ip = IP(src=ip_src, dst=ip_dst)
                    icmp = ICMP(type = 8, code = 0)

                    icmp_pkt = ether/ip/icmp
                    sendp(icmp_pkt, verbose=0)

                    #--> if ARP broadcast received --> port is not checked
                    if self.mem.getARPIPReq().has_key(ip_src):
                        print("ARP request received from " + str(ip_src) + " --> ingress port is not checked")
                        self.mem.getARPIPReq().clear()
                        return 0
        #Otherwise assume that ingress port is checked
        return 1

