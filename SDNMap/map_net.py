__author__ = 'mininet'

from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.dhcp import *
from scapy.layers.dns import *
from tools import tools
from memory import memory
from ruleconstructor import ruleconstructor
from network_map import network_map
from Node import Node
import time
from Target import Target
from network import network
import copy

class map_net(object):

    def __init__(self,ip,mac,mask):
        self.myip=ip
        self.mymac=mac
        self.mymask=mask
        self.tools=tools()
        self.mem=memory()
        self.network_map=network_map(ip,mac)
        #print("Network mapper initialized at... " + str(self.myip) + " - " + str(self.mymac))


    def IntToIP(self,num):
        s1=int(num/math.pow(2,24))
        s2=int((num-s1*math.pow(2,24))/math.pow(2,16))
        s3=int((num-s1*math.pow(2,24)-s2*math.pow(2,16))/math.pow(2,8))
        s4=(int(num-s1*math.pow(2,24)-s2*math.pow(2,16)-s3*math.pow(2,8)))
        ip = str(s1) + "." + str(s2) + "." + str(s3) + "." + str(s4)
        return ip

    def IPtoInt(self,ip):
        s1=math.pow(2,24)*int(ip.split(".")[0],10)
        s2=math.pow(2,16)*int(ip.split(".")[1],10)
        s3=math.pow(2,8)*int(ip.split(".")[2],10)
        s4=int(ip.split(".")[3],10)
        ip = int(s1 + s2 + s3 + s4)
        return ip

    #perform ARP scan to find all your neighbors
    def ARPScan(self,responseTimeout,prefix,mynetwork):
        self.mem.setMapping(1)
        my_ip_addr = self.myip.split(".")

        space = self.IPtoInt("255.255.255.255") - self.IPtoInt(self.mymask)
        size = int(math.pow(2,(32 - prefix)))
        lowerIPSpace = self.IPtoInt(mynetwork)
        if lowerIPSpace<0:
            lowerIPSpace=0
        upperIPSpace = lowerIPSpace + size
        if upperIPSpace>(space+lowerIPSpace):
            upperIPSpace=space+lowerIPSpace

        print("Performing ARP scan... ")
        for i in range(lowerIPSpace,upperIPSpace):
            ip_src = self.IntToIP(i)
            if str(self.myip)!=ip_src:
                print("Sending ARP request to " + str(ip_src))
                ether = Ether(src=self.mymac, dst="ff:ff:ff:ff:ff:ff")
                arp = ARP(op="who-has", hwsrc=self.mymac, hwdst="00:00:00:00:00:00", psrc=self.myip, pdst=ip_src)
                arppkt = ether/arp
                sendp(arppkt, verbose=0)
        time.sleep(responseTimeout)

        ARPsReplies = copy.copy(self.mem.getRecvARPReplies())
        print(str(self.myip) + " / " + str(self.mymac) + " received response from the following hosts: ")
        for key in ARPsReplies.keys():
            print(str(key) + " / " + ARPsReplies[key])

        self.mem.setMapping(0)

        return ARPsReplies

    #probe neighbor ARP cache to find connected host
    def probeNeighborARPCache(self,probeIP,probeMAC,responseTimeout,prefix,mynetwork):
        self.mem.setMapping(1)
        my_ip_addr = self.myip.split(".")

        space = self.IPtoInt("255.255.255.255") - self.IPtoInt(self.mymask)
        size = int(math.pow(2,(32 - prefix)))
        lowerIPSpace = self.IPtoInt(mynetwork)
        if lowerIPSpace<0:
            lowerIPSpace=0
        upperIPSpace = lowerIPSpace + size
        if upperIPSpace>(space+lowerIPSpace):
            upperIPSpace=space+lowerIPSpace

        #perform a ping sweep on your neighbor
        print("Performing ping sweep to " + str(probeIP) + "...")
        for i in range(lowerIPSpace,upperIPSpace):
            ip_src = self.IntToIP(i)
            if str(self.myip)!=ip_src and ip_src!=str(probeIP):
                hw_src = self.mymac
                hw_dst = probeMAC
                #ip_src = str(self.myip.split(".")[0]) + "." + str(self.myip.split(".")[1]) + "." + str(self.myip.split(".")[2]) + "." + str(i)
                ip_dst = probeIP

                #put probed IP address into memory to see how many responses will be received
                self.mem.getARPScan()[ip_src] = []

                #send ping request
                ether = Ether(src=hw_src, dst=hw_dst)
                ip = IP(src=ip_src, dst=ip_dst)
                icmp = ICMP(type = 8, code = 0)
                icmp_pkt = ether/ip/icmp
                sendp(icmp_pkt, verbose=0)
                #print("Check if host at " + str(ip_dst) + " - " + str(hw_dst) + " is reachable from " + str(ip_src) + " - " + str(hw_src))

        #wait for 2 seconds and begin analyzing ARP requests
        #wait for 4(-6) seconds since delay between probes is min 1 sec and max 2 sec as specified in RFC 5227 https://tools.ietf.org/html/rfc5227
        time.sleep(6)
        print("Ping sweep completed!")
        ARPs = copy.copy(self.mem.getARPScan())
        self.mem.getARPScan().clear()
        self.mem.setMapping(0)

        IPs=[]
        print(str(probeIP) + " can connect to:")
        for key in ARPs.keys():
            adr = ARPs.get(key)
            #by default, if less than 3 responses are received, it can be assumed that our neighbor received an ARP reply at some point
            #3 ARP requests are send as specified in RFC 5227 https://tools.ietf.org/html/rfc5227
            if len(adr)<3 and str(probeIP)!=str(key) and key not in self.mem.getFakeIPs():
                print(str(adr) + " - " + str(key))
                IPs.append(key)

        return IPs

    def mapHostsARP(self,prefix,mynetwork):
        responseTimeout=2

        print("------- ARP scan --------")
        hosts = self.ARPScan(responseTimeout,prefix,mynetwork)
        print("----------------------------")

        scansuccess=0

        for key in hosts.keys():
            probeIP = key
            probeMAC = hosts[key]
            scansuccess=1
            #add neighbors to network map
            self.network_map.addNeighbor(Node(probeIP,probeMAC,None))
        return scansuccess

    def mapHostsSweep(self,prefix,mynetwork):
        responseTimeout=2
        hosts = self.network_map.getNeighbor()

        for key in hosts.keys():
            probeIP = key
            probeMAC = hosts[key].mac

            #add neighbors to network map
            self.network_map.addNeighbor(Node(probeIP,probeMAC,None))

            print("------- Ping sweep to " + str(probeIP) + " --------")
            neighbors_n = self.probeNeighborARPCache(probeIP,probeMAC,responseTimeout,prefix,mynetwork)
            print("----------------------------")

            for nn in neighbors_n:
                nn_mac=None
                if hosts.has_key(nn):
                    nn_mac = hosts[nn].mac
                self.network_map.addNeighbor_Neighbor(key,Node(nn,nn_mac,None))

        self.network_map.printNetwork()


