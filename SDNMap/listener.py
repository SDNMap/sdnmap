__author__ = 'mininet'

from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.dhcp import *
from scapy.layers.dns import *
from tools import tools
from memory import memory
from Target import Target
import socket
import thread


class listener(object):

    def __init__(self,ip,mac):
        self.myip=ip
        self.mymac=mac
        self.tools=tools()
        self.mem=memory()
        #print("Listener initialized at... " + str(self.myip) + " - " + str(self.mymac))

    def listen(self):
        #self.sniffing()
        thread.start_new_thread(self.sniffing,())


    def sniffing(self):
        #print("Start sniffing packets...")
        sniff(filter="icmp", prn=self.readPkts)

    def pingResponseRecv(self,pkt):
        hw_src = pkt[0][Ether].src
        hw_dst = pkt[0][Ether].dst
        ip_src = pkt[0][IP].src
        ip_dst = pkt[0][IP].dst
        icmp = pkt[0]
        icmp[ICMP].type = 0
        icmp[ICMP].code = 0
        if pkt[0].haslayer(Raw):
            if str(pkt[0][Raw]).split("#")!=0:
                #print(str(pkt[0][Raw]))
                if len(str(pkt[0][Raw]).split("#"))!=0:
                    nonce=int(str(pkt[0][Raw]).split("#")[1],10)
                    option=int(str(pkt[0][Raw]).split("#")[2],10)
                    ip = self.tools.decodeIP(int(str(pkt[0][Raw]).split("#")[3].split("%")[0],10)) #ip
                    mac = self.tools.decodeMAC(int(str(pkt[0][Raw]).split("#")[3].split("%")[1],10)) #mac

                    recv_dst_ip = icmp[IP].dst
                    recv_src_ip = icmp[IP].src
                    recv_dst_mac = icmp[Ether].dst
                    recv_src_mac = icmp[Ether].src

                    #create new packet raw data
                    icmp[Raw]=self.tools.createNonce(nonce,option,recv_src_ip,recv_src_mac,recv_dst_ip,recv_dst_mac,56)

                    #set real IP and MAC and send back

                    '''
                    icmp[IP].src = self.myip
                    icmp[Ether].src = self.mymac
                    icmp[IP].dst = ip
                    icmp[Ether].dst = mac
                    '''
                    icmp[IP].src = ip_dst
                    icmp[Ether].src = hw_dst
                    icmp[IP].dst = ip_src
                    icmp[Ether].dst = hw_src

                    if option==6:
                        icmp[IP].dst = ip
                    if option==5:
                        icmp[Ether].dst = mac
                    if option==4:
                        icmp[IP].dst = ip
                        icmp[Ether].dst = mac

                    #print("Nonce " + str(nonce) + " ip " + ip + " mac " + mac)
                    #self.tools.decodeARPTable(str(pkt[0][Raw]),ip_src)
                    #print("Send icmp response to " + str(ip_src))
                    if nonce>10000 and nonce<99999:
                        #print("Send icmp response to " + str(ip_src))
                        sendp(icmp,verbose=0)

    def pingReplyRecv(self,pkt):
        if pkt[0].haslayer(Raw):
            if str(pkt[0][Raw]).split("#")!=0:
                #print(str(pkt[0][Raw]))
                if len(str(pkt[0][Raw]).split("#"))!=0:
                    nonce=int(str(pkt[0][Raw]).split("#")[1],10)
                    recv_src_ip = self.tools.decodeIP(int(str(pkt[0][Raw]).split("#")[3].split("%")[0],10)) #ip src
                    recv_src_mac = self.tools.decodeMAC(int(str(pkt[0][Raw]).split("#")[3].split("%")[1],10)) #mac src
                    recv_dst_ip = self.tools.decodeIP(int(str(pkt[0][Raw]).split("#")[3].split("%")[2],10)) #ip dst
                    recv_dst_mac = self.tools.decodeMAC(int(str(pkt[0][Raw]).split("#")[3].split("%")[3],10)) #mac dst

                    self.mem.getNonces()[nonce] = Target(nonce,recv_src_ip,recv_src_mac,recv_dst_ip,recv_dst_mac) #store sent nonce in memory

                #self.tools.decodeARPTable(str(pkt[0][Raw]),ip_src)
                #print("Send icmp response to " + str(ip_src))
                #if challange>10000 and challange<99999:



    def readPkts(self,pkt):
        #print("packet received...")
        if pkt[0].haslayer(IP) and (pkt[0][IP].dst==self.myip or pkt[0][Ether].dst==self.mymac):
            ip_pkt = pkt[0][IP]
            eth_pkt = pkt[0][Ether]
            if pkt[0].haslayer(ICMP):
                #if pkt[0].haslayer(Raw):
                #    print(str(pkt[0][Raw]))
                #print("received ICMP packet from " + str(eth_pkt.src) + " to " + str(eth_pkt.dst) + " - " + str(ip_pkt.src) + " to " + str(ip_pkt.dst) + " id " + str(ip_pkt.id))

                #send ping response
                if pkt[0][ICMP].type==8:
                    self.pingResponseRecv(pkt)

                #receive ping response
                if pkt[0][ICMP].type==0:
                    self.pingReplyRecv(pkt)

                #answer to a ping packet with fake mac and fake src IP addresses
                if pkt[0][ICMP].type==8 and pkt[0][IP].id==7:

                    #get first non null number of mac address
                    hw_src = pkt[0][Ether].src
                    hw_dst = pkt[0][Ether].dst

                    nounce = hw_src.split(":")
                    for n in nounce:
                        intn = self.tools.keyFormula(n,16)
                        if intn!=0:
                            break

                    #print("Received from IP " + str(pkt[0][IP].src))
                    ip_src = self.tools.reconNounceIP(pkt[0][IP].src,intn)
                    #print("Reconstructed IP to " + str(ip_src))
                    ip_dst = pkt[0][IP].dst
                    icmp = pkt[0]
                    icmp[ICMP].type = 0
                    icmp[ICMP].code = 0
                    icmp[IP].src = ip_dst
                    icmp[IP].dst = ip_src
                    icmp[IP].id = 8
                    icmp[Ether].src = hw_dst
                    icmp[Ether].dst = hw_src
                    #print("Send icmp response to " + str(ip_src))
                    sendp(icmp,verbose=0)

                #get ping response from a ping request with fake MAC and fake src IP addresses
                if pkt[0][IP].id==8:
                    #assume reply from ping to check for dst IP address rule only
                    hw_src = pkt[0][Ether].src
                    hw_dst = pkt[0][Ether].dst

                    self.mem.seenMacs.append(hw_dst)

                #answer ping request for a packet with fake IP addresses and fake MAC src addresses
                if pkt[0][ICMP].type==8 and pkt[0][IP].id==9:

                    #get first non null number of IP address
                    ip_dst = pkt[0][IP].dst
                    ip_src = pkt[0][IP].src

                    nounce = ip_src.split(".")
                    for n in nounce:
                        intn = self.tools.keyFormula(n,10)
                        if intn!=0:
                            break

                    #print("receiver IP nounce " + str(intn) + " - src ip " + str(ip_src) + " dst ip " + str(ip_dst) + " - src mac " + str(pkt[0][Ether].src) + " dst mac " + str(pkt[0][Ether].dst))
                    hw_src = self.tools.reconNounceMAC(pkt[0][Ether].src, intn)
                    #print("reconstructed mac " + str(hw_src))
                    hw_dst = pkt[0][Ether].dst

                    icmp = pkt[0]
                    icmp[ICMP].type = 0
                    icmp[ICMP].code = 0
                    icmp[IP].src = ip_dst
                    icmp[IP].dst = ip_src
                    icmp[IP].id = 10
                    icmp[Ether].src = hw_dst
                    icmp[Ether].dst = hw_src
                    #print("Send icmp response to " + str(ip_src))
                    sendp(icmp,verbose=0)

                #get ping response from a ping request with fake IP and fake src MAC addresses
                if pkt[0][IP].id==10:
                    #assume reply from ping to check for dst MAC address rule only
                    ip_src = pkt[0][IP].src
                    ip_dst = pkt[0][IP].dst

                    self.mem.seenIPs.append(ip_dst)

                #answer ping request for a packet with fake src IP and fake src MAC addresses
                if pkt[0][ICMP].type==8 and pkt[0][IP].id==11:

                    #get first non null number of IP address
                    ip_dst = pkt[0][IP].dst
                    ip_src = self.tools.reconNounceIP(pkt[0][IP].src,pkt[0][IP].id)
                    hw_src = self.tools.reconNounceMAC(pkt[0][Ether].src,pkt[0][IP].id)
                    #print("reconstructed mac and ip " + str(hw_src) + " - " + str(ip_src))
                    hw_dst = pkt[0][Ether].dst

                    icmp = pkt[0]
                    icmp[ICMP].type = 0
                    icmp[ICMP].code = 0
                    icmp[IP].src = pkt[0][IP].src
                    icmp[IP].dst = ip_src
                    icmp[IP].id = 12
                    icmp[Ether].src = pkt[0][Ether].src
                    icmp[Ether].dst = hw_src
                    #print("Send icmp response to " + str(ip_src))
                    sendp(icmp,verbose=0)

                #get ping response from a ping request with fake src IP and fake src MAC addresses
                if pkt[0][IP].id==12:
                    #assume reply from ping to check for dst address rule only
                    ip_src = pkt[0][IP].src
                    hw_src = pkt[0][Ether].src

                    self.mem.seenIPs.append(ip_src)
                    self.mem.seenMacs.append(hw_src)

                if pkt[0][ICMP].type==8 and pkt[0][IP].id==111:

                    hw_src = pkt[0][Ether].src
                    hw_dst = pkt[0][Ether].dst
                    ip_src = pkt[0][IP].src
                    ip_dst = pkt[0][IP].dst

                    print("Send icmp response from " + str(ip_src) + " - " + str(ip_dst))

                    icmp = pkt[0]
                    icmp[ICMP].type = 0
                    icmp[ICMP].code = 0
                    icmp[IP].src = ip_dst
                    icmp[IP].dst = ip_src
                    icmp[Ether].src = hw_dst
                    icmp[Ether].dst = hw_src
                    #print("Send icmp response to " + str(ip_src))
                    sendp(icmp,verbose=0)

                #receive message from host that is not supposed to be contacted
                if pkt[0][ICMP].type==0 and pkt[0][IP].id==120:
                    if pkt[0].haslayer(Raw):
                        #print(str(pkt[0][Raw]))
                        addresses=self.tools.decodeResponseAddresses(str(pkt[0][Raw]))

                    #get decoded addresses and send answer back
                    hw_src = addresses.split(",")[1]
                    hw_dst = addresses.split(",")[3]
                    ip_src = addresses.split(",")[0]
                    ip_dst = addresses.split(",")[2]

                    print("Send icmp response from " + str(ip_src) + " - " + str(ip_dst))

                    icmp = pkt[0]
                    icmp[ICMP].type = 0
                    icmp[ICMP].code = 0
                    icmp[IP].src = ip_src
                    icmp[IP].dst = ip_dst
                    icmp[IP].id = 121
                    icmp[Ether].src = hw_src
                    icmp[Ether].dst = hw_dst
                    icmp[Raw] = str(self.tools.encodeIP(self.myip))
                    #print("Send icmp response to " + str(ip_src))
                    sendp(icmp,verbose=0)

                if pkt[0][ICMP].type==0 and pkt[0][IP].id==121:
                    if pkt[0].haslayer(Raw):
                        realSrc = self.tools.decodeIP(int(str(pkt[0][Raw])))
                        if realSrc!=self.myip:
                            print("Received reply from " + str(realSrc ))
                            self.mem.seenIPs.append(realSrc)