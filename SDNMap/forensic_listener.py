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
import time
import datetime


class forensic_listener(object):

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
        sniff(prn=self.readPkts)


    def pingReplyRecv(self,pkt):
        self.mem.getRecvICMPReplies()[pkt[0][IP].dst] = pkt[0][IP].dst
        if pkt[0].haslayer(Raw):
            if str(pkt[0][Raw]).split("#")!=0:
                #print("Ping reply " + str(pkt[0][Raw]))
                if len(str(pkt[0][Raw]).split("#"))!=0:
                    try:
                        nonce=int(str(pkt[0][Raw]).split("#")[1],10)
                        self.mem.getNonces()[nonce] = nonce #store sent nonce in memory
                    except:
                        test=1

    def arpRecv(self,pkt):
        if pkt[0].haslayer(ARP): #and pkt[0][ARP].op=="who-has":
            #pkt[0].show2()
            if pkt[0][ARP].op==1: #ARP request
                req_ip_addr = pkt[0][ARP].pdst
                #check if host scan is performed
                if self.mem.isMapping()==1:
                    ts = time.time()
                    timestamp = datetime.datetime.fromtimestamp(ts).strftime('%H%M%S%s')
                    if self.mem.getARPScan().has_key(req_ip_addr):
                        self.mem.getARPScan()[req_ip_addr].append(timestamp)
                        #print("Store " + str(req_ip_addr) + " at " + str(timestamp))
                    else:
                        self.mem.getARPScan()[req_ip_addr] = []
                        self.mem.getARPScan()[req_ip_addr].append(timestamp)
                        #print("Store " + str(req_ip_addr) + " at " + str(timestamp))
                else:
                    self.mem.getARPIPReq()[req_ip_addr] = req_ip_addr
            elif pkt[0][ARP].op==2: #ARP reply
                recv_ip_addr = pkt[0][ARP].psrc
                recv_mac_addr = pkt[0][ARP].hwsrc
                #print("ARP ip " + str(recv_ip_addr) + " mac " + str(recv_mac_addr))
                #ARP reply host received
                if self.mem.isMapping()==1:
                    self.mem.getRecvARPReplies()[recv_ip_addr] = recv_mac_addr


    def icmppnrRecv(self,pkt):
        self.mem.getrecvICMP_PNR().append(pkt)

    def tcpRecv(self,pkt):
        if pkt[0].haslayer(TCP):
            if pkt[0][TCP].flags==20: #check for RST and ACK flags
                ip_dst = pkt[0][IP].dst
                self.mem.getSeenTCP_Pktsself()[ip_dst] = pkt[0]

    def readPkts(self,pkt):

        if pkt[0].haslayer(ARP):
            self.arpRecv(pkt)
        if pkt[0].haslayer(TCP):
            self.tcpRecv(pkt)
        if pkt[0].haslayer(IP):    # and (pkt[0][IP].dst==self.myip or pkt[0][Ether].dst==self.mymac)
            if pkt[0].haslayer(ICMP):
                #receive ping request
                #if pkt[0][ICMP].type==8:
                #    self.pingResponseRecv(pkt)
                #receive ping response
                if pkt[0][ICMP].type==0:
                    self.pingReplyRecv(pkt)
                #receive ICMP port unreachable error
                if pkt[0][ICMP].type==3 and pkt[0][ICMP].code==3:
                    self.icmppnrRecv(pkt)