__author__ = 'mininet'


import random
import math
from Node import Node
from network import network
from memory import memory
from network_map import network_map

class tools(object):

    def __init__(self):
        self.network=network()
        self.mem=memory()

    def randMAC(self,mymac):
        found=1
        while found==1:
            s1=str(mymac).split(":")[0]
            s2=str(mymac).split(":")[1]
            s3=str(mymac).split(":")[2]

            #s1=hex(random.randint(0,255))[2:].zfill(2)
            #s2=hex(random.randint(0,255))[2:].zfill(2)
            #s3=hex(random.randint(0,255))[2:].zfill(2)
            s4=hex(random.randint(0,255))[2:].zfill(2)
            s5=hex(random.randint(0,255))[2:].zfill(2)
            s6=hex(random.randint(0,255))[2:].zfill(2)
            mac = str(s1) + ":" + str(s2) + ":" + str(s3) + ":" + str(s4) + ":" + str(s5) + ":" + str(s6)
            if mac!=mymac:
                found=2
        return mac

    def randIP(self,myip):
        found=1
        while found==1:
            s1=random.randint(0,255)
            s2=random.randint(0,255)
            s3=random.randint(0,255)
            s4=random.randint(0,255)
            ip = str(s1) + "." + str(s2) + "." + str(s3) + "." + str(s4)
            if ip!=myip and ip not in network_map.network.keys():
                found=2
        return ip

    def specNode(self,myip,i):
            return self.network.getNode(i,myip)


    def nounceIP(self,myip,n):
        s1=int(myip.split(".")[0]) + n
        s2=int(myip.split(".")[1]) + n
        s3=int(myip.split(".")[2]) + n
        s4=int(myip.split(".")[3]) + n
        ip = str(s1) + "." + str(s2) + "." + str(s3) + "." + str(s4)
        return ip

    def reconNounceIP(self,ip,n):
        s1=int(ip.split(".")[0]) - n
        s2=int(ip.split(".")[1]) - n
        s3=int(ip.split(".")[2]) - n
        s4=int(ip.split(".")[3]) - n
        ip = str(s1) + "." + str(s2) + "." + str(s3) + "." + str(s4)
        return ip

    def nounceMAC(self,mymac,n):
        s1=hex(int(mymac.split(":")[0],16) + n)[2:].zfill(2)
        s2=hex(int(mymac.split(":")[1],16) + n)[2:].zfill(2)
        s3=hex(int(mymac.split(":")[2],16) + n)[2:].zfill(2)
        s4=hex(int(mymac.split(":")[3],16) + n)[2:].zfill(2)
        s5=hex(int(mymac.split(":")[4],16) + n)[2:].zfill(2)
        s6=hex(int(mymac.split(":")[5],16) + n)[2:].zfill(2)
        mac = str(s1) + ":" + str(s2) + ":" + str(s3) + ":" + str(s4) + ":" + str(s5) + ":" + str(s6)
        return mac

    def reconNounceMAC(self,mac,n):
        s1=hex(int(mac.split(":")[0],16) - n)[2:].zfill(2)
        s2=hex(int(mac.split(":")[1],16) - n)[2:].zfill(2)
        s3=hex(int(mac.split(":")[2],16) - n)[2:].zfill(2)
        s4=hex(int(mac.split(":")[3],16) - n)[2:].zfill(2)
        s5=hex(int(mac.split(":")[4],16) - n)[2:].zfill(2)
        s6=hex(int(mac.split(":")[5],16) - n)[2:].zfill(2)
        mac = str(s1) + ":" + str(s2) + ":" + str(s3) + ":" + str(s4) + ":" + str(s5) + ":" + str(s6)
        return mac

    def keyFormula(self,n,b):
        return int(n,b)%10+1

    def encodeMAC(self,mac):
        s1=math.pow(2,40)*int(mac.split(":")[0],16)
        s2=math.pow(2,32)*int(mac.split(":")[1],16)
        s3=math.pow(2,24)*int(mac.split(":")[2],16)
        s4=math.pow(2,16)*int(mac.split(":")[3],16)
        s5=math.pow(2,8)*int(mac.split(":")[4],16)
        s6=int(mac.split(":")[5],16)
        mac = int(s1 + s2 + s3 + s4 + s5 + s6)
        return mac

    def decodeMAC(self,mac):
        s1=int(mac/math.pow(2,40))
        s2=int((mac-s1*math.pow(2,40))/math.pow(2,32))
        s3=int((mac-s1*math.pow(2,40)-s2*math.pow(2,32))/math.pow(2,24))
        s4=int((mac-s1*math.pow(2,40)-s2*math.pow(2,32)-s3*math.pow(2,24))/math.pow(2,16))
        s5=int((mac-s1*math.pow(2,40)-s2*math.pow(2,32)-s3*math.pow(2,24)-s4*math.pow(2,16))/math.pow(2,8))
        s6=int(mac-s1*math.pow(2,40)-s2*math.pow(2,32)-s3*math.pow(2,24)-s4*math.pow(2,16)-s5*math.pow(2,8))
        mac = str(hex(s1)[2:].zfill(2)) + ":" + str(hex(s2)[2:].zfill(2)) + ":" + str(hex(s3)[2:].zfill(2)) + ":" + str(hex(s4)[2:].zfill(2)) + ":" + str(hex(s5)[2:].zfill(2)) + ":" + str(hex(s6)[2:].zfill(2))
        return mac

    def encodeIP(self,ip):
        s1=math.pow(2,24)*int(ip.split(".")[0],10)
        s2=math.pow(2,16)*int(ip.split(".")[1],10)
        s3=math.pow(2,8)*int(ip.split(".")[2],10)
        s4=int(ip.split(".")[3],10)
        ip = int(s1 + s2 + s3 + s4)
        return ip

    def decodeIP(self,ip):
        s1=int(ip/math.pow(2,24))
        s2=int((ip-s1*math.pow(2,24))/math.pow(2,16))
        s3=int((ip-s1*math.pow(2,24)-s2*math.pow(2,16))/math.pow(2,8))
        s4=(int(ip-s1*math.pow(2,24)-s2*math.pow(2,16)-s3*math.pow(2,8)))
        ip = str(s1) + "." + str(s2) + "." + str(s3) + "." + str(s4)
        return ip


    def decodeResponseAddresses(self,code):
        addr=code.split("#")
        src_ip=self.decodeIP(int(addr[0],10))
        src_mac=self.decodeMAC(int(addr[1],10))
        dst_ip=self.decodeIP(int(addr[2],10))
        dst_mac=self.decodeMAC(int(addr[3],10))
        return (src_ip + "," + src_mac + "," + dst_ip + "," + dst_mac)

    def createNonce(self,nonce,testOption,src_ip,src_mac,dst_ip,dst_mac,padlen):
        if nonce==None:
            nonce = random.randint(10000,99999)
        enc_src_ip = self.encodeIP(src_ip)
        enc_src_mac = self.encodeMAC(src_mac)
        enc_dst_ip = self.encodeIP(dst_ip)
        enc_dst_mac = self.encodeMAC(dst_mac)

        raw= "#" + str(nonce) + "#" + str(testOption) + "#" + str(enc_src_ip) + "%" + str(enc_src_mac) + "%" + str(enc_dst_ip) + "%" + str(enc_dst_mac) + "%";
        i=1
        while len(raw) < padlen:
            raw=raw+str(i)
            i=i+1
            if i==10:
                i=1
        return raw

    def getDiffIP(self,myIP):
        p1 = str(myIP).split(".")[0]
        p2 = str(myIP).split(".")[1]
        p3 = str(myIP).split(".")[2]
        p4 = str(myIP).split(".")[3]

        p4_new = int(p4) + random.randint(10,255)
        if p4_new>255:
            p4_new=255
        new_ip = p1 + "." + p2 + "." + p3 + "." + str(p4_new)
        self.mem.getFakeIPs().append(new_ip)
        return new_ip


    def createTimeNonce(self,nonce,padlen):
        if nonce==None:
            nonce = random.randint(10000,99999)
            import time
            ts = time.time()
            import datetime
            nonce = datetime.datetime.fromtimestamp(ts).strftime('%d%H%M%S%s')

        raw= "#" + str(nonce) + "#"
        i=1
        while len(raw) < padlen:
            raw=raw+str(i)
            i=i+1
            if i==10:
                i=1
        return raw