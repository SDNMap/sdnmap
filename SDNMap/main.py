__author__ = 'Stefan'


from scapy.layers.dhcp import *
from scapy.layers.dns import *
from forensic_icmp_prober import forensic_icmp_prober
from forensic_tcp_prober import forensic_tcp_prober
from forensic_port_prober import forensic_port_prober
from forensic_listener import forensic_listener
from reconstr_actions import reconstr_actions
from forensic_protocol_prober import forensic_protocol_prober
from forensic_switchport_prober import forensic_switchport_prober
from network_map import network_map
from ruleconstructor import ruleconstructor
from map_net import map_net
from tools import tools
from memory import memory
from network import network
import socket
import fcntl
import struct
import os
import sys

tools=tools()
mem=memory()
network=network()

#get public IP address of host
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

#get MAC address of host
def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])

def getNetMask(iface):
    return socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM),35099, struct.pack('256s', iface))[20:24])


if(len(sys.argv)<5):
    print "Not enough arguments! \nEnter network to scan (e.g. 10.0.0.0/24), scanning protocol ['ICMP,TCP'], interface (e.g. eth0) and ports [80.443] (or [] for no ports)"
    sys.exit(0)


interface=""
for iface in os.listdir('/sys/class/net'):
    if "eth" in iface:
        interface=iface
interface=str(sys.argv[3])

MY_IP = get_ip_address(interface)
MY_MAC = getHwAddr(interface)
MY_MASK = getNetMask(interface)

forensic_listener = forensic_listener(MY_IP, MY_MAC)
forensic_listener.listen()

forensic_icmp_prober = forensic_icmp_prober(MY_IP, MY_MAC)
forensic_tcp_prober = forensic_tcp_prober(MY_IP, MY_MAC)
forensic_port_prober = forensic_port_prober(MY_IP, MY_MAC)
reconstr_actions = reconstr_actions(MY_IP,MY_MAC)
#timing_prober = timing_prober(MY_IP,MY_MAC)
forensic_protocol_prober = forensic_protocol_prober(MY_IP,MY_MAC)
forensic_switchport_prober = forensic_switchport_prober(MY_IP,MY_MAC)
map_net = map_net(MY_IP,MY_MAC,MY_MASK)
network_map=network_map(MY_IP,MY_MAC)

ruleconstructor=ruleconstructor()

#print 'Number of arguments:', len(sys.argv), 'arguments.'
#print str(sys.argv[1])
#print str(sys.argv[2])


#scan_net = str(raw_input("Enter network to scan (e.g. 10.0.0.0/24)"))
#scan_pro = str(raw_input("Enter scanning protocol ['ICMP,TCP']"))

scan_net = str(sys.argv[1])
scan_pro = str(sys.argv[2])
scan_ports  = str(sys.argv[4])

#while scan_pro!=str('ICMP') and scan_pro!=str('TCP'):
#    scan_pro = str(raw_input("Enter scanning protocol ['ICMP,TCP']"))

mynet=str(scan_net.split("/")[0])
prefix=int(scan_net.split("/")[1])

print("Scanning " + str(mynet) + " / " + str(prefix))

#delete old network map
network_map.getAllNeighbor_Neighbor().clear()
network_map.getNeighbor().clear()
ruleconstructor.clearRules()

#populate new network_map
scansuccess=map_net.mapHostsARP(prefix,mynet)

if scansuccess==1:
    ruleconstructor.addARPFlood()

    #print("--- Check if network is a SDN network ---")
    #timing_prober.determineIfSDN(tIP,tMAC)
    reachable=0

    results=[]

    #print select neighbor node for detailed probing
    for key in network_map.getNeighbor().keys():
        n = network_map.getNeighbor()[key]

        #reset all values
        hw_src=None
        hw_dst=None
        ip_src=None
        ip_dst=None
        orig_srcIP=None
        recv_srcIP=None
        orig_dstIP=None
        recv_dstIP=None
        icmp=None
        tcp=None
        udp=None
        reachable=0
        reactive=0
        tMAC=None
        tIP=None

        print("Use " + str(n.ip) + " / " + str(n.mac) + " for probing")
        tMAC = n.mac
        tIP = n.ip

        #determine allowed ports
        ports = scan_ports.split("[")[1].split("]")[0]
        scanPorts=[]
        reachableSrcPorts_tcp=[]
        reachableDstPorts_tcp=[]
        reachableSrcPorts_udp=[]
        reachableDstPorts_udp=[]

        if len(ports.split(",")) >0:
            for p in ports.split(","):
                if p != "":
                    scanPorts.append(int(p))
            if len(scanPorts)!=0:
                [reachableSrcPorts_tcp,reachableDstPorts_tcp,reachableSrcPorts_udp,reachableDstPorts_udp]=forensic_port_prober.determinePorts(tIP,tMAC,scanPorts)

        if len(reachableSrcPorts_tcp)>0 and len(reachableDstPorts_tcp)>0:
                srcPort = reachableSrcPorts_tcp[0]
                dstPort = reachableDstPorts_tcp[0]
        elif len(reachableSrcPorts_udp)>0 and len(reachableDstPorts_udp)>0:
                srcPort = reachableSrcPorts_udp[0]
                dstPort = reachableDstPorts_udp[0]
        else:
            srcPort = random.randint(61000,65000)
            dstPort = random.randint(36000,37000)
            reachableSrcPorts_udp.append(srcPort)
            reachableDstPorts_udp.append(dstPort)
            reachableSrcPorts_tcp.append(srcPort)
            reachableDstPorts_tcp.append(dstPort)

        print("--- Determine enforced protocols ---")
        [tcp,icmp,udp] = forensic_protocol_prober.determineProtocol(tIP, tMAC, srcPort, dstPort)

        routing=0
        actions=0

        if icmp==0:
            print("User selected ICMP as scanning protocol, which is not allowed, therefore switching to TCP\n")
            scan_pro='TCP'

        if tcp==0:
            print("User selected TCP as scanning protocol, which is not allowed, therefore switching to ICMP\n")
            scan_pro='ICMP'

        if udp==1:
            print("")
            print("--- Determine if IP addresses are rewritten ---")
            [orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP]=reconstr_actions.reconstrAction(tIP,tMAC,scanPorts)

        if 'ICMP' in scan_pro:  #icmp==1:
            print("--- Determine which L2/L3 fields are enforced using ICMP ---")
            [ip_src,ip_dst,hw_src,hw_dst,reachable,reactive]=forensic_icmp_prober.determineRouting(tIP, tMAC)

        elif 'TCP' in scan_pro: #tcp==1:
            print("--- Determine which L2/L3 fields are enforced using TCP ---")
            [ip_src,ip_dst,hw_src,hw_dst,reachable,reactive]=forensic_tcp_prober.determineTCPRouting(tIP, tMAC, srcPort, dstPort)

        results.append([hw_src,hw_dst,ip_src,ip_dst,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP,icmp,tcp,udp,reachable,reactive,tMAC,tIP,reachableSrcPorts_tcp,reachableDstPorts_tcp,reachableSrcPorts_udp,reachableDstPorts_udp])
        #print([hw_src,hw_dst,ip_src,ip_dst,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP,icmp,tcp,udp,reachable,reactive,tMAC,tIP])
        #else:
            #print("No implemented protocols are supported!")

    port_check=0
    '''
    for res in results:
        [hw_src,hw_dst,ip_src,ip_dst,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP,icmp,tcp,udp,reachable,reactive,tMAC,tIP]=res
        if reachable==1:
            if ip_src==None and reactive==False:
                map_net.mapHostsSweep(prefix,mynet)
                print("")
                print("--- Determine if ingress port is enforced ---")
                port_check=forensic_switchport_prober.ingressPortCheckL3()
                po_checked=1
                break
    '''

    [hw_src,hw_dst,ip_src,ip_dst,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP,icmp,tcp,udp,reachable,reactive,tMAC,tIP,reachableSrcPorts_tcp,reachableDstPorts_tcp,reachableSrcPorts_udp,reachableDstPorts_udp]=results[0]
    if reactive==False and ip_src==None:
        print("")
        print("--- Determine if ingress port is enforced ---")
        port_check=forensic_switchport_prober.ingressPortCheckL2()
        if port_check==-1:
            print("Not enough neighbors of " + str(MY_IP) + " were found to check for ingress port!")
            port_check=0

    if ip_src!=None:
        print("Can't spoof source IP address, ingress port usage cannot be evaluated!")

    #if the controller follows a reactive approach, the ingress port cannot be enforced
    if reactive==True:
        port_check=0

    for res in results:
        [hw_src,hw_dst,ip_src,ip_dst,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP,icmp,tcp,udp,reachable,reactive,tMAC,tIP,reachableSrcPorts_tcp,reachableDstPorts_tcp,reachableSrcPorts_udp,reachableDstPorts_udp]=res

        blockedSrcPort_tcp=[]
        blockedDstPort_tcp=[]
        blockedSrcPort_udp=[]
        blockedDstPort_udp=[]
        for scanPort in scanPorts:
            if scanPort not in reachableSrcPorts_tcp:
                blockedSrcPort_tcp.append(scanPort)
            if scanPort not in reachableDstPorts_tcp:
                blockedDstPort_tcp.append(scanPort)
            if scanPort not in reachableSrcPorts_udp:
                blockedSrcPort_udp.append(scanPort)
            if scanPort not in reachableDstPorts_udp:
                blockedDstPort_udp.append(scanPort)

	if (tcp==0 and udp==0 and icmp==0):
		ruleconstructor.addRule(hw_src,hw_dst,ip_src,ip_dst,port_check,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP,0,0,0,"#OUT_PORT",None,None,0)

                rev_hw_src=None
                rev_hw_dst=None
                rev_ip_src=None
                rev_ip_dst=None
                rev_recv_srcIP=recv_srcIP
                rev_recv_dstIP=recv_dstIP
                rev_orig_srcIP=orig_srcIP
                rev_orig_dstIP=orig_dstIP

                #construct reverse rule
                if hw_src!=None:
                    rev_hw_src=tMAC

                if hw_dst!=None:
                    rev_hw_dst=MY_MAC

                if ip_src!=None:
                    rev_ip_src=tIP

                if ip_dst!=None:
                    rev_ip_dst=MY_IP

                if orig_srcIP!=recv_srcIP:
                    rev_recv_srcIP=recv_dstIP
                    rev_orig_srcIP=orig_dstIP

                if orig_dstIP!=recv_dstIP:
                    rev_recv_dstIP=MY_IP
                    rev_orig_dstIP=recv_srcIP

                ruleconstructor.addRule(rev_hw_src,rev_hw_dst,rev_ip_src,rev_ip_dst,port_check,rev_orig_srcIP,rev_recv_srcIP,rev_orig_dstIP,rev_recv_dstIP,0,0,0,"#OUT_PORT",None,None,0)

        if tcp!=1 or udp!=1 or icmp!=1:
            proto_ports=0
            #if (len(blockedSrcPort)!=0 or len(blockedDstPort)!=0):
            if tcp==1:
                for i in range(0,len(reachableSrcPorts_tcp)):
                    srcPort = reachableSrcPorts_tcp[i]
                    dstPort = reachableDstPorts_tcp[i]
                    tp_src=srcPort
                    tp_dst=dstPort
                    proto_ports=1

                    #print([hw_src,hw_dst,ip_src,ip_dst,port_check,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP,0,tcp,udp,"#OUT_PORT",tp_src,tp_dst,reachable])

                    ruleconstructor.addRule(hw_src,hw_dst,ip_src,ip_dst,port_check,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP,0,tcp,0,"#OUT_PORT",tp_src,tp_dst,reachable)

                    rev_hw_src=None
                    rev_hw_dst=None
                    rev_ip_src=None
                    rev_ip_dst=None
                    rev_recv_srcIP=recv_srcIP
                    rev_recv_dstIP=recv_dstIP
                    rev_orig_srcIP=orig_srcIP
                    rev_orig_dstIP=orig_dstIP

                    #construct reverse rule
                    if hw_src!=None:
                        rev_hw_src=tMAC

                    if hw_dst!=None:
                        rev_hw_dst=MY_MAC

                    if ip_src!=None:
                        rev_ip_src=tIP

                    if ip_dst!=None:
                        rev_ip_dst=MY_IP

                    if orig_srcIP!=recv_srcIP:
                        rev_recv_srcIP=recv_dstIP
                        rev_orig_srcIP=orig_dstIP

                    if orig_dstIP!=recv_dstIP:
                        rev_recv_dstIP=MY_IP
                        rev_orig_dstIP=recv_srcIP

                    ruleconstructor.addRule(rev_hw_src,rev_hw_dst,rev_ip_src,rev_ip_dst,port_check,rev_orig_srcIP,rev_recv_srcIP,rev_orig_dstIP,rev_recv_dstIP,0,tcp,0,"#OUT_PORT",tp_dst,tp_src,reachable)

                if (len(reachableSrcPorts_tcp)!=0):
                    tcp=0

            for i in range(0,len(blockedSrcPort_tcp)):
                srcPort = blockedSrcPort_tcp[i]
                dstPort = blockedSrcPort_tcp[i]
                tp_src=srcPort
                tp_dst=dstPort
                ruleconstructor.addRule(hw_src,hw_dst,ip_src,ip_dst,port_check,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP,0,1,0,"#OUT_PORT",tp_src,tp_dst,0)

            if udp==1:
                for i in range(0,len(reachableSrcPorts_udp)):
                    srcPort = reachableSrcPorts_udp[i]
                    dstPort = reachableDstPorts_udp[i]
                    tp_src=srcPort
                    tp_dst=dstPort
                    proto_ports=1

                    #print([hw_src,hw_dst,ip_src,ip_dst,port_check,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP,0,tcp,udp,"#OUT_PORT",tp_src,tp_dst,reachable])

                    ruleconstructor.addRule(hw_src,hw_dst,ip_src,ip_dst,port_check,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP,0,0,udp,"#OUT_PORT",tp_src,tp_dst,reachable)

                    rev_hw_src=None
                    rev_hw_dst=None
                    rev_ip_src=None
                    rev_ip_dst=None
                    rev_recv_srcIP=recv_srcIP
                    rev_recv_dstIP=recv_dstIP
                    rev_orig_srcIP=orig_srcIP
                    rev_orig_dstIP=orig_dstIP

                    #construct reverse rule
                    if hw_src!=None:
                        rev_hw_src=tMAC

                    if hw_dst!=None:
                        rev_hw_dst=MY_MAC

                    if ip_src!=None:
                        rev_ip_src=tIP

                    if ip_dst!=None:
                        rev_ip_dst=MY_IP

                    if orig_srcIP!=recv_srcIP:
                        rev_recv_srcIP=recv_dstIP
                        rev_orig_srcIP=orig_dstIP

                    if orig_dstIP!=recv_dstIP:
                        rev_recv_dstIP=MY_IP
                        rev_orig_dstIP=recv_srcIP

                    ruleconstructor.addRule(rev_hw_src,rev_hw_dst,rev_ip_src,rev_ip_dst,port_check,rev_orig_srcIP,rev_recv_srcIP,rev_orig_dstIP,rev_recv_dstIP,0,0,udp,"#OUT_PORT",tp_dst,tp_src,reachable)

                if(len(reachableSrcPorts_udp)!=0):
                    udp=0

            for i in range(0,len(blockedSrcPort_udp)):
                srcPort = blockedSrcPort_udp[i]
                dstPort = blockedSrcPort_udp[i]
                tp_src=srcPort
                tp_dst=dstPort
                ruleconstructor.addRule(hw_src,hw_dst,ip_src,ip_dst,port_check,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP,0,0,1,"#OUT_PORT",tp_src,tp_dst,0)

            if icmp==1:
                #print([hw_src,hw_dst,ip_src,ip_dst,port_check,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP,0,tcp,udp,"#OUT_PORT",tp_src,tp_dst,reachable])

                ruleconstructor.addRule(hw_src,hw_dst,ip_src,ip_dst,port_check,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP,icmp,0,0,"#OUT_PORT",None,None,reachable)

                rev_hw_src=None
                rev_hw_dst=None
                rev_ip_src=None
                rev_ip_dst=None
                rev_recv_srcIP=recv_srcIP
                rev_recv_dstIP=recv_dstIP
                rev_orig_srcIP=orig_srcIP
                rev_orig_dstIP=orig_dstIP

                #construct reverse rule
                if hw_src!=None:
                    rev_hw_src=tMAC

                if hw_dst!=None:
                    rev_hw_dst=MY_MAC

                if ip_src!=None:
                    rev_ip_src=tIP

                if ip_dst!=None:
                    rev_ip_dst=MY_IP

                if orig_srcIP!=recv_srcIP:
                    rev_recv_srcIP=recv_dstIP
                    rev_orig_srcIP=orig_dstIP

                if orig_dstIP!=recv_dstIP:
                    rev_recv_dstIP=MY_IP
                    rev_orig_dstIP=recv_srcIP

                ruleconstructor.addRule(rev_hw_src,rev_hw_dst,rev_ip_src,rev_ip_dst,port_check,rev_orig_srcIP,rev_recv_srcIP,rev_orig_dstIP,rev_recv_dstIP,icmp,0,0,"#OUT_PORT",None,None,reachable)
	
        else:
            #forensic_switchport_prober.mapHosts()
            if hw_src==None and hw_dst==None and ip_src==None and ip_dst==None and port_check==0:
                    print("SDN controller does not enforce any header fields between " + str(MY_IP) + " and " + str(tIP))
            else:
                ruleconstructor.addRule(hw_src,hw_dst,ip_src,ip_dst,port_check,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP,icmp,tcp,udp,"#OUT_PORT",None,None,reachable)
                #print([hw_src,hw_dst,ip_src,ip_dst,port_check,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP,icmp,tcp,udp,"#OUT_PORT",None,None,reachable])

                rev_hw_src=None
                rev_hw_dst=None
                rev_ip_src=None
                rev_ip_dst=None
                rev_recv_srcIP=recv_srcIP
                rev_recv_dstIP=recv_dstIP
                rev_orig_srcIP=orig_srcIP
                rev_orig_dstIP=orig_dstIP

                #construct reverse rule
                if hw_src!=None:
                    rev_hw_src=tMAC

                if hw_dst!=None:
                    rev_hw_dst=MY_MAC

                if ip_src!=None:
                    rev_ip_src=tIP

                if ip_dst!=None:
                    rev_ip_dst=MY_IP

                if orig_srcIP!=recv_srcIP:
                    rev_recv_srcIP=recv_dstIP
                    rev_orig_srcIP=orig_dstIP

                if orig_dstIP!=recv_dstIP:
                    rev_recv_dstIP=MY_IP
                    rev_orig_dstIP=recv_srcIP

                ruleconstructor.addRule(rev_hw_src,rev_hw_dst,rev_ip_src,rev_ip_dst,port_check,rev_orig_srcIP,rev_recv_srcIP,rev_orig_dstIP,rev_recv_dstIP,icmp,tcp,udp,"#OUT_PORT",None,None,reachable)

        '''
        if proto_ports==0:
            if hw_src==None and hw_dst==None and ip_src==None and ip_dst==None and port_check==0:
                print("SDN controller has a reactive approach and does not enforce any header fields between " + str(MY_IP) + " and " + str(tIP))
            else:
                #forensic_switchport_prober.mapHosts()
                ruleconstructor.addRule(hw_src,hw_dst,ip_src,ip_dst,port_check,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP,icmp,tcp,udp,"#OUT_PORT",None,None,reachable)

                rev_hw_src=None
                rev_hw_dst=None
                rev_ip_src=None
                rev_ip_dst=None
                rev_recv_srcIP=recv_srcIP
                rev_recv_dstIP=recv_dstIP
                rev_orig_srcIP=orig_srcIP
                rev_orig_dstIP=orig_dstIP

                #construct reverse rule
                if hw_src!=None:
                    rev_hw_src=tMAC

                if hw_dst!=None:
                    rev_hw_dst=MY_MAC

                if ip_src!=None:
                    rev_ip_src=tIP

                if ip_dst!=None:
                    rev_ip_dst=MY_IP

                if orig_srcIP!=recv_srcIP:
                    rev_recv_srcIP=recv_dstIP
                    rev_orig_srcIP=orig_dstIP

                if orig_dstIP!=recv_dstIP:
                    rev_recv_dstIP=recv_srcIP
                    rev_orig_dstIP=orig_srcIP

                ruleconstructor.addRule(rev_hw_src,rev_hw_dst,rev_ip_src,rev_ip_dst,port_check,rev_orig_srcIP,rev_recv_srcIP,rev_orig_dstIP,rev_recv_dstIP,icmp,tcp,udp,"#OUT_PORT",None,None,reachable)
        '''

    if len(ruleconstructor.rules)!=0:
        ruleconstructor.printRules()
    else:
        print("No rules reconstructed!")

elif scansuccess==0:
    print("--- ARP scan cannot be performed, no network connections can be found!")
