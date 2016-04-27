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
from scipy.stats import ttest_ind


class timing_prober(object):

    def __init__(self,ip,mac):
        self.myip=ip
        self.mymac=mac
        self.tools=tools()
        self.mem=memory()
        self.ruleconstructor=ruleconstructor()
        self.recv_target=None
        self.sent_target=None
        self.network=network()
        #print("Timing Prober initialized at... " + str(self.myip) + " - " + str(self.mymac))

    def checkTimingPattern(self,probeIP,probeMAC,responseTimeout):

        #use correct mac and IP
        hw_src = self.mymac
        hw_dst = probeMAC
        ip_src = self.myip
        ip_dst = probeIP
        print("Check if host at " + str(ip_dst) + " - " + str(hw_dst) + " is reachable from " + str( ip_src) + " - " + str(hw_src))

        #send ping request
        ether = Ether(src=hw_src, dst=hw_dst)
        ip = IP(src=ip_src, dst=ip_dst)
        icmp = ICMP(type = 8, code = 0)

        icmp_pkt = ether/ip/icmp

        count=0
        first_probe_list=[]
        second_probe_list=[]
        idle_times=[5,5,11,11,11,11]     #[6,6,11,11,16,16,31,31,61,61]

        sdn_net=0

        t=0.0
        for wait in idle_times:
            print "Measuring probing time..."
            while count < 2:
                ans,unans=srp(icmp_pkt, verbose=0)
                rx = ans[0][1]
                tx = ans[0][0]
                delta = rx.time-tx.sent_time
                if count==0:
                    first_probe_list.append(delta)
                if count==1:
                    second_probe_list.append(delta)
                count+=1
            print("Waiting for " + str(wait) + " seconds")
            time.sleep(wait)
            count=0

        #print("First times: " + str(first_probe_list[:]))
        #print("Second times: " + str(second_probe_list[:]))
        t, p = ttest_ind(first_probe_list, second_probe_list, equal_var=False)

        #assuming a 95% confidence interval we have to test if p<0.05 which means the samples are different
        if p<0.1:
            print("Performing a t-test, t " + str(t) + " p " + str(p) + "(90% confidence interval), SDN network is assumed")
            sdn_net+=1
        else:
            print("Performing a t-test, t " + str(t) + " p " + str(p) + "(90% confidence interval), SDN network is not assumed")
        #print("t " + str(t) + " p " + str(p))

        numSamples = len(first_probe_list)
        thresholdCounter=0
        for i in range(len(first_probe_list)):
            f_time = first_probe_list[i]
            s_time = second_probe_list[i]
            factor = f_time/s_time
            if factor > 10:
                thresholdCounter+=1

        if thresholdCounter >= (numSamples/2):
            print("Comparing probing times shows that half of the probing time series shows a factor of 10 difference --> SDN network is assumed")
            sdn_net+=1
        else:
            print("Comparing probing time series shows no significant difference --> SDN network is not assumed")

        return sdn_net

    def determineIfSDN(self,probeIP,probeMAC):

        responseTimeout=2

        self.checkTimingPattern(probeIP,probeMAC,responseTimeout)
