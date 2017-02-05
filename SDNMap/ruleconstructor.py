__author__ = 'mininet'

from Target import Target

class ruleconstructor(object):

    #def __init__(self):

    instance = None

    def __new__(cls, *args, **kwargs):
        if not cls.instance:
            cls.instance = super(ruleconstructor, cls).__new__(cls, *args, **kwargs)
        return cls.instance

    def __init__(self):
        self.rules=[]

    def clearRules(self):
        self.rules=[]

    def addARPFlood(self):
        rule="match=type:arp,arp_op=1 "
        rule=rule+"actions=FLOOD"
        self.rules.append(rule)

    def addRuleARP(self,hw_src,hw_dst,in_port,out_port,reachable):
        rule="match=arp,"

        if in_port==1:
            rule=rule+"in_port:#IN_PORT,"

        if hw_src!=None:
            rule=rule+"dl_src:"+hw_src+","

        if hw_dst!=None:
            rule=rule+"dl_dst:"+hw_dst

        if reachable==1:
            rule=rule+" actions=output:" + str(out_port)
            self.rules.append(rule)
        else:
            rule=rule+" actions=drop"
            self.rules.append(rule)

    def addRule(self,hw_src,hw_dst,ip_src,ip_dst,in_port,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP,icmp,tcp,udp,out_port,tp_src,tp_dst,reachable):
        #print(hw_src,hw_dst,ip_src,ip_dst,in_port,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP,icmp,tcp,udp,out_port,tp_src,tp_dst,reachable)
        rule="match="
        if ((tcp==0 and udp==0 and icmp==0) or (tcp==1 and udp==1 and icmp==1)):
            rule=rule+"type:ip,"
            rule=self.ruleMatch(rule,hw_src,hw_dst,ip_src,ip_dst,tp_src,tp_dst,in_port)
            rule=self.ruleAction(rule,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP)

        elif icmp==1 and (tcp==0 and udp==0):
            rule=rule+"type:icmp,"
            rule=self.ruleMatch(rule,hw_src,hw_dst,ip_src,ip_dst,tp_src,tp_dst,in_port)
            rule=self.ruleAction(rule,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP)

        elif tcp==1 and (udp==0 and icmp==0):
            rule=rule+"type:tcp,"
            rule=self.ruleMatch(rule,hw_src,hw_dst,ip_src,ip_dst,tp_src,tp_dst,in_port)
            rule=self.ruleAction(rule,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP)

        elif udp==1 and (icmp==0 and tcp==0):
            rule=rule+"type:udp,"
            rule=self.ruleMatch(rule,hw_src,hw_dst,ip_src,ip_dst,tp_src,tp_dst,in_port)
            rule=self.ruleAction(rule,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP)

        elif icmp==1 and tcp==1 and udp==0:
            rule=rule+"type:icmp,tcp,"
            rule=self.ruleMatch(rule,hw_src,hw_dst,ip_src,ip_dst,tp_src,tp_dst,in_port)
            rule=self.ruleAction(rule,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP)

        elif icmp==1 and tcp==0 and udp==1:
            rule=rule+"type:icmp,udp,"
            rule=self.ruleMatch(rule,hw_src,hw_dst,ip_src,ip_dst,tp_src,tp_dst,in_port)
            rule=self.ruleAction(rule,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP)

        elif icmp==0 and tcp==1 and udp==1:
            rule=rule+"type:tcp,udp,"
            rule=self.ruleMatch(rule,hw_src,hw_dst,ip_src,ip_dst,tp_src,tp_dst,in_port)
            rule=self.ruleAction(rule,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP)

        if reachable==1:
            rule=rule+"output:" + str(out_port)
            self.rules.append(rule)
        else:
            rule=rule+"drop"
            self.rules.append(rule)


    def ruleMatch(self,rule,hw_src,hw_dst,ip_src,ip_dst,tp_src,tp_dst,in_port):
        if in_port==1:
            rule=rule+"in_port:#IN_PORT,"

        if hw_src!=None:
            rule=rule+"dl_src:"+hw_src+","

        if hw_dst!=None:
            rule=rule+"dl_dst:"+hw_dst+","

        if tp_src!=None:
            rule=rule+"tp_src:"+str(tp_src)+","

        if tp_dst!=None:
            rule=rule+"tp_dst:"+str(tp_dst)+","

        if ip_src!=None:
            rule=rule+"nw_src:"+ip_src+","

        if ip_dst!=None:
            rule=rule+"nw_dst:"+ip_dst+","

        return rule[:-1]


    def ruleAction(self,rule,orig_srcIP,recv_srcIP,orig_dstIP,recv_dstIP):
        rule=rule+" actions="

        if orig_srcIP!=recv_srcIP:
            rule=rule+"mod_nw_src:"+recv_srcIP+","

        if orig_dstIP!=recv_dstIP:
            rule=rule+"mod_nw_dst:"+recv_dstIP+","

        return rule


    def printRules(self):
        print("")
        print(" ------- Reconstructed rules ---------")
        for rule in self.rules:
            print(rule)
        print(" -------------------------------------")
