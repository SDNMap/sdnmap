__author__ = 'mininet'


class Target(object):


    def __init__(self,nonce,src_ip,src_mac,dst_ip,dst_mac):
        self.nonce=nonce
        self.src_ip=src_ip
        self.dst_ip=dst_ip
        self.src_mac=src_mac
        self.dst_mac=dst_mac
