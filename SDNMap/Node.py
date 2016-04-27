__author__ = 'mininet'


class Node(object):

    def __init__(self,myip,mymac,links=[]):
        self.ip=myip
        self.mac=mymac
        self.neighbors=links