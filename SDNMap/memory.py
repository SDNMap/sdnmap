__author__ = 'mininet'

class memory(object):

    instance = None

    def __new__(cls, *args, **kwargs):
        if not cls.instance:
            cls.instance = super(memory, cls).__new__(cls, *args, **kwargs)
        return cls.instance

    def __init__(self):
        self.seenNonces={}
        self.seenARPIPReq={}
        self.getARPScanDict={}
        self.recvARPReplies={}
        self.receivedICMP_PNR=[]
        self.seenTCP_Pkts={}
        self.fakeIPs=[]
        self.mapping=0
        self.recvICMPReplies={}

    def getNonces(self):
        return self.seenNonces

    def getRecvICMPReplies(self):
        return self.recvICMPReplies

    def getARPIPReq(self):
        return self.seenARPIPReq

    def getARPScan(self):
        return self.getARPScanDict

    def getrecvICMP_PNR(self):
        return self.receivedICMP_PNR

    def getSeenTCP_Pktsself(self):
        return self.seenTCP_Pkts

    def isMapping(self):
        return self.mapping

    def setMapping(self,m):
        self.mapping = m

    def getRecvARPReplies(self):
        return self.recvARPReplies

    def getFakeIPs(self):
        return self.fakeIPs