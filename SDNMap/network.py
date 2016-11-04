__author__ = 'mininet'

from Node import Node
import subprocess

class network(object):

    instance = None

    def __new__(cls, *args, **kwargs):
        if not cls.instance:
            cls.instance = super(network, cls).__new__(cls, *args, **kwargs)
        return cls.instance

    def __init__(self):
        self.arpCache={}
        self.nodesF={}
        self.nodesF[1] = Node("10.0.0.1","00:00:00:00:00:01",[2,3])
        self.nodesF[2] = Node("10.0.0.2","00:00:00:00:00:02",[4])
        self.nodesF[3] = Node("10.0.0.3","00:00:00:00:00:03",[])
        self.nodesF[4] = Node("10.0.0.4","00:00:00:00:00:04",[])
        self.nodesF[5] = Node("10.0.0.5","00:00:00:00:00:05",[])
        self.nodesF[6] = Node("10.0.0.6","00:00:00:00:00:06",[])

    def readARPtable(self,myip):
        nodes=[]
        output = subprocess.Popen(["arp", "-n"],stdout=subprocess.PIPE)
        while True:
            line=output.stdout.readline()
            if line !='':
                line_s = line.split(" ")
                line_s = filter(lambda a: a !="",line_s)
                #print(line_s)

                if line_s[0][:1].isdigit() and line_s[2][:1].isdigit():
                    nodes.append(Node(line_s[0], line_s[2],[]))
            else:
                break
        self.arpCache[myip] = nodes


    def getNode(self,n,myip):
        nodes={}

        nodes[1] = Node("10.0.0.1","00:00:00:00:00:01",[])
        nodes[2] = Node("10.0.0.2","00:00:00:00:00:02",[])
        nodes[3] = Node("10.0.0.3","00:00:00:00:00:03",[])
        nodes[4] = Node("10.0.0.4","00:00:00:00:00:04",[])
        nodes[5] = Node("10.0.0.5","00:00:00:00:00:05",[])
        nodes[6] = Node("10.0.0.6","00:00:00:00:00:06",[])


        '''
        nodes[1] = Node("10.1.1.1","00:00:00:01:01:01",[])
        nodes[2] = Node("10.1.2.1","00:00:00:01:02:01",[])
        nodes[3] = Node("10.3.2.1","00:00:00:03:02:01",[])
        nodes[4] = Node("10.3.3.1","00:00:00:03:03:01",[])
        nodes[5] = Node("10.1.5.1","00:00:00:00:00:05",[])
        nodes[6] = Node("10.1.6.1","00:00:00:00:00:06",[])
        '''

        node = nodes[n]

        self.readARPtable(myip)

        for arpNode in self.arpCache[myip]:
            if node.ip==arpNode.ip:
               node.mac=arpNode.mac

        if node.mac==None or node.mac=="":
            node.mac=nodes[n].mac

        return node
