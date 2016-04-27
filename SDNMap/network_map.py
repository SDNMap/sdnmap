__author__ = 'mininet'

from Node import Node

class network_map(object):

    instance = None

    def __new__(cls, *args, **kwargs):
        if not cls.instance:
            cls.instance = super(network_map, cls).__new__(cls, *args, **kwargs)
        return cls.instance

    def __init__(self,ip,mac):
        self.network={}
        self.neighbor_neighbor={}
        self.my_ip=ip
        self.my_mac=mac

    def addNeighbor(self,node):
        self.network[node.ip] = node

    def addNeighbor_Neighbor(self,ip,node):
        if self.neighbor_neighbor.has_key(ip):
            if self.containsNode(ip,node)==False:
                self.neighbor_neighbor[ip].append(node)
        else:
            self.neighbor_neighbor[ip] = []
            self.neighbor_neighbor[ip].append(node)

    def containsNode(self,ip,node):
        for n in self.neighbor_neighbor[ip]:
            if node.ip==n.ip:
                return True
        return False


    def getNeighbor(self):
        return self.network

    def getNeighbor_Neighbor(self,ip):
        return self.neighbor_neighbor[ip]

    def getAllNeighbor_Neighbor(self):
        return self.neighbor_neighbor


    def printNetwork(self):
        print("-------- Printing network map --------")
        print(" -" + str(self.my_ip) + " / " + str(self.my_mac))
        for key in self.network.keys():
            n = self.network[key]
            node = n
            print("     -" + str(node.ip) + " / " + str(node.mac))
            if self.neighbor_neighbor.has_key(node.ip):
                for nn in self.neighbor_neighbor[node.ip]:
                    if nn.mac==None:
                        print("         -" + str(nn.ip))
                    else:
                        print("         -" + str(nn.ip) + " / " + str(nn.mac))
        print("---------------------------------------")