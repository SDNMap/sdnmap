__author__ = 'mininet'

import subprocess
from Node import Node

class hostmap(object):

    instance = None

    def __new__(cls, *args, **kwargs):
        if not cls.instance:
            cls.instance = super(hostmap, cls).__new__(cls, *args, **kwargs)
        return cls.instance

    def __init__(self):
        self.arpCache={}


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