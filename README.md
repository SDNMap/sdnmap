# SDNMap #

Please make sure that you have Python, Scapy 2.2, installed on your Linux system since these are required to run SDNMap.

### Using SDNMap

SDNMap is a scanning tool to reconstruct the composition of OpenFlow rules in SDN networks from a source host to any destination host in a network.
No prior knowledge of the SDN controller or network is required. 

SDNMap is an open-source software and can be used under the terms of the Creative Commons (CC0) license.
For details about the functionality of SDNMap we refer to the research paper "Adversarial Network Forensics in Software Defined Networking" (currently under review).
Please contact us with any questions at: sdnmap@gmail.com

----------------------------------------
### Scanning hosts with SDNMap

To perform a flow rules reconstruction scan, the user has to provide the following input arguments to SDNMap:

- IP address prefix to scan (e.g. 10.0.0.0/24 for a range of hosts or 10.0.0.2/32 for a single host)
- The selected scanning protocol (ICMP or TCP)
- The network interface of the host (e.g. eth0)
- A list of ports in [] separated by a comma (',') that should be scanned for TCP and UDP, e.g. [80,443], or an empty list [] if exact port numbers should not be scanned

SDNMap has to be executed with root privileges. An example for starting SDNMap to scan the network 10.0.0.0/24 with TCP and evaluate ports 80 and 443 looks like the following:

*sudo python main.py 10.0.0.0/24 TCP eth0 [80,443]*

After the completion of a scan, SDNMap will print a list of reconstructed flow rules.

In the following we show an example output of a scan performed by SDNMap:


-------------------------------------------------------------
```
root@sdnmaphost:~/# python main.py 10.0.0.2/32 TCP h1-eth0 [80,120]
Scanning 10.0.0.2 / 32
------- ARP scan --------
Performing ARP scan... 
Sending ARP request to 10.0.0.2
10.0.0.1 / 00:00:00:00:00:01 received response from the following hosts: 
10.0.0.2 / 00:00:00:00:00:02
----------------------------
Use 10.0.0.2 / 00:00:00:00:00:02 for probing
------- Test which TCP ports, using ports [80, 120], are checked --------
Probing 10.0.0.2 - 00:00:00:00:00:02 with TCP source port 80 and destination port 80
Replied!
Probing 10.0.0.2 - 00:00:00:00:00:02 with TCP source port 80 and destination port 120
No reply received!
Probing 10.0.0.2 - 00:00:00:00:00:02 with TCP source port 120 and destination port 80
No reply received!
Probing 10.0.0.2 - 00:00:00:00:00:02 with TCP source port 120 and destination port 120
No reply received!
Probing 10.0.0.2 - 00:00:00:00:00:02 with spoofed IP source and TCP source port 80 and destination port 80
Received ARP request for 10.0.0.171
Probing 10.0.0.2 - 00:00:00:00:00:02 with spoofed IP source and TCP source port 80 and destination port 120
No reply received!
Probing 10.0.0.2 - 00:00:00:00:00:02 with spoofed IP source and TCP source port 120 and destination port 80
Received ARP request for 10.0.0.143
Probing 10.0.0.2 - 00:00:00:00:00:02 with spoofed IP source and TCP source port 120 and destination port 120
No reply received!

-------------------------------------------
------- Test which UDP ports, using ports [80, 120], are checked --------
Probing 10.0.0.2 - 00:00:00:00:00:02 with UDP source port 80 and destination port 80
Replied at port 80!
Probing 10.0.0.2 - 00:00:00:00:00:02 with UDP source port 80 and destination port 120
No reply received!
Probing 10.0.0.2 - 00:00:00:00:00:02 with UDP source port 120 and destination port 80
Replied at port 80!
Probing 10.0.0.2 - 00:00:00:00:00:02 with UDP source port 120 and destination port 120
No reply received!
Probing 10.0.0.2 - 00:00:00:00:00:02 with spoofed IP source and UDP source port 80 and destination port 80
Received ARP request for 10.0.0.86
Probing 10.0.0.2 - 00:00:00:00:00:02 with spoofed IP source and UDP source port 80 and destination port 120
No reply received!
Probing 10.0.0.2 - 00:00:00:00:00:02 with spoofed IP source and UDP source port 120 and destination port 80
Received ARP request for 10.0.0.160
Probing 10.0.0.2 - 00:00:00:00:00:02 with spoofed IP source and UDP source port 120 and destination port 120
No reply received!

-------------------------------------------
--- Determine enforced protocols ---
------- Check with TCP --------
Check if host at 10.0.0.2 - 00:00:00:00:00:02 is reachable with src addresses 10.0.0.1 - 00:00:00:00:00:01 with TCP on src port 80 and dst port 80
Host is reachable via TCP!
-------------------------------------------
------- Check with ICMP -------
Check if host at 10.0.0.2 - 00:00:00:00:00:02 is reachable with src addresses 10.0.0.1 - 00:00:00:00:00:01 with ICMP
Host is reachable via ICMP!
-------------------------------------------
------- Check with UDP --------
Check if host at 10.0.0.2 - 00:00:00:00:00:02 is reachable with src addresses 10.0.0.1 - 00:00:00:00:00:01 with UDP on src port 80 and dst port 80
Host is reachable via UDP!
-------------------------------------------

Accepted protocols: 
TCP
ICMP
UDP


--- Determine if IP addresses are rewritten ---
Sending UDP packet to port 80 at 10.0.0.2 / 00:00:00:00:00:02
Received ICMP Port Unreachable message
IP addresses are not rewritten

--- Determine which L2/L3 fields are enforced using TCP ---
------- Check if SDN is reactive --------
Check if host at 10.0.0.2 - 00:00:00:00:00:02 is reachable with src addresses 10.0.0.1 - 00:00:00:00:00:01 from port 80 to port 80
Proactive approach is assumed based on probing response times (difference factor 1 < 10)
Check if host at 10.0.0.2 - 00:00:00:00:00:02 is reachable with src addresses 10.0.0.195 - 00:00:00:da:69:a0 from port 80 to port 80
Spoof ARP cache at 10.0.0.2 from 10.0.0.195 to 00:00:00:00:00:01
Proactive approach is assumed since no response for fake addresses received
-------------------------------------------
------- Check if layer 3 routing is used --------
Check if host at 10.0.0.2 - 00:00:00:00:00:02 is reachable with src addresses 10.0.0.231 - 00:00:00:00:00:01 from port 80 to port 80
ARP req for fake IP src received!
Spoof ARP cache at 10.0.0.2 from 10.0.0.231 to 00:00:00:00:00:01
Check if host at 10.0.0.2 - 00:00:00:00:00:02 is reachable from 10.0.0.231 - 00:00:00:00:00:01 from port 80 to port 80
-------------------------------------------
------- Check if layer 2 routing is used --------
Check if host at 10.0.0.2 - 00:00:00:00:00:02 is reachable with src addresses 10.0.0.1 - 00:00:00:1d:2f:07 from port 80 to port 80
Response to fake src MAC received!
Spoof ARP cache at 10.0.0.2 from 10.0.0.1 to 00:00:00:1d:2f:07
Check if host at 10.0.0.2 - 00:00:00:00:00:02 is reachable from 10.0.0.1 - 00:00:00:00:00:01 from port 80 to port 80
Spoof ARP cache at 10.0.0.2 from 10.0.0.1 to 00:00:00:00:00:01
-------------------------------------------

--- Determine if ingress port is enforced ---
Not enough neighbors of 10.0.0.1 were found to check for ingress port!

 ------- Reconstructed rules ---------
match=type:arp,arp_op=1 actions=FLOOD
match=type:tcp,dl_dst:00:00:00:00:00:02,tp_src:80,tp_dst:80,nw_dst:10.0.0.2 actions=output:#OUT_PORT
match=type:tcp,dl_dst:00:00:00:00:00:01,tp_src:80,tp_dst:80,nw_dst:10.0.0.1 actions=output:#OUT_PORT
match=type:tcp,dl_dst:00:00:00:00:00:02,tp_src:120,tp_dst:80,nw_dst:10.0.0.2 actions=output:#OUT_PORT
match=type:tcp,dl_dst:00:00:00:00:00:01,tp_src:80,tp_dst:120,nw_dst:10.0.0.1 actions=output:#OUT_PORT
match=type:udp,dl_dst:00:00:00:00:00:02,tp_src:80,tp_dst:80,nw_dst:10.0.0.2 actions=output:#OUT_PORT
match=type:udp,dl_dst:00:00:00:00:00:01,tp_src:80,tp_dst:80,nw_dst:10.0.0.1 actions=output:#OUT_PORT
match=type:udp,dl_dst:00:00:00:00:00:02,tp_src:120,tp_dst:80,nw_dst:10.0.0.2 actions=output:#OUT_PORT
match=type:udp,dl_dst:00:00:00:00:00:01,tp_src:80,tp_dst:120,nw_dst:10.0.0.1 actions=output:#OUT_PORT
match=type:icmp,dl_dst:00:00:00:00:00:02,nw_dst:10.0.0.2 actions=output:#OUT_PORT
match=type:icmp,dl_dst:00:00:00:00:00:01,nw_dst:10.0.0.1 actions=output:#OUT_PORT

```
-------------------------------------------------------------


