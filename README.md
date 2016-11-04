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

In the following we show example outputs of two scans performed by SDNMap:


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


And another example output of SDNMap:

-------------------------------------------------------------
```
root@sdnmaphost:~/# python main.py 10.0.0.0/24 ICMP eth0 []
Scanning 10.0.0.0 / 24
------- ARP scan --------
Performing ARP scan... 
Sending ARP request to 10.0.0.0
Sending ARP request to 10.0.0.2
Sending ARP request to 10.0.0.3
Sending ARP request to 10.0.0.4
Sending ARP request to 10.0.0.5
Sending ARP request to 10.0.0.6
Sending ARP request to 10.0.0.7
Sending ARP request to 10.0.0.8
Sending ARP request to 10.0.0.9
Sending ARP request to 10.0.0.10
Sending ARP request to 10.0.0.11
Sending ARP request to 10.0.0.12
Sending ARP request to 10.0.0.13
Sending ARP request to 10.0.0.14
Sending ARP request to 10.0.0.15
Sending ARP request to 10.0.0.16
Sending ARP request to 10.0.0.17
Sending ARP request to 10.0.0.18
Sending ARP request to 10.0.0.19
Sending ARP request to 10.0.0.20
Sending ARP request to 10.0.0.21
Sending ARP request to 10.0.0.22
Sending ARP request to 10.0.0.23
Sending ARP request to 10.0.0.24
Sending ARP request to 10.0.0.25
Sending ARP request to 10.0.0.26
Sending ARP request to 10.0.0.27
Sending ARP request to 10.0.0.28
Sending ARP request to 10.0.0.29
Sending ARP request to 10.0.0.30
Sending ARP request to 10.0.0.31
Sending ARP request to 10.0.0.32
Sending ARP request to 10.0.0.33
Sending ARP request to 10.0.0.34
Sending ARP request to 10.0.0.35
Sending ARP request to 10.0.0.36
Sending ARP request to 10.0.0.37
Sending ARP request to 10.0.0.38
Sending ARP request to 10.0.0.39
Sending ARP request to 10.0.0.40
Sending ARP request to 10.0.0.41
Sending ARP request to 10.0.0.42
Sending ARP request to 10.0.0.43
Sending ARP request to 10.0.0.44
Sending ARP request to 10.0.0.45
Sending ARP request to 10.0.0.46
Sending ARP request to 10.0.0.47
Sending ARP request to 10.0.0.48
Sending ARP request to 10.0.0.49
Sending ARP request to 10.0.0.50
Sending ARP request to 10.0.0.51
Sending ARP request to 10.0.0.52
Sending ARP request to 10.0.0.53
Sending ARP request to 10.0.0.54
Sending ARP request to 10.0.0.55
Sending ARP request to 10.0.0.56
Sending ARP request to 10.0.0.57
Sending ARP request to 10.0.0.58
Sending ARP request to 10.0.0.59
Sending ARP request to 10.0.0.60
Sending ARP request to 10.0.0.61
Sending ARP request to 10.0.0.62
Sending ARP request to 10.0.0.63
Sending ARP request to 10.0.0.64
Sending ARP request to 10.0.0.65
Sending ARP request to 10.0.0.66
Sending ARP request to 10.0.0.67
Sending ARP request to 10.0.0.68
Sending ARP request to 10.0.0.69
Sending ARP request to 10.0.0.70
Sending ARP request to 10.0.0.71
Sending ARP request to 10.0.0.72
Sending ARP request to 10.0.0.73
Sending ARP request to 10.0.0.74
Sending ARP request to 10.0.0.75
Sending ARP request to 10.0.0.76
Sending ARP request to 10.0.0.77
Sending ARP request to 10.0.0.78
Sending ARP request to 10.0.0.79
Sending ARP request to 10.0.0.80
Sending ARP request to 10.0.0.81
Sending ARP request to 10.0.0.82
Sending ARP request to 10.0.0.83
Sending ARP request to 10.0.0.84
Sending ARP request to 10.0.0.85
Sending ARP request to 10.0.0.86
Sending ARP request to 10.0.0.87
Sending ARP request to 10.0.0.88
Sending ARP request to 10.0.0.89
Sending ARP request to 10.0.0.90
Sending ARP request to 10.0.0.91
Sending ARP request to 10.0.0.92
Sending ARP request to 10.0.0.93
Sending ARP request to 10.0.0.94
Sending ARP request to 10.0.0.95
Sending ARP request to 10.0.0.96
Sending ARP request to 10.0.0.97
Sending ARP request to 10.0.0.98
Sending ARP request to 10.0.0.99
Sending ARP request to 10.0.0.100
Sending ARP request to 10.0.0.101
Sending ARP request to 10.0.0.102
Sending ARP request to 10.0.0.103
Sending ARP request to 10.0.0.104
Sending ARP request to 10.0.0.105
Sending ARP request to 10.0.0.106
Sending ARP request to 10.0.0.107
Sending ARP request to 10.0.0.108
Sending ARP request to 10.0.0.109
Sending ARP request to 10.0.0.110
Sending ARP request to 10.0.0.111
Sending ARP request to 10.0.0.112
Sending ARP request to 10.0.0.113
Sending ARP request to 10.0.0.114
Sending ARP request to 10.0.0.115
Sending ARP request to 10.0.0.116
Sending ARP request to 10.0.0.117
Sending ARP request to 10.0.0.118
Sending ARP request to 10.0.0.119
Sending ARP request to 10.0.0.120
Sending ARP request to 10.0.0.121
Sending ARP request to 10.0.0.122
Sending ARP request to 10.0.0.123
Sending ARP request to 10.0.0.124
Sending ARP request to 10.0.0.125
Sending ARP request to 10.0.0.126
Sending ARP request to 10.0.0.127
Sending ARP request to 10.0.0.128
Sending ARP request to 10.0.0.129
Sending ARP request to 10.0.0.130
Sending ARP request to 10.0.0.131
Sending ARP request to 10.0.0.132
Sending ARP request to 10.0.0.133
Sending ARP request to 10.0.0.134
Sending ARP request to 10.0.0.135
Sending ARP request to 10.0.0.136
Sending ARP request to 10.0.0.137
Sending ARP request to 10.0.0.138
Sending ARP request to 10.0.0.139
Sending ARP request to 10.0.0.140
Sending ARP request to 10.0.0.141
Sending ARP request to 10.0.0.142
Sending ARP request to 10.0.0.143
Sending ARP request to 10.0.0.144
Sending ARP request to 10.0.0.145
Sending ARP request to 10.0.0.146
Sending ARP request to 10.0.0.147
Sending ARP request to 10.0.0.148
Sending ARP request to 10.0.0.149
Sending ARP request to 10.0.0.150
Sending ARP request to 10.0.0.151
Sending ARP request to 10.0.0.152
Sending ARP request to 10.0.0.153
Sending ARP request to 10.0.0.154
Sending ARP request to 10.0.0.155
Sending ARP request to 10.0.0.156
Sending ARP request to 10.0.0.157
Sending ARP request to 10.0.0.158
Sending ARP request to 10.0.0.159
Sending ARP request to 10.0.0.160
Sending ARP request to 10.0.0.161
Sending ARP request to 10.0.0.162
Sending ARP request to 10.0.0.163
Sending ARP request to 10.0.0.164
Sending ARP request to 10.0.0.165
Sending ARP request to 10.0.0.166
Sending ARP request to 10.0.0.167
Sending ARP request to 10.0.0.168
Sending ARP request to 10.0.0.169
Sending ARP request to 10.0.0.170
Sending ARP request to 10.0.0.171
Sending ARP request to 10.0.0.172
Sending ARP request to 10.0.0.173
Sending ARP request to 10.0.0.174
Sending ARP request to 10.0.0.175
Sending ARP request to 10.0.0.176
Sending ARP request to 10.0.0.177
Sending ARP request to 10.0.0.178
Sending ARP request to 10.0.0.179
Sending ARP request to 10.0.0.180
Sending ARP request to 10.0.0.181
Sending ARP request to 10.0.0.182
Sending ARP request to 10.0.0.183
Sending ARP request to 10.0.0.184
Sending ARP request to 10.0.0.185
Sending ARP request to 10.0.0.186
Sending ARP request to 10.0.0.187
Sending ARP request to 10.0.0.188
Sending ARP request to 10.0.0.189
Sending ARP request to 10.0.0.190
Sending ARP request to 10.0.0.191
Sending ARP request to 10.0.0.192
Sending ARP request to 10.0.0.193
Sending ARP request to 10.0.0.194
Sending ARP request to 10.0.0.195
Sending ARP request to 10.0.0.196
Sending ARP request to 10.0.0.197
Sending ARP request to 10.0.0.198
Sending ARP request to 10.0.0.199
Sending ARP request to 10.0.0.200
Sending ARP request to 10.0.0.201
Sending ARP request to 10.0.0.202
Sending ARP request to 10.0.0.203
Sending ARP request to 10.0.0.204
Sending ARP request to 10.0.0.205
Sending ARP request to 10.0.0.206
Sending ARP request to 10.0.0.207
Sending ARP request to 10.0.0.208
Sending ARP request to 10.0.0.209
Sending ARP request to 10.0.0.210
Sending ARP request to 10.0.0.211
Sending ARP request to 10.0.0.212
Sending ARP request to 10.0.0.213
Sending ARP request to 10.0.0.214
Sending ARP request to 10.0.0.215
Sending ARP request to 10.0.0.216
Sending ARP request to 10.0.0.217
Sending ARP request to 10.0.0.218
Sending ARP request to 10.0.0.219
Sending ARP request to 10.0.0.220
Sending ARP request to 10.0.0.221
Sending ARP request to 10.0.0.222
Sending ARP request to 10.0.0.223
Sending ARP request to 10.0.0.224
Sending ARP request to 10.0.0.225
Sending ARP request to 10.0.0.226
Sending ARP request to 10.0.0.227
Sending ARP request to 10.0.0.228
Sending ARP request to 10.0.0.229
Sending ARP request to 10.0.0.230
Sending ARP request to 10.0.0.231
Sending ARP request to 10.0.0.232
Sending ARP request to 10.0.0.233
Sending ARP request to 10.0.0.234
Sending ARP request to 10.0.0.235
Sending ARP request to 10.0.0.236
Sending ARP request to 10.0.0.237
Sending ARP request to 10.0.0.238
Sending ARP request to 10.0.0.239
Sending ARP request to 10.0.0.240
Sending ARP request to 10.0.0.241
Sending ARP request to 10.0.0.242
Sending ARP request to 10.0.0.243
Sending ARP request to 10.0.0.244
Sending ARP request to 10.0.0.245
Sending ARP request to 10.0.0.246
Sending ARP request to 10.0.0.247
Sending ARP request to 10.0.0.248
Sending ARP request to 10.0.0.249
Sending ARP request to 10.0.0.250
Sending ARP request to 10.0.0.251
Sending ARP request to 10.0.0.252
Sending ARP request to 10.0.0.253
Sending ARP request to 10.0.0.254
Sending ARP request to 10.0.0.255
10.0.0.1 / 00:00:00:00:00:01 received response from the following hosts: 
10.0.0.3 / 00:00:00:00:00:03
10.0.0.2 / 00:00:00:00:00:02
----------------------------
Use 10.0.0.3 / 00:00:00:00:00:03 for probing
--- Determine enforced protocols ---
------- Check with TCP --------
Check if host at 10.0.0.3 - 00:00:00:00:00:03 is reachable with src addresses 10.0.0.1 - 00:00:00:00:00:01 with TCP on src port 62227 and dst port 36773
Host is reachable via TCP!
-------------------------------------------
------- Check with ICMP -------
Check if host at 10.0.0.3 - 00:00:00:00:00:03 is reachable with src addresses 10.0.0.1 - 00:00:00:00:00:01 with ICMP
Host is reachable via ICMP!
-------------------------------------------
------- Check with UDP --------
Check if host at 10.0.0.3 - 00:00:00:00:00:03 is reachable with src addresses 10.0.0.1 - 00:00:00:00:00:01 with UDP on src port 62227 and dst port 36773
Host is reachable via UDP!
-------------------------------------------

Accepted protocols: 
TCP
ICMP
UDP



--- Determine if IP addresses are rewritten ---
Sending UDP packet to port 36765 at 10.0.0.3 / 00:00:00:00:00:03
Received ICMP Port Unreachable message
IP addresses are not rewritten

------- Check if layer 3 routing is used --------
Check if host at 10.0.0.3 - 00:00:00:00:00:03 is reachable with src addresses 10.0.0.203 - 00:00:00:00:00:01
ARP req for fake IP src received!
Spoof ARP cache at 10.0.0.3 from 10.0.0.203 to 00:00:00:00:00:01
Check if host at 10.0.0.3 - 00:00:00:00:00:03 is reachable with src addresses 10.0.0.203 - 00:00:00:00:00:01
-------------------------------------------
------- Check if layer 2 routing is used --------
Check if host at 10.0.0.3 - 00:00:00:00:00:03 is reachable with src addresses 10.0.0.1 - 00:00:00:a4:41:43
Response to fake src MAC received!
Spoof ARP cache at 10.0.0.3 from 10.0.0.1 to 00:00:00:a4:41:43
Check if host at 10.0.0.3 - 00:00:00:00:00:03 is reachable with src addresses 10.0.0.1 - 00:00:00:00:00:01
Response to fake src and dst MAC received!
Spoof ARP cache at 10.0.0.3 from 10.0.0.1 to 00:00:00:00:00:01
-------------------------------------------
Use 10.0.0.2 / 00:00:00:00:00:02 for probing
--- Determine enforced protocols ---
------- Check with TCP --------
Check if host at 10.0.0.2 - 00:00:00:00:00:02 is reachable with src addresses 10.0.0.1 - 00:00:00:00:00:01 with TCP on src port 63615 and dst port 36933
Host is reachable via TCP!
-------------------------------------------
------- Check with ICMP -------
Check if host at 10.0.0.2 - 00:00:00:00:00:02 is reachable with src addresses 10.0.0.1 - 00:00:00:00:00:01 with ICMP
Host is reachable via ICMP!
-------------------------------------------
------- Check with UDP --------
Check if host at 10.0.0.2 - 00:00:00:00:00:02 is reachable with src addresses 10.0.0.1 - 00:00:00:00:00:01 with UDP on src port 63615 and dst port 36933
Host is reachable via UDP!
-------------------------------------------

Accepted protocols: 
TCP
ICMP
UDP



--- Determine if IP addresses are rewritten ---
Sending UDP packet to port 36012 at 10.0.0.2 / 00:00:00:00:00:02
Received ICMP Port Unreachable message
IP addresses are not rewritten

------- Check if layer 3 routing is used --------
Check if host at 10.0.0.2 - 00:00:00:00:00:02 is reachable with src addresses 10.0.0.39 - 00:00:00:00:00:01
ARP req for fake IP src received!
Spoof ARP cache at 10.0.0.2 from 10.0.0.39 to 00:00:00:00:00:01
Check if host at 10.0.0.2 - 00:00:00:00:00:02 is reachable with src addresses 10.0.0.39 - 00:00:00:00:00:01
-------------------------------------------
------- Check if layer 2 routing is used --------
Check if host at 10.0.0.2 - 00:00:00:00:00:02 is reachable with src addresses 10.0.0.1 - 00:00:00:f9:21:0c
Response to fake src MAC received!
Spoof ARP cache at 10.0.0.2 from 10.0.0.1 to 00:00:00:f9:21:0c
Check if host at 10.0.0.2 - 00:00:00:00:00:02 is reachable with src addresses 10.0.0.1 - 00:00:00:00:00:01
Response to fake src and dst MAC received!
Spoof ARP cache at 10.0.0.2 from 10.0.0.1 to 00:00:00:00:00:01
-------------------------------------------

--- Determine if ingress port is enforced ---
Selecting two hosts to use for probing...
Sending Ping request from 10.0.0.3 / 00:00:00:00:00:03 to 10.0.0.2 / 00:00:00:00:00:02
Received ARP request for 10.0.0.3 --> ingress port is not checked

 ------- Reconstructed rules ---------
match=type:arp,arp_op=1 actions=FLOOD
match=type:ip,nw_dst:10.0.0.3 actions=output:#OUT_PORT
match=type:ip,nw_dst:10.0.0.1 actions=output:#OUT_PORT
match=type:ip,nw_dst:10.0.0.2 actions=output:#OUT_PORT
match=type:ip,nw_dst:10.0.0.1 actions=output:#OUT_PORT
 -------------------------------------
```
-------------------------------------------------------------

In the shown example above, the rule "match=type:ip,nw_dst:10.0.0.1 actions=output:#OUT_PORT" is shown twice since they are the return rules from 10.0.0.2 and from 10.0.0.3

