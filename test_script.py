from scapy.all import IP, TCP, sendp
from scapy.layers.l2 import Loopback

packet = Loopback() / IP(src="203.0.113.5", dst="127.0.0.1") / TCP(dport=80, sport=12345)
sendp(packet, iface="lo", verbose=0)
