import os
import time
from scapy.all import Ether, IP, TCP, sendp

iface = os.getenv("TEST_IFACE", "eth0")
dst_mac = os.getenv("TEST_DST_MAC", "ff:ff:ff:ff:ff:ff")
dst_ip = os.getenv("TEST_DST_IP", "127.0.0.1")
http_src_ip = os.getenv("TEST_HTTP_SRC_IP", "141.98.11.11")
scan_src_ip = os.getenv("TEST_SCAN_SRC_IP", "198.51.100.99")

print("[+] Simulating HTTP flood")
for i in range(15):
    packet = Ether(dst=dst_mac) / IP(src=http_src_ip, dst=dst_ip) / TCP(dport=80, sport=1024 + i)
    sendp(packet, iface=iface, verbose=0)

time.sleep(2)
print("[+] Simulating port scan")
for port in range(1, 25):
    packet = Ether(dst=dst_mac) / IP(src=scan_src_ip, dst=dst_ip) / TCP(dport=port, sport=55555)
    sendp(packet, iface=iface, verbose=0)

print("[✓] Test traffic sent")
