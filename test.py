#!/usr/bin/env python3
import argparse
import os
import sys
import time
from scapy.all import Ether, IP, TCP, sendp, get_if_hwaddr


def require_root():
    if os.geteuid() != 0:
        print("[ERROR] Run this script with sudo/root.")
        sys.exit(1)


def build_parser():
    parser = argparse.ArgumentParser(description="Advanced Linux test traffic generator for DevSecOps IDS")
    parser.add_argument("--iface", required=True, help="Network interface, e.g. eth0 / ens33 / enp0s3")
    parser.add_argument("--target-ip", required=True, help="Target IP to send packets to")
    parser.add_argument("--target-mac", help="Target MAC address. If omitted, interface MAC will be used")
    parser.add_argument(
        "--mode",
        choices=["http_flood", "port_scan", "suspicious_port", "malicious_ip", "mixed"],
        default="mixed",
        help="Type of attack simulation",
    )
    parser.add_argument("--count", type=int, default=35, help="Packet count for flood-type tests")
    parser.add_argument("--delay", type=float, default=0.02, help="Delay between packets in seconds")
    return parser


def send_http_flood(iface, target_ip, target_mac, count, delay):
    print(f"[+] Simulating HTTP flood -> {target_ip}:80 on {iface}")
    src_ip = "45.61.136.85"
    for i in range(count):
        pkt = Ether(dst=target_mac) / IP(src=src_ip, dst=target_ip) / TCP(sport=12000 + i, dport=80)
        sendp(pkt, iface=iface, verbose=0)
        time.sleep(delay)
    print("[✓] HTTP flood sent")


def send_port_scan(iface, target_ip, target_mac, delay):
    print(f"[+] Simulating port scan -> {target_ip} on {iface}")
    src_ip = "91.92.109.126"
    for port in range(1, 45):
        pkt = Ether(dst=target_mac) / IP(src=src_ip, dst=target_ip) / TCP(sport=23000 + port, dport=port)
        sendp(pkt, iface=iface, verbose=0)
        time.sleep(delay)
    print("[✓] Port scan sent")


def send_suspicious_port(iface, target_ip, target_mac, delay):
    print(f"[+] Simulating suspicious-port traffic -> {target_ip}:4444 and :31337")
    src_ip = "103.24.77.190"
    suspicious_ports = [4444, 31337, 4444, 31337, 4444, 31337]
    for i, port in enumerate(suspicious_ports):
        pkt = Ether(dst=target_mac) / IP(src=src_ip, dst=target_ip) / TCP(sport=31000 + i, dport=port)
        sendp(pkt, iface=iface, verbose=0)
        time.sleep(delay)
    print("[✓] Suspicious-port traffic sent")


def send_malicious_ip(iface, target_ip, target_mac, delay):
    print(f"[+] Simulating malicious IP traffic -> {target_ip}")
    src_ip = "141.98.11.11"
    for i in range(12):
        pkt = Ether(dst=target_mac) / IP(src=src_ip, dst=target_ip) / TCP(sport=41000 + i, dport=80)
        sendp(pkt, iface=iface, verbose=0)
        time.sleep(delay)
    print("[✓] Malicious-IP traffic sent")


def send_mixed(iface, target_ip, target_mac, count, delay):
    print("[+] Running mixed scenario")
    send_http_flood(iface, target_ip, target_mac, count, delay)
    time.sleep(1)
    send_port_scan(iface, target_ip, target_mac, delay)
    time.sleep(1)
    send_suspicious_port(iface, target_ip, target_mac, delay)
    time.sleep(1)
    send_malicious_ip(iface, target_ip, target_mac, delay)
    print("[✓] Mixed scenario complete")


def main():
    require_root()
    parser = build_parser()
    args = parser.parse_args()

    target_mac = args.target_mac or get_if_hwaddr(args.iface)

    print("🛡️ Advanced DevSecOps IDS Test Generator")
    print(f"Interface : {args.iface}")
    print(f"Target IP : {args.target_ip}")
    print(f"Target MAC: {target_mac}")
    print(f"Mode      : {args.mode}")
    print()

    if args.mode == "http_flood":
        send_http_flood(args.iface, args.target_ip, target_mac, args.count, args.delay)
    elif args.mode == "port_scan":
        send_port_scan(args.iface, args.target_ip, target_mac, args.delay)
    elif args.mode == "suspicious_port":
        send_suspicious_port(args.iface, args.target_ip, target_mac, args.delay)
    elif args.mode == "malicious_ip":
        send_malicious_ip(args.iface, args.target_ip, target_mac, args.delay)
    else:
        send_mixed(args.iface, args.target_ip, target_mac, args.count, args.delay)

    print("\n[✓] Done. Now check:")
    print("    - dashboard live feed")
    print("    - /api/alerts")
    print("    - docker compose logs -f ids")


if __name__ == "__main__":
    main()
