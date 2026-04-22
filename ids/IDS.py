import ipaddress
import json
import os
import socket
import subprocess
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Deque

import requests
from dotenv import load_dotenv
from scapy.all import IP, TCP, Raw, sniff

load_dotenv()


def _read_csv(name: str, default: str = "") -> set[str]:
    raw = os.getenv(name, default)
    return {item.strip() for item in raw.split(",") if item.strip()}


def _read_int_csv(name: str, default: str = "") -> set[int]:
    values = set()
    for item in _read_csv(name, default):
        try:
            values.add(int(item))
        except ValueError:
            pass
    return values


def _read_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name, str(default)).strip().lower()
    return value in {"1", "true", "yes", "on"}


MALICIOUS_IPS = _read_csv("MALICIOUS_IPS", "141.98.11.11,198.51.100.99")
SUSPICIOUS_PORTS = _read_int_csv("SUSPICIOUS_PORTS", "4444,31337,4445")
TRUSTED_IPS = _read_csv("TRUSTED_IPS", "8.8.8.8,1.1.1.1")

PROTECTED_HOSTS = _read_csv("PROTECTED_HOSTS", "")
HTTP_PORTS = _read_int_csv("HTTP_PORTS", "80,8080,8000")
HTTPS_PORTS = _read_int_csv("HTTPS_PORTS", "443,8443")

ANOMALY_THRESHOLD = int(os.getenv("ANOMALY_THRESHOLD", "15"))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "5"))

PORT_SCAN_THRESHOLD = int(os.getenv("PORT_SCAN_THRESHOLD", "10"))
PORT_SCAN_WINDOW = int(os.getenv("PORT_SCAN_WINDOW", "10"))

IGNORE_PRIVATE_TO_PRIVATE = _read_bool("IGNORE_PRIVATE_TO_PRIVATE", False)

ENABLE_AUTO_BLOCK = _read_bool("ENABLE_AUTO_BLOCK", False)
AUTO_BLOCK_ON = os.getenv("AUTO_BLOCK_ON", "CRITICAL").strip().upper()

THREAT_API_URL = os.getenv("THREAT_API_URL", "https://api.abuseipdb.com/api/v2/check")
API_KEY = os.getenv("API_KEY", "").strip()
ABUSE_SCORE_THRESHOLD = int(os.getenv("ABUSE_SCORE_THRESHOLD", "50"))

LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "/app/logs/alerts.json")
BLOCKED_IPS_PATH = os.getenv("BLOCKED_IPS_PATH", "/app/logs/blocked_ips.json")
GEO_API_URL = os.getenv("GEO_API_URL", "http://ip-api.com/json")
SNIFF_IFACES_RAW = os.getenv("SNIFF_IFACES", "")

# prevents one attack from creating hundreds of duplicate alerts
ATTACK_COOLDOWN = int(os.getenv("ATTACK_COOLDOWN", "15"))

os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
os.makedirs(os.path.dirname(BLOCKED_IPS_PATH), exist_ok=True)


def parse_ifaces() -> list[str] | None:
    if not SNIFF_IFACES_RAW.strip():
        return None
    return [iface.strip() for iface in SNIFF_IFACES_RAW.split(",") if iface.strip()]


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_local_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
        )
    except ValueError:
        return ip in {"localhost"}


def get_self_ips() -> set[str]:
    ips = {"127.0.0.1", "::1", "localhost"}

    try:
        hostname = socket.gethostname()
        for result in socket.getaddrinfo(hostname, None):
            candidate = result[4][0]
            if is_valid_ip(candidate):
                ips.add(candidate)
    except Exception:
        pass

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ips.add(sock.getsockname()[0])
        sock.close()
    except Exception:
        pass

    return ips


SELF_IPS = get_self_ips()
SNIFF_IFACES = parse_ifaces()


def is_self_ip(ip: str) -> bool:
    return ip in SELF_IPS


def is_trusted_ip(ip: str) -> bool:
    return ip in TRUSTED_IPS


def should_skip_api_lookup(ip: str) -> bool:
    return not ip or is_local_ip(ip) or is_self_ip(ip) or is_trusted_ip(ip)


class JSONFileLogger:
    def __init__(self, filepath: str) -> None:
        self.filepath = filepath

    def log(
        self,
        severity: str,
        message: str,
        attack_type: str,
        geo: str,
        src_ip: str,
        dst_ip: str,
        src_port: int | None = None,
        dst_port: int | None = None,
        details: dict | None = None,
    ) -> None:
        record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "severity": severity,
            "message": message,
            "attack_type": attack_type,
            "geo": geo,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "details": details or {},
        }
        try:
            with open(self.filepath, "a", encoding="utf-8") as file:
                file.write(json.dumps(record) + "\n")
        except Exception as exc:
            print(f"[ERROR] failed to write to log file: {exc}")


class NIDS:
    def __init__(self) -> None:
        self.ip_traffic: defaultdict[tuple[str, str, int], Deque[float]] = defaultdict(deque)
        self.scanned_ports: defaultdict[tuple[str, str], Deque[tuple[float, int]]] = defaultdict(deque)
        self.geo_cache: dict[str, str] = {}
        self.abuse_cache: dict[str, bool] = {}
        self.blocked_ips: set[str] = set()
        self.last_alert_time: defaultdict[tuple[str, str], float] = defaultdict(float)
        self.active_attacks: dict[tuple[str, str, int | None, str], float] = {}
        self.logger = JSONFileLogger(LOG_FILE_PATH)
        self._load_blocked_ips()

    def _load_blocked_ips(self) -> None:
        if not os.path.exists(BLOCKED_IPS_PATH):
            return
        try:
            with open(BLOCKED_IPS_PATH, "r", encoding="utf-8") as file:
                ips = json.load(file)
            if isinstance(ips, list):
                self.blocked_ips.update(str(ip) for ip in ips)
        except Exception as exc:
            print(f"[ERROR] failed to load blocked IPs: {exc}")

    def _save_blocked_ips(self) -> None:
        try:
            with open(BLOCKED_IPS_PATH, "w", encoding="utf-8") as file:
                json.dump(sorted(self.blocked_ips), file, indent=2)
        except Exception as exc:
            print(f"[ERROR] failed to save blocked IPs: {exc}")

    def is_protected_target(self, ip: str) -> bool:
        if PROTECTED_HOSTS:
            return ip in PROTECTED_HOSTS
        return is_self_ip(ip)

    def looks_like_http(self, packet) -> bool:
        if not packet.haslayer(Raw):
            return False
        try:
            payload = packet[Raw].load.decode(errors="ignore").upper()
        except Exception:
            return False

        methods = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")
        return payload.startswith(methods) or "HTTP/" in payload

    def should_alert_once(self, src_ip: str, dst_ip: str, dst_port: int | None, attack_type: str, now: float) -> bool:
        key = (src_ip, dst_ip, dst_port, attack_type)
        last_seen = self.active_attacks.get(key, 0.0)

        if now - last_seen < ATTACK_COOLDOWN:
            return False

        self.active_attacks[key] = now
        return True

    def get_geo(self, ip: str) -> str:
        if is_local_ip(ip):
            return "Local, Local Network"

        if ip in self.geo_cache:
            return self.geo_cache[ip]

        try:
            response = requests.get(f"{GEO_API_URL}/{ip}", timeout=2)
            data = response.json()
            city = data.get("city", "Unknown")
            country = data.get("country", "Unknown")
            geo = f"{city}, {country}" if city != "Unknown" or country != "Unknown" else "Unknown, Unknown"
        except Exception:
            geo = "Unknown, Unknown"

        self.geo_cache[ip] = geo
        return geo

    def auto_block(self, ip: str) -> bool:
        if not ENABLE_AUTO_BLOCK:
            return False

        if ip in self.blocked_ips or is_self_ip(ip) or is_trusted_ip(ip) or is_local_ip(ip):
            return False

        commands = [
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
            ["iptables", "-I", "DOCKER-USER", "1", "-s", ip, "-j", "DROP"],
        ]

        try:
            check = subprocess.run(commands[0], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if check.returncode != 0:
                subprocess.run(commands[1], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(commands[2], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            self.blocked_ips.add(ip)
            self._save_blocked_ips()
            print(f"[AUTO-RESPONSE] Blocked {ip} via iptables")
            return True
        except Exception as exc:
            print(f"[ERROR] Failed to block {ip}: {exc}")
            return False

    def check_api(self, ip: str) -> bool:
        if not API_KEY or should_skip_api_lookup(ip):
            return False

        if ip in self.abuse_cache:
            return self.abuse_cache[ip]

        try:
            response = requests.get(
                THREAT_API_URL,
                headers={"Key": API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=5,
            )
            if response.status_code == 200:
                score = response.json().get("data", {}).get("abuseConfidenceScore", 0)
                result = int(score) >= ABUSE_SCORE_THRESHOLD
                self.abuse_cache[ip] = result
                return result
        except Exception as exc:
            print(f"[ERROR] API check failed for {ip}: {exc}")

        self.abuse_cache[ip] = False
        return False

    def trigger_alert(
        self,
        severity: str,
        message: str,
        attack_type: str,
        geo: str,
        src_ip: str,
        dst_ip: str,
        src_port: int | None = None,
        dst_port: int | None = None,
        reason: str = "",
    ) -> None:
        key = (src_ip, reason or attack_type)
        now = time.time()

        if now - self.last_alert_time[key] < 2:
            return

        self.last_alert_time[key] = now

        print(f"[{severity}] {message} [{attack_type}] ({src_ip} -> {dst_ip}) Loc: {geo} - {reason}")
        self.logger.log(
            severity=severity,
            message=message,
            attack_type=attack_type,
            geo=geo,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            details={"reason": reason},
        )

    def analyze_packet(self, packet) -> None:
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if is_trusted_ip(src_ip) or is_trusted_ip(dst_ip):
            return

        if is_self_ip(src_ip) and is_self_ip(dst_ip):
            return

        noisy_prefixes = ("172.17.", "172.18.", "172.19.", "192.168.65.")
        if src_ip.startswith(noisy_prefixes) and dst_ip.startswith(noisy_prefixes):
            return

        src_port = packet[TCP].sport if packet.haslayer(TCP) else None
        dst_port = packet[TCP].dport if packet.haslayer(TCP) else None

        if dst_ip == "255.255.255.255":
            return

        if (
            is_local_ip(src_ip)
            and is_local_ip(dst_ip)
            and dst_port is not None
            and dst_port > 1024
            and src_port is not None
            and src_port > 1024
        ):
            if dst_port not in SUSPICIOUS_PORTS and not self.is_protected_target(dst_ip):
                return

        if IGNORE_PRIVATE_TO_PRIVATE and is_local_ip(src_ip) and is_local_ip(dst_ip):
            if not self.is_protected_target(dst_ip):
                return

        if src_ip in self.blocked_ips or dst_ip in self.blocked_ips:
            blocked_ip = src_ip if src_ip in self.blocked_ips else dst_ip
            geo = self.get_geo(blocked_ip)
            self.trigger_alert(
                "CRITICAL",
                "Blocked IP Traffic Dropped",
                "Blocked IP",
                geo,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                "Traffic involving a blocked IP was observed.",
            )
            return

        reasons: list[str] = []
        attack_type = "Unknown"
        local_detected = False
        now = time.time()

        if src_ip in MALICIOUS_IPS:
            reasons.append("Source IP present in local blocklist")
            attack_type = "Malicious IP"
            local_detected = True

        if dst_port in SUSPICIOUS_PORTS or src_port in SUSPICIOUS_PORTS:
            reasons.append("Suspicious port usage")
            attack_type = "Suspicious Port"
            local_detected = True

        ip_count = 0
        if dst_port is not None:
            traffic_key = (src_ip, dst_ip, dst_port)
            self.ip_traffic[traffic_key].append(now)

            while self.ip_traffic[traffic_key] and self.ip_traffic[traffic_key][0] < now - RATE_LIMIT_WINDOW:
                self.ip_traffic[traffic_key].popleft()

            ip_count = len(self.ip_traffic[traffic_key])

        is_incoming_to_protected = self.is_protected_target(dst_ip)
        is_http_port = dst_port in HTTP_PORTS if dst_port is not None else False
        is_https_port = dst_port in HTTPS_PORTS if dst_port is not None else False

        # anomaly / flood detection with cooldown
        if ip_count > ANOMALY_THRESHOLD and is_incoming_to_protected:
            candidate_attack = None
            candidate_reason = None

            if is_http_port:
                if self.looks_like_http(packet):
                    candidate_attack = "HTTP Flood"
                    candidate_reason = (
                        f"Possible HTTP flood: {ip_count} packets to protected web service in {RATE_LIMIT_WINDOW}s"
                    )
                else:
                    candidate_attack = "Brute Force / DoS"
                    candidate_reason = (
                        f"High-rate traffic to protected web port ({ip_count} packets in {RATE_LIMIT_WINDOW}s)"
                    )

            elif is_https_port:
                candidate_attack = "Brute Force / DoS"
                candidate_reason = (
                    f"Suspicious HTTPS traffic spike to protected host ({ip_count} packets in {RATE_LIMIT_WINDOW}s)"
                )

            elif dst_port == 22:
                candidate_attack = "SSH Brute Force"
                candidate_reason = (
                    f"High traffic anomaly to SSH service (> {ANOMALY_THRESHOLD} in {RATE_LIMIT_WINDOW}s)"
                )

            elif dst_port is not None and dst_port < 1024:
                candidate_attack = "Brute Force / DoS"
                candidate_reason = (
                    f"High traffic anomaly to protected service (> {ANOMALY_THRESHOLD} in {RATE_LIMIT_WINDOW}s)"
                )

            if candidate_attack and candidate_reason:
                if self.should_alert_once(src_ip, dst_ip, dst_port, candidate_attack, now):
                    reasons.append(candidate_reason)
                    attack_type = candidate_attack
                    local_detected = True

        # port scan detection with cooldown
        if dst_port is not None and is_incoming_to_protected:
            history = self.scanned_ports[(src_ip, dst_ip)]
            history.append((now, dst_port))

            while history and history[0][0] < now - PORT_SCAN_WINDOW:
                history.popleft()

            unique_ports = {port for _, port in history}

            if len(unique_ports) >= PORT_SCAN_THRESHOLD:
                if self.should_alert_once(src_ip, dst_ip, None, "Port Scan", now):
                    reasons.append(
                        f"Port scan detected ({len(unique_ports)} unique ports in {PORT_SCAN_WINDOW}s)"
                    )
                    attack_type = "Port Scan"
                    local_detected = True

        if not local_detected:
            return

        severity = "LOW"

        if len(reasons) >= 2:
            severity = "MEDIUM"

        if attack_type in {"Port Scan", "SSH Brute Force", "HTTP Flood", "Suspicious Port"}:
            severity = "HIGH"

        if attack_type == "Brute Force / DoS":
            severity = "MEDIUM"

        if attack_type == "Malicious IP":
            severity = "CRITICAL"

        if not is_local_ip(src_ip) and self.check_api(src_ip):
            reasons.append(f"AbuseIPDB score >= {ABUSE_SCORE_THRESHOLD}")
            severity = "CRITICAL"
            attack_type = "Malicious IP"

        geo = self.get_geo(src_ip)

        self.trigger_alert(
            severity,
            "Threat Detected",
            attack_type,
            geo,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            ", ".join(reasons),
        )

        if ENABLE_AUTO_BLOCK and severity == AUTO_BLOCK_ON:
            self.auto_block(src_ip)

    def analyze_packet_safe(self, packet) -> None:
        try:
            self.analyze_packet(packet)
        except Exception as exc:
            print(f"[ERROR] Exception processing packet: {exc}")


def start_nids() -> None:
    print("🚀 NIDS Started")
    print(f"Logging to: {LOG_FILE_PATH}")
    print(f"Interfaces: {SNIFF_IFACES if SNIFF_IFACES else 'all available interfaces'}")
    print(f"Protected hosts: {PROTECTED_HOSTS if PROTECTED_HOSTS else 'self IPs only'}")
    print(f"Attack cooldown: {ATTACK_COOLDOWN}s")
    print(f"Auto block enabled: {ENABLE_AUTO_BLOCK} ({AUTO_BLOCK_ON})")
    print("Press Ctrl+C to stop\n")

    nids = NIDS()
    sniff_kwargs = {"prn": nids.analyze_packet_safe, "store": 0}

    if SNIFF_IFACES:
        sniff_kwargs["iface"] = SNIFF_IFACES

    sniff(**sniff_kwargs)


if __name__ == "__main__":
    start_nids()
