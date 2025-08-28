# src/otsec/core/discovery.py

from __future__ import annotations

import os
import sys
import re
import ssl
import json
import socket
import http.client
from typing import List, Dict
from ipaddress import ip_network, IPv4Network
from scapy.all import sr1, IP, TCP, conf

# ------------------ Ports & labels ------------------

PORT_SERVICES: Dict[int, str] = {
    # ICS / OT
    502: "Modbus (ICS)",
    20000: "DNP3 (ICS)",
    47808: "BACnet (Building Automation)",
    44818: "EtherNet/IP (ICS)",

    # IoT messaging
    1883: "MQTT (IoT)",
    8883: "MQTT over TLS",

    # Cameras / media
    554: "RTSP (IP Camera)",

    # Web / mgmt (very common on embedded)
    80: "HTTP (Web/IoT)",
    81: "HTTP-alt (IoT)",
    8000: "HTTP-alt (IoT)",
    8080: "HTTP-alt (IoT)",
    8443: "HTTPS-alt (IoT)",
    443: "HTTPS (Web/IoT)",

    # Embedded admin
    23: "Telnet (Legacy/IoT)",
    22: "SSH (IoT/Embedded)",
}

COMMON_PORTS: List[int] = list(PORT_SERVICES.keys())

# Optional: risk map (used by shell/info rendering)
SERVICE_RISK: Dict[str, tuple[str, str]] = {
    "Modbus (ICS)": ("⚡", "High"),
    "DNP3 (ICS)": ("⚡", "High"),
    "BACnet (Building Automation)": ("🏢", "High"),
    "EtherNet/IP (ICS)": ("⚙️", "High"),
    "MQTT (IoT)": ("📡", "Medium"),
    "MQTT over TLS": ("📡", "Medium"),
    "RTSP (IP Camera)": ("🎥", "Medium"),
    "HTTP (Web/IoT)": ("🌐", "Medium"),
    "HTTP-alt (IoT)": ("🌐", "Medium"),
    "HTTPS (Web/IoT)": ("🔒", "Medium"),
    "HTTPS-alt (IoT)": ("🔒", "Medium"),
    "Telnet (Legacy/IoT)": ("🛠️", "High"),
    "SSH (IoT/Embedded)": ("🛠️", "Medium"),
}

# ------------------ Priv check ------------------

def require_root():
    """Exit if not running as root (needed for raw SYN scans)."""
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[!] OTSec requires root privileges for raw socket scanning.")
        print("    Try: sudo otsec scan <CIDR>   or use --safe for TCP connect mode.")
        sys.exit(1)

# ------------------ Helpers ------------------

def _iter_targets(cidr_or_ip: str) -> List[str]:
    """
    Accepts single IP like '10.0.0.5' or CIDR like '10.0.0.0/24'.
    Returns a list of string IPs to scan.
    """
    net: IPv4Network = ip_network(cidr_or_ip, strict=False)
    if net.num_addresses == 1:
        return [str(net.network_address)]
    return [str(h) for h in net.hosts()]

def classify(open_ports: List[int]) -> str:
    """Quick & simple proto hint from open ports (priority order)."""
    if 502 in open_ports:   return "modbus"
    if 20000 in open_ports: return "dnp3"
    if 47808 in open_ports: return "bacnet"
    if 44818 in open_ports: return "ethernet/ip"
    if 1883 in open_ports:  return "mqtt"
    if 8883 in open_ports:  return "mqtts"
    if 554 in open_ports:   return "camera/rtsp"
    if any(p in open_ports for p in (443, 8443)): return "https/iot"
    if any(p in open_ports for p in (80, 81, 8000, 8080)): return "http/iot"
    if 23 in open_ports:    return "telnet"
    if 22 in open_ports:    return "ssh"
    return "unknown"

# ------------------ Fingerprinters (lightweight) ------------------

TITLE_RE = re.compile(r"<title>(.*?)</title>", re.I | re.S)

def _http_fingerprint(ip: str, port: int = 80, timeout: float = 2.0) -> dict:
    """
    Try HEAD first; if no Server header, fall back to GET / (small read) and parse title.
    """
    out: Dict[str, str] = {}
    try:
        # HEAD
        conn = http.client.HTTPConnection(ip, port=port, timeout=timeout)
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        ver_map = {10: "1.0", 11: "1.1", 20: "2.0"}
        ver = ver_map.get(resp.version, str(resp.version))
        out["http_firstline"] = f"HTTP/{ver} {resp.status} {resp.reason}"
        server = resp.getheader("Server", "")
        if server:
            out["http_server"] = server
        conn.close()

        # GET fallback for Server/Title
        if not out.get("http_server") or "http_title" not in out:
            conn = http.client.HTTPConnection(ip, port=port, timeout=timeout)
            conn.request("GET", "/")
            resp = conn.getresponse()
            server = resp.getheader("Server", "")
            if server:
                out["http_server"] = server
            try:
                body = resp.read(4096).decode(errors="ignore")
                m = TITLE_RE.search(body)
                if m:
                    out["http_title"] = m.group(1).strip()[:120]
            except Exception:
                pass
            conn.close()
    except Exception:
        pass
    return out

def _https_fingerprint(ip: str, port: int = 443, timeout: float = 3.0) -> dict:
    """
    HTTPS fingerprint: do a HEAD over TLS (no cert verify), then GET fallback + <title>.
    """
    out: Dict[str, str] = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # HEAD
        conn = http.client.HTTPSConnection(ip, port=port, timeout=timeout, context=ctx)
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        ver_map = {10: "1.0", 11: "1.1", 20: "2.0"}
        ver = ver_map.get(resp.version, str(resp.version))
        out["http_firstline"] = f"HTTPS/{ver} {resp.status} {resp.reason}"
        server = resp.getheader("Server", "")
        if server:
            out["http_server"] = server
        conn.close()

        # GET fallback for Server/Title
        if not out.get("http_server") or "http_title" not in out:
            conn = http.client.HTTPSConnection(ip, port=port, timeout=timeout, context=ctx)
            conn.request("GET", "/")
            resp = conn.getresponse()
            server = resp.getheader("Server", "")
            if server:
                out["http_server"] = server
            try:
                body = resp.read(4096).decode(errors="ignore")
                m = TITLE_RE.search(body)
                if m:
                    out["http_title"] = m.group(1).strip()[:120]
            except Exception:
                pass
            conn.close()
    except Exception:
        pass
    return out

def _rtsp_fingerprint(ip: str, port: int = 554, timeout: float = 2.0) -> dict:
    out: Dict[str, str] = {}
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        payload = (
            f"OPTIONS rtsp://{ip}/ RTSP/1.0\r\n"
            "CSeq: 1\r\n"
            "User-Agent: OTSec\r\n\r\n"
        ).encode()
        s.sendall(payload)
        data = s.recv(512).decode(errors="ignore")
        out["rtsp_banner"] = (data.split("\r\n")[0] if data else "")[:200]
        s.close()
    except Exception:
        pass
    return out

def _mqtt_fingerprint(ip: str, port: int = 1883, timeout: float = 2.0) -> dict:
    """
    Minimal/non-intrusive MQTT probe: just see if broker talks first.
    For full protocol negotiation, switch to pymodbus/equivalent MQTT lib later.
    """
    out: Dict[str, str] = {}
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        try:
            data = s.recv(96)
            if data:
                out["mqtt_banner"] = data.hex()[:96]
        except Exception:
            pass
        s.close()
    except Exception:
        pass
    return out

def fingerprint_host(ip: str, open_ports: List[int], timeout: float = 2.0) -> dict:
    """
    Collect lightweight fingerprints from open ports to feed vuln matching.
    """
    fp: Dict[str, str] = {}

    # HTTP variants
    for p in (80, 81, 8000, 8080):
        if p in open_ports:
            fp.update(_http_fingerprint(ip, p, timeout))

    # HTTPS variants
    for p in (443, 8443):
        if p in open_ports:
            fp.update(_https_fingerprint(ip, p, timeout))

    # RTSP
    if 554 in open_ports:
        fp.update(_rtsp_fingerprint(ip, 554, timeout))

    # MQTT
    if 1883 in open_ports:
        fp.update(_mqtt_fingerprint(ip, 1883, timeout))
    if 8883 in open_ports:
        # Placeholder note that TLS broker is visible; extend with real MQTT/TLS probe later.
        fp["mqtt_tls"] = "open (TLS not probed)"

    return fp

# ------------------ Scanner (safe/raw + optional vuln) ------------------

def scan_subnet(
    cidr: str,
    timeout: float = 0.5,
    safe: bool = False,
    verbose: bool = False,
    vuln: bool = False,
) -> List[dict]:
    """
    Scan a subnet or single IP for devices with common OT/IoT ports open.

    - safe=True   → TCP connect scan (no root needed)
    - verbose=True→ per-probe logs + fingerprint dump
    - vuln=True   → add fingerprints + vulnerability hints + CVEs using vuln_db

    Returns a list of dicts like:
      {
        "ip": "x.x.x.x",
        "open_ports": [..],
        "services": ["Modbus (ICS)", ...],
        "proto_hint": "modbus|mqtt|...",
        # present only when vuln=True:
        "fingerprints": {...},
        "vuln_hints": [...],
        "vuln_cves": [...]
      }
    """
    results: List[dict] = []
    conf.verb = 0  # silence scapy chatter

    if vuln:
        # Lazy import to avoid cycles and optional dependency issues
        from otsec.core.vuln_db import get_hints_for_services, get_cves_from_fingerprints

    ips = _iter_targets(cidr)

    if not safe:
        require_root()

    for ip_str in ips:
        host_info = {"ip": ip_str, "open_ports": [], "services": []}

        for port in COMMON_PORTS:
            if safe:
                # TCP connect scan (user-mode)
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(timeout)
                    s.connect((ip_str, port))
                    host_info["open_ports"].append(port)
                    host_info["services"].append(PORT_SERVICES.get(port, f"Unknown({port})"))
                    if verbose:
                        print(f"[VERBOSE] {ip_str}:{port} → OPEN (TCP connect)")
                except (socket.timeout, ConnectionRefusedError, OSError):
                    if verbose:
                        print(f"[VERBOSE] {ip_str}:{port} → CLOSED/filtered")
                finally:
                    try:
                        s.close()
                    except Exception:
                        pass
            else:
                # Raw SYN scan (root)
                pkt = IP(dst=ip_str) / TCP(dport=port, flags="S")
                resp = sr1(pkt, timeout=timeout)
                if resp and resp.haslayer(TCP) and (resp[TCP].flags & 0x12):  # SYN/ACK
                    host_info["open_ports"].append(port)
                    host_info["services"].append(PORT_SERVICES.get(port, f"Unknown({port})"))
                    if verbose:
                        print(f"[VERBOSE] {ip_str}:{port} → OPEN (SYN-ACK)")
                else:
                    if verbose:
                        print(f"[VERBOSE] {ip_str}:{port} → CLOSED/filtered")

        if not host_info["open_ports"]:
            continue

        host_info["proto_hint"] = classify(host_info["open_ports"])

        if vuln:
            fp = fingerprint_host(ip_str, host_info["open_ports"], timeout=1.5)
            if fp:
                host_info["fingerprints"] = fp
                if verbose:
                    # Helpful for tuning signatures in YAML
                    print(f"[VERBOSE] Fingerprints for {ip_str}: {json.dumps(fp, ensure_ascii=False)}")
            # Map hints by service and CVEs by banners
            hints = get_hints_for_services(host_info.get("services", []))
            cves = get_cves_from_fingerprints(fp)
            if hints:
                host_info["vuln_hints"] = hints
            if cves:
                host_info["vuln_cves"] = cves

        results.append(host_info)

    return results

