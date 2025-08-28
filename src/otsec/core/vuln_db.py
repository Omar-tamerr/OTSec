# src/otsec/core/vuln_db.py
"""
YAML-backed IoT/OT vulnerability hints & signatures with safe built-ins.

Load order (merged in this order):
  1) Built-in defaults in this file
  2) Packaged YAML at otsec/data/vulns.yaml (if present)
  3) External YAML pointed by env var OTSEC_VULN_DB (if present)

YAML schema:
  hints:
    "<service-name>":
      - "hint string"
      - ...
  signatures:
    - proto: "HTTP|RTSP|MQTT|BACnet|GENERIC"
      needle: "text or regex"
      regex: true|false   # optional, default false
      notes:
        - "CVE-..., advisory, or remediation"
        - ...
"""

from __future__ import annotations
from typing import Dict, List, Tuple, Any
import os
import re

# Optional: PyYAML
try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # gracefully handle if not installed

# Python 3.9+ stdlib resource access
try:
    from importlib.resources import files as pkg_files
except Exception:
    pkg_files = None

# ---------------- Built-in minimal DB (safe defaults) ----------------

_BUILTIN_HINTS: Dict[str, List[str]] = {
    "Modbus (ICS)": [
        "Insecure by design (no authentication, plaintext).",
        "Risk: register read/write manipulation, coil control.",
        "Mitigate: segment network, gateway filtering, monitor unexpected function codes.",
    ],
    "BACnet (Building Automation)": [
        "Who-Is/I-Am discovery allows easy device enumeration.",
        "Risk: write-property on misconfigured devices.",
        "Mitigate: BBMD hygiene, BACnet/SC, ACLs, segment broadcast domains.",
    ],
    "EtherNet/IP (ICS)": [
        "CIP exposure may allow discovery and tag manipulation on misconfigured devices.",
        "Mitigate: cell/area zones, ACLs, CIP security profiles where available.",
    ],
    "MQTT (IoT)": [
        "Often runs with anonymous access or weak creds.",
        "Risk: subscribe/publish without auth; topic brute-force.",
        "Mitigate: disable anonymous, TLS + authz, audit retained topics.",
    ],
    "MQTT over TLS": [
        "Ensure server/client cert validation and topic-level authorization.",
    ],
    "RTSP (IP Camera)": [
        "Streams are often unauthenticated and unencrypted.",
        "Risk: sniffing/unauthorized viewing on old firmwares.",
        "Mitigate: enforce auth, prefer SRTP, isolate camera VLAN.",
    ],
    "HTTP (Web/IoT)": [
        "Default creds and outdated embedded servers are common.",
        "Risk: RCE, info leak, auth bypass (Boa, GoAhead, RomPager).",
        "Mitigate: change defaults, update firmware, block mgmt from untrusted nets.",
    ],
    "HTTP-alt (IoT)": [
        "Same risks as HTTP; check alternative web UI on this port.",
    ],
    "HTTPS (Web/IoT)": [
        "Verify TLS config and firmware patch level; embedded servers are often old.",
    ],
    "HTTPS-alt (IoT)": [
        "Alternate HTTPS admin UI; confirm cert and patch level.",
    ],
    "Telnet (Legacy/IoT)": [
        "Legacy remote shell; often default/weak creds.",
        "Mitigate: disable Telnet, use SSH with keys, segment mgmt.",
    ],
    "SSH (IoT/Embedded)": [
        "Harden auth (keys only) and restrict management networks.",
    ],
}

# Built-in signatures (safe, common)
# Use concise, *indicative* notes to avoid false positives across distros with backports.
_BUILTIN_SIGNATURES: List[Dict[str, Any]] = [
    # IoT/embedded web servers
    {"proto": "HTTP", "needle": "Boa",      "regex": False, "notes": ["CVE-2017-9833 – Boa info leak/DoS (check version)."]},
    {"proto": "HTTP", "needle": "GoAhead",  "regex": False, "notes": ["CVE-2017-17562 – GoAhead overflow (verify version)."]},
    {"proto": "HTTP", "needle": "RomPager", "regex": False, "notes": ["CVE-2014-9222 – Misfortune Cookie."]},
    {"proto": "HTTP", "needle": "Basic realm=\"", "regex": False, "notes": ["HTTP Basic auth exposed; verify default creds."]},

    # MQTT
    {"proto": "MQTT", "needle": "Mosquitto", "regex": False, "notes": ["CVE-2017-7653 – Mosquitto auth bypass (<1.4.15)."]},

    # RTSP / cameras
    {"proto": "RTSP", "needle": "Dahua",     "regex": False, "notes": ["CVE-2017-7921 – Dahua auth bypass (check lineage)."]},
    {"proto": "RTSP", "needle": "Hikvision", "regex": False, "notes": ["Known auth bypass family in older Hikvision firmware."]},

    # Generic Apache example (safe: advisory-level, not hard CVE claim)
    {"proto": "HTTP", "needle": "Apache/",       "regex": False, "notes": ["Apache detected — review version & distro advisories."]},
    {"proto": "HTTP", "needle": r"Apache/2\.4\.18", "regex": True,  "notes": ["Outdated Apache banner (2.4.18). Check backports & update."]},
]

# ---------------- YAML loaders & merge ----------------

def _merge_hints(dst: Dict[str, List[str]], src: Dict[str, List[str]]) -> None:
    for k, v in (src or {}).items():
        lst = dst.setdefault(k, [])
        for item in v or []:
            s = str(item)
            if s not in lst:
                lst.append(s)

def _merge_sigs_list(dst_list: List[dict], src_list: List[dict]) -> None:
    for item in src_list or []:
        proto = str(item.get("proto", "") or "GENERIC")
        needle = str(item.get("needle", "")).strip()
        if not needle:
            continue
        notes = [str(x) for x in (item.get("notes") or [])]
        is_regex = bool(item.get("regex", False))
        dst_list.append({"proto": proto, "needle": needle, "notes": notes, "regex": is_regex})

def _load_yaml_dict(path: str) -> dict:
    if not yaml:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def _load_packaged_yaml() -> dict:
    if not (pkg_files and yaml):
        return {}
    try:
        res = pkg_files("otsec.data").joinpath("vulns.yaml")
        if res and res.is_file():
            with res.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}

# Loaded DB (immutable for callers)
_HINTS: Dict[str, List[str]] = dict(_BUILTIN_HINTS)
_SIGNATURES_LIST: List[Dict[str, Any]] = list(_BUILTIN_SIGNATURES)

# Merge packaged YAML (if present)
_pack = _load_packaged_yaml()
_merge_hints(_HINTS, _pack.get("hints") or {})
_merge_sigs_list(_SIGNATURES_LIST, _pack.get("signatures") or [])

# Merge external YAML (if env var set)
_ext_path = os.environ.get("OTSEC_VULN_DB", "").strip()
if _ext_path:
    _ext = _load_yaml_dict(_ext_path)
    _merge_hints(_HINTS, _ext.get("hints") or {})
    _merge_sigs_list(_SIGNATURES_LIST, _ext.get("signatures") or [])

# ---------------- Utilities ----------------

def _dedupe_preserve_order(items: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for x in items:
        key = x.strip().lower()
        if key not in seen:
            seen.add(key)
            out.append(x)
    return out

# ---------------- Public API ----------------

def get_hints_for_services(services: List[str]) -> List[str]:
    out: List[str] = []
    for svc in services or []:
        out.extend(_HINTS.get(svc, []))
    return _dedupe_preserve_order(out)

def get_cves_from_fingerprints(fps: Dict[str, str]) -> List[str]:
    """
    fps keys may include:
      http_firstline, http_server, http_title,
      rtsp_banner, mqtt_banner, ...
    Matching considers the *proto* inferred from the key:
      - keys starting with 'http' → HTTP
      - 'rtsp' → RTSP
      - 'mqtt' → MQTT
      - 'bacnet' → BACnet
      - otherwise → GENERIC
    """
    matches: List[str] = []
    corpus: List[Tuple[str, str]] = []

    for k, v in (fps or {}).items():
        if not v:
            continue
        proto = (
            "HTTP" if k.startswith("http") else
            "RTSP" if k.startswith("rtsp") else
            "MQTT" if k.startswith("mqtt") else
            "BACnet" if k.startswith("bacnet") else
            "GENERIC"
        )
        corpus.append((proto, str(v)))

    # Evaluate rules
    for proto, text in corpus:
        tlow = text.lower()
        for sig in _SIGNATURES_LIST:
            sproto = sig["proto"]
            needle = sig["needle"]
            notes  = sig.get("notes", [])
            is_rx  = bool(sig.get("regex", False))

            if sproto != proto:
                continue

            matched = False
            if is_rx:
                try:
                    if re.search(needle, text, re.I):
                        matched = True
                except re.error:
                    # bad regex → skip gracefully
                    continue
            else:
                if needle.lower() in tlow:
                    matched = True

            if matched:
                matches.extend(notes)

    return _dedupe_preserve_order(matches)

