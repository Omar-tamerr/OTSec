# OTSec - Offensive OT/IoT Security Toolkit
# Copyright (c) 2025 Omar Tamer
# Licensed under the MIT License (see LICENSE file for details)


from __future__ import annotations

import os
import atexit
import shlex
import json
from datetime import datetime
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any

import click
import readline

from otsec.core.banner import banner_text
from otsec.core.discovery import scan_subnet, PORT_SERVICES

# Service risk/emoji map (keep in sync with discovery if you centralize later)
SERVICE_RISK = {
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

HISTFILE = os.path.expanduser("~/.otsec_history")
CONFIGFILE = os.path.expanduser("~/.otsec_config.json")

# ---------- Completion data ----------
ROOT_COMMANDS = [
    "scan", "info", "export", "targets",
    "inject", "modbus", "target",
    "clear", "cls", "help", "exit", "quit", "q",
]
INJECT_SUBS = ["modbus"]
MODBUS_SUBS = ["read"]
TARGET_SUBS = ["set", "pick", "show", "clear"]
COMMON_BOOL_FLAGS = ["--safe", "--verbose", "--vuln", "-s", "-v"]  # includes --vuln
EXPORT_FLAGS = ["--type", "-t"]
MODBUS_READ_FLAGS = ["--target", "--register", "-r", "--count", "-c", "--unit", "-u", "--port", "-p", "--timeout"]
INJECT_MODBUS_FLAGS = [
    "--target", "--register", "-r", "--value", "-v", "--unit", "-u",
    "--port", "-p", "--timeout", "--read-back", "--force"
]


def _print_help():
    click.echo("""
Commands:
  scan <CIDR|IP> [--safe] [--verbose] [--vuln]
      Scan subnet or single IP for OT/IoT devices

  targets
      List last scan results with indices

  info [IP]
      Show details (uses default target if omitted)

  export <path> [--type json|txt|xml]
      Export last scan results

  modbus read [--target IP] --register N [--count 1] [--unit 1] [--port 502]
      Read holding registers (safe, read-only)

  inject modbus [--target IP] --register N --value X [--unit 1] [--port 502]
                [--timeout 3.0] [--read-back] [--force]
      Write Modbus register (lab-only; DRY-RUN by default)

  target set <IP|INDEX>
      Set default target (INDEX from last scan, 1-based)

  target pick <INDEX>
      Same as 'target set <INDEX>'

  target show
      Show default target

  target clear
      Clear default target

  clear | cls
      Clear the screen

  help
      Show this help

  exit | quit | q
      Exit interactive mode

Examples:
  scan 192.168.1.0/24 --safe --vuln
  targets
  target set 1
  info
  export results.json --type json

SAFETY:
  • This toolkit is for authorized lab/testing only.
  • Modbus injection defaults to DRY-RUN. Use --force to actually write (with confirmation).
""")


def _load_history():
    try:
        if os.path.exists(HISTFILE):
            readline.read_history_file(HISTFILE)
    except Exception:
        pass


def _save_history():
    try:
        os.makedirs(os.path.dirname(HISTFILE), exist_ok=True)
        readline.write_history_file(HISTFILE)
    except Exception:
        pass


def _load_config():
    try:
        if os.path.exists(CONFIGFILE):
            with open(CONFIGFILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_config(cfg: dict):
    try:
        with open(CONFIGFILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass


def _export_results(targets, path, fmt="json"):
    """Export scan results in json/txt/xml."""
    if not targets:
        raise ValueError("No results to export. Run a scan first.")

    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    fmt = fmt.lower()

    if fmt == "json":
        payload = {"generated_at_utc": timestamp, "tool": "OTSec", "results": targets}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        return path

    if fmt == "txt":
        lines = [f"OTSec Export - {timestamp}\n"]
        for t in targets:
            lines.append(f"Target: {t['ip']}")
            lines.append(f"  Open Ports : {', '.join(map(str, t['open_ports']))}")
            services = ", ".join(t.get("services", []))
            lines.append(f"  Services   : {services}")
            hints = t.get("vuln_hints", [])
            cves = t.get("vuln_cves", [])
            if hints or cves:
                lines.append("  Security:")
                for h in _dedupe(hints)[:8]:
                    lines.append(f"    • {h}")
                for c in _dedupe(cves)[:8]:
                    lines.append(f"    • {c}")
            lines.append("")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines).rstrip() + "\n")
        return path

    if fmt == "xml":
        root = ET.Element("otsec_export", generated_at_utc=timestamp, tool="OTSec")
        for t in targets:
            host = ET.SubElement(root, "host", ip=t["ip"])
            ports = ET.SubElement(host, "open_ports")
            for p in t["open_ports"]:
                ET.SubElement(ports, "port").text = str(p)
            svcs = ET.SubElement(host, "services")
            for s in t.get("services", []):
                ET.SubElement(svcs, "service").text = s
            if "vuln_hints" in t or "vuln_cves" in t:
                sec = ET.SubElement(host, "security")
                for h in _dedupe(t.get("vuln_hints", [])):
                    ET.SubElement(sec, "hint").text = h
                for c in _dedupe(t.get("vuln_cves", [])):
                    ET.SubElement(sec, "cve").text = c
        tree = ET.ElementTree(root)
        try:
            ET.indent(tree, space="  ")
        except Exception:
            pass
        tree.write(path, encoding="utf-8", xml_declaration=True)
        return path

    raise ValueError("Unsupported export type. Use json, txt, or xml.")


# ---------- Helpers for rendering ----------

def _dedupe(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in items or []:
        key = x.strip().lower()
        if key not in seen:
            seen.add(key)
            out.append(x)
    return out


def _service_bucket(name: str) -> str:
    n = name.lower()
    if "modbus" in n: return "Modbus (ICS)"
    if "dnp3" in n: return "DNP3 (ICS)"
    if "bacnet" in n: return "BACnet (Building Automation)"
    if "ethernet/ip" in n or "ethernet" in n: return "EtherNet/IP (ICS)"
    if n.startswith("mqtt"): return "MQTT (IoT)" if "tls" not in n else "MQTT over TLS"
    if "rtsp" in n: return "RTSP (IP Camera)"
    if n.startswith("http-alt") or "http-alt" in n: return "HTTP-alt (IoT)"
    if n.startswith("http"): return "HTTP (Web/IoT)"
    if n.startswith("https-alt") or "https-alt" in n: return "HTTPS-alt (IoT)"
    if n.startswith("https"): return "HTTPS (Web/IoT)"
    if "telnet" in n: return "Telnet (Legacy/IoT)"
    if n == "ssh" or "ssh" in n: return "SSH (IoT/Embedded)"
    return name


def _render_security_summary(t: Dict[str, Any], show_cves_inline: int = 1, show_hints_inline: int = 2) -> List[str]:
    """
    Compact multi-line security preview for scan listing.
    """
    lines = []
    hints = _dedupe(t.get("vuln_hints", []))
    cves  = _dedupe(t.get("vuln_cves", []))
    if not hints and not cves:
        return lines

    lines.append(click.style("     Security:", bold=True))
    for h in hints[:show_hints_inline]:
        lines.append(f"       • {h}")
    for c in cves[:show_cves_inline]:
        lines.append(click.style(f"       • {c}", fg="yellow"))
    more = max(0, len(hints) - show_hints_inline) + max(0, len(cves) - show_cves_inline)
    if more:
        lines.append(click.style(f"       … {more} more (use 'info {t['ip']}' for details)", fg="cyan"))
    return lines


def _render_info_sections(t: Dict[str, Any]) -> List[str]:
    """
    Pretty, grouped, deduped security sections for `info`.
    """
    lines = []
    # Group services into buckets
    svcs = [ _service_bucket(s) for s in t.get("services", []) ]
    svcs = _dedupe(svcs)

    # Build a map service -> hints
    from otsec.core.vuln_db import get_hints_for_services
    grouped = {}  # service -> [hints...]
    for s in svcs:
        grouped.setdefault(s, [])

    # De-dupe hints then add to each applicable service if it matches category name
    all_hints = _dedupe(t.get("vuln_hints", []))
    for s in svcs:
        # Pull hints for this service name from DB (ensures relevant grouping)
        for h in get_hints_for_services([s]):
            if h not in grouped[s]:
                grouped[s].append(h)

    # Header per service with severity color
    for s in svcs:
        icon, sev = SERVICE_RISK.get(s, ("ℹ️", "Info"))
        sev_color = "red" if sev == "High" else "yellow" if sev == "Medium" else "white"
        lines.append(click.style(f" {icon} {s}", fg=sev_color, bold=True))
        for h in grouped.get(s, [])[:6]:
            lines.append(f"   - {h}")
        lines.append("")

    # CVE section (global to the host)
    cves = _dedupe(t.get("vuln_cves", []))
    if cves:
        lines.append(click.style(" CVEs / Signatures:", fg="yellow", bold=True))
        for c in cves:
            lines.append(click.style(f"   • {c}", fg="yellow"))
        lines.append("")
    return lines


# ---------- Readline completion helpers ----------

def _list_files(prefix: str) -> list[str]:
    try:
        p = Path(prefix or ".")
        base = p.parent if prefix and not p.is_dir() else p
        start = p.name if prefix else ""
        return [
            str(base / x) + ("/" if (base / x).is_dir() else "")
            for x in os.listdir(base)
            if x.startswith(start)
        ]
    except Exception:
        return []


def _last_scanned_ips(targets) -> list[str]:
    return [t["ip"] for t in targets] if targets else []


def _completer_factory(get_state):
    def complete(text, state):
        buf = readline.get_line_buffer()
        try:
            parts = shlex.split(buf, posix=True)
            if buf.endswith(" "):
                parts.append("")
        except ValueError:
            parts = buf.split()

        default_target, targets = get_state()
        token_index = len(parts) - 1
        curr = parts[token_index] if parts else ""

        suggestions = []
        if token_index == 0:
            suggestions = ROOT_COMMANDS
        else:
            cmd = parts[0].lower()
            if cmd == "scan":
                suggestions = COMMON_BOOL_FLAGS
            elif cmd == "info":
                suggestions = _last_scanned_ips(targets)
                if default_target:
                    suggestions.append(default_target)
            elif cmd == "export":
                suggestions = EXPORT_FLAGS + _list_files(curr)
            elif cmd == "inject":
                if token_index == 1:
                    suggestions = INJECT_SUBS
                else:
                    sub = parts[1].lower() if len(parts) > 1 else ""
                    if sub == "modbus":
                        suggestions = INJECT_MODBUS_FLAGS
                        if default_target and ("--target" in parts or curr.startswith("--t")):
                            suggestions.append(default_target)
            elif cmd == "modbus":
                if token_index == 1:
                    suggestions = MODBUS_SUBS
                else:
                    sub = parts[1].lower() if len(parts) > 1 else ""
                    if sub == "read":
                        suggestions = MODBUS_READ_FLAGS
                        if default_target and ("--target" in parts or curr.startswith("--t")):
                            suggestions.append(default_target)
            elif cmd == "target":
                if token_index == 1:
                    suggestions = TARGET_SUBS
                elif token_index == 2 and parts[1].lower() in ("set", "pick"):
                    # suggest indices and last ips
                    suggestions = [str(i) for i in range(1, len(targets) + 1)] + _last_scanned_ips(targets)
                    if default_target:
                        suggestions.append(default_target)

        matches = [s for s in suggestions if s.startswith(curr)]
        return matches[state] if state < len(matches) else None

    return complete


def interactive_shell():
    """Start the OTSec interactive shell."""
    # History + config
    _load_history()
    atexit.register(_save_history)
    cfg = _load_config()
    default_target = cfg.get("default_target")

    # Install TAB completion
    def _get_state():
        return (default_target, targets)

    readline.set_completer_delims(" \t\n")
    readline.set_completer(_completer_factory(_get_state))
    try:
        readline.parse_and_bind("tab: complete")
    except Exception:
        pass

    # Greeting + banner
    click.echo(banner_text("0.1"))
    note = "[+] Entering OTSec interactive mode. Type 'help' for commands, 'exit' to quit."
    if default_target:
        note += f"  (default target: {default_target})"
    click.echo(click.style(note + "\n", fg="cyan"))

    targets: List[Dict[str, Any]] = []  # last scan results

    def _resolve_index_or_ip(token: str) -> str | None:
        # Allow target set <INDEX> or <IP>
        if token.isdigit():
            idx = int(token)
            if 1 <= idx <= len(targets):
                return targets[idx - 1]["ip"]
            return None
        return token  # assume IP

    while True:
        try:
            raw = input("OTSec> ").strip()
        except (EOFError, KeyboardInterrupt):
            click.echo("\n[!] Exiting OTSec")
            break

        if not raw:
            continue

        try:
            parts = shlex.split(raw)
        except ValueError:
            click.echo(click.style("[!] Parse error. Check your quotes or spacing.", fg="red"))
            continue

        cmd = parts[0].lower()

        # ---- Exit ----
        if cmd in ("exit", "quit", "q"):
            click.echo("[!] Goodbye.")
            break

        # ---- Help ----
        if cmd == "help":
            _print_help()
            continue

        # ---- Clear ----
        if cmd in ("clear", "cls"):
            os.system("cls" if os.name == "nt" else "clear")
            click.echo(banner_text("0.1"))
            if default_target:
                click.echo(click.style(f"(default target: {default_target})\n", fg="cyan"))
            continue

        # ---- Targets (list last results) ----
        if cmd == "targets":
            if not targets:
                click.echo(click.style("[i] No results yet. Run 'scan <CIDR|IP>' first.", fg="yellow"))
                continue
            click.echo("\n" + click.style("=== Last Scan Targets ===", bold=True) + "\n")
            for i, t in enumerate(targets, start=1):
                ip_s = click.style(t["ip"], fg="green", bold=True)
                ports = ", ".join(str(p) for p in t["open_ports"])
                svc_preview_list = t.get("services", [])
                svc_preview = ", ".join(svc_preview_list[:4]) + (f", +{len(svc_preview_list)-4} more" if len(svc_preview_list) > 4 else "")
                click.echo(f" [{i}] 🔹 Target: {ip_s}")
                click.echo(f"     Open Ports : {ports}")
                click.echo(f"     Services   : {svc_preview}\n")
            continue

        # ---- Target mgmt ----
        if cmd == "target":
            if len(parts) < 2:
                click.echo(click.style("[!] Usage: target <set|pick|show|clear> [IP|INDEX]", fg="yellow"))
                continue
            sub = parts[1].lower()
            if sub in ("set", "pick"):
                if len(parts) < 3:
                    click.echo(click.style("[!] Usage: target set <IP|INDEX>", fg="yellow"))
                    continue
                resolved = _resolve_index_or_ip(parts[2])
                if not resolved:
                    click.echo(click.style("[!] Invalid index. Use 'targets' to see indices.", fg="red"))
                    continue
                default_target = resolved
                cfg["default_target"] = default_target
                _save_config(cfg)
                click.echo(click.style(f"[+] Default target set to {default_target}", fg="green"))
            elif sub == "show":
                if default_target:
                    click.echo(click.style(f"[i] Default target: {default_target}", fg="cyan"))
                else:
                    click.echo(click.style("[i] No default target set. Use 'target set <IP|INDEX>'.", fg="yellow"))
            elif sub == "clear":
                default_target = None
                cfg.pop("default_target", None)
                _save_config(cfg)
                click.echo(click.style("[+] Default target cleared.", fg="green"))
            else:
                click.echo(click.style("[!] Unknown subcommand. Use: target <set|pick|show|clear>", fg="yellow"))
            continue

        # ---- Scan ----
        if cmd == "scan":
            if len(parts) < 2:
                click.echo(click.style("[!] Usage: scan <CIDR|IP> [--safe] [--verbose] [--vuln]", fg="yellow"))
                continue

            cidr = parts[1]
            safe = "--safe" in parts[2:] or "-s" in parts[2:]
            verbose = "--verbose" in parts[2:] or "-v" in parts[2:]
            vuln = "--vuln" in parts[2:]

            try:
                results = scan_subnet(cidr, safe=safe, verbose=verbose, vuln=vuln)
            except SystemExit:
                click.echo(click.style("[!] Scanning raw sockets requires root. Use '--safe' or 'sudo'.", fg="red"))
                continue
            except Exception as e:
                click.echo(click.style(f"[!] Scan failed: {e}", fg="red"))
                continue

            targets = results or []
            if not targets:
                click.echo(click.style("[i] No OT/IoT devices detected on this target/range.", fg="yellow"))
                continue

            click.echo("\n" + click.style("=== OTSec Scan Results ===", bold=True) + "\n")
            for i, t in enumerate(targets, start=1):
                ip_s = click.style(t["ip"], fg="green", bold=True)
                ports = ", ".join(str(p) for p in t["open_ports"])
                svc_preview_list = t.get("services", [])
                svc_preview = ", ".join(svc_preview_list[:4]) + (f", +{len(svc_preview_list)-4} more" if len(svc_preview_list) > 4 else "")
                idx = click.style(f"[{i}]", fg="cyan", bold=True)
                click.echo(f" {idx} 🔹 Target: {ip_s}")
                click.echo(f"     Open Ports : {ports}")
                click.echo(f"     Services   : {svc_preview}")
                # Compact security preview
                for line in _render_security_summary(t):
                    click.echo(line)
                # Fingerprint teaser
                fp = t.get("fingerprints", {})
                server = fp.get("http_server")
                title = fp.get("http_title")
                if server or title:
                    click.echo("     Fingerprint:", nl=False)
                    if server:
                        click.echo(f" Server={server}", nl=False)
                    if title:
                        trim = title[:60] + ("…" if len(title) > 60 else "")
                        click.echo(f' Title="{trim}"', nl=False)
                    click.echo("")
                click.echo("")
            continue

        # ---- Info ----
        if cmd == "info":
            if len(parts) >= 2:
                ip = parts[1]
            else:
                if not default_target:
                    click.echo(click.style("[!] Usage: info <IP>  (or set a default target with 'target set <IP|INDEX>')", fg="yellow"))
                    continue
                ip = default_target

            target = next((t for t in targets if t["ip"] == ip), None)
            bar = "=" * 50
            click.echo("\n" + bar)
            click.echo(f" 📡 Target Information: {click.style(ip, fg='green', bold=True)}")
            click.echo(bar)

            if not target:
                click.echo(" Proto Hint : unknown")
                click.echo("\n Open Ports & Services:\n   (no data — scan first)\n")
                click.echo(bar + "\n")
                continue

            # Ports/services
            proto_hint = target.get("services", ["unknown"])[0]
            click.echo(f" Proto Hint : {click.style(proto_hint, fg='yellow', bold=True)}")
            ports = ", ".join(str(p) for p in target.get("open_ports", []))
            click.echo(f" Open Ports : {ports}")
            svc_list = ", ".join(target.get("services", []))
            click.echo(f" Services   : {svc_list}")

            # Fingerprints (if any)
            fp = target.get("fingerprints", {})
            if fp:
                click.echo("\n Fingerprints:")
                for k in ("http_server", "http_firstline", "http_title", "rtsp_banner", "mqtt_banner"):
                    if k in fp:
                        val = fp[k]
                        if k == "http_title" and len(val) > 90:
                            val = val[:87] + "…"
                        click.echo(f"   - {k}: {val}")

            # Grouped security sections
            click.echo("\n Security Findings:\n")
            for line in _render_info_sections(target):
                click.echo(line)

            click.echo(bar + "\n")
            continue

        # ---- Export ----
        if cmd == "export":
            if len(parts) < 2:
                click.echo(click.style("[!] Usage: export <path> [--type json|txt|xml]", fg="yellow"))
                continue

            path = parts[1]
            fmt = "json"
            for i, token in enumerate(parts[2:], start=2):
                if token in ("--type", "-t"):
                    if i + 1 < len(parts):
                        fmt = parts[i + 1].lower()
                    else:
                        click.echo(click.style("[!] Missing value for --type", fg="red"))
                        continue

            if fmt == "json" and path.lower().endswith(".txt"):
                fmt = "txt"
            elif fmt == "json" and path.lower().endswith(".xml"):
                fmt = "xml"

            try:
                out = _export_results(targets, path, fmt=fmt)
                click.echo(click.style(f"[+] Results saved to {out} ({fmt.upper()})", fg="green"))
            except Exception as e:
                click.echo(click.style(f"[!] Export failed: {e}", fg="red"))
            continue

        # ---- Inject Modbus (lab-only; DRY-RUN default) ----
        if cmd == "inject" and len(parts) >= 2 and parts[1].lower() == "modbus":
            try:
                from otsec.core.injectors.modbus import write_holding_register
            except Exception as e:
                click.echo(click.style(f"[!] Modbus injector not available: {e}", fg="red"))
                click.echo("    Tip: pip install pymodbus  (and ensure injector file exists)")
                continue

            click.echo(click.style(
                "⚠️  Authorized lab/testing only. You are responsible for compliance.\n"
                "    This action is DRY-RUN by default. Use --force to actually write.",
                fg="yellow", bold=True
            ))

            def _get_opt(name, default=None, required=False, cast=str):
                if f"--{name}" in parts:
                    idx = parts.index(f"--{name}")
                    if idx + 1 < len(parts):
                        try:
                            return cast(parts[idx + 1])
                        except Exception:
                            return default
                short = {"register": "-r", "value": "-v", "unit": "-u", "port": "-p"}.get(name)
                if short and short in parts:
                    idx = parts.index(short)
                    if idx + 1 < len(parts):
                        try:
                            return cast(parts[idx + 1])
                        except Exception:
                            return default
                if required:
                    raise ValueError(f"Missing required --{name}")
                return default

            try:
                target = _get_opt("target", cast=str) or default_target
                if not target:
                    raise ValueError("No target provided. Set one with 'target set <IP|INDEX>' or pass --target IP")
                register = _get_opt("register", required=True, cast=int)
                value = _get_opt("value", required=True, cast=int)
                unit = _get_opt("unit", default=1, cast=int)
                port = _get_opt("port", default=502, cast=int)
                timeout = _get_opt("timeout", default=3.0, cast=float)
                read_back = "--read-back" in parts
                force = "--force" in parts
            except ValueError as ve:
                click.echo(click.style(f"[!] {ve}", fg="red"))
                click.echo("Usage: inject modbus [--target IP] --register N --value X "
                           "[--unit 1] [--port 502] [--timeout 3.0] [--read-back] [--force]")
                continue

            dry_run = not force
            if not dry_run:
                if not click.confirm(click.style(
                    f"Proceed to WRITE register {register}={value} on {target}:{port} (unit {unit})?",
                    fg="red", bold=True
                ), default=False):
                    click.echo(click.style("[i] Aborted.", fg="yellow"))
                    continue

            try:
                res = write_holding_register(
                    host=target,
                    register=register,
                    value=value,
                    unit=unit,
                    port=port,
                    timeout=timeout,
                    dry_run=dry_run,
                    read_back=read_back,
                )
                click.echo(json.dumps(res, indent=2))
            except Exception as e:
                click.echo(click.style(f"[!] Injection failed: {e}", fg="red"))
            continue

        # ---- Modbus read (safe, read-only) ----
        if cmd == "modbus" and len(parts) >= 2 and parts[1].lower() == "read":
            try:
                from otsec.core.injectors.modbus import read_holding_registers
            except Exception as e:
                click.echo(click.style(f"[!] Modbus reader not available: {e}", fg="red"))
                click.echo("    Tip: pip install pymodbus")
                continue

            def _get_opt(name, default=None, required=False, cast=str):
                if f"--{name}" in parts:
                    idx = parts.index(f"--{name}")
                    if idx + 1 < len(parts):
                        try:
                            return cast(parts[idx + 1])
                        except Exception:
                            return default
                short = {"register": "-r", "count": "-c", "unit": "-u", "port": "-p"}.get(name)
                if short and short in parts:
                    idx = parts.index(short)
                    if idx + 1 < len(parts):
                        try:
                            return cast(parts[idx + 1])
                        except Exception:
                            return default
                if required:
                    raise ValueError(f"Missing required --{name}")
                return default

            try:
                target = _get_opt("target", cast=str) or default_target
                if not target:
                    raise ValueError("No target provided. Set one with 'target set <IP|INDEX>' or pass --target IP")
                register = _get_opt("register", required=True, cast=int)
                count = _get_opt("count", default=1, cast=int)
                unit = _get_opt("unit", default=1, cast=int)
                port = _get_opt("port", default=502, cast=int)
                timeout = _get_opt("timeout", default=3.0, cast=float)
            except ValueError as ve:
                click.echo(click.style(f"[!] {ve}", fg="red"))
                click.echo("Usage: modbus read [--target IP] --register N [--count 1] [--unit 1] [--port 502] [--timeout 3.0]")
                continue

            try:
                res = read_holding_registers(
                    host=target,
                    register=register,
                    count=count,
                    unit=unit,
                    port=port,
                    timeout=timeout,
                )
                click.echo(json.dumps(res, indent=2))
            except Exception as e:
                click.echo(click.style(f"[!] Read failed: {e}", fg="red"))
            continue

        # ---- Unknown ----
        click.echo(click.style(f"[!] Unknown command: {cmd}. Type 'help' for usage.", fg="yellow"))

