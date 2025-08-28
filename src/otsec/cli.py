
import json
import click

from otsec.core.discovery import scan_subnet
from otsec.core.shell import interactive_shell
from otsec.core.injectors.modbus import (
    write_holding_register,
    read_holding_registers,  # NOTE: plural
)
# from otsec.core.banner import banner_text


@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
@click.version_option("0.1", prog_name="OTSec")
def main():
    """OTSec - Offensive OT/IoT Security Toolkit"""
    # Do NOT print the big banner here; the shell handles it.
    pass


@main.command(help="Start OTSec interactive shell")
def shell():
    interactive_shell()


@main.command(help="Discover OT/IoT devices on a subnet")
@click.argument("cidr")
@click.option("--json-out", is_flag=True, help="Output results as JSON")
@click.option("--safe", is_flag=True, help="Run in safe mode (no root needed, slower)")
@click.option("--verbose", is_flag=True, help="Show detailed scan output")
@click.option("--vuln", is_flag=True, help="Fingerprint & show vulnerability hints (slightly slower)")
def scan(cidr, json_out, safe, verbose, vuln):
    results = scan_subnet(cidr, safe=safe, verbose=verbose, vuln=vuln)

    if json_out:
        click.echo(json.dumps(results, indent=2))
        return

    click.echo("\n=== OTSec Scan Results ===\n")
    for r in results:
        ip = click.style(r["ip"], fg="green", bold=True)
        ports = ", ".join(str(p) for p in r["open_ports"])
        services = ", ".join(r.get("services", []))
        if len(services) > 80:
            services = services[:77] + "..."
        click.echo(f" 🔹 Target: {ip}")
        click.echo(f"     Open Ports : {ports}")
        click.echo(f"     Services   : {services}")
        if vuln:
            hints = r.get("vuln_hints", [])
            cves = r.get("vuln_cves", [])
            if hints or cves:
                click.echo(click.style("     Security:", bold=True))
                for h in hints:
                    click.echo(f"       • {h}")
                for c in cves:
                    click.echo(click.style(f"       • {c}", fg="yellow"))
        click.echo("")


@main.command(name="modbus-read", help="Read Modbus holding registers (safe, read-only)")
@click.option("--target", required=True, metavar="IP", help="Target Modbus/TCP device IP")
@click.option("--register", "-r", type=int, required=True, help="Start holding register (0..65535)")
@click.option("--count", "-c", type=int, default=1, show_default=True, help="Number of registers to read (1..125)")
@click.option("--unit", "-u", type=int, default=1, show_default=True, help="Modbus unit/slave id")
@click.option("--port", "-p", type=int, default=502, show_default=True, help="Modbus/TCP port")
@click.option("--timeout", type=float, default=3.0, show_default=True, help="Socket timeout seconds")
def modbus_read(target, register, count, unit, port, timeout):
    try:
        res = read_holding_registers(
            host=target,
            register=register,
            count=count,
            unit=unit,
            port=port,
            timeout=timeout,
        )
    except Exception as e:
        click.echo(click.style(f"[!] Read failed: {e}", fg="red"))
        raise SystemExit(1)
    click.echo(json.dumps(res, indent=2))


@main.group(help="Inject false data / manipulate values (lab-only, authorized testing)")
def inject():
    pass


@inject.command("modbus", help="Write a Modbus holding register (lab-only)")
@click.option("--target", required=True, metavar="IP", help="Target Modbus/TCP device IP")
@click.option("--register", "-r", type=int, required=True, help="Holding register address (0..65535)")
@click.option("--value", "-v", type=int, required=True, help="Value to write (0..65535)")
@click.option("--unit", "-u", type=int, default=1, show_default=True, help="Modbus unit/slave id")
@click.option("--port", "-p", type=int, default=502, show_default=True, help="Modbus/TCP port")
@click.option("--timeout", type=float, default=3.0, show_default=True, help="Socket timeout seconds")
@click.option("--read-back", is_flag=True, help="Read the register after write to verify")
@click.option("--force", is_flag=True, help="Actually perform the write (default is dry-run)")
def inject_modbus(target, register, value, unit, port, timeout, read_back, force):
    """
    Example:
      otsec inject modbus --target 10.10.233.25 -r 40001 -v 9999      # DRY-RUN (default)
      otsec inject modbus --target 10.10.233.25 -r 40001 -v 9999 --force --read-back
    """
    # Safety banner
    click.echo(click.style("⚠️  Authorized lab/testing only. You are responsible for compliance.", fg="yellow", bold=True))

    dry_run = not force
    if not dry_run:
        if not click.confirm(
            click.style(
                f"Proceed to WRITE register {register}={value} on {target}:{port} (unit {unit})?",
                fg="red",
                bold=True,
            ),
            default=False,
        ):
            click.echo(click.style("[i] Aborted.", fg="yellow"))
            return

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
    except Exception as e:
        click.echo(click.style(f"[!] Injection failed: {e}", fg="red"))
        return

    click.echo(json.dumps(res, indent=2))

