#!/usr/bin/env python3
"""
port_scanner.py - Multi-threaded Port Scanner with Banner Grabbing
Part of STRYKER by Andrews

LEGAL NOTICE: For authorized penetration testing ONLY.
Only use against systems you own or have explicit written permission to test.
"""

import argparse
import sys
import io
import socket
import concurrent.futures
import time
from datetime import datetime

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.rule import Rule
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TaskProgressColumn
from rich import box

console = Console(highlight=False)

# ── Port definitions ───────────────────────────────────────────────────────────

COMMON_PORTS = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP",
    53:    "DNS",
    80:    "HTTP",
    110:   "POP3",
    111:   "RPC",
    135:   "MSRPC",
    139:   "NetBIOS",
    143:   "IMAP",
    443:   "HTTPS",
    445:   "SMB",
    465:   "SMTPS",
    587:   "SMTP/TLS",
    993:   "IMAPS",
    995:   "POP3S",
    1433:  "MSSQL",
    1521:  "Oracle DB",
    2181:  "ZooKeeper",
    2375:  "Docker",
    2376:  "Docker TLS",
    3000:  "Node.js/Dev",
    3306:  "MySQL",
    3389:  "RDP",
    4200:  "Angular Dev",
    4443:  "HTTPS Alt",
    5000:  "Flask/Dev",
    5432:  "PostgreSQL",
    5672:  "RabbitMQ",
    5900:  "VNC",
    6379:  "Redis",
    6443:  "Kubernetes",
    7000:  "Cassandra",
    8000:  "HTTP Alt",
    8008:  "HTTP Alt",
    8080:  "HTTP Proxy",
    8081:  "HTTP Alt",
    8082:  "HTTP Alt",
    8083:  "HTTP Alt",
    8088:  "HTTP Alt",
    8090:  "HTTP Alt",
    8443:  "HTTPS Alt",
    8888:  "Jupyter",
    9000:  "SonarQube",
    9090:  "Prometheus",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch",
    10250: "Kubernetes",
    27017: "MongoDB",
    27018: "MongoDB",
    28017: "MongoDB Web",
}

PORT_SETS = {
    "common":   list(COMMON_PORTS.keys()),
    "web":      [80, 443, 8000, 8008, 8080, 8081, 8082, 8083, 8088, 8090, 8443, 8888, 4443],
    "database": [1433, 1521, 3306, 5432, 6379, 7000, 9200, 9300, 27017, 27018, 28017],
    "dev":      [3000, 4200, 5000, 8080, 8888, 9000, 9090],
    "top100":   list(range(1, 1025)),
}

RISK_PORTS = {
    21:    ("HIGH",   "FTP — often allows anonymous login and plaintext credentials"),
    22:    ("MEDIUM", "SSH — ensure key-based auth only, no default passwords"),
    23:    ("CRITICAL","Telnet — transmits credentials in plaintext, replace with SSH"),
    25:    ("MEDIUM", "SMTP — check for open relay misconfiguration"),
    135:   ("HIGH",   "MSRPC — common attack vector on Windows"),
    139:   ("HIGH",   "NetBIOS — legacy protocol, often exploitable"),
    445:   ("CRITICAL","SMB — EternalBlue/WannaCry attack surface, patch immediately"),
    1433:  ("CRITICAL","MSSQL exposed to internet — restrict access via firewall"),
    1521:  ("CRITICAL","Oracle DB exposed to internet — restrict access via firewall"),
    2375:  ("CRITICAL","Docker daemon without TLS — full host takeover possible"),
    3306:  ("CRITICAL","MySQL exposed to internet — restrict to localhost or VPN"),
    3389:  ("HIGH",   "RDP — common brute-force target, restrict access"),
    5432:  ("CRITICAL","PostgreSQL exposed to internet — restrict access"),
    5900:  ("HIGH",   "VNC — remote desktop, ensure password is set"),
    6379:  ("CRITICAL","Redis exposed without auth — data theft/RCE possible"),
    8080:  ("LOW",    "HTTP proxy/dev server — verify not exposing internal services"),
    9200:  ("CRITICAL","Elasticsearch exposed — often no auth, data readable by anyone"),
    27017: ("CRITICAL","MongoDB exposed — often no auth, full database access possible"),
}

# ── Port result ────────────────────────────────────────────────────────────────

class PortResult:
    def __init__(self, port, state, service, banner="", risk=None, risk_detail=""):
        self.port        = port
        self.state       = state
        self.service     = service
        self.banner      = banner
        self.risk        = risk
        self.risk_detail = risk_detail

    def __str__(self):
        return f"{self.port}/{self.service} [{self.state}] {self.banner}"


# ── Scanning ───────────────────────────────────────────────────────────────────

def resolve_host(target):
    """Resolve hostname to IP."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        return None


def grab_banner(ip, port, timeout=2):
    """Try to grab service banner."""
    banner = ""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Send probes for common services
        if port in (80, 8080, 8000, 8008, 8088, 8090):
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port == 22:
            pass  # SSH sends banner automatically
        elif port == 21:
            pass  # FTP sends banner automatically
        elif port == 25:
            pass  # SMTP sends banner automatically
        else:
            sock.send(b"\r\n")

        data = sock.recv(1024)
        banner = data.decode("utf-8", errors="replace").strip()
        banner = banner.split("\n")[0][:80]  # first line only
        sock.close()
    except Exception:
        pass
    return banner


def scan_port(ip, port, timeout, grab_banners):
    """Scan a single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            banner  = grab_banner(ip, port) if grab_banners else ""
            risk, risk_detail = RISK_PORTS.get(port, (None, ""))

            return PortResult(
                port=port,
                state="open",
                service=service,
                banner=banner,
                risk=risk,
                risk_detail=risk_detail
            )
    except Exception:
        pass
    return None


# ── Output ─────────────────────────────────────────────────────────────────────

RISK_COLOR = {
    "CRITICAL": "[bold red]CRITICAL[/bold red]",
    "HIGH":     "[red]HIGH[/red]",
    "MEDIUM":   "[yellow]MEDIUM[/yellow]",
    "LOW":      "[cyan]LOW[/cyan]",
}


def print_results(results, target, ip, elapsed):
    console.print()

    if not results:
        console.print(Panel(
            f"[green]No open ports found on {target}[/green]\n"
            "[dim]Try scanning more ports with --ports top100 or a custom range.[/dim]",
            title="Result", border_style="green"
        ))
        return

    # Summary panel
    risky = [r for r in results if r.risk in ("CRITICAL", "HIGH")]
    console.print(Panel(
        f"[white]Host:[/white]        [cyan]{target}[/cyan]  ({ip})\n"
        f"[white]Open ports:[/white]  [green]{len(results)}[/green]\n"
        f"[white]High risk:[/white]   [red]{len(risky)}[/red]\n"
        f"[white]Scan time:[/white]   {elapsed:.1f}s",
        title=f"[bold red]{len(results)} Open Port(s) Found[/bold red]",
        border_style="red"
    ))
    console.print()

    # Results table
    table = Table(box=box.ROUNDED, show_lines=True)
    table.add_column("Port",    style="cyan",  width=8,  justify="right")
    table.add_column("Service", style="white", width=16)
    table.add_column("Risk",    width=10, justify="center")
    table.add_column("Banner",  style="dim",   max_width=35)
    table.add_column("Detail",  style="dim",   max_width=40)

    for r in sorted(results, key=lambda x: x.port):
        risk_display = RISK_COLOR.get(r.risk, "[dim]INFO[/dim]") if r.risk else "[dim]—[/dim]"
        table.add_row(
            str(r.port),
            r.service,
            risk_display,
            r.banner[:35] if r.banner else "",
            r.risk_detail[:40] if r.risk_detail else ""
        )

    console.print(table)

    # High risk warnings
    if risky:
        console.print()
        console.print(Rule("[bold red] Critical Findings [/bold red]", style="red"))
        for r in risky:
            if r.risk == "CRITICAL":
                console.print(f"\n  [bold red][!] Port {r.port}/{r.service}[/bold red]")
                console.print(f"      [dim]{r.risk_detail}[/dim]")
        console.print()


# ── CLI ────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Port Scanner - part of STRYKER",
        epilog="""
Port sets:
  common   = 50 well-known ports (default)
  web      = HTTP/HTTPS ports only
  database = Database ports only
  dev      = Development server ports
  top100   = Ports 1-1024

Examples:
  python scanning/port_scanner.py -t example.com
  python scanning/port_scanner.py -t example.com --ports web
  python scanning/port_scanner.py -t example.com --ports 80,443,8080,3306
  python scanning/port_scanner.py -t example.com --ports top100 --threads 100
  python scanning/port_scanner.py -t example.com -o results.txt

Only test systems you own or have written permission to test.
        """
    )
    parser.add_argument("-t",  "--target",   required=True, help="Target host or IP")
    parser.add_argument("-p",  "--ports",    default="common",
                        help="Port set or comma-separated list (default: common)")
    parser.add_argument("--threads",         type=int, default=50,
                        help="Threads (default: 50)")
    parser.add_argument("--timeout",         type=float, default=1.0,
                        help="Connection timeout seconds (default: 1.0)")
    parser.add_argument("--no-banners",      action="store_true",
                        help="Skip banner grabbing (faster)")
    parser.add_argument("-o", "--output",    help="Save results to file")
    return parser.parse_args()


def main():
    args = parse_args()

    console.print(Panel.fit(
        "[bold red]STRYKER[/bold red] [white]//[/white] [cyan]Port Scanner[/cyan]\n"
        "[dim]TCP | Banner Grabbing | Risk Assessment | For authorized testing only[/dim]",
        border_style="red"
    ))
    console.print()

    # Resolve target
    target = args.target.replace("https://", "").replace("http://", "").split("/")[0]
    console.print(f"  [dim]Resolving:[/dim] [cyan]{target}[/cyan]")
    ip = resolve_host(target)
    if not ip:
        console.print(f"  [red]Could not resolve host: {target}[/red]")
        sys.exit(1)
    console.print(f"  [dim]IP Address:[/dim] [cyan]{ip}[/cyan]")

    # Build port list
    if args.ports in PORT_SETS:
        ports = PORT_SETS[args.ports]
        console.print(f"  [dim]Port set:[/dim]  [cyan]{args.ports}[/cyan] ({len(ports)} ports)")
    else:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",")]
            console.print(f"  [dim]Ports:[/dim]     [cyan]{args.ports}[/cyan]")
        except ValueError:
            console.print(f"  [red]Invalid port specification: {args.ports}[/red]")
            sys.exit(1)

    console.print(f"  [dim]Threads:[/dim]   [cyan]{args.threads}[/cyan]")
    console.print(f"  [dim]Timeout:[/dim]   [cyan]{args.timeout}s[/cyan]")
    console.print()

    # Scan
    results = []
    start   = time.time()
    grab    = not args.no_banners

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task(f"Scanning {target}...", total=len(ports))

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(scan_port, ip, port, args.timeout, grab): port
                for port in ports
            }
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    risk_tag = f"[red][{result.risk}][/red] " if result.risk in ("CRITICAL","HIGH") else ""
                    progress.print(
                        f"  [green][+][/green] {risk_tag}"
                        f"[cyan]{result.port}[/cyan]/{result.service}"
                        + (f"  [dim]{result.banner[:50]}[/dim]" if result.banner else "")
                    )
                progress.advance(task)

    elapsed = time.time() - start
    print_results(results, target, ip, elapsed)

    if args.output and results:
        with open(args.output, "w") as f:
            f.write(f"# STRYKER Port Scan — {target} ({ip})\n")
            f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Open ports: {len(results)}\n\n")
            for r in sorted(results, key=lambda x: x.port):
                f.write(f"{r}\n")
        console.print(f"[green]Results saved to {args.output}[/green]")


if __name__ == "__main__":
    main()