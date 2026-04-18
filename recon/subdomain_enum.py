#!/usr/bin/env python3
"""
subdomain_enum.py - Subdomain Enumerator
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

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.rule import Rule
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TaskProgressColumn
from rich import box

console = Console(highlight=False)

# ── Wordlist ───────────────────────────────────────────────────────────────────

WORDLIST = [
    # Common
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "remote", "vpn", "admin", "portal", "dashboard",
    # Dev / staging
    "dev", "staging", "stage", "test", "uat", "qa",
    "beta", "alpha", "demo", "sandbox", "preview",
    "dev2", "staging2", "test2", "old", "new",
    # API
    "api", "api2", "api3", "v1", "v2", "v3",
    "rest", "graphql", "ws", "websocket", "grpc",
    # Apps
    "app", "app2", "mobile", "m", "web", "web2",
    "shop", "store", "pay", "payments", "checkout",
    "blog", "news", "docs", "help", "support",
    "status", "monitor", "metrics", "health",
    # Auth
    "auth", "login", "sso", "oauth", "id", "identity",
    "accounts", "account", "user", "users", "profile",
    # Infrastructure
    "cdn", "static", "assets", "media", "img", "images",
    "files", "uploads", "download", "downloads",
    "git", "gitlab", "github", "bitbucket", "code", "repo",
    "ci", "cd", "jenkins", "travis", "deploy",
    # DB / internal
    "db", "database", "mysql", "postgres", "mongo", "redis",
    "internal", "intranet", "private", "corp", "office",
    "vpn", "proxy", "gateway", "firewall", "router",
    # Email
    "mail", "mail2", "smtp", "pop3", "imap", "mx",
    "email", "newsletter", "lists", "mailing",
    # Analytics / monitoring
    "analytics", "stats", "metrics", "grafana", "kibana",
    "elastic", "logstash", "splunk", "datadog",
    # Cloud
    "aws", "gcp", "azure", "cloud", "s3", "bucket",
    # Business
    "crm", "erp", "hr", "finance", "sales", "marketing",
    "partners", "clients", "customer", "b2b", "wholesale",
    # Ghana / Africa specific
    "gh", "africa", "ng", "ke", "za",
]

# ── Finding ────────────────────────────────────────────────────────────────────

class Subdomain:
    def __init__(self, fqdn, ip, status_code=None, title=None, server=None):
        self.fqdn        = fqdn
        self.ip          = ip
        self.status_code = status_code
        self.title       = title
        self.server      = server

    def __str__(self):
        return f"{self.fqdn} [{self.ip}] HTTP {self.status_code}"


# ── Resolution ─────────────────────────────────────────────────────────────────

def resolve_dns(fqdn):
    """Try to resolve a subdomain via DNS."""
    try:
        ip = socket.gethostbyname(fqdn)
        return ip
    except (socket.gaierror, socket.timeout):
        return None


def probe_http(fqdn, ip, timeout=6):
    """Probe subdomain over HTTP/HTTPS and grab basic info."""
    status_code = None
    title       = None
    server      = None

    for scheme in ("https", "http"):
        url = f"{scheme}://{fqdn}"
        try:
            with httpx.Client(verify=False, follow_redirects=True, timeout=timeout) as client:
                resp = client.get(url, headers={"User-Agent": "STRYKER-Recon/1.0"})
                status_code = resp.status_code
                server = resp.headers.get("server", "")

                # Extract page title
                import re
                match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                if match:
                    title = match.group(1).strip()[:60]

                break
        except Exception:
            pass

    return status_code, title, server


def check_subdomain(word, domain, http_probe):
    """Check a single subdomain candidate."""
    fqdn = f"{word}.{domain}"
    ip   = resolve_dns(fqdn)

    if not ip:
        return None

    status_code, title, server = None, None, None
    if http_probe:
        status_code, title, server = probe_http(fqdn, ip)

    return Subdomain(
        fqdn=fqdn,
        ip=ip,
        status_code=status_code,
        title=title or "",
        server=server or ""
    )


# ── Also check certificate transparency logs ──────────────────────────────────

def check_crt_sh(domain):
    """Query crt.sh for subdomains from certificate transparency logs."""
    found = set()
    try:
        with httpx.Client(verify=False, timeout=15) as client:
            resp = client.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers={"User-Agent": "STRYKER-Recon/1.0"}
            )
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(f".{domain}") and "*" not in sub:
                            found.add(sub)
    except Exception:
        pass
    return found


# ── Output ─────────────────────────────────────────────────────────────────────

def status_color(code):
    if code is None:
        return "[dim]N/A[/dim]"
    if code < 300:
        return f"[green]{code}[/green]"
    if code < 400:
        return f"[yellow]{code}[/yellow]"
    if code < 500:
        return f"[red]{code}[/red]"
    return f"[dim]{code}[/dim]"


def print_results(found, domain, elapsed):
    console.print()

    if not found:
        console.print(Panel(
            f"[yellow]No subdomains found for {domain}[/yellow]\n"
            "[dim]Try increasing threads or adding a custom wordlist.[/dim]",
            title="Result", border_style="yellow"
        ))
        return

    table = Table(
        title=f"[bold red]{len(found)} Subdomain(s) Found — {domain}[/bold red]",
        box=box.ROUNDED,
        show_lines=True
    )
    table.add_column("Subdomain",   style="cyan",  no_wrap=True)
    table.add_column("IP Address",  style="white", no_wrap=True)
    table.add_column("Status",      justify="center", no_wrap=True)
    table.add_column("Server",      style="dim",   no_wrap=True)
    table.add_column("Title",       style="dim",   max_width=40)

    for sub in sorted(found, key=lambda s: s.fqdn):
        table.add_row(
            sub.fqdn,
            sub.ip,
            status_color(sub.status_code),
            sub.server[:20] if sub.server else "",
            sub.title[:40] if sub.title else ""
        )

    console.print(table)
    console.print(f"\n  [dim]Scan completed in {elapsed:.1f}s[/dim]\n")


# ── CLI ────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Subdomain Enumerator - part of STRYKER",
        epilog="""
Examples:
  python recon/subdomain_enum.py -d example.com
  python recon/subdomain_enum.py -d example.com -t 50 --no-http
  python recon/subdomain_enum.py -d example.com --crt
  python recon/subdomain_enum.py -d example.com -o subdomains.txt

Only test domains you own or have written permission to test.
        """
    )
    parser.add_argument("-d", "--domain",   required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-t", "--threads",  type=int, default=30, help="Threads (default: 30)")
    parser.add_argument("--no-http",        action="store_true", help="Skip HTTP probing (faster)")
    parser.add_argument("--crt",            action="store_true", help="Also query crt.sh cert transparency logs")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist file (one word per line)")
    parser.add_argument("-o", "--output",   help="Save results to file")
    return parser.parse_args()


def main():
    args = parse_args()

    console.print(Panel.fit(
        "[bold red]STRYKER[/bold red] [white]//[/white] [cyan]Subdomain Enumerator[/cyan]\n"
        "[dim]DNS brute-force + Certificate Transparency | For authorized testing only[/dim]",
        border_style="red"
    ))
    console.print()
    console.print(f"  [dim]Target:[/dim]  [cyan]{args.domain}[/cyan]")
    console.print(f"  [dim]Threads:[/dim] [cyan]{args.threads}[/cyan]")
    console.print(f"  [dim]HTTP probe:[/dim] [cyan]{'No' if args.no_http else 'Yes'}[/cyan]")
    console.print()

    # Load wordlist
    words = WORDLIST.copy()
    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                custom = [line.strip() for line in f if line.strip()]
            words = list(set(words + custom))
            console.print(f"  [dim]Wordlist:[/dim] {len(words)} words (built-in + custom)")
        except FileNotFoundError:
            console.print(f"  [yellow]Wordlist file not found: {args.wordlist} — using built-in[/yellow]")
    else:
        console.print(f"  [dim]Wordlist:[/dim] {len(words)} built-in words")

    # crt.sh
    crt_extras = set()
    if args.crt:
        console.print()
        console.print("  [dim]Querying certificate transparency logs (crt.sh)...[/dim]")
        crt_extras = check_crt_sh(args.domain)
        if crt_extras:
            console.print(f"  [green]crt.sh found {len(crt_extras)} additional candidates[/green]")
            for sub in crt_extras:
                prefix = sub.replace(f".{args.domain}", "")
                if prefix not in words:
                    words.append(prefix)

    console.print()

    found   = []
    start   = time.time()
    http_probe = not args.no_http

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task(f"Scanning {args.domain}...", total=len(words))

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(check_subdomain, word, args.domain, http_probe): word
                for word in words
            }
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    progress.print(f"  [green][+][/green] [cyan]{result.fqdn}[/cyan] [{result.ip}]")
                progress.advance(task)

    elapsed = time.time() - start
    print_results(found, args.domain, elapsed)

    if args.output and found:
        with open(args.output, "w") as f:
            f.write(f"# STRYKER Subdomain Enumeration — {args.domain}\n")
            f.write(f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Found: {len(found)}\n\n")
            for sub in sorted(found, key=lambda s: s.fqdn):
                f.write(f"{sub}\n")
        console.print(f"[green]Results saved to {args.output}[/green]")


if __name__ == "__main__":
    main()