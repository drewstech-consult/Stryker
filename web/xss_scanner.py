#!/usr/bin/env python3
"""
xss_scanner.py - Defensive XSS & Template Exposure Scanner
Part of STRYKER by Andrews

LEGAL NOTICE: For authorized security testing ONLY.
Only use against systems you own or have explicit written permission to test.

Goals:
- Reduce false positives
- Use safe marker-based reflection checks
- Detect likely unsafe reflection contexts
- Detect likely template expression evaluation more carefully
- Report DOM XSS indicators and modern security headers
"""

import argparse
import sys
import io
import re
import json
import html
import hashlib
import urllib.parse
from dataclasses import dataclass, asdict
from typing import List, Dict, Tuple, Optional, Iterable
from collections import defaultdict

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True
    )
    sys.stderr = io.TextIOWrapper(
        sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True
    )

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

console = Console(highlight=False)

# ── Safer reflection markers ───────────────────────────────────────────────────

REFLECTION_MARKERS = [
    "__STRYKER_XSS_TEST__",
    'STRYKER"QUOTE_TEST',
    "STRYKER'SQUOTE_TEST",
    "<STRYKER_TEST_TAG>",
]

# Multiple template markers so we do not flag based on random page numbers.
TEMPLATE_TESTS = [
    ("{{7*7}}", "49"),
    ("{{6*6}}", "36"),
    ("${7*7}", "49"),
    ("${6*6}", "36"),
]

COMMON_INPUTS = [
    "q", "s", "search", "query", "keyword", "term",
    "name", "username", "user", "email",
    "message", "comment", "text", "content",
    "url", "redirect", "return", "next", "ref",
    "id", "page", "cat", "category", "tag",
]

DOM_SINKS = [
    "document.write(",
    ".innerHTML",
    ".outerHTML",
    "insertAdjacentHTML(",
    "eval(",
    "Function(",
    "setTimeout(",
    "setInterval(",
]

DOM_SOURCES = [
    "location.hash",
    "location.search",
    "document.URL",
    "document.documentURI",
    "document.referrer",
    "window.name",
]

# ── Models ─────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    url: str
    param: str
    payload: str
    vuln_type: str
    evidence: str
    severity: str = "Low"
    confidence: str = "Low"
    context: str = "Unknown"
    group_key: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)

    def dedupe_key(self) -> Tuple[str, str, str, str, str, str, str]:
        return (
            self.url,
            self.param,
            self.vuln_type,
            self.severity,
            self.confidence,
            self.context,
            self.evidence,
        )

# ── Utility helpers ────────────────────────────────────────────────────────────

def sha_preview(text: str, limit: int = 5000) -> str:
    return hashlib.sha256(text[:limit].encode("utf-8", errors="ignore")).hexdigest()

def is_html_response(resp: httpx.Response) -> bool:
    content_type = resp.headers.get("content-type", "").lower()
    return (
        "text/html" in content_type
        or "application/xhtml+xml" in content_type
        or content_type == ""
    )

def html_escape_variants(payload: str) -> List[str]:
    variants = [
        html.escape(payload, quote=False),
        html.escape(payload, quote=True),
    ]
    return list(dict.fromkeys(variants))

def shorten(text: str, max_len: int = 180) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= max_len else text[: max_len - 3] + "..."

def extract_forms(page_html: str, base_url: str) -> List[Dict]:
    forms: List[Dict] = []

    form_pattern = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
    action_pattern = re.compile(r'action=["\']([^"\']*)["\']', re.I)
    method_pattern = re.compile(r'method=["\']([^"\']*)["\']', re.I)
    input_pattern = re.compile(
        r'<(?:input|textarea|select)\b[^>]*name=["\']([^"\']+)["\']',
        re.I,
    )

    for match in form_pattern.finditer(page_html):
        form_html = match.group(0)
        action_match = action_pattern.search(form_html)
        method_match = method_pattern.search(form_html)

        action = action_match.group(1).strip() if action_match else base_url
        method = method_match.group(1).upper().strip() if method_match else "GET"

        action = urllib.parse.urljoin(base_url, action)
        inputs = input_pattern.findall(form_html)

        if inputs:
            forms.append(
                {
                    "action": action,
                    "method": method,
                    "inputs": inputs,
                }
            )

    return forms

def build_test_url(url: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    params[param] = payload
    new_query = urllib.parse.urlencode(params, doseq=True)
    return parsed._replace(query=new_query).geturl()

def baseline_fingerprint(resp: httpx.Response) -> Dict:
    text = resp.text or ""
    title_match = re.search(r"<title>(.*?)</title>", text, re.I | re.S)
    title = title_match.group(1).strip() if title_match else ""
    return {
        "status_code": resp.status_code,
        "length": len(text),
        "hash": sha_preview(text),
        "title": title,
        "content_type": resp.headers.get("content-type", ""),
    }

def find_occurrence_snippet(payload: str, text: str, radius: int = 120) -> Tuple[int, str, str]:
    idx = text.find(payload)
    matched = payload

    if idx == -1:
        for variant in html_escape_variants(payload):
            idx = text.find(variant)
            if idx != -1:
                matched = variant
                break

    if idx == -1:
        return -1, "", ""

    start = max(0, idx - radius)
    end = min(len(text), idx + len(matched) + radius)
    snippet = text[start:end]
    normalized = snippet.replace("\n", " ").replace("\r", " ")
    return idx, matched, normalized

def detect_context(payload: str, text: str) -> Tuple[str, str]:
    idx, matched, snippet = find_occurrence_snippet(payload, text)
    if idx == -1:
        return "Unknown", ""

    lower_snippet = snippet.lower()

    if "<script" in lower_snippet and "</script>" in lower_snippet:
        return "JavaScript", shorten(snippet)

    if re.search(r'=\s*["\'][^"\']*' + re.escape(matched), snippet, re.I):
        return "HTML Attribute", shorten(snippet)

    if "<" in snippet and ">" in snippet:
        return "HTML Body", shorten(snippet)

    return "Text", shorten(snippet)

def response_contains_raw(payload: str, text: str) -> bool:
    return payload in text

def response_contains_escaped(payload: str, text: str) -> bool:
    return any(v in text for v in html_escape_variants(payload))

def classify_reflection(payload: str, response_text: str) -> Optional[Tuple[str, str, str, str]]:
    raw = response_contains_raw(payload, response_text)
    escaped = response_contains_escaped(payload, response_text)
    context, snippet = detect_context(payload, response_text)

    if escaped and not raw:
        return (
            "Info",
            "High",
            context,
            f"Marker reflected only in escaped form ({context}). Likely encoded output. Snippet: {snippet}",
        )

    if raw:
        if context == "JavaScript":
            return (
                "High",
                "Medium",
                context,
                f"Raw marker reflected inside script context. Review required. Snippet: {snippet}",
            )
        if context == "HTML Attribute":
            return (
                "Medium",
                "Medium",
                context,
                f"Raw marker reflected in HTML attribute context. Encoding should be verified. Snippet: {snippet}",
            )
        if context == "HTML Body":
            return (
                "Medium",
                "Low",
                context,
                f"Raw marker reflected in HTML body. Could be harmless reflection or unsafe rendering. Snippet: {snippet}",
            )
        return (
            "Low",
            "Low",
            context,
            f"Marker reflected as raw text. Snippet: {snippet}",
        )

    return None

def dedupe_findings(findings: Iterable[Finding]) -> List[Finding]:
    seen = set()
    out: List[Finding] = []

    for finding in findings:
        key = finding.dedupe_key()
        if key not in seen:
            seen.add(key)
            out.append(finding)

    return out

def severity_rank(value: str) -> int:
    return {"High": 4, "Medium": 3, "Low": 2, "Info": 1}.get(value, 0)

def confidence_rank(value: str) -> int:
    return {"High": 3, "Medium": 2, "Low": 1}.get(value, 0)

def choose_stronger(existing: Finding, incoming: Finding) -> Finding:
    if severity_rank(incoming.severity) > severity_rank(existing.severity):
        return incoming
    if severity_rank(incoming.severity) == severity_rank(existing.severity):
        if confidence_rank(incoming.confidence) > confidence_rank(existing.confidence):
            return incoming
    return existing

# ── Template evaluation verification ───────────────────────────────────────────

def likely_value_context(snippet: str, expected: str) -> bool:
    patterns = [
        rf'[:=]\s*["\']?{re.escape(expected)}(?:["\'<\s]|$)',
        rf'>\s*{re.escape(expected)}\s*<',
        rf'value=["\']{re.escape(expected)}["\']',
        rf'content=["\']{re.escape(expected)}["\']',
    ]
    return any(re.search(pattern, snippet, re.I) for pattern in patterns)

def check_template_evaluation_for_param(
    client: httpx.Client,
    url: str,
    param: str,
    timeout: float,
) -> Optional[Finding]:
    """
    Stronger logic:
    - Send several distinct math expressions
    - Ignore responses where payload is reflected (raw or escaped)
    - Require at least 2 different payload/result pairs
    - Require result to appear in a likely value context
    - Keep severity/confidence conservative
    """
    matches: List[Tuple[str, str, str]] = []

    for payload, expected in TEMPLATE_TESTS:
        test_url = build_test_url(url, param, payload)

        try:
            resp = client.get(test_url, timeout=timeout)
        except httpx.RequestError:
            continue

        if not is_html_response(resp):
            continue

        text = resp.text

        raw_reflected = payload in text
        escaped_reflected = any(v in text for v in html_escape_variants(payload))

        # If payload is reflected at all, treat it as reflection, not template execution.
        if raw_reflected or escaped_reflected:
            continue

        for match in re.finditer(re.escape(expected), text):
            start = max(0, match.start() - 80)
            end = min(len(text), match.end() + 80)
            snippet = text[start:end]

            if likely_value_context(snippet, expected):
                matches.append((payload, expected, shorten(snippet)))
                break

    unique_pairs = {(p, e) for p, e, _ in matches}

    # Need at least two distinct expression/result pairs.
    if len(unique_pairs) >= 2:
        examples = "; ".join([f"{p}→{e}" for p, e in list(unique_pairs)[:2]])
        snippets = " | ".join([s for _, _, s in matches[:2]])

        return Finding(
            url=url,
            param=param,
            payload=", ".join([p for p, _, _ in matches[:2]]),
            vuln_type="Possible Template Expression Evaluation",
            evidence=(
                f"Non-reflected expressions produced expected values in likely value contexts "
                f"({examples}). Manual confirmation required. Snippets: {snippets}"
            ),
            severity="Low",
            confidence="Low",
            context="Template Engine",
            group_key=f"{url}|template",
        )

    return None

# ── Checks ─────────────────────────────────────────────────────────────────────

def check_reflected_get(client: httpx.Client, url: str, timeout: float) -> List[Finding]:
    findings: List[Finding] = []
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))

    if not params:
        params = {k: "test" for k in COMMON_INPUTS[:5]}

    for param in params:
        template_finding = check_template_evaluation_for_param(client, url, param, timeout)
        if template_finding:
            findings.append(template_finding)

        for marker in REFLECTION_MARKERS:
            test_url = build_test_url(url, param, marker)

            try:
                resp = client.get(test_url, timeout=timeout)
            except httpx.RequestError:
                continue

            if not is_html_response(resp):
                continue

            classified = classify_reflection(marker, resp.text)
            if classified:
                severity, confidence, context, evidence = classified
                findings.append(
                    Finding(
                        url=url,
                        param=param,
                        payload=marker,
                        vuln_type="Reflected Input Exposure (GET)",
                        evidence=evidence,
                        severity=severity,
                        confidence=confidence,
                        context=context,
                        group_key=f"{url}|reflected_get|{context}",
                    )
                )
                break

    return findings

def check_forms(client: httpx.Client, url: str, html_text: str, timeout: float) -> List[Finding]:
    findings: List[Finding] = []
    forms = extract_forms(html_text, url)

    for form in forms:
        for input_name in form["inputs"]:
            for marker in REFLECTION_MARKERS[:3]:
                data = {i: "test" for i in form["inputs"]}
                data[input_name] = marker

                try:
                    if form["method"] == "POST":
                        resp = client.post(form["action"], data=data, timeout=timeout)
                    else:
                        resp = client.get(form["action"], params=data, timeout=timeout)
                except httpx.RequestError:
                    continue

                if not is_html_response(resp):
                    continue

                classified = classify_reflection(marker, resp.text)
                if classified:
                    severity, confidence, context, evidence = classified
                    findings.append(
                        Finding(
                            url=form["action"],
                            param=input_name,
                            payload=marker,
                            vuln_type=f"Reflected Input Exposure ({form['method']} form)",
                            evidence=evidence,
                            severity=severity,
                            confidence=confidence,
                            context=context,
                            group_key=f"{form['action']}|forms|{context}",
                        )
                    )
                    break

    return findings

def check_dom_xss_indicators(client: httpx.Client, url: str, timeout: float) -> List[Finding]:
    findings: List[Finding] = []

    try:
        resp = client.get(url, timeout=timeout)
    except httpx.RequestError:
        return findings

    text = resp.text.lower()

    found_sinks = [sink for sink in DOM_SINKS if sink.lower() in text]
    found_sources = [source for source in DOM_SOURCES if source.lower() in text]

    if found_sinks and found_sources:
        findings.append(
            Finding(
                url=url,
                param="DOM",
                payload=", ".join(found_sources[:2]),
                vuln_type="DOM XSS Source + Sink Pattern",
                evidence=f"Found source(s): {', '.join(found_sources[:2])} and sink(s): {', '.join(found_sinks[:2])}",
                severity="Medium",
                confidence="Medium",
                context="Client-side JavaScript",
                group_key=f"{url}|dom_source_sink",
            )
        )
    elif found_sinks:
        findings.append(
            Finding(
                url=url,
                param="DOM",
                payload=", ".join(found_sinks[:2]),
                vuln_type="DOM Sink Present",
                evidence=f"Sink(s) present without confirmed untrusted source flow: {', '.join(found_sinks[:2])}",
                severity="Info",
                confidence="Low",
                context="Client-side JavaScript",
                group_key=f"{url}|dom_sink_only",
            )
        )

    return findings

def check_headers(client: httpx.Client, url: str, timeout: float) -> List[Finding]:
    findings: List[Finding] = []

    try:
        resp = client.get(url, timeout=timeout)
    except httpx.RequestError:
        return findings

    headers = {k.lower(): v for k, v in resp.headers.items()}
    missing = []

    if "content-security-policy" not in headers:
        missing.append("Content-Security-Policy")
    if "x-content-type-options" not in headers:
        missing.append("X-Content-Type-Options")
    if "referrer-policy" not in headers:
        missing.append("Referrer-Policy")

    if urllib.parse.urlparse(url).scheme == "https" and "strict-transport-security" not in headers:
        missing.append("Strict-Transport-Security")

    if missing:
        findings.append(
            Finding(
                url=url,
                param="HTTP Headers",
                payload="N/A",
                vuln_type="Missing Security Headers",
                evidence=f"Missing: {', '.join(missing)}",
                severity="Low",
                confidence="High",
                context="HTTP Response",
                group_key=f"{url}|headers_missing",
            )
        )

    csp = headers.get("content-security-policy", "")
    if csp:
        weak_parts = []
        csp_lower = csp.lower()

        if "'unsafe-inline'" in csp_lower:
            weak_parts.append("'unsafe-inline'")
        if "'unsafe-eval'" in csp_lower:
            weak_parts.append("'unsafe-eval'")

        if weak_parts:
            findings.append(
                Finding(
                    url=url,
                    param="Content-Security-Policy",
                    payload=", ".join(weak_parts),
                    vuln_type="Weak CSP Configuration",
                    evidence=f"CSP contains risky directive(s): {', '.join(weak_parts)}",
                    severity="Medium",
                    confidence="High",
                    context="HTTP Response",
                    group_key=f"{url}|headers_csp",
                )
            )

    return findings

# ── Grouping ───────────────────────────────────────────────────────────────────

def group_findings(findings: List[Finding]) -> List[Finding]:
    grouped: Dict[str, Finding] = {}
    grouped_params: Dict[str, List[str]] = defaultdict(list)

    for finding in findings:
        key = finding.group_key or (
            f"{finding.url}|{finding.vuln_type}|{finding.context}|{finding.severity}|{finding.confidence}"
        )

        if key not in grouped:
            grouped[key] = finding
        else:
            grouped[key] = choose_stronger(grouped[key], finding)

        if finding.param not in grouped_params[key]:
            grouped_params[key].append(finding.param)

    output: List[Finding] = []

    for key, finding in grouped.items():
        params = grouped_params[key]
        if len(params) > 1 and finding.param not in ("DOM", "HTTP Headers", "Content-Security-Policy"):
            new_finding = Finding(
                url=finding.url,
                param=", ".join(params),
                payload=finding.payload,
                vuln_type=finding.vuln_type,
                evidence=f"{finding.evidence} | Affected parameters: {', '.join(params)}",
                severity=finding.severity,
                confidence=finding.confidence,
                context=finding.context,
                group_key=finding.group_key,
            )
            output.append(new_finding)
        else:
            output.append(finding)

    output = dedupe_findings(output)
    output.sort(
        key=lambda f: (severity_rank(f.severity), confidence_rank(f.confidence)),
        reverse=True,
    )
    return output

# ── Scanner ────────────────────────────────────────────────────────────────────

def scan(
    url: str,
    checks: List[str],
    headers: Dict[str, str],
    cookies: Dict[str, str],
    timeout: float,
    insecure: bool,
) -> Tuple[List[Finding], Dict]:
    findings: List[Finding] = []

    with httpx.Client(
        headers=headers,
        cookies=cookies,
        follow_redirects=True,
        verify=not insecure,
    ) as client:
        try:
            baseline = client.get(url, timeout=timeout)
        except httpx.RequestError as exc:
            console.print(f"  [red]Could not reach {url}: {exc}[/red]")
            return [], {}

        baseline_info = baseline_fingerprint(baseline)
        console.print(
            f"  [dim]Baseline:[/dim] status=[cyan]{baseline_info['status_code']}[/cyan] "
            f"size=[cyan]{baseline_info['length']}[/cyan] chars "
            f"hash=[cyan]{baseline_info['hash'][:12]}[/cyan]"
        )
        console.print()

        if "reflected" in checks or "all" in checks:
            console.print("  [dim]Testing reflected input exposure via GET parameters...[/dim]")
            findings.extend(check_reflected_get(client, url, timeout))

        if "forms" in checks or "all" in checks:
            console.print("  [dim]Testing forms for reflected input exposure...[/dim]")
            findings.extend(check_forms(client, url, baseline.text, timeout))

        if "dom" in checks or "all" in checks:
            console.print("  [dim]Checking DOM XSS indicators...[/dim]")
            findings.extend(check_dom_xss_indicators(client, url, timeout))

        if "headers" in checks or "all" in checks:
            console.print("  [dim]Checking security headers...[/dim]")
            findings.extend(check_headers(client, url, timeout))

    findings = group_findings(findings)

    summary = {
        "target": url,
        "total": len(findings),
        "high": sum(1 for f in findings if f.severity == "High"),
        "medium": sum(1 for f in findings if f.severity == "Medium"),
        "low": sum(1 for f in findings if f.severity == "Low"),
        "info": sum(1 for f in findings if f.severity == "Info"),
    }
    return findings, summary

# ── Output ─────────────────────────────────────────────────────────────────────

def print_findings(findings: List[Finding], summary: Dict) -> None:
    console.print()

    if not findings:
        console.print(
            Panel(
                "[green]No significant XSS indicators detected.[/green]\n"
                "[dim]This does not guarantee the target is secure.[/dim]",
                title="Result",
                border_style="green",
            )
        )
        return

    console.print(
        Panel(
            f"[red]High:[/red]   [bold red]{summary.get('high', 0)}[/bold red]\n"
            f"[yellow]Medium:[/yellow] [bold yellow]{summary.get('medium', 0)}[/bold yellow]\n"
            f"[cyan]Low:[/cyan]    [bold cyan]{summary.get('low', 0)}[/bold cyan]\n"
            f"[white]Info:[/white]   [bold]{summary.get('info', 0)}[/bold]\n"
            f"[white]Total:[/white]  [bold]{summary.get('total', 0)}[/bold]",
            title=f"[bold red]{summary.get('total', 0)} Finding(s)[/bold red]",
            border_style="red",
        )
    )

    table = Table(box=box.ROUNDED, show_lines=True)
    table.add_column("Severity", width=8, justify="center")
    table.add_column("Confidence", width=10, justify="center")
    table.add_column("Type", style="red", no_wrap=True)
    table.add_column("Param", style="cyan")
    table.add_column("Context", style="yellow", no_wrap=True)
    table.add_column("Payload", style="magenta", max_width=26)
    table.add_column("Evidence", style="dim", max_width=60)

    sev_map = {
        "High": "[bold red]HIGH[/bold red]",
        "Medium": "[yellow]MED[/yellow]",
        "Low": "[cyan]LOW[/cyan]",
        "Info": "[white]INFO[/white]",
    }
    conf_map = {
        "High": "[bold green]HIGH[/bold green]",
        "Medium": "[green]MED[/green]",
        "Low": "[dim]LOW[/dim]",
    }

    for finding in findings:
        table.add_row(
            sev_map.get(finding.severity, finding.severity),
            conf_map.get(finding.confidence, finding.confidence),
            finding.vuln_type,
            finding.param,
            finding.context,
            finding.payload,
            finding.evidence,
        )

    console.print(table)

def save_json(findings: List[Finding], summary: Dict, output_file: str) -> None:
    data = {
        "summary": summary,
        "findings": [f.to_dict() for f in findings],
    }
    with open(output_file, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)

def save_text(findings: List[Finding], summary: Dict, output_file: str) -> None:
    with open(output_file, "w", encoding="utf-8") as handle:
        handle.write(f"Target: {summary.get('target')}\n")
        handle.write(f"Total: {summary.get('total')}\n")
        handle.write(
            f"High: {summary.get('high')} | Medium: {summary.get('medium')} | "
            f"Low: {summary.get('low')} | Info: {summary.get('info')}\n\n"
        )

        for index, finding in enumerate(findings, 1):
            handle.write(f"[{index}] {finding.vuln_type}\n")
            handle.write(f"  Severity:   {finding.severity}\n")
            handle.write(f"  Confidence: {finding.confidence}\n")
            handle.write(f"  URL:        {finding.url}\n")
            handle.write(f"  Param:      {finding.param}\n")
            handle.write(f"  Context:    {finding.context}\n")
            handle.write(f"  Payload:    {finding.payload}\n")
            handle.write(f"  Evidence:   {finding.evidence}\n\n")

# ── CLI ────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Defensive XSS Scanner - part of STRYKER",
        epilog="""
Examples:
  python web/xss_scanner.py -u "https://example.com/search?q=hello"
  python web/xss_scanner.py -u "https://example.com" --checks reflected dom
  python web/xss_scanner.py -u "https://example.com" --checks all -o results.json

Only test systems you own or have written permission to test.
        """,
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument(
        "--checks",
        nargs="+",
        choices=["reflected", "forms", "dom", "headers", "all"],
        default=["all"],
        help="Which checks to run (default: all)",
    )
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        help="Custom header, e.g. 'Authorization: Bearer x'",
    )
    parser.add_argument(
        "-c",
        "--cookie",
        action="append",
        default=[],
        help="Cookie, e.g. 'session=abc'",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Save findings to file (.json or .txt)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification",
    )
    return parser.parse_args()

def main():
    args = parse_args()

    console.print(
        Panel.fit(
            "[bold red]STRYKER[/bold red] [white]//[/white] [cyan]XSS Scanner Pro[/cyan]\n"
            "[dim]Defensive reflection analysis | template verification | DOM indicators | headers | Authorized testing only[/dim]",
            border_style="red",
        )
    )
    console.print()

    headers: Dict[str, str] = {}
    for header_item in args.header:
        if ":" in header_item:
            key, value = header_item.split(":", 1)
            headers[key.strip()] = value.strip()

    cookies: Dict[str, str] = {}
    for cookie_item in args.cookie:
        if "=" in cookie_item:
            key, value = cookie_item.split("=", 1)
            cookies[key.strip()] = value.strip()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Scanning {args.url[:60]}...", total=None)
        findings, summary = scan(
            url=args.url,
            checks=args.checks,
            headers=headers,
            cookies=cookies,
            timeout=args.timeout,
            insecure=args.insecure,
        )
        progress.update(task, completed=True)

    print_findings(findings, summary)

    if args.output:
        if args.output.lower().endswith(".json"):
            save_json(findings, summary, args.output)
        else:
            save_text(findings, summary, args.output)
        console.print(f"\n[green]Findings saved to {args.output}[/green]")

if __name__ == "__main__":
    main()