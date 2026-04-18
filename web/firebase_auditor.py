#!/usr/bin/env python3
"""
firebase_auditor.py - Firebase Security Rules Auditor
Part of STRYKER by Andrews

LEGAL NOTICE: For authorized penetration testing ONLY.
Only use against systems you own or have explicit written permission to test.
"""

import argparse
import sys
import io
import json
import re
import urllib.parse

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

# ── Finding ────────────────────────────────────────────────────────────────────

class Finding:
    def __init__(self, check, severity, title, detail, recommendation):
        self.check          = check
        self.severity       = severity
        self.title          = title
        self.detail         = detail
        self.recommendation = recommendation

    def __str__(self):
        return f"[{self.severity}][{self.check}] {self.title}"


# ── Checks ─────────────────────────────────────────────────────────────────────

def check_open_firestore(project_id, headers):
    """Try reading Firestore REST API without authentication."""
    findings = []
    base = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents"

    common_collections = [
        "users", "orders", "products", "payments",
        "messages", "posts", "customers", "invoices",
        "admin", "config", "settings", "transactions",
    ]

    with httpx.Client(follow_redirects=True, verify=False) as client:
        for collection in common_collections:
            url = f"{base}/{collection}"
            try:
                resp = client.get(url, headers=headers, timeout=10)

                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        docs = data.get("documents", [])
                        count = len(docs)
                        findings.append(Finding(
                            check="Open Firestore Read",
                            severity="CRITICAL",
                            title=f"Collection '{collection}' readable without auth",
                            detail=f"Found {count} document(s) accessible at /{collection}",
                            recommendation=f"Add auth check to Firestore rules:\n  match /{collection}/{{doc}} {{ allow read: if request.auth != null; }}"
                        ))
                    except Exception:
                        findings.append(Finding(
                            check="Open Firestore Read",
                            severity="CRITICAL",
                            title=f"Collection '{collection}' returned 200 without auth",
                            detail="Firestore responded with 200 — data may be accessible",
                            recommendation="Review and restrict Firestore security rules immediately"
                        ))

                elif resp.status_code == 403:
                    console.print(f"  [dim]/{collection} — [green]protected (403)[/green][/dim]")

            except httpx.RequestError:
                pass

    return findings


def check_open_realtime_db(project_id, headers):
    """Try reading Firebase Realtime Database without auth."""
    findings = []
    urls = [
        f"https://{project_id}.firebaseio.com/.json",
        f"https://{project_id}-default-rtdb.firebaseio.com/.json",
    ]

    common_paths = [
        "users", "orders", "products", "messages",
        "config", "admin", "payments", "customers",
    ]

    with httpx.Client(follow_redirects=True, verify=False) as client:
        for base_url in urls:
            # Try root
            try:
                resp = client.get(base_url, headers=headers, timeout=10)
                if resp.status_code == 200:
                    data = resp.text
                    if data and data != "null":
                        findings.append(Finding(
                            check="Open Realtime DB",
                            severity="CRITICAL",
                            title="Realtime Database root readable without auth",
                            detail=f"Database at {base_url} returned data without authentication",
                            recommendation='Set rules to: { "rules": { ".read": "auth != null", ".write": "auth != null" } }'
                        ))
            except httpx.RequestError:
                pass

            # Try common paths
            for path in common_paths:
                url = base_url.replace(".json", f"/{path}.json")
                try:
                    resp = client.get(url, headers=headers, timeout=8)
                    if resp.status_code == 200:
                        data = resp.text.strip()
                        if data and data != "null":
                            findings.append(Finding(
                                check="Open Realtime DB",
                                severity="CRITICAL",
                                title=f"Path '/{path}' readable without auth",
                                detail=f"Data found at {url}",
                                recommendation=f'Set rules: {{ "rules": {{ "{path}": {{ ".read": "auth != null" }} }} }}'
                            ))
                except httpx.RequestError:
                    pass

    return findings


def check_firebase_config_exposed(target_url):
    """Check if Firebase config is exposed in page source."""
    findings = []

    with httpx.Client(follow_redirects=True, verify=False) as client:
        try:
            resp = client.get(target_url, timeout=10)
            html = resp.text

            # Look for Firebase config patterns
            patterns = [
                (r'apiKey\s*:\s*["\']([A-Za-z0-9_-]{35,})["\']',    "API Key"),
                (r'authDomain\s*:\s*["\']([^"\']+)["\']',             "Auth Domain"),
                (r'databaseURL\s*:\s*["\']([^"\']+)["\']',            "Database URL"),
                (r'storageBucket\s*:\s*["\']([^"\']+)["\']',          "Storage Bucket"),
                (r'messagingSenderId\s*:\s*["\']([^"\']+)["\']',       "Messaging Sender ID"),
                (r'measurementId\s*:\s*["\']([^"\']+)["\']',          "Measurement ID"),
            ]

            exposed = []
            for pattern, label in patterns:
                match = re.search(pattern, html)
                if match:
                    exposed.append(f"{label}: {match.group(1)[:20]}...")

            if exposed:
                findings.append(Finding(
                    check="Exposed Firebase Config",
                    severity="MEDIUM",
                    title="Firebase configuration exposed in page source",
                    detail="Found: " + ", ".join(exposed),
                    recommendation=(
                        "Firebase config keys in frontend JS are expected but ensure:\n"
                        "  1. Firestore/RTDB rules require authentication\n"
                        "  2. API key restrictions are set in Google Cloud Console\n"
                        "  3. Authorized domains list is restricted in Firebase Console"
                    )
                ))

            # Check for admin SDK credentials (critical if found)
            admin_patterns = [
                r'private_key\s*:\s*["\']-----BEGIN',
                r'client_email\s*:\s*["\'][^"\']+\.iam\.gserviceaccount\.com',
                r'"type"\s*:\s*"service_account"',
            ]
            for pattern in admin_patterns:
                if re.search(pattern, html):
                    findings.append(Finding(
                        check="Exposed Admin Credentials",
                        severity="CRITICAL",
                        title="Firebase Admin SDK credentials exposed in frontend",
                        detail="Service account credentials found in page source — full admin access possible",
                        recommendation="Remove service account credentials from frontend immediately. Never use Admin SDK in client-side code."
                    ))
                    break

        except httpx.RequestError as e:
            console.print(f"  [yellow]Could not fetch {target_url}: {e}[/yellow]")

    return findings


def check_storage_rules(project_id, headers):
    """Check if Firebase Storage buckets are publicly accessible."""
    findings = []
    bucket = f"{project_id}.appspot.com"
    test_urls = [
        f"https://storage.googleapis.com/{bucket}/",
        f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o",
    ]

    with httpx.Client(follow_redirects=True, verify=False) as client:
        for url in test_urls:
            try:
                resp = client.get(url, headers=headers, timeout=10)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        items = data.get("items", data.get("prefixes", []))
                        findings.append(Finding(
                            check="Open Storage Bucket",
                            severity="HIGH",
                            title="Firebase Storage bucket publicly accessible",
                            detail=f"Storage at {bucket} returned {len(items)} item(s) without auth",
                            recommendation="Update Storage rules:\n  allow read: if request.auth != null;"
                        ))
                    except Exception:
                        pass
            except httpx.RequestError:
                pass

    return findings


def check_auth_providers(project_id):
    """Check Firebase Authentication configuration via API."""
    findings = []

    url = f"https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri"

    # Check if anonymous auth is enabled (common misconfiguration)
    with httpx.Client(verify=False) as client:
        try:
            resp = client.post(
                url,
                json={"identifier": "test@test.com", "continueUri": f"https://{project_id}.web.app"},
                timeout=10
            )
            if resp.status_code == 400:
                data = resp.json()
                error = data.get("error", {}).get("message", "")
                if "API_KEY" in error:
                    findings.append(Finding(
                        check="Auth Configuration",
                        severity="INFO",
                        title="Firebase Auth API accessible",
                        detail="Authentication endpoints are reachable — verify sign-up restrictions",
                        recommendation="In Firebase Console → Authentication → Settings, restrict sign-in methods and authorized domains"
                    ))
        except httpx.RequestError:
            pass

    return findings


def extract_project_id(target):
    """Try to extract Firebase project ID from URL or string."""
    # Direct project ID
    if not target.startswith("http"):
        return target

    patterns = [
        r'https://([a-z0-9-]+)\.firebaseio\.com',
        r'https://([a-z0-9-]+)-default-rtdb\.firebaseio\.com',
        r'https://([a-z0-9-]+)\.web\.app',
        r'https://([a-z0-9-]+)\.firebaseapp\.com',
        r'https://firestore\.googleapis\.com/v1/projects/([a-z0-9-]+)',
        r'project[_-]?id["\s:=]+["\']?([a-z0-9-]+)',
    ]

    for pattern in patterns:
        match = re.search(pattern, target)
        if match:
            return match.group(1)

    return None


# ── Output ─────────────────────────────────────────────────────────────────────

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
SEV_COLOR = {
    "CRITICAL": "[bold red]CRITICAL[/bold red]",
    "HIGH":     "[red]HIGH[/red]",
    "MEDIUM":   "[yellow]MEDIUM[/yellow]",
    "INFO":     "[cyan]INFO[/cyan]",
}


def print_findings(findings, project_id):
    console.print()

    if not findings:
        console.print(Panel(
            f"[green]No Firebase misconfigurations detected for project '{project_id}'.[/green]\n"
            "[dim]Verify manually in Firebase Console → Rules → Simulator.[/dim]",
            title="Result", border_style="green"
        ))
        return

    findings.sort(key=lambda f: SEV_ORDER.get(f.severity, 99))
    critical = sum(1 for f in findings if f.severity == "CRITICAL")
    high     = sum(1 for f in findings if f.severity == "HIGH")
    medium   = sum(1 for f in findings if f.severity == "MEDIUM")

    console.print(Panel(
        f"[bold red]Critical: {critical}[/bold red]   "
        f"[red]High: {high}[/red]   "
        f"[yellow]Medium: {medium}[/yellow]   "
        f"[white]Total: {len(findings)}[/white]",
        title=f"[bold red]{len(findings)} Finding(s) — Project: {project_id}[/bold red]",
        border_style="red"
    ))
    console.print()

    for i, f in enumerate(findings, 1):
        console.print(Panel(
            f"[dim]Check:[/dim]          {f.check}\n"
            f"[dim]Detail:[/dim]         {f.detail}\n\n"
            f"[dim]Recommendation:[/dim] [green]{f.recommendation}[/green]",
            title=f"{SEV_COLOR[f.severity]}  {f.title}",
            border_style="red" if f.severity in ("CRITICAL", "HIGH") else "yellow"
        ))
        console.print()


# ── CLI ────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Firebase Rules Auditor - part of STRYKER",
        epilog="""
Examples:
  python web/firebase_auditor.py -p my-project-id
  python web/firebase_auditor.py -p my-project-id --checks firestore storage
  python web/firebase_auditor.py -u https://myapp.web.app
  python web/firebase_auditor.py -p my-project-id -o findings.txt

Only test projects you own or have written permission to test.
        """
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--project", help="Firebase project ID (e.g. my-app-12345)")
    group.add_argument("-u", "--url",     help="App URL to extract project ID from")
    parser.add_argument(
        "--checks", nargs="+",
        choices=["firestore", "rtdb", "config", "storage", "auth", "all"],
        default=["all"],
        help="Which checks to run (default: all)"
    )
    parser.add_argument("-H", "--header", action="append", default=[],
                        help="Custom header")
    parser.add_argument("-o", "--output", help="Save findings to file")
    return parser.parse_args()


def main():
    args = parse_args()

    console.print(Panel.fit(
        "[bold red]STRYKER[/bold red] [white]//[/white] [cyan]Firebase Rules Auditor[/cyan]\n"
        "[dim]Firestore | Realtime DB | Storage | Auth | For authorized testing only[/dim]",
        border_style="red"
    ))
    console.print()

    # Resolve project ID
    project_id = args.project if args.project else extract_project_id(args.url)
    if not project_id:
        console.print("[red]Could not determine Firebase project ID. Use -p to specify it directly.[/red]")
        sys.exit(1)

    console.print(f"  [dim]Project ID:[/dim] [cyan]{project_id}[/cyan]")
    console.print()

    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    checks = args.checks
    all_findings = []

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console) as progress:

        if "firestore" in checks or "all" in checks:
            t = progress.add_task("Checking Firestore rules...", total=None)
            all_findings += check_open_firestore(project_id, headers)
            progress.update(t, completed=True)

        if "rtdb" in checks or "all" in checks:
            t = progress.add_task("Checking Realtime Database...", total=None)
            all_findings += check_open_realtime_db(project_id, headers)
            progress.update(t, completed=True)

        if "config" in checks or "all" in checks:
            if args.url:
                t = progress.add_task("Checking for exposed config...", total=None)
                all_findings += check_firebase_config_exposed(args.url)
                progress.update(t, completed=True)

        if "storage" in checks or "all" in checks:
            t = progress.add_task("Checking Storage rules...", total=None)
            all_findings += check_storage_rules(project_id, headers)
            progress.update(t, completed=True)

        if "auth" in checks or "all" in checks:
            t = progress.add_task("Checking Auth configuration...", total=None)
            all_findings += check_auth_providers(project_id)
            progress.update(t, completed=True)

    print_findings(all_findings, project_id)

    if args.output and all_findings:
        with open(args.output, "w") as f:
            for finding in all_findings:
                f.write(str(finding) + "\n")
        console.print(f"[green]Findings saved to {args.output}[/green]")


if __name__ == "__main__":
    main()