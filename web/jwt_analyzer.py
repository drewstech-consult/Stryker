#!/usr/bin/env python3
"""
jwt_analyzer.py - JWT Token Analyzer & Security Tester
Part of STRYKER by Andrews

LEGAL NOTICE: For authorized penetration testing ONLY.
Only use against systems you own or have explicit written permission to test.
"""

import argparse
import sys
import io
import json
import base64
import hmac
import hashlib
import re
import time
from datetime import datetime, timezone

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich import box

console = Console(highlight=False)

# ── Common weak secrets to test ────────────────────────────────────────────────

WEAK_SECRETS = [
    "secret", "password", "123456", "test", "key",
    "jwt_secret", "your-secret-key", "mysecret", "supersecret",
    "secret123", "jwtkey", "token", "auth", "private",
    "changeme", "default", "admin", "letmein", "qwerty",
    "your-256-bit-secret", "your-secret", "secretkey",
    "", "null", "undefined", "none",
]

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


# ── JWT Core ───────────────────────────────────────────────────────────────────

def b64_decode(data):
    """Base64url decode with padding fix."""
    data = data.replace("-", "+").replace("_", "/")
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.b64decode(data)


def decode_jwt(token):
    """Decode JWT without verification. Returns (header, payload, signature)."""
    try:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return None, None, None

        header    = json.loads(b64_decode(parts[0]))
        payload   = json.loads(b64_decode(parts[1]))
        signature = parts[2]

        return header, payload, signature
    except Exception as e:
        return None, None, None


def format_timestamp(ts):
    """Convert Unix timestamp to human readable."""
    try:
        dt = datetime.fromtimestamp(int(ts), tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def is_expired(payload):
    """Check if token is expired."""
    exp = payload.get("exp")
    if not exp:
        return None
    return int(time.time()) > int(exp)


# ── Checks ─────────────────────────────────────────────────────────────────────

def check_algorithm(header, payload):
    """Check for dangerous algorithm configurations."""
    findings = []
    alg = header.get("alg", "").upper()

    # None algorithm attack
    if alg == "NONE" or alg == "":
        findings.append(Finding(
            check="Algorithm",
            severity="CRITICAL",
            title="Algorithm set to 'none' — signature bypass possible",
            detail="JWT uses 'none' algorithm meaning no signature verification is required",
            recommendation="Always enforce HS256, RS256 or ES256. Reject tokens with alg=none."
        ))

    # Weak algorithm
    elif alg in ("HS256", "HS384", "HS512"):
        findings.append(Finding(
            check="Algorithm",
            severity="INFO",
            title=f"Symmetric algorithm in use: {alg}",
            detail="HMAC algorithms are safe if the secret is strong and kept private",
            recommendation="Ensure the signing secret is at least 32 random characters. Consider RS256 for distributed systems."
        ))

    # RS/ES algorithms — strong
    elif alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"):
        findings.append(Finding(
            check="Algorithm",
            severity="INFO",
            title=f"Asymmetric algorithm in use: {alg}",
            detail="Strong algorithm — public/private key pair is used",
            recommendation="Ensure private key is kept secure and rotated periodically."
        ))

    # Algorithm confusion attack vector
    if alg.startswith("RS") or alg.startswith("ES"):
        findings.append(Finding(
            check="Algorithm Confusion",
            severity="HIGH",
            title="Potential algorithm confusion attack vector",
            detail=f"Server uses {alg} — if server accepts both RS/HS algorithms, attacker may forge tokens using the public key as HMAC secret",
            recommendation="Explicitly reject HS* algorithms on endpoints expecting RS/ES tokens. Never allow algorithm switching."
        ))

    return findings


def check_expiry(payload):
    """Check token expiry configuration."""
    findings = []

    # No expiry
    if "exp" not in payload:
        findings.append(Finding(
            check="Expiry",
            severity="HIGH",
            title="Token has no expiration (exp claim missing)",
            detail="Token never expires — if stolen it can be used indefinitely",
            recommendation="Always set 'exp' claim. Recommended: 15 minutes for access tokens, 7 days for refresh tokens."
        ))
    else:
        exp_time = format_timestamp(payload["exp"])
        expired  = is_expired(payload)

        if expired:
            findings.append(Finding(
                check="Expiry",
                severity="MEDIUM",
                title="Token is expired",
                detail=f"Token expired at {exp_time}",
                recommendation="If server still accepts this token, it is not validating expiry. Fix server-side JWT validation."
            ))
        else:
            # Check if expiry is very far in the future (more than 30 days)
            ttl = int(payload["exp"]) - int(time.time())
            if ttl > 60 * 60 * 24 * 30:
                days = ttl // 86400
                findings.append(Finding(
                    check="Expiry",
                    severity="MEDIUM",
                    title=f"Token expiry is very long ({days} days)",
                    detail=f"Token expires at {exp_time}",
                    recommendation="Use short-lived access tokens (15-60 min) with refresh tokens for better security."
                ))

    # No issued-at claim
    if "iat" not in payload:
        findings.append(Finding(
            check="Claims",
            severity="LOW",
            title="Missing 'iat' (issued at) claim",
            detail="Cannot determine when token was issued",
            recommendation="Always include 'iat' claim for audit trails and token age validation."
        ))

    return findings


def check_sensitive_data(payload):
    """Check if sensitive data is stored in payload."""
    findings = []

    sensitive_keys = [
        "password", "pwd", "pass", "secret", "key", "private",
        "credit_card", "card", "ssn", "cvv", "pin",
        "api_key", "token", "auth_token",
    ]

    found_sensitive = []
    for key in payload:
        if any(s in key.lower() for s in sensitive_keys):
            found_sensitive.append(key)

    if found_sensitive:
        findings.append(Finding(
            check="Sensitive Data",
            severity="HIGH",
            title="Sensitive data found in JWT payload",
            detail=f"Potentially sensitive claims: {', '.join(found_sensitive)}",
            recommendation="Never store passwords, secrets, or sensitive PII in JWT payload. JWT is base64 encoded — not encrypted."
        ))

    # Check for PII
    pii_keys = ["email", "phone", "address", "dob", "birth", "ssn", "national_id"]
    found_pii = [k for k in payload if any(p in k.lower() for p in pii_keys)]

    if found_pii:
        findings.append(Finding(
            check="PII in Token",
            severity="MEDIUM",
            title="Personal data found in JWT payload",
            detail=f"PII claims: {', '.join(found_pii)}",
            recommendation="Minimize PII in tokens. JWT payload is readable by anyone who has the token."
        ))

    return findings


def check_weak_secret(token):
    """Try to crack HMAC signature with common weak secrets."""
    findings = []
    parts = token.strip().split(".")
    if len(parts) != 3:
        return findings

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    sig = b64_decode(parts[2])

    console.print("  [dim]Testing weak secrets...[/dim]")
    for secret in WEAK_SECRETS:
        for alg, digest in [("HS256", hashlib.sha256), ("HS384", hashlib.sha384), ("HS512", hashlib.sha512)]:
            test_sig = hmac.new(secret.encode(), signing_input, digest).digest()
            if hmac.compare_digest(test_sig, sig):
                findings.append(Finding(
                    check="Weak Secret",
                    severity="CRITICAL",
                    title=f"JWT secret cracked: '{secret}'",
                    detail=f"Signature verified with secret='{secret}' using {alg}. Attacker can forge any token.",
                    recommendation=f"Immediately rotate the JWT secret. Use a random string of 32+ characters. Never use common words."
                ))
                return findings

    return findings


def check_endpoint(token, url, header_name):
    """Test if server validates JWT properly."""
    findings = []
    parts = token.strip().split(".")
    if len(parts) != 3:
        return findings

    with httpx.Client(follow_redirects=True, verify=False) as client:

        # Test 1: tampered payload
        try:
            header_data, payload_data, _ = decode_jwt(token)
            if payload_data:
                tampered = payload_data.copy()

                # Try privilege escalation
                for role_key in ["role", "roles", "admin", "isAdmin", "scope", "permissions"]:
                    if role_key in tampered:
                        tampered[role_key] = "admin" if tampered[role_key] != "admin" else "superadmin"

                tampered_payload = base64.urlsafe_b64encode(
                    json.dumps(tampered, separators=(",", ":")).encode()
                ).rstrip(b"=").decode()

                tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"
                resp = client.get(url, headers={header_name: f"Bearer {tampered_token}"}, timeout=10)

                if resp.status_code == 200:
                    findings.append(Finding(
                        check="Endpoint Validation",
                        severity="CRITICAL",
                        title="Server accepted tampered JWT payload",
                        detail=f"Modified payload accepted at {url} — signature not being verified",
                        recommendation="Verify JWT signature on every request. Never trust payload without signature verification."
                    ))
        except Exception:
            pass

        # Test 2: none algorithm
        try:
            none_header = base64.urlsafe_b64encode(
                json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()

            none_token = f"{none_header}.{parts[1]}."
            resp = client.get(url, headers={header_name: f"Bearer {none_token}"}, timeout=10)

            if resp.status_code == 200:
                findings.append(Finding(
                    check="None Algorithm",
                    severity="CRITICAL",
                    title="Server accepted token with alg=none",
                    detail=f"Endpoint {url} accepted unsigned token — complete auth bypass possible",
                    recommendation="Explicitly reject tokens with alg=none. Whitelist allowed algorithms."
                ))
        except Exception:
            pass

    return findings


# ── Output ─────────────────────────────────────────────────────────────────────

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = {
    "CRITICAL": "[bold red]CRITICAL[/bold red]",
    "HIGH":     "[red]HIGH[/red]",
    "MEDIUM":   "[yellow]MEDIUM[/yellow]",
    "LOW":      "[cyan]LOW[/cyan]",
    "INFO":     "[dim]INFO[/dim]",
}


def print_token_info(header, payload):
    """Print decoded token contents."""
    console.print()
    console.print(Rule("[cyan] Token Contents [/cyan]", style="cyan"))
    console.print()

    # Header
    console.print("[dim]Header:[/dim]")
    for k, v in header.items():
        console.print(f"  [cyan]{k:<16}[/cyan] {v}")
    console.print()

    # Payload
    console.print("[dim]Payload:[/dim]")
    for k, v in payload.items():
        if k in ("exp", "iat", "nbf"):
            console.print(f"  [cyan]{k:<16}[/cyan] {v}  [dim]({format_timestamp(v)})[/dim]")
        else:
            console.print(f"  [cyan]{k:<16}[/cyan] {v}")

    # Expiry status
    console.print()
    expired = is_expired(payload)
    if expired is None:
        console.print("  [yellow]No expiry set[/yellow]")
    elif expired:
        console.print("  [red]Token is EXPIRED[/red]")
    else:
        ttl = int(payload["exp"]) - int(time.time())
        console.print(f"  [green]Token is valid — expires in {ttl // 3600}h {(ttl % 3600) // 60}m[/green]")
    console.print()


def print_findings(findings):
    console.print()
    if not findings:
        console.print(Panel(
            "[green]No critical JWT vulnerabilities detected.[/green]\n"
            "[dim]Always verify server-side validation manually.[/dim]",
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
        title=f"[bold red]{len(findings)} Finding(s)[/bold red]",
        border_style="red"
    ))
    console.print()

    for f in findings:
        color = "red" if f.severity in ("CRITICAL", "HIGH") else "yellow"
        console.print(Panel(
            f"[dim]Detail:[/dim]         {f.detail}\n\n"
            f"[dim]Fix:[/dim]            [green]{f.recommendation}[/green]",
            title=f"{SEV_COLOR[f.severity]}  {f.title}",
            border_style=color
        ))
        console.print()


# ── CLI ────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="JWT Analyzer - part of STRYKER",
        epilog="""
Examples:
  python web/jwt_analyzer.py -t "eyJhbGci..."
  python web/jwt_analyzer.py -t "eyJhbGci..." --checks decode expiry secret
  python web/jwt_analyzer.py -t "eyJhbGci..." -u https://api.example.com/profile
  python web/jwt_analyzer.py -t "eyJhbGci..." -o findings.txt

Only test tokens and systems you own or have written permission to test.
        """
    )
    parser.add_argument("-t", "--token",  required=True, help="JWT token to analyze")
    parser.add_argument(
        "--checks", nargs="+",
        choices=["decode", "algorithm", "expiry", "sensitive", "secret", "endpoint", "all"],
        default=["all"],
        help="Which checks to run (default: all)"
    )
    parser.add_argument("-u", "--url",    help="Endpoint URL to test token against")
    parser.add_argument("-H", "--header-name", default="Authorization",
                        help="Header name to send token in (default: Authorization)")
    parser.add_argument("-o", "--output", help="Save findings to file")
    return parser.parse_args()


def main():
    args = parse_args()

    console.print(Panel.fit(
        "[bold red]STRYKER[/bold red] [white]//[/white] [cyan]JWT Analyzer[/cyan]\n"
        "[dim]Decode | Algorithm | Expiry | Weak Secrets | Endpoint Testing[/dim]",
        border_style="red"
    ))
    console.print()

    token = args.token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:]

    # Decode
    header, payload, signature = decode_jwt(token)
    if not header or not payload:
        console.print("[red]Invalid JWT token — could not decode.[/red]")
        sys.exit(1)

    checks = args.checks
    all_findings = []

    # Always show decoded contents
    print_token_info(header, payload)

    console.print(Rule("[dim] Running checks [/dim]", style="red"))
    console.print()

    if "algorithm" in checks or "all" in checks:
        all_findings += check_algorithm(header, payload)

    if "expiry" in checks or "all" in checks:
        all_findings += check_expiry(payload)

    if "sensitive" in checks or "all" in checks:
        all_findings += check_sensitive_data(payload)

    if "secret" in checks or "all" in checks:
        alg = header.get("alg", "").upper()
        if alg.startswith("HS"):
            all_findings += check_weak_secret(token)
        else:
            console.print(f"  [dim]Skipping secret brute-force — algorithm is {alg} (not HMAC)[/dim]")

    if ("endpoint" in checks or "all" in checks) and args.url:
        console.print("  [dim]Testing endpoint validation...[/dim]")
        all_findings += check_endpoint(token, args.url, args.header_name)

    print_findings(all_findings)

    if args.output and all_findings:
        with open(args.output, "w") as f:
            for finding in all_findings:
                f.write(str(finding) + "\n")
        console.print(f"[green]Findings saved to {args.output}[/green]")


if __name__ == "__main__":
    main()