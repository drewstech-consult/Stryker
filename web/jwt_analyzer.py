#!/usr/bin/env python3
"""
jwt_analyzer.py - Defensive JWT Token Analyzer
Part of STRYKER by Andrews

LEGAL NOTICE: For authorized security review ONLY.
Only use against tokens and systems you own or have explicit written permission to assess.

This version is defensive:
- decodes and explains JWTs
- classifies token type
- checks claims quality and expiry
- flags risky token contents conservatively
- avoids active endpoint bypass attempts
- avoids secret brute-force behavior
"""

import argparse
import sys
import io
import json
import base64
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True
    )
    sys.stderr = io.TextIOWrapper(
        sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True
    )

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich import box

console = Console(highlight=False)

# ── Models ─────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    check: str
    severity: str
    confidence: str
    title: str
    detail: str
    recommendation: str

    def to_dict(self) -> Dict:
        return asdict(self)

    def __str__(self) -> str:
        return f"[{self.severity}][{self.check}] {self.title}"

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COLOR = {
    "CRITICAL": "[bold red]CRITICAL[/bold red]",
    "HIGH": "[red]HIGH[/red]",
    "MEDIUM": "[yellow]MEDIUM[/yellow]",
    "LOW": "[cyan]LOW[/cyan]",
    "INFO": "[dim]INFO[/dim]",
}
CONF_COLOR = {
    "HIGH": "[bold green]HIGH[/bold green]",
    "MEDIUM": "[green]MEDIUM[/green]",
    "LOW": "[dim]LOW[/dim]",
}

# ── JWT Core ───────────────────────────────────────────────────────────────────

def b64_decode(data: str) -> bytes:
    data = data.replace("-", "+").replace("_", "/")
    padding = (4 - len(data) % 4) % 4
    if padding:
        data += "=" * padding
    return base64.b64decode(data)

def decode_jwt(token: str) -> Tuple[Optional[Dict], Optional[Dict], Optional[str]]:
    try:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return None, None, None

        header = json.loads(b64_decode(parts[0]).decode("utf-8", errors="replace"))
        payload = json.loads(b64_decode(parts[1]).decode("utf-8", errors="replace"))
        signature = parts[2]
        return header, payload, signature
    except Exception:
        return None, None, None

def format_timestamp(ts) -> str:
    try:
        dt = datetime.fromtimestamp(int(ts), tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)

def unix_now() -> int:
    return int(time.time())

def token_ttl_seconds(payload: Dict) -> Optional[int]:
    exp = payload.get("exp")
    if exp is None:
        return None
    try:
        return int(exp) - unix_now()
    except Exception:
        return None

def is_expired(payload: Dict) -> Optional[bool]:
    ttl = token_ttl_seconds(payload)
    if ttl is None:
        return None
    return ttl < 0

# ── Classification ─────────────────────────────────────────────────────────────

def classify_token_type(header: Dict, payload: Dict) -> Tuple[str, str]:
    iss = str(payload.get("iss", "")).lower()
    aud = payload.get("aud")
    firebase = payload.get("firebase")
    azp = payload.get("azp")
    scope = payload.get("scope")

    if "securetoken.google.com" in iss or "session.firebase.google.com" in iss or firebase:
        return (
            "Firebase ID Token",
            "Looks like a Firebase / Google Identity Platform token based on issuer or firebase claims.",
        )

    if "accounts.google.com" in iss or "https://accounts.google.com" in iss:
        return (
            "Google Identity Token",
            "Looks like a Google-issued identity token.",
        )

    if scope or azp:
        return (
            "OAuth-style JWT",
            "Contains claims commonly seen in delegated auth flows.",
        )

    if aud:
        return (
            "Application JWT",
            "General application token with audience claim.",
        )

    return (
        "Generic JWT",
        "Could not confidently identify a specific token family.",
    )

# ── Checks ─────────────────────────────────────────────────────────────────────

def check_algorithm(header: Dict, payload: Dict) -> List[Finding]:
    findings: List[Finding] = []
    alg = str(header.get("alg", "")).upper()
    token_type, _ = classify_token_type(header, payload)

    if alg in ("", "NONE"):
        findings.append(Finding(
            check="Algorithm",
            severity="CRITICAL",
            confidence="HIGH",
            title="Unsigned JWT algorithm",
            detail="The token header indicates alg=none or no algorithm value. Unsigned tokens must not be accepted by production verifiers.",
            recommendation="Reject unsigned tokens and explicitly allow only approved algorithms."
        ))
        return findings

    if alg in ("HS256", "HS384", "HS512"):
        findings.append(Finding(
            check="Algorithm",
            severity="INFO",
            confidence="HIGH",
            title=f"Symmetric signing in use: {alg}",
            detail="HMAC-based signing is acceptable when the signing secret is strong, random, and kept server-side only.",
            recommendation="Use a long random secret, rotate it periodically, and keep algorithm validation strict."
        ))
        return findings

    if alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"):
        findings.append(Finding(
            check="Algorithm",
            severity="INFO",
            confidence="HIGH",
            title=f"Asymmetric signing in use: {alg}",
            detail=f"The token uses public/private key signing. This is expected for many identity systems, including {token_type}.",
            recommendation="Ensure the verifier strictly enforces the expected algorithm and trusted issuer keys."
        ))

        kid = header.get("kid")
        if not kid:
            findings.append(Finding(
                check="Header",
                severity="LOW",
                confidence="MEDIUM",
                title="Missing key identifier (kid)",
                detail="No kid header is present. This is not always wrong, but it can make key selection harder in multi-key deployments.",
                recommendation="Use kid where your verifier depends on key rotation or multiple signing keys."
            ))

        return findings

    findings.append(Finding(
        check="Algorithm",
        severity="LOW",
        confidence="LOW",
        title=f"Unrecognized or uncommon algorithm: {alg}",
        detail="The analyzer did not recognize this algorithm as a common JWT signing choice.",
        recommendation="Verify that the server explicitly allows only intended algorithms."
    ))
    return findings

def check_registered_claims(payload: Dict) -> List[Finding]:
    findings: List[Finding] = []

    # exp
    if "exp" not in payload:
        findings.append(Finding(
            check="Expiry",
            severity="HIGH",
            confidence="HIGH",
            title="Missing exp claim",
            detail="The token does not include an expiration time. Tokens without expiry can remain usable indefinitely if accepted.",
            recommendation="Include exp on all bearer tokens and keep access-token lifetimes short."
        ))
    else:
        expired = is_expired(payload)
        exp_text = format_timestamp(payload["exp"])

        if expired is True:
            findings.append(Finding(
                check="Expiry",
                severity="MEDIUM",
                confidence="HIGH",
                title="Token is expired",
                detail=f"The exp claim is in the past: {exp_text}.",
                recommendation="Ensure expired tokens are rejected consistently server-side."
            ))
        elif expired is False:
            ttl = token_ttl_seconds(payload)
            if ttl is not None and ttl > 60 * 60 * 24 * 30:
                days = ttl // 86400
                findings.append(Finding(
                    check="Expiry",
                    severity="MEDIUM",
                    confidence="HIGH",
                    title=f"Very long token lifetime ({days} days)",
                    detail=f"The token remains valid until {exp_text}. Long-lived bearer tokens increase exposure if stolen.",
                    recommendation="Use short-lived access tokens and refresh flows where appropriate."
                ))

    # iat
    if "iat" not in payload:
        findings.append(Finding(
            check="Claims",
            severity="LOW",
            confidence="MEDIUM",
            title="Missing iat claim",
            detail="The token does not include an issued-at time.",
            recommendation="Include iat when useful for age checks, revocation logic, or debugging."
        ))
    else:
        try:
            iat = int(payload["iat"])
            if iat > unix_now() + 300:
                findings.append(Finding(
                    check="Claims",
                    severity="LOW",
                    confidence="MEDIUM",
                    title="iat appears to be in the future",
                    detail=f"The iat claim is later than current system time: {format_timestamp(iat)}.",
                    recommendation="Check clock skew and token issuance logic."
                ))
        except Exception:
            pass

    # nbf
    if "nbf" in payload:
        try:
            nbf = int(payload["nbf"])
            if nbf > unix_now() + 300:
                findings.append(Finding(
                    check="Claims",
                    severity="LOW",
                    confidence="HIGH",
                    title="Token is not yet valid (nbf in future)",
                    detail=f"The token should not be accepted before {format_timestamp(nbf)}.",
                    recommendation="Verify that verifiers enforce nbf if your system relies on it."
                ))
        except Exception:
            pass

    # aud / iss / sub
    if "sub" not in payload:
        findings.append(Finding(
            check="Claims",
            severity="LOW",
            confidence="MEDIUM",
            title="Missing sub claim",
            detail="No subject claim is present.",
            recommendation="Use sub to represent the stable principal identifier when applicable."
        ))

    if "iss" not in payload:
        findings.append(Finding(
            check="Claims",
            severity="LOW",
            confidence="MEDIUM",
            title="Missing iss claim",
            detail="No issuer claim is present.",
            recommendation="Use iss and validate it server-side against expected issuers."
        ))

    if "aud" not in payload:
        findings.append(Finding(
            check="Claims",
            severity="LOW",
            confidence="MEDIUM",
            title="Missing aud claim",
            detail="No audience claim is present.",
            recommendation="Use aud and validate it server-side to reduce token confusion across services."
        ))

    return findings

def check_sensitive_data(payload: Dict, token_type: str) -> List[Finding]:
    findings: List[Finding] = []

    sensitive_keys = [
        "password", "pwd", "pass", "secret", "private", "api_key", "access_key",
        "refresh_token", "auth_token", "session_secret", "client_secret", "pin", "cvv"
    ]
    found_sensitive = [
        key for key in payload.keys()
        if any(marker in key.lower() for marker in sensitive_keys)
    ]

    if found_sensitive:
        findings.append(Finding(
            check="Sensitive Data",
            severity="HIGH",
            confidence="HIGH",
            title="Sensitive secrets present in JWT payload",
            detail=f"The payload contains claim names that look sensitive: {', '.join(found_sensitive)}.",
            recommendation="Do not place secrets, passwords, or credential material in JWT payloads."
        ))

    pii_keys = ["email", "phone", "address", "dob", "birth", "national_id", "ssn"]
    found_pii = [
        key for key in payload.keys()
        if any(marker in key.lower() for marker in pii_keys)
    ]

    if found_pii:
        sev = "INFO" if token_type in ("Firebase ID Token", "Google Identity Token") else "LOW"
        findings.append(Finding(
            check="PII",
            severity=sev,
            confidence="HIGH",
            title="Readable PII present in token payload",
            detail=f"Claims include: {', '.join(found_pii)}. JWT payloads are encoded, not encrypted.",
            recommendation="Minimize personal data in tokens where possible, especially for broad client-side exposure."
        ))

    return findings

def check_header_structure(header: Dict) -> List[Finding]:
    findings: List[Finding] = []

    typ = str(header.get("typ", "")).upper()
    if typ and typ != "JWT":
        findings.append(Finding(
            check="Header",
            severity="LOW",
            confidence="MEDIUM",
            title=f"Unexpected typ header: {typ}",
            detail="The token type header is present but not equal to JWT.",
            recommendation="Keep typ consistent if your verifiers or gateways rely on it."
        ))

    return findings

def check_firebase_context(header: Dict, payload: Dict) -> List[Finding]:
    findings: List[Finding] = []
    token_type, _ = classify_token_type(header, payload)

    if token_type != "Firebase ID Token":
        return findings

    iss = str(payload.get("iss", ""))
    aud = str(payload.get("aud", ""))
    sub = str(payload.get("sub", ""))

    if not iss.startswith("https://securetoken.google.com/") and not iss.startswith("https://session.firebase.google.com/"):
        findings.append(Finding(
            check="Firebase",
            severity="LOW",
            confidence="MEDIUM",
            title="Unexpected Firebase issuer format",
            detail=f"The token looks Firebase-like, but the issuer is unusual: {iss}",
            recommendation="Verify issuer and project binding against your expected Firebase project."
        ))

    if aud and iss:
        project_hint = iss.rstrip("/").split("/")[-1]
        if project_hint and project_hint != aud:
            findings.append(Finding(
                check="Firebase",
                severity="LOW",
                confidence="HIGH",
                title="Issuer / audience project mismatch",
                detail=f"Firebase-style issuer project '{project_hint}' does not match aud '{aud}'.",
                recommendation="Verify that tokens are accepted only for the intended Firebase project."
            ))

    if sub and len(sub) < 6:
        findings.append(Finding(
            check="Firebase",
            severity="LOW",
            confidence="LOW",
            title="Very short sub value",
            detail="The Firebase subject value looks unusually short.",
            recommendation="Verify principal identifiers are well-formed."
        ))

    return findings

# ── Output ─────────────────────────────────────────────────────────────────────

def print_token_info(header: Dict, payload: Dict) -> None:
    token_type, token_note = classify_token_type(header, payload)

    console.print()
    console.print(Rule("[cyan] Token Overview [/cyan]", style="cyan"))
    console.print(f"[dim]Type:[/dim] [cyan]{token_type}[/cyan]")
    console.print(f"[dim]Note:[/dim] {token_note}")
    console.print()

    console.print("[dim]Header:[/dim]")
    for key, value in header.items():
        console.print(f"  [cyan]{key:<16}[/cyan] {value}")
    console.print()

    console.print("[dim]Payload:[/dim]")
    for key, value in payload.items():
        if key in ("exp", "iat", "nbf"):
            console.print(f"  [cyan]{key:<16}[/cyan] {value}  [dim]({format_timestamp(value)})[/dim]")
        else:
            console.print(f"  [cyan]{key:<16}[/cyan] {value}")

    console.print()
    expired = is_expired(payload)
    if expired is None:
        console.print("  [yellow]No expiry set[/yellow]")
    elif expired:
        console.print("  [red]Token is EXPIRED[/red]")
    else:
        ttl = token_ttl_seconds(payload) or 0
        console.print(f"  [green]Token is valid — expires in {ttl // 3600}h {(ttl % 3600) // 60}m[/green]")
    console.print()

def print_findings(findings: List[Finding]) -> None:
    console.print()
    if not findings:
        console.print(Panel(
            "[green]No major JWT hygiene issues detected.[/green]\n"
            "[dim]This analyzer does not prove server-side verification quality by itself.[/dim]",
            title="Result",
            border_style="green"
        ))
        return

    findings.sort(key=lambda f: SEV_ORDER.get(f.severity, 99))

    counts = {
        "CRITICAL": sum(1 for f in findings if f.severity == "CRITICAL"),
        "HIGH": sum(1 for f in findings if f.severity == "HIGH"),
        "MEDIUM": sum(1 for f in findings if f.severity == "MEDIUM"),
        "LOW": sum(1 for f in findings if f.severity == "LOW"),
        "INFO": sum(1 for f in findings if f.severity == "INFO"),
    }

    console.print(Panel(
        f"[bold red]Critical: {counts['CRITICAL']}[/bold red]   "
        f"[red]High: {counts['HIGH']}[/red]   "
        f"[yellow]Medium: {counts['MEDIUM']}[/yellow]   "
        f"[cyan]Low: {counts['LOW']}[/cyan]   "
        f"[white]Info: {counts['INFO']}[/white]   "
        f"[bold]Total: {len(findings)}[/bold]",
        title=f"[bold red]{len(findings)} Finding(s)[/bold red]",
        border_style="red"
    ))
    console.print()

    for finding in findings:
        border = "red" if finding.severity in ("CRITICAL", "HIGH") else ("yellow" if finding.severity == "MEDIUM" else "cyan")
        console.print(Panel(
            f"[dim]Confidence:[/dim]    {CONF_COLOR.get(finding.confidence, finding.confidence)}\n"
            f"[dim]Detail:[/dim]        {finding.detail}\n\n"
            f"[dim]Fix:[/dim]           [green]{finding.recommendation}[/green]",
            title=f"{SEV_COLOR[finding.severity]}  {finding.title}",
            border_style=border
        ))
        console.print()

def save_text(findings: List[Finding], output_file: str) -> None:
    with open(output_file, "w", encoding="utf-8") as handle:
        for finding in findings:
            handle.write(str(finding) + "\n")
            handle.write(f"  Confidence: {finding.confidence}\n")
            handle.write(f"  Detail: {finding.detail}\n")
            handle.write(f"  Fix: {finding.recommendation}\n\n")

def save_json(findings: List[Finding], output_file: str, header: Dict, payload: Dict) -> None:
    data = {
        "header": header,
        "payload": payload,
        "token_type": classify_token_type(header, payload)[0],
        "findings": [f.to_dict() for f in findings],
    }
    with open(output_file, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)

# ── CLI ────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Defensive JWT Analyzer - part of STRYKER",
        epilog="""
Examples:
  python web/jwt_analyzer.py -t "eyJhbGci..."
  python web/jwt_analyzer.py -t "eyJhbGci..." --checks algorithm claims sensitive
  python web/jwt_analyzer.py -t "eyJhbGci..." -o findings.json

Use only on tokens and systems you own or are explicitly authorized to assess.
        """
    )
    parser.add_argument("-t", "--token", required=True, help="JWT token to analyze")
    parser.add_argument(
        "--checks",
        nargs="+",
        choices=["decode", "algorithm", "claims", "sensitive", "context", "all"],
        default=["all"],
        help="Which checks to run (default: all)"
    )
    parser.add_argument("-o", "--output", help="Save findings to file (.txt or .json)")
    return parser.parse_args()

def main():
    args = parse_args()

    console.print(Panel.fit(
        "[bold red]STRYKER[/bold red] [white]//[/white] [cyan]JWT Analyzer Pro[/cyan]\n"
        "[dim]Decode | Algorithm | Claims | PII Review | Token Context[/dim]",
        border_style="red"
    ))
    console.print()

    token = args.token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    header, payload, signature = decode_jwt(token)
    if not header or not payload:
        console.print("[red]Invalid JWT token — could not decode.[/red]")
        sys.exit(1)

    print_token_info(header, payload)
    console.print(Rule("[dim] Running checks [/dim]", style="red"))
    console.print()

    checks = args.checks
    findings: List[Finding] = []

    if "algorithm" in checks or "all" in checks:
        findings.extend(check_algorithm(header, payload))
        findings.extend(check_header_structure(header))

    if "claims" in checks or "all" in checks:
        findings.extend(check_registered_claims(payload))

    if "sensitive" in checks or "all" in checks:
        token_type, _ = classify_token_type(header, payload)
        findings.extend(check_sensitive_data(payload, token_type))

    if "context" in checks or "all" in checks:
        findings.extend(check_firebase_context(header, payload))

    print_findings(findings)

    if args.output:
        if args.output.lower().endswith(".json"):
            save_json(findings, args.output, header, payload)
        else:
            save_text(findings, args.output)
        console.print(f"[green]Findings saved to {args.output}[/green]")

if __name__ == "__main__":
    main()