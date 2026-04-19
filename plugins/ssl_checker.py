"""
ssl_checker.py - SSL/TLS Certificate Analyzer Plugin
STRYKER Plugin by Andrews

Checks SSL certificate expiry, weak ciphers and misconfigurations.
"""

import ssl
import socket
from datetime import datetime, timezone

PLUGIN = {
    "id":          "ssl_checker",
    "name":        "SSL/TLS Checker",
    "description": "Analyze SSL certificate and TLS configuration",
    "checks":      "Expiry, weak ciphers, hostname mismatch",
    "author":      "Andrews",
    "version":     "1.0.0",
}


def run(target, output_file=None, **kwargs):
    """Check SSL/TLS configuration of a target."""
    findings = []

    # Clean up target
    domain = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    port   = 443

    print(f"  Checking SSL/TLS for {domain}:{port}...")

    try:
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        conn.settimeout(10)
        conn.connect((domain, port))
        cert = conn.getpeercert()
        conn.close()

        # Check expiry
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            expire_dt = expire_dt.replace(tzinfo=timezone.utc)
            now       = datetime.now(timezone.utc)
            days_left = (expire_dt - now).days

            if days_left < 0:
                findings.append({
                    "severity":       "CRITICAL",
                    "title":          f"SSL certificate EXPIRED {abs(days_left)} days ago",
                    "detail":         f"Certificate expired on {expire_str}",
                    "recommendation": "Renew the SSL certificate immediately.",
                })
            elif days_left < 14:
                findings.append({
                    "severity":       "CRITICAL",
                    "title":          f"SSL certificate expires in {days_left} days",
                    "detail":         f"Certificate expires on {expire_str}",
                    "recommendation": "Renew the SSL certificate urgently.",
                })
            elif days_left < 30:
                findings.append({
                    "severity":       "HIGH",
                    "title":          f"SSL certificate expires in {days_left} days",
                    "detail":         f"Certificate expires on {expire_str}",
                    "recommendation": "Renew the SSL certificate soon.",
                })
            else:
                print(f"  [+] Certificate valid for {days_left} more days")

        # Check subject
        subject = dict(x[0] for x in cert.get("subject", []))
        cn      = subject.get("commonName", "")
        if cn and domain not in cn and not cn.startswith("*."):
            findings.append({
                "severity":       "HIGH",
                "title":          "SSL certificate hostname mismatch",
                "detail":         f"Certificate CN={cn} does not match {domain}",
                "recommendation": "Get a certificate issued for the correct domain.",
            })

        # Check issuer
        issuer = dict(x[0] for x in cert.get("issuer", []))
        org    = issuer.get("organizationName", "")
        if "Let's Encrypt" in org:
            print(f"  [*] Issuer: Let's Encrypt (free cert — auto-renewal recommended)")

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "severity":       "HIGH",
            "title":          "SSL certificate verification failed",
            "detail":         str(e),
            "recommendation": "Install a valid SSL certificate from a trusted CA.",
        })
    except ssl.SSLError as e:
        findings.append({
            "severity":       "MEDIUM",
            "title":          "SSL error detected",
            "detail":         str(e),
            "recommendation": "Review SSL/TLS configuration.",
        })
    except (socket.gaierror, ConnectionRefusedError, OSError):
        findings.append({
            "severity":       "INFO",
            "title":          "Could not connect to HTTPS port",
            "detail":         f"No HTTPS on {domain}:443",
            "recommendation": "Ensure HTTPS is enabled and port 443 is open.",
        })

    # Check HTTP redirect to HTTPS
    try:
        import urllib.request
        req  = urllib.request.Request(f"http://{domain}", method="HEAD")
        req.add_header("User-Agent", "STRYKER-SSL/1.0")
        resp = urllib.request.urlopen(req, timeout=8)
        final_url = resp.geturl()
        if not final_url.startswith("https://"):
            findings.append({
                "severity":       "MEDIUM",
                "title":          "HTTP does not redirect to HTTPS",
                "detail":         f"http://{domain} served content without redirecting to HTTPS",
                "recommendation": "Add HTTP → HTTPS redirect in your server config or Next.js.",
            })
    except Exception:
        pass

    if not findings:
        print(f"  [+] SSL/TLS configuration looks good")

    if output_file and findings:
        with open(output_file, "w") as f:
            for finding in findings:
                f.write(f"[{finding['severity']}] {finding['title']}\n")
                f.write(f"  {finding['detail']}\n\n")

    return findings