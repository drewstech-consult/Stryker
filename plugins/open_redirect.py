"""
open_redirect.py - Open Redirect Scanner Plugin
STRYKER Plugin by Andrews

Tests for open redirect vulnerabilities that can be used
for phishing and OAuth token theft.
"""

import urllib.parse

PLUGIN = {
    "id":          "open_redirect",
    "name":        "Open Redirect Scanner",
    "description": "Detect open redirect vulnerabilities",
    "checks":      "URL parameters, redirect chains",
    "author":      "Andrews",
    "version":     "1.0.0",
}

REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "return",
    "return_url", "returnUrl", "next", "url", "target",
    "redir", "destination", "dest", "goto", "link",
    "callback", "continue", "ref", "referrer",
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com%2F",
    "https:evil.com",
    "javascript:alert(1)",
    "//evil.com/%2F..",
    "https://evil.com?@legitimate.com",
]


def run(target, output_file=None, **kwargs):
    """Test for open redirect vulnerabilities."""
    findings = []

    try:
        import httpx
    except ImportError:
        print("  [!] httpx not installed. Run: pip install httpx")
        return findings

    parsed = urllib.parse.urlparse(target)
    base   = f"{parsed.scheme}://{parsed.netloc}"
    domain = parsed.netloc

    print(f"  Testing {len(REDIRECT_PARAMS)} redirect parameters on {domain}...")

    with httpx.Client(follow_redirects=False, verify=False, timeout=8) as client:
        for param in REDIRECT_PARAMS:
            for payload in REDIRECT_PAYLOADS[:4]:
                test_url = f"{base}?{param}={urllib.parse.quote(payload)}"

                try:
                    resp = client.get(test_url)

                    # Check if response redirects to our payload
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("location", "")
                        if "evil.com" in location or location.startswith("//evil"):
                            findings.append({
                                "severity":       "HIGH",
                                "title":          f"Open redirect via '{param}' parameter",
                                "detail":         f"Redirected to: {location}",
                                "recommendation": (
                                    "Validate redirect URLs against an allowlist of trusted domains. "
                                    "Never redirect to user-supplied URLs without validation."
                                ),
                            })
                            break

                    # Check for meta refresh or JS redirect
                    if resp.status_code == 200:
                        body_lower = resp.text.lower()
                        if "evil.com" in body_lower and ("location" in body_lower or "redirect" in body_lower):
                            findings.append({
                                "severity":       "MEDIUM",
                                "title":          f"Possible client-side redirect via '{param}'",
                                "detail":         f"Payload reflected in page with redirect indicators",
                                "recommendation": "Validate all redirect parameters server-side.",
                            })
                            break

                except Exception:
                    pass

    if not findings:
        print(f"  [+] No open redirects detected")

    if output_file and findings:
        with open(output_file, "w") as f:
            for finding in findings:
                f.write(f"[{finding['severity']}] {finding['title']}\n")

    return findings