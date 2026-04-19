#!/usr/bin/env python3
"""
autopilot.py - STRYKER Automated Pentest Pipeline
By Andrews | For authorized testing only

Runs a full penetration test automatically:
Recon → Port Scan → Web Vulns → Auth → Post-Exploit → Report
"""

import os
import sys
import io
import json
import time
import subprocess
import sqlite3
from datetime import datetime
from pathlib import Path
try:
    import httpx
except ImportError:
    httpx = None

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)

# ── Auto-fix Git Bash PTY ──────────────────────────────────────────────────────
if not sys.stdout.isatty() and os.name == "nt":
    import shutil
    winpty = shutil.which("winpty")
    if winpty:
        result = subprocess.run([winpty, sys.executable] + sys.argv)
        sys.exit(result.returncode)

os.environ["PYTHONUNBUFFERED"] = "1"

RED    = "\033[91m"
DKRED  = "\033[31m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
DIM    = "\033[2m"
BOLD   = "\033[1m"
RST    = "\033[0m"

def p(t=""):
    sys.stdout.write(str(t) + "\n")
    sys.stdout.flush()

def line():
    p(f"{DKRED}{'=' * 70}{RST}")

def header(title):
    line()
    p(f"{BOLD}{RED}  {title}{RST}")
    line()

def success(t): p(f"  {GREEN}[+]{RST} {t}")
def warn(t):    p(f"  {YELLOW}[!]{RST} {t}")
def info(t):    p(f"  {CYAN}[*]{RST} {t}")
def err(t):     p(f"  {RED}[x]{RST} {t}")

def ask(label, default=""):
    sys.stdout.write(f"  {CYAN}{label}{RST} ")
    sys.stdout.flush()
    val = input().strip()
    return val if val else default

# ── Database ───────────────────────────────────────────────────────────────────

DB_PATH = Path("stryker_data.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target      TEXT,
            started_at  TEXT,
            finished_at TEXT,
            status      TEXT,
            findings    INTEGER DEFAULT 0
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER,
            tool        TEXT,
            severity    TEXT,
            title       TEXT,
            target      TEXT,
            detail      TEXT,
            created_at  TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS targets (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            domain     TEXT UNIQUE,
            last_scan  TEXT,
            scan_count INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


def save_scan(target):
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    now  = datetime.now().isoformat()
    c.execute(
        "INSERT INTO scans (target, started_at, status) VALUES (?, ?, ?)",
        (target, now, "running")
    )
    scan_id = c.lastrowid

    c.execute("""
        INSERT INTO targets (domain, last_scan, scan_count)
        VALUES (?, ?, 1)
        ON CONFLICT(domain) DO UPDATE SET
            last_scan  = excluded.last_scan,
            scan_count = scan_count + 1
    """, (target, now))

    conn.commit()
    conn.close()
    return scan_id


def finish_scan(scan_id, findings_count):
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute(
        "UPDATE scans SET finished_at=?, status=?, findings=? WHERE id=?",
        (datetime.now().isoformat(), "complete", findings_count, scan_id)
    )
    conn.commit()
    conn.close()


def save_finding(scan_id, tool, severity, title, target, detail):
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute(
        "INSERT INTO findings (scan_id, tool, severity, title, target, detail, created_at) VALUES (?,?,?,?,?,?,?)",
        (scan_id, tool, severity, title, target, detail, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


def get_history(limit=10):
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute("""
        SELECT id, target, started_at, status, findings
        FROM scans ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_findings(scan_id):
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute("""
        SELECT tool, severity, title, target, detail
        FROM findings WHERE scan_id=? ORDER BY
        CASE severity
            WHEN 'CRITICAL' THEN 1
            WHEN 'HIGH'     THEN 2
            WHEN 'MEDIUM'   THEN 3
            WHEN 'LOW'      THEN 4
            ELSE 5
        END
    """, (scan_id,))
    rows = c.fetchall()
    conn.close()
    return rows


# ── Pipeline stages ────────────────────────────────────────────────────────────

def run_tool(cmd, label):
    """Run a tool subprocess and return output."""
    info(f"Running {label}...")
    start = time.time()
    try:
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"

        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=300,
            env=env
        )
        elapsed = time.time() - start
        success(f"{label} completed in {elapsed:.1f}s")

        stdout = result.stdout.decode("utf-8", errors="replace") if result.stdout else ""
        stderr = result.stderr.decode("utf-8", errors="replace") if result.stderr else ""
        return stdout + stderr

    except subprocess.TimeoutExpired:
        warn(f"{label} timed out after 300s")
        return ""
    except Exception as e:
        err(f"{label} failed: {e}")
        return ""



def crawl_urls(base_url, max_pages=30):
    """Crawl a website and find URLs with parameters."""
    import re
    from urllib.parse import urljoin, urlparse, parse_qsl

    info(f"Crawling {base_url} for parameterized URLs...")

    visited    = set()
    to_visit   = [base_url]
    param_urls = []
    base_domain = urlparse(base_url).netloc

    try:
        with httpx.Client(follow_redirects=True, verify=False, timeout=10) as client:
            while to_visit and len(visited) < max_pages:
                url = to_visit.pop(0)
                if url in visited:
                    continue
                visited.add(url)

                try:
                    resp = client.get(url, headers={"User-Agent": "STRYKER-Crawler/1.0"})
                    if "text/html" not in resp.headers.get("content-type", ""):
                        continue

                    # Find all links
                    links = re.findall(r'href=["\'](https?://[^"\'\s>]+|/[^"\'\s>]*)["\'\s>]', resp.text)
                    for link in links:
                        full = urljoin(base_url, link)
                        parsed = urlparse(full)

                        # Only follow same domain
                        if parsed.netloc != base_domain:
                            continue

                        # Collect URLs with parameters
                        if parsed.query and parse_qsl(parsed.query):
                            clean = full.split("#")[0]
                            if clean not in param_urls:
                                param_urls.append(clean)
                                p(f"  {GREEN}[+]{RST} Found: {CYAN}{clean[:80]}{RST}")

                        # Queue for crawling
                        clean_link = full.split("#")[0]
                        if clean_link not in visited and clean_link not in to_visit:
                            to_visit.append(clean_link)

                except Exception:
                    pass

    except Exception as e:
        err(f"Crawler error: {e}")

    success(f"Found {len(param_urls)} URL(s) with parameters across {len(visited)} pages")
    return param_urls

def stage_recon(target, output_dir, threads):
    """Stage 1 — Subdomain enumeration."""
    header("STAGE 1 — RECON")
    info(f"Target domain: {target}")

    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    out    = str(output_dir / "subdomains.txt")

    output = run_tool([
        sys.executable, "recon/subdomain_enum.py",
        "-d", domain,
        "-t", str(threads),
        "--crt",
        "-o", out
    ], "Subdomain Enumerator")

    # Parse found subdomains
    subdomains = []
    for line_text in output.split("\n"):
        if "[+]" in line_text and "." in line_text:
            parts = line_text.split("[+]")
            if len(parts) > 1:
                sub = parts[1].strip().split()[0]
                if sub:
                    subdomains.append(sub)

    success(f"Found {len(subdomains)} subdomain(s)")
    return subdomains, domain


def stage_portscan(targets, output_dir, threads):
    """Stage 2 — Port scanning."""
    header("STAGE 2 — PORT SCAN")

    all_open = []
    scan_targets = targets[:5]  # limit to 5 targets

    for target in scan_targets:
        info(f"Scanning {target}...")
        out = str(output_dir / f"ports_{target.replace('.', '_')}.txt")

        output = run_tool([
            sys.executable, "scanning/port_scanner.py",
            "-t", target,
            "--ports", "common",
            "--threads", str(threads),
            "--timeout", "1.0",
            "-o", out
        ], f"Port Scanner ({target})")

        for line_text in output.split("\n"):
            if "[+]" in line_text and "/" in line_text:
                all_open.append({"target": target, "line": line_text.strip()})

    success(f"Found {len(all_open)} open port(s) across {len(scan_targets)} target(s)")
    return all_open


def stage_web_scan(base_url, output_dir, cookie, auth_header, param_urls=None):
    """Stage 3 — Web vulnerability scanning."""
    header("STAGE 3 — WEB VULNERABILITY SCAN")

    findings  = []
    auth_args = []
    if cookie:      auth_args += ["-c", cookie]
    if auth_header: auth_args += ["-H", auth_header]

    # Use crawled URLs if available, otherwise just base URL
    scan_urls = param_urls if param_urls else [base_url]
    info(f"Scanning {len(scan_urls)} URL(s) for vulnerabilities...")

    # Write URLs to file for multi-URL scanning
    urls_file = str(output_dir / "crawled_urls.txt")
    with open(urls_file, "w") as f:
        for u in scan_urls:
            f.write(u + "\n")

    # SQLi — scan all crawled URLs
    info("Testing for SQL injection...")
    sqli_out = str(output_dir / "sqli.txt")
    if len(scan_urls) > 1:
        run_tool([
            sys.executable, "web/sqli_detector.py",
            "-l", urls_file,
            "--checks", "error", "boolean",
            "-t", "5",
            "-o", sqli_out
        ] + auth_args, "SQLi Detector")
    else:
        run_tool([
            sys.executable, "web/sqli_detector.py",
            "-u", base_url,
            "--checks", "error", "boolean",
            "-o", sqli_out
        ] + auth_args, "SQLi Detector")

    # NoSQL
    info("Testing for NoSQL injection...")
    nosql_out = str(output_dir / "nosql.txt")
    run_tool([
        sys.executable, "web/nosql_injector.py",
        "-u", base_url,
        "--checks", "get", "post",
        "-o", nosql_out
    ] + auth_args, "NoSQL Injector")

    # XSS — scan all crawled URLs
    info("Testing for XSS...")
    xss_out = str(output_dir / "xss.txt")
    for i, url in enumerate(scan_urls[:10]):  # limit to 10 URLs
        out_i = str(output_dir / f"xss_{i}.txt")
        output = run_tool([
            sys.executable, "web/xss_scanner.py",
            "-u", url,
            "--checks", "all",
            "-o", out_i
        ] + auth_args, f"XSS Scanner ({url[-40:]})")
        for line_text in output.split("\n"):
            if "HIGH" in line_text or "CRITICAL" in line_text:
                findings.append(line_text.strip())

    # CORS
    info("Testing CORS configuration...")
    cors_out = str(output_dir / "cors.txt")
    run_tool([
        sys.executable, "post_exploit/cors_exploiter.py",
        "-u", base_url,
        "--endpoints",
        "-o", cors_out
    ] + auth_args, "CORS Exploiter")

    return findings


def stage_secrets(base_url, output_dir):
    """Stage 4 — Secrets and config scan."""
    header("STAGE 4 — SECRETS SCAN")

    out = str(output_dir / "secrets.txt")
    run_tool([
        sys.executable, "post_exploit/secrets_scanner.py",
        "-u", base_url,
        "-o", out
    ], "Secrets Scanner")


def stage_firebase(project_id, output_dir):
    """Stage 5 — Firebase audit."""
    header("STAGE 5 — FIREBASE AUDIT")

    if not project_id:
        warn("No Firebase project ID provided — skipping")
        return

    out = str(output_dir / "firebase.txt")
    run_tool([
        sys.executable, "web/firebase_auditor.py",
        "-p", project_id,
        "--checks", "all",
        "-o", out
    ], "Firebase Auditor")


def stage_privesc(base_url, token, output_dir):
    """Stage 6 — Privilege escalation."""
    header("STAGE 6 — PRIVILEGE ESCALATION")

    cmd = [
        sys.executable, "post_exploit/privesc_checker.py",
        "-u", base_url,
        "--checks", "admin", "bypass",
        "-o", str(output_dir / "privesc.txt")
    ]
    if token:
        cmd += ["-t", token]

    run_tool(cmd, "Privesc Checker")


def collect_findings(output_dir, scan_id):
    """Parse all output files and collect findings for the report."""
    findings   = []
    output_files = list(output_dir.glob("*.txt"))

    tool_map = {
        "sqli":     ("SQLi Detector",    "web/sqli_detector.py"),
        "nosql":    ("NoSQL Injector",   "web/nosql_injector.py"),
        "xss":      ("XSS Scanner",      "web/xss_scanner.py"),
        "cors":     ("CORS Exploiter",   "post_exploit/cors_exploiter.py"),
        "secrets":  ("Secrets Scanner",  "post_exploit/secrets_scanner.py"),
        "firebase": ("Firebase Auditor", "web/firebase_auditor.py"),
        "privesc":  ("Privesc Checker",  "post_exploit/privesc_checker.py"),
        "ports":    ("Port Scanner",     "scanning/port_scanner.py"),
        "subs":     ("Subdomain Enum",   "recon/subdomain_enum.py"),
    }

    sev_keywords = {
        "CRITICAL": "CRITICAL",
        "HIGH":     "HIGH",
        "MEDIUM":   "MEDIUM",
        "LOW":      "LOW",
    }

    for output_file in output_files:
        stem = output_file.stem.lower()
        tool_name = "Unknown"
        for key, (name, _) in tool_map.items():
            if key in stem:
                tool_name = name
                break

        try:
            content = output_file.read_text(errors="replace")
            for line_text in content.split("\n"):
                line_lower = line_text.lower()
                for sev_key, sev_val in sev_keywords.items():
                    if f"[{sev_key.lower()}]" in line_lower or sev_key in line_text:
                        title = line_text.strip()[:100]
                        if title and len(title) > 10:
                            findings.append({
                                "severity":       sev_val,
                                "title":          title,
                                "tool":           tool_name,
                                "target":         "",
                                "description":    title,
                                "payload":        "",
                                "evidence":       f"Found by {tool_name}",
                                "recommendation": "Review and remediate this finding."
                            })
                            save_finding(
                                scan_id, tool_name, sev_val,
                                title, "", title
                            )
                        break
        except Exception:
            pass

    # Deduplicate
    seen     = set()
    unique   = []
    for f in findings:
        key = f["title"][:60]
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


def generate_report(target, findings, output_dir, client_name):
    """Generate PDF report from all findings."""
    header("STAGE 7 — GENERATING REPORT")

    if not findings:
        warn("No findings to report")
        return

    findings_file = output_dir / "all_findings.json"
    with open(findings_file, "w") as f:
        json.dump(findings, f, indent=2)

    report_file = output_dir / f"stryker_report_{target.replace('.', '_')}.pdf"

    run_tool([
        sys.executable, "reporting/report_generator.py",
        "-f", str(findings_file),
        "-t", client_name,
        "-e", "Automated Web Application Security Assessment",
        "-o", str(report_file)
    ], "Report Generator")

    if report_file.exists():
        success(f"Report saved: {report_file}")
        return str(report_file)
    return None


# ── History and scan management ────────────────────────────────────────────────

def show_history():
    rows = get_history(15)
    if not rows:
        p(f"  {DIM}No scan history yet.{RST}")
        return

    p()
    header("SCAN HISTORY")
    p()
    p(f"  {CYAN}{'ID':<6} {'Target':<35} {'Date':<22} {'Status':<10} {'Findings'}{RST}")
    p(f"  {DIM}{'─'*6} {'─'*35} {'─'*22} {'─'*10} {'─'*8}{RST}")
    for row in rows:
        scan_id, target, started, status, findings = row
        date    = started[:16].replace("T", " ") if started else "—"
        status_color = GREEN if status == "complete" else YELLOW
        p(f"  {CYAN}{scan_id:<6}{RST} {target:<35} {DIM}{date:<22}{RST} "
          f"{status_color}{status:<10}{RST} {RED if findings > 0 else GREEN}{findings}{RST}")
    p()


def show_findings(scan_id):
    rows = get_findings(scan_id)
    if not rows:
        p(f"  {DIM}No findings for scan {scan_id}{RST}")
        return

    p()
    header(f"FINDINGS — SCAN #{scan_id}")
    p()
    sev_colors = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN}

    for tool, severity, title, target, detail in rows:
        color = sev_colors.get(severity, DIM)
        p(f"  {color}[{severity}]{RST} {title[:65]}")
        p(f"    {DIM}Tool: {tool}{RST}")
        if target:
            p(f"    {DIM}Target: {target}{RST}")
        p()


# ── Main autopilot ─────────────────────────────────────────────────────────────


SKULL = [
    "             .                    .",
    "          .node.              .node.",
    "         (  o  )            (  o  )",
    "      ____|___|______________|___|____",
    "     /   .-'                  `-.    \\",
    "    /  .'   __    ___    __    `.    \\",
    "   |  /    /  \\  /   \\  /  \\   \\   |",
    "   | |    | () || ( ) || () |   |  |",
    "   | |     \\__/  \\___/  \\__/    |  |",
    "   |  \\      ___________         /  |",
    "    \\  `.   /    | |    \\     .'   /",
    "     \\   `-'  ___| |___  `-'`    /",
    "      \\      /___________\\      /",
    "       `----'               `----'",
]

AUTOPILOT_ART = [
    r"  ___  _   _ _____ ___________ _____ _     _____ _____ ",
    r" / _ \| | | |_   _|  _  | ___ \_   _| |   |  _  |_   _|",
    r"/ /_\ \ | | | | | | | | | |_/ / | | | |   | | | | | |  ",
    r"|  _  | | | | | | | | | |  __/  | | | |   | | | | | |  ",
    r"| | | | |_| | | | \ \_/ / |    _| |_| |___\ \_/ / | |  ",
    r"\_| |_/\___/  \_/  \___/\_|    \___/\_____/\___/  \_/  ",
]

def show_banner():
    os.system("cls" if os.name == "nt" else "clear")
    for skull_line in SKULL:
        p(f"{RED}{skull_line}{RST}")
        time.sleep(0.02)
    p()
    for art_line in AUTOPILOT_ART:
        p(f"{BOLD}{RED}{art_line}{RST}")
        time.sleep(0.03)
    p()
    p(f"{DIM}  Full Automated Penetration Testing Pipeline  |  by Andrews  |  v1.0.0{RST}")
    p()
    line()
    try:
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute("SELECT COUNT(*) FROM scans")
        total_scans = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM findings")
        total_findings = c.fetchone()[0]
        conn.close()
    except Exception:
        total_scans = total_findings = 0
    now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    p(f"  {DIM}Scans run:{RST} {GREEN}{total_scans}{RST}   "
      f"{DIM}Findings:{RST} {RED}{total_findings}{RST}   "
      f"{DIM}Session:{RST}  {CYAN}{now}{RST}")
    line()
    p()
    p(f"  {DIM}Commands:{RST}  {CYAN}scan{RST}  {CYAN}history{RST}  {CYAN}findings <id>{RST}  {CYAN}exit{RST}")
    p()


def run_autopilot():
    """Interactive autopilot console."""
    show_banner()

    while True:
        try:
            sys.stdout.write(f"{BOLD}{RED}autopilot{RST}{WHITE}@{RST}{CYAN}stryker{RST}{DIM} > {RST}")
            sys.stdout.flush()
            cmd = input().strip()
        except (KeyboardInterrupt, EOFError):
            p(f"\n  {DIM}Type exit to quit.{RST}\n")
            continue

        if not cmd:
            continue

        parts  = cmd.split(maxsplit=1)
        action = parts[0].lower()
        arg    = parts[1].strip() if len(parts) > 1 else ""

        if action in ("exit", "quit", "q"):
            p()
            p(f"  {RED}Autopilot shutting down.{RST}")
            p()
            break

        elif action == "history":
            show_history()

        elif action == "findings":
            if not arg:
                p(f"  {YELLOW}Usage: findings <scan_id>  eg: findings 1{RST}\n")
            else:
                try:
                    show_findings(int(arg))
                except ValueError:
                    p(f"  {RED}Invalid scan ID.{RST}\n")

        elif action == "scan":
            p()
            header("NEW AUTOMATED SCAN")
            p()
            p(f"  {DIM}STRYKER Autopilot will run all tools automatically:{RST}")
            p(f"  {DIM}Recon → Port scan → Web vulns → Secrets → Report{RST}")
            p()

            target = ask("Target URL or domain >")
            if not target.strip():
                p(f"  {RED}No target. Going back.{RST}\n")
                continue

            # Normalize target
            if not target.startswith("http"):
                target = "https://" + target
            domain = target.replace("https://", "").replace("http://", "").split("/")[0]

            p()
            client_name   = ask(f"Client name [{domain}] >") or domain
            cookie        = ask("Session cookie (Enter to skip) >")
            auth_header   = ask("Auth header (Enter to skip) >")
            firebase_id   = ask("Firebase project ID (Enter to skip) >")
            token         = ask("JWT token (Enter to skip) >")
            threads       = int(ask("Threads [30] >") or "30")

            # Setup output directory
            timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = Path(f"scans/{domain}_{timestamp}")
            output_dir.mkdir(parents=True, exist_ok=True)

            p()
            line()
            p(f"  {RED}STRYKER AUTOPILOT ENGAGED{RST}")
            p(f"  {DIM}Target:  {target}{RST}")
            p(f"  {DIM}Output:  {output_dir}{RST}")
            p(f"  {DIM}Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RST}")
            line()
            p()

            scan_id    = save_scan(domain)
            start_time = time.time()

            # Run all stages
            subdomains, base_domain = stage_recon(domain, output_dir, threads)

            scan_targets = [domain] + subdomains[:4]
            stage_portscan(scan_targets, output_dir, threads)

            # Crawl for parameterized URLs before web scanning
            header("STAGE 2.5 — URL CRAWLER")
            param_urls = crawl_urls(target, max_pages=30) if httpx else []
            if not param_urls:
                warn("No parameterized URLs found — scanning homepage only")
                param_urls = [target]

            stage_web_scan(target, output_dir, cookie, auth_header, param_urls)
            stage_secrets(target, output_dir)

            if firebase_id:
                stage_firebase(firebase_id.strip(), output_dir)

            stage_privesc(target, token or None, output_dir)

            # Collect and report
            findings    = collect_findings(output_dir, scan_id)
            report_path = generate_report(domain, findings, output_dir, client_name)

            finish_scan(scan_id, len(findings))
            elapsed = time.time() - start_time

            p()
            line()
            p(f"  {GREEN}AUTOPILOT COMPLETE{RST}")
            p(f"  {DIM}Duration:  {elapsed/60:.1f} minutes{RST}")
            p(f"  {DIM}Findings:  {len(findings)}{RST}")
            p(f"  {DIM}Output:    {output_dir}{RST}")
            if report_path:
                p(f"  {DIM}Report:    {report_path}{RST}")
            p(f"  {DIM}Scan ID:   {scan_id} — type 'findings {scan_id}' to review{RST}")
            line()
            p()

        elif action == "banner":
            show_banner()

        else:
            p(f"  {DIM}Unknown command. Type {CYAN}scan{RST}{DIM}, {CYAN}history{RST}{DIM}, "
              f"or {CYAN}exit{RST}{DIM}.{RST}\n")


if __name__ == "__main__":
    init_db()
    run_autopilot()