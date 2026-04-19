#!/usr/bin/env python3
"""
ai_analyst.py - AI-Powered Security Analysis
Part of STRYKER by Andrews

Uses Claude AI to analyze findings, explain vulnerabilities in plain English,
suggest fixes, and generate professional executive summaries.

LEGAL NOTICE: For authorized penetration testing ONLY.
"""

import os
import sys
import io
import json
import time
import sqlite3
from pathlib import Path
from datetime import datetime

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)

# Fix Git Bash PTY
if not sys.stdout.isatty() and os.name == "nt":
    import shutil
    winpty = shutil.which("winpty")
    if winpty:
        import subprocess
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

DB_PATH = Path("stryker_data.db")

# ── Claude API ─────────────────────────────────────────────────────────────────

def call_claude(prompt, system="You are an expert penetration tester and security consultant."):
    """Call Claude API and return response text."""
    try:
        import urllib.request
        import urllib.error

        payload = json.dumps({
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1000,
            "system": system,
            "messages": [{"role": "user", "content": prompt}]
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "Content-Type":      "application/json",
                "anthropic-version": "2023-06-01",
            },
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["content"][0]["text"]

    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        if e.code == 401:
            return "ERROR: Invalid API key. Set ANTHROPIC_API_KEY environment variable."
        elif e.code == 429:
            return "ERROR: API rate limit hit. Try again in a moment."
        return f"ERROR: API returned {e.code}: {body[:200]}"
    except Exception as e:
        return f"ERROR: {e}"


# ── Analysis functions ─────────────────────────────────────────────────────────

def analyze_finding(finding):
    """Get AI explanation and fix for a single finding."""
    prompt = f"""You are analyzing a security finding from a penetration test.

Finding:
- Severity: {finding.get('severity', 'Unknown')}
- Title: {finding.get('title', '')}
- Tool: {finding.get('tool', '')}
- Target: {finding.get('target', '')}
- Description: {finding.get('description', '')}
- Evidence: {finding.get('evidence', '')}

Provide:
1. PLAIN ENGLISH EXPLANATION (2-3 sentences, as if explaining to a non-technical business owner)
2. REAL-WORLD IMPACT (what could an attacker actually do with this?)
3. SPECIFIC FIX (exact code or configuration change needed)
4. PRIORITY (should this be fixed today, this week, or this month?)

Be direct and practical. No jargon."""

    return call_claude(prompt)


def generate_executive_summary(target, findings, client_name):
    """Generate an AI-written executive summary for the report."""
    sev_counts = {}
    for f in findings:
        sev = f.get("severity", "INFO")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    finding_titles = "\n".join([
        f"- [{f.get('severity','?')}] {f.get('title','')}"
        for f in findings[:15]
    ])

    prompt = f"""Write a professional executive summary for a penetration test report.

Client: {client_name}
Target: {target}
Date: {datetime.now().strftime('%B %d, %Y')}

Findings summary:
{json.dumps(sev_counts, indent=2)}

Key findings:
{finding_titles}

Write 3 paragraphs:
1. Overview of the assessment and what was tested
2. Key findings and their business risk (mention the most critical ones by name)
3. Recommended next steps and remediation priority

Tone: Professional but clear. The reader is a business owner, not a technical person.
Length: 200-250 words.
Do NOT use bullet points — write in flowing paragraphs."""

    return call_claude(prompt, system=(
        "You are a senior penetration tester writing a report for a business client. "
        "Be professional, clear and focus on business impact."
    ))


def explain_findings_simple(findings):
    """Generate a simple non-technical summary of all findings."""
    if not findings:
        return "No vulnerabilities were identified during this assessment."

    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    high     = [f for f in findings if f.get("severity") == "HIGH"]

    titles = "\n".join([f"- {f.get('title','')}" for f in findings[:10]])

    prompt = f"""A security scan found these vulnerabilities on a website:

{titles}

Explain these in simple language for a business owner who is not technical.
Focus on: what could go wrong, what data is at risk, and what to do first.
Write 2-3 short paragraphs. No technical jargon. No bullet points."""

    return call_claude(prompt)


def suggest_attack_chain(findings, target):
    """Ask AI to identify the most dangerous combination of findings."""
    if len(findings) < 2:
        return None

    titles = "\n".join([
        f"- [{f.get('severity','?')}] {f.get('title','')} (tool: {f.get('tool','')})"
        for f in findings[:10]
    ])

    prompt = f"""You are a penetration tester. Given these findings on {target}:

{titles}

Describe the most dangerous attack chain — how could an attacker combine 2-3 of these 
findings to cause maximum damage? Be specific about the sequence of steps.
Keep it to 3-4 sentences. This is for a security report to show the client why 
fixing these issues is urgent."""

    return call_claude(prompt)


def get_fix_priority(findings):
    """Ask AI to prioritize the fix order."""
    if not findings:
        return None

    titles = "\n".join([
        f"- [{f.get('severity','?')}] {f.get('title','')}"
        for f in findings[:12]
    ])

    prompt = f"""Given these security findings, provide a prioritized fix order:

{titles}

Create a simple action plan:
- Fix TODAY (within 24 hours)
- Fix THIS WEEK (within 7 days)
- Fix THIS MONTH (within 30 days)

For each item, give one sentence on why it's that priority.
Be direct and practical."""

    return call_claude(prompt)


# ── Terminal UI ────────────────────────────────────────────────────────────────

BANNER_LINES = [
    r"   _   ___ ",
    r"  /_\ |_ _|",
    r" / _ \ | | ",
    r"/_/ \_\___|",
    r"",
    r"  ___  _   _   _   _  _   _____  ___ ___ ",
    r" / _ \| | | | | | | \| | |_   _| | __| _ \\",
    r"| (_) | |_| | | |_| .` |   | |   | _||   /",
    r" \__\_\\___/   \___/_|\_|   |_|   |___|_|_\\",
]


def show_banner():
    os.system("cls" if os.name == "nt" else "clear")
    p()
    for line_text in BANNER_LINES:
        p(f"{BOLD}{RED}{line_text}{RST}")
        time.sleep(0.03)
    p()
    p(f"{DIM}  AI-Powered Security Analysis  |  Powered by Claude  |  by Andrews{RST}")
    p()
    line()
    p(f"  {DIM}Commands:{RST}  "
      f"{CYAN}analyze <scan_id>{RST}  "
      f"{CYAN}explain <scan_id>{RST}  "
      f"{CYAN}priority <scan_id>{RST}  "
      f"{CYAN}chain <scan_id>{RST}  "
      f"{CYAN}history{RST}  "
      f"{CYAN}exit{RST}")
    line()
    p()


def load_findings_from_db(scan_id):
    """Load findings from SQLite database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute(
            "SELECT tool, severity, title, target, detail FROM findings WHERE scan_id=?",
            (scan_id,)
        )
        rows = c.fetchall()
        c.execute("SELECT target FROM scans WHERE id=?", (scan_id,))
        scan = c.fetchone()
        conn.close()

        findings = [
            {
                "tool":        r[0],
                "severity":    r[1],
                "title":       r[2],
                "target":      r[3],
                "description": r[4],
                "evidence":    r[4],
            }
            for r in rows
        ]
        target = scan[0] if scan else "Unknown"
        return findings, target
    except Exception as e:
        err(f"Could not load findings: {e}")
        return [], "Unknown"


def load_findings_from_json(path):
    """Load findings from a JSON file."""
    try:
        with open(path) as f:
            data = json.load(f)
        return data, "Unknown"
    except Exception as e:
        err(f"Could not load JSON: {e}")
        return [], "Unknown"


def show_history():
    """Show scan history."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute(
            "SELECT id, target, started_at, status, findings FROM scans ORDER BY id DESC LIMIT 15"
        )
        rows = c.fetchall()
        conn.close()
    except Exception:
        rows = []

    p()
    header("SCAN HISTORY")
    if not rows:
        p(f"  {DIM}No scans found. Run autopilot.py first to generate findings.{RST}")
        p()
        return

    p(f"  {CYAN}{'ID':<6}{RST}  {WHITE}{'Target':<35}{RST}  {DIM}{'Date':<18}{RST}  {'Findings'}")
    p(f"  {'─'*6}  {'─'*35}  {'─'*18}  {'─'*8}")
    for row in rows:
        scan_id, target, started, status, findings = row
        date     = started[:16].replace("T", " ") if started else "—"
        findings_c = f"{RED}{findings}{RST}" if findings > 0 else f"{GREEN}0{RST}"
        p(f"  {CYAN}{scan_id:<6}{RST}  {target:<35}  {DIM}{date:<18}{RST}  {findings_c}")
    p()
    p(f"  {DIM}Use: analyze <id>  |  explain <id>  |  priority <id>  |  chain <id>{RST}")
    p()


def run_analyze(scan_id_or_path):
    """Full AI analysis of a scan."""
    # Try as scan ID first
    try:
        scan_id  = int(scan_id_or_path)
        findings, target = load_findings_from_db(scan_id)
    except ValueError:
        findings, target = load_findings_from_json(scan_id_or_path)

    if not findings:
        warn("No findings found. Run autopilot.py first or provide a findings JSON file.")
        return

    p()
    header(f"AI ANALYSIS — {target}")
    info(f"Analyzing {len(findings)} finding(s) with Claude AI...")
    p()

    # Analyze top 5 findings individually
    for i, finding in enumerate(findings[:5], 1):
        sev   = finding.get("severity", "?")
        title = finding.get("title", "")[:60]
        color = RED if sev in ("CRITICAL", "HIGH") else YELLOW

        p(f"  {color}[{sev}]{RST} {WHITE}{title}{RST}")
        p(f"  {DIM}Analyzing...{RST}")

        analysis = analyze_finding(finding)
        if analysis.startswith("ERROR:"):
            err(analysis)
            break

        # Print analysis with indentation
        for line_text in analysis.split("\n"):
            if line_text.strip():
                p(f"  {DIM}│{RST} {line_text}")
        p()

    line()


def run_explain(scan_id_or_path):
    """Plain English explanation of findings."""
    try:
        scan_id  = int(scan_id_or_path)
        findings, target = load_findings_from_db(scan_id)
    except ValueError:
        findings, target = load_findings_from_json(scan_id_or_path)

    if not findings:
        warn("No findings found.")
        return

    p()
    header("PLAIN ENGLISH EXPLANATION")
    info("Generating non-technical summary...")
    p()

    explanation = explain_findings_simple(findings)
    if explanation.startswith("ERROR:"):
        err(explanation)
        return

    for line_text in explanation.split("\n"):
        p(f"  {line_text}")
    p()
    line()
    p()


def run_priority(scan_id_or_path):
    """AI-generated fix priority list."""
    try:
        scan_id  = int(scan_id_or_path)
        findings, target = load_findings_from_db(scan_id)
    except ValueError:
        findings, target = load_findings_from_json(scan_id_or_path)

    if not findings:
        warn("No findings found.")
        return

    p()
    header("AI FIX PRIORITY")
    info("Generating prioritized action plan...")
    p()

    priority = get_fix_priority(findings)
    if not priority or priority.startswith("ERROR:"):
        err(priority or "Failed to get priority")
        return

    for line_text in priority.split("\n"):
        if "TODAY" in line_text:
            p(f"  {RED}{line_text}{RST}")
        elif "WEEK" in line_text:
            p(f"  {YELLOW}{line_text}{RST}")
        elif "MONTH" in line_text:
            p(f"  {CYAN}{line_text}{RST}")
        elif line_text.strip():
            p(f"  {line_text}")
    p()
    line()
    p()


def run_chain(scan_id_or_path):
    """AI attack chain analysis."""
    try:
        scan_id  = int(scan_id_or_path)
        findings, target = load_findings_from_db(scan_id)
    except ValueError:
        findings, target = load_findings_from_json(scan_id_or_path)

    if not findings:
        warn("No findings found.")
        return

    p()
    header("AI ATTACK CHAIN ANALYSIS")
    info("Identifying most dangerous attack combinations...")
    p()

    chain = suggest_attack_chain(findings, target)
    if not chain or chain.startswith("ERROR:"):
        err(chain or "Failed to generate attack chain")
        return

    for line_text in chain.split("\n"):
        if line_text.strip():
            p(f"  {RED}>{RST} {line_text}")
    p()
    line()
    p()


def run_summary(scan_id_or_path, client_name="Target Organization"):
    """Generate AI executive summary."""
    try:
        scan_id  = int(scan_id_or_path)
        findings, target = load_findings_from_db(scan_id)
    except ValueError:
        findings, target = load_findings_from_json(scan_id_or_path)

    if not findings:
        warn("No findings found.")
        return

    p()
    header("AI EXECUTIVE SUMMARY")
    info("Writing executive summary with Claude...")
    p()

    summary = generate_executive_summary(target, findings, client_name)
    if summary.startswith("ERROR:"):
        err(summary)
        return

    for line_text in summary.split("\n"):
        p(f"  {line_text}")
    p()
    line()
    p()


# ── Main loop ──────────────────────────────────────────────────────────────────

def check_api_key():
    """Check if API key is configured."""
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        warn("ANTHROPIC_API_KEY not set.")
        p()
        p(f"  {DIM}To use AI analysis, set your API key:{RST}")
        p(f"  {DIM}Windows:{RST}  {CYAN}set ANTHROPIC_API_KEY=your-key-here{RST}")
        p(f"  {DIM}Mac/Linux:{RST} {CYAN}export ANTHROPIC_API_KEY=your-key-here{RST}")
        p()
        p(f"  {DIM}Get your key at:{RST} {CYAN}console.anthropic.com{RST}")
        p()
        return False
    return True


def main():
    show_banner()

    if not check_api_key():
        p(f"  {DIM}You can still use commands — they will show the error message until key is set.{RST}")
        p()

    while True:
        try:
            sys.stdout.write(f"{BOLD}{RED}ai{RST}{WHITE}@{RST}{CYAN}stryker{RST}{DIM} > {RST}")
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
            p(f"  {RED}AI Analyst signing off.{RST}")
            p()
            break

        elif action == "history":
            show_history()

        elif action == "analyze":
            if not arg:
                p(f"  {YELLOW}Usage: analyze <scan_id>  eg: analyze 1{RST}\n")
            else:
                run_analyze(arg)

        elif action == "explain":
            if not arg:
                p(f"  {YELLOW}Usage: explain <scan_id>  eg: explain 1{RST}\n")
            else:
                run_explain(arg)

        elif action == "priority":
            if not arg:
                p(f"  {YELLOW}Usage: priority <scan_id>  eg: priority 1{RST}\n")
            else:
                run_priority(arg)

        elif action == "chain":
            if not arg:
                p(f"  {YELLOW}Usage: chain <scan_id>  eg: chain 1{RST}\n")
            else:
                run_chain(arg)

        elif action == "summary":
            if not arg:
                p(f"  {YELLOW}Usage: summary <scan_id>  eg: summary 1{RST}\n")
            else:
                parts2 = arg.split(maxsplit=1)
                sid    = parts2[0]
                client = parts2[1] if len(parts2) > 1 else "Target Organization"
                run_summary(sid, client)

        elif action == "banner":
            show_banner()

        else:
            p(f"  {DIM}Unknown command. Try: {CYAN}analyze 1{RST}{DIM}, {CYAN}explain 1{RST}{DIM}, "
              f"{CYAN}priority 1{RST}{DIM}, {CYAN}chain 1{RST}{DIM}, {CYAN}history{RST}{DIM}.{RST}\n")


if __name__ == "__main__":
    main()