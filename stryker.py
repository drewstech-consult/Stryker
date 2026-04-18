#!/usr/bin/env python3
"""
STRYKER - Penetration Testing Framework
By Andrews | For authorized testing only
"""

import os
import sys
import io
import time
import subprocess
from datetime import datetime


# ── Auto-fix Git Bash PTY issue ───────────────────────────────────────────────
# If running in Git Bash without a PTY (isatty=False), relaunch via winpty
# automatically so the user never has to do anything manually.
if not sys.stdout.isatty() and os.name == "nt":
    import shutil
    winpty = shutil.which("winpty")
    if winpty:
        # Relaunch this script through winpty and exit current process
        result = subprocess.run([winpty, sys.executable] + sys.argv)
        sys.exit(result.returncode)

# ── Critical: fix Git Bash buffering ──────────────────────────────────────────
# Git Bash reports isatty=False which causes Python to buffer all output.
# We replace stdout with a raw unbuffered writer that bypasses this entirely.
os.environ["PYTHONUNBUFFERED"] = "1"
sys.stdout = io.TextIOWrapper(
    sys.stdout.buffer,
    encoding="utf-8",
    errors="replace",
    line_buffering=True
)

# ── ANSI colors ────────────────────────────────────────────────────────────────
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

def red(t):    return f"{BOLD}{RED}{t}{RST}"
def cyan(t):   return f"{CYAN}{t}{RST}"
def green(t):  return f"{BOLD}{GREEN}{t}{RST}"
def yellow(t): return f"{YELLOW}{t}{RST}"
def dim(t):    return f"{DIM}{t}{RST}"
def white(t):  return f"{WHITE}{t}{RST}"

def ask(label):
    sys.stdout.write(f"  {CYAN}{label}{RST} ")
    sys.stdout.flush()
    try:
        return input()
    except (KeyboardInterrupt, EOFError):
        return ""

# ── Banner ─────────────────────────────────────────────────────────────────────

SKULL = [
    "          .                 .",
    "       .node.             .node.",
    "      (  o  )           (  o  )",
    "   ____|___|_____________|___|____",
    "  /   .-'                 `-.    \\",
    " /  .'   __    ___    __   `.    \\",
    "|  /    /  \\  /   \\  /  \\    \\   |",
    "| |    | () || ( ) || () |    |  |",
    "| |     \\__/  \\___/  \\__/     |  |",
    "|  \\       ___________        /  |",
    " \\  `.   /     | |    \\    .'   /",
    "  \\   `-'  ____| |___  `-'`   /",
    "   \\      /___________\\      /",
    "    `----'             `----'",
]

STRYKER = [
    " _____ _____________   ___   __ ___________ ",
    "/  ___|_   _| ___ \\ \\ / / | / /|  ___| ___ \\",
    "\\ `--.  | | | |_/ / \\ V /| |/ / | |__ | |_/ /",
    " `--. \\ | | |    /   \\ / |    \\ |  __||    / ",
    "/\\__/ / | | | |\\ \\   | | | |\\  \\| |___| |\\ \\ ",
    "\\____/  \\_/ \\_| \\_|  \\_/ \\_| \\_/\\____/\\_| \\_|",
]

VERSION  = "v1.0.0"
OPERATOR = "Andrews"

# ── Tools ──────────────────────────────────────────────────────────────────────

TOOLS = {
    "Web": [
        {
            "id":          1,
            "name":        "SQLi Detector",
            "file":        "web/sqli_detector.py",
            "description": "Find SQL injection vulnerabilities",
            "checks":      "Error, Boolean, Time-based",
            "status":      "ready",
        },
        {
            "id":          2,
            "name":        "NoSQL Injector",
            "file":        "web/nosql_injector.py",
            "description": "Test MongoDB, Firebase, CouchDB injection",
            "checks":      "Operator, Auth Bypass, Firebase",
            "status":      "ready",
        },
        {
            "id":          3,
            "name":        "XSS Scanner",
            "file":        "web/xss_scanner.py",
            "description": "Detect cross-site scripting vulnerabilities",
            "checks":      "Reflected, DOM, Forms, Headers",
            "status":      "ready",
        },
        {
            "id":          4,
            "name":        "Firebase Auditor",
            "file":        "web/firebase_auditor.py",
            "description": "Audit Firebase security rules & config",
            "checks":      "Firestore, RTDB, Storage, Auth, Config",
            "status":      "ready",
        },
        {
            "id":          5,
            "name":        "JWT Analyzer",
            "file":        "web/jwt_analyzer.py",
            "description": "Decode and test JWT token security",
            "checks":      "Algorithm, Expiry, Secrets, Endpoint",
            "status":      "ready",
        },
    ],
    "Recon": [
        {
            "id":          6,
            "name":        "Subdomain Enumerator",
            "file":        "recon/subdomain_enum.py",
            "description": "Discover subdomains of a target domain",
            "checks":      "DNS brute-force + crt.sh",
            "status":      "ready",
        },
    ],
    "Scanning": [
        {
            "id":          7,
            "name":        "Port Scanner",
            "file":        "scanning/port_scanner.py",
            "description": "Scan open ports and detect services",
            "checks":      "TCP / Banner grab / Risk rating",
            "status":      "ready",
        },
    ],
    "Reporting": [
        {
            "id":          8,
            "name":        "Report Generator",
            "file":        "reporting/report_generator.py",
            "description": "Generate a PDF report from scan findings",
            "checks":      "PDF / HTML output",
            "status":      "coming",
        },
    ],
}

ALL_TOOLS = [t for cat in TOOLS.values() for t in cat]

# ── Display ────────────────────────────────────────────────────────────────────

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def show_banner():
    clear()
    for skull_line in SKULL:
        p(f"{RED}{skull_line}{RST}")
        time.sleep(0.02)
    p()
    for s in STRYKER:
        p(f"{BOLD}{RED}{s}{RST}")
        time.sleep(0.03)
    p()
    p(f"{DIM}  Penetration Testing Framework  |  by {OPERATOR}  |  {VERSION}{RST}")
    p()
    line()
    ready = sum(1 for t in ALL_TOOLS if t["status"] == "ready")
    total = len(ALL_TOOLS)
    now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    p(f"  {dim('Tools ready:')} {green(str(ready) + '/' + str(total))}    "
      f"{dim('Session:')} {CYAN}{now}{RST}    "
      f"{dim('Operator:')} {red(OPERATOR)}")
    line()
    p()
    p(f"  Type {cyan('help')} to see all commands.")
    p()

def show_help():
    p()
    header("COMMANDS")
    p()
    cmds = [
        ("help",     "Show this help menu"),
        ("modules",  "Show all available tools"),
        ("use 1",    "Launch tool number 1 - SQLi Detector"),
        ("info 1",   "Show details about a tool"),
        ("clear",    "Clear the screen"),
        ("banner",   "Show the banner again"),
        ("exit",     "Exit Stryker"),
    ]
    for cmd, desc in cmds:
        p(f"  {cyan(f'{cmd:<14}')}  {white(desc)}")
    p()
    line()
    p()

def show_modules():
    p()
    header("STRYKER MODULES")
    for category, tools in TOOLS.items():
        p()
        p(f"  {red('[ ' + category.upper() + ' ]')}")
        p()
        for tool in tools:
            status = green("READY") if tool["status"] == "ready" else dim("SOON")
            p(f"    {cyan(str(tool['id']))}  {white(tool['name']):<26} {status}")
            p(f"       {dim(tool['description'])}")
            p(f"       {yellow('Method:')} {dim(tool['checks'])}")
            p()
    line()
    p(f"  {dim('Launch a tool:')} {cyan('use <id>')}   {dim('Example:')} {cyan('use 1')}")
    p()

def show_info(tool):
    p()
    header(f"TOOL - {tool['name'].upper()}")
    p()
    p(f"  {cyan('Name        ')}  {tool['name']}")
    p(f"  {cyan('Description ')}  {tool['description']}")
    p(f"  {cyan('Method      ')}  {tool['checks']}")
    p(f"  {cyan('File        ')}  {tool['file']}")
    status = green("Ready to use") if tool["status"] == "ready" else dim("Coming soon")
    p(f"  {cyan('Status      ')}  {status}")
    p()
    if tool["status"] == "ready":
        p(f"  Launch with: {cyan('use ' + str(tool['id']))}")
    else:
        p(f"  {dim('Not available yet.')}")
    p()
    line()
    p()

# ── Launchers ──────────────────────────────────────────────────────────────────

def launch_sqli():
    p()
    header("TOOL 1 - SQLi DETECTOR")
    p()
    p(f"  {dim('Scans a URL for SQL injection vulnerabilities.')}")
    p(f"  {dim('URL must have a ? parameter — e.g: https://site.com/page?id=1')}")
    p()

    p(f"  {white('Step 1 of 3')} - Enter the target URL")
    url = ask("URL >")
    if not url.strip():
        p(f"\n  {red('No URL entered. Going back.')}\n")
        return

    p()
    p(f"  {white('Step 2 of 3')} - Choose scan depth")
    p(f"  {dim('all=full  error=quick  time=deep')}")
    checks = ask("Scan type [all] >") or "all"

    p()
    p(f"  {white('Step 3 of 3')} - Authentication {dim('(Enter to skip)')}")
    cookie = ask("Cookie  >")
    header_val = ask("Header  >")

    p()
    output = ask("Save to file? (Enter to skip) >")

    cmd = [sys.executable, "web/sqli_detector.py", "-u", url.strip(), "--checks"] + checks.split()
    if cookie:     cmd += ["-c", cookie]
    if header_val: cmd += ["-H", header_val]
    if output:     cmd += ["-o", output]

    p()
    line()
    p(f"  {red('Target acquired - running scan...')}")
    line()
    p()
    subprocess.run(cmd)
    p()
    line()
    p(f"  {green('Strike complete.')}")
    line()
    p()
    p(f"  Type {cyan('use 1')} to scan again or {cyan('modules')} to see all tools.")
    p()


def launch_nosql():
    p()
    header("TOOL 2 - NoSQL INJECTOR")
    p()
    p(f"  {dim('Tests MongoDB, Firebase and CouchDB for injection vulnerabilities.')}")
    p(f"  {dim('Works on APIs and apps using NoSQL databases.')}")
    p()

    p(f"  {white('Step 1 of 3')} - Enter the target URL")
    p(f"  {dim('Example: https://site.com/api/users?id=1')}")
    url = ask("URL >")
    if not url.strip():
        p(f"\n  {red('No URL entered. Going back.')}\n")
        return

    p()
    p(f"  {white('Step 2 of 3')} - Choose check type")
    p(f"  {dim('all      = run all checks (recommended)')}")
    p(f"  {dim('get      = test URL parameters only')}")
    p(f"  {dim('post     = test JSON login/search endpoints')}")
    p(f"  {dim('firebase = test Firebase REST endpoints')}")
    checks = ask("Check type [all] >") or "all"

    p()
    p(f"  {white('Step 3 of 3')} - Authentication {dim('(Enter to skip)')}")
    cookie = ask("Cookie  >")
    header_val = ask("Header  >")

    p()
    output = ask("Save to file? (Enter to skip) >")

    cmd = [sys.executable, "web/nosql_injector.py", "-u", url.strip(), "--checks"] + checks.split()
    if cookie:     cmd += ["-c", cookie]
    if header_val: cmd += ["-H", header_val]
    if output:     cmd += ["-o", output]

    p()
    line()
    p(f"  {red('Target acquired - running NoSQL scan...')}")
    line()
    p()
    subprocess.run(cmd)
    p()
    line()
    p(f"  {green('Strike complete.')}")
    line()
    p()
    p(f"  Type {cyan('use 2')} to scan again or {cyan('modules')} to see all tools.")
    p()


def launch_xss():
    p()
    header("TOOL 3 - XSS SCANNER")
    p()
    p(f"  {dim('Scans for Cross-Site Scripting vulnerabilities.')}")
    p(f"  {dim('Tests reflected XSS, DOM sinks, form inputs and security headers.')}")
    p()

    p(f"  {white('Step 1 of 3')} - Enter the target URL")
    p(f"  {dim('Example: https://site.com/search?q=hello')}")
    url = ask("URL >")
    if not url.strip():
        p(f"\n  {red('No URL entered. Going back.')}\n")
        return

    p()
    p(f"  {white('Step 2 of 3')} - Choose check type")
    p(f"  {dim('all       = run all checks (recommended)')}")
    p(f"  {dim('reflected = test URL parameters for reflected XSS')}")
    p(f"  {dim('forms     = test form inputs')}")
    p(f"  {dim('dom       = check for dangerous DOM sinks')}")
    p(f"  {dim('headers   = check for missing security headers')}")
    checks = ask("Check type [all] >") or "all"

    p()
    p(f"  {white('Step 3 of 3')} - Authentication {dim('(Enter to skip)')}")
    cookie = ask("Cookie  >")
    header_val = ask("Header  >")

    p()
    output = ask("Save to file? (Enter to skip) >")

    cmd = [sys.executable, "web/xss_scanner.py", "-u", url.strip(), "--checks"] + checks.split()
    if cookie:     cmd += ["-c", cookie]
    if header_val: cmd += ["-H", header_val]
    if output:     cmd += ["-o", output]

    p()
    line()
    p(f"  {red('Target acquired - running XSS scan...')}")
    line()
    p()
    subprocess.run(cmd)
    p()
    line()
    p(f"  {green('Strike complete.')}")
    line()
    p()
    p(f"  Type {cyan('use 3')} to scan again or {cyan('modules')} to see all tools.")
    p()


def launch_firebase():
    p()
    header("TOOL 4 - FIREBASE AUDITOR")
    p()
    p(f"  {dim('Audits Firebase project for security misconfigurations.')}")
    p(f"  {dim('Checks Firestore, Realtime DB, Storage, Auth and exposed config.')}")
    p()

    p(f"  {white('Step 1 of 2')} - Enter your Firebase Project ID")
    p(f"  {dim('Find it in Firebase Console -> Project Settings')}")
    p(f"  {dim('Example: my-app-12345')}")
    p(f"  {dim('Or enter your app URL and it will extract the ID:')}")
    p(f"  {dim('Example: https://myapp.web.app')}")
    target = ask("Project ID or URL >")
    if not target.strip():
        p(f"\n  {red('No input. Going back.')}\n")
        return

    p()
    p(f"  {white('Step 2 of 2')} - Choose checks")
    p(f"  {dim('all       = run all checks (recommended)')}")
    p(f"  {dim('firestore = check Firestore rules')}")
    p(f"  {dim('rtdb      = check Realtime Database rules')}")
    p(f"  {dim('storage   = check Storage bucket rules')}")
    p(f"  {dim('config    = check for exposed API keys in page source')}")
    p(f"  {dim('auth      = check Auth configuration')}")
    checks = ask("Check type [all] >") or "all"

    p()
    output = ask("Save to file? (Enter to skip) >")

    # Determine if input is URL or project ID
    if target.strip().startswith("http"):
        cmd = [sys.executable, "web/firebase_auditor.py", "-u", target.strip(), "--checks"] + checks.split()
    else:
        cmd = [sys.executable, "web/firebase_auditor.py", "-p", target.strip(), "--checks"] + checks.split()

    if output: cmd += ["-o", output]

    p()
    line()
    p(f"  {red('Target acquired - auditing Firebase project...')}")
    line()
    p()
    subprocess.run(cmd)
    p()
    line()
    p(f"  {green('Audit complete.')}")
    line()
    p()
    p(f"  Type {cyan('use 4')} to audit again or {cyan('modules')} to see all tools.")
    p()


def launch_jwt():
    p()
    header("TOOL 5 - JWT ANALYZER")
    p()
    p(f"  {dim('Decodes and audits JWT tokens for security vulnerabilities.')}")
    p(f"  {dim('Finds weak secrets, bad algorithms, missing expiry, and more.')}")
    p()
    p(f"  {dim('How to get your JWT token:')}")
    p(f"  {dim('  1. Log into your app in Chrome')}")
    p(f"  {dim('  2. Open DevTools (F12) -> Application -> Cookies')}")
    p(f"  {dim('  3. Copy the auth-token or JWT cookie value')}")
    p()

    p(f"  {white('Step 1 of 3')} - Paste your JWT token")
    token = ask("Token >")
    if not token.strip():
        p(f"\n  {red('No token entered. Going back.')}\n")
        return

    p()
    p(f"  {white('Step 2 of 3')} - Choose checks")
    p(f"  {dim('all       = run all checks (recommended)')}")
    p(f"  {dim('algorithm = check signing algorithm')}")
    p(f"  {dim('expiry    = check token expiration')}")
    p(f"  {dim('sensitive = check for sensitive data in payload')}")
    p(f"  {dim('secret    = try to crack weak HMAC secrets')}")
    p(f"  {dim('endpoint  = test token against a live endpoint')}")
    checks = ask("Check type [all] >") or "all"

    p()
    p(f"  {white('Step 3 of 3')} - Endpoint test {dim('(optional)')}")
    p(f"  {dim('Enter a protected API URL to test token validation.')}")
    p(f"  {dim('Press Enter to skip.')}")
    url = ask("API URL >")

    p()
    output = ask("Save to file? (Enter to skip) >")

    cmd = [sys.executable, "web/jwt_analyzer.py", "-t", token.strip(), "--checks"] + checks.split()
    if url:    cmd += ["-u", url]
    if output: cmd += ["-o", output]

    p()
    line()
    p(f"  {red('Analyzing token...')}")
    line()
    p()
    subprocess.run(cmd)
    p()
    line()
    p(f"  {green('Analysis complete.')}")
    line()
    p()
    p(f"  Type {cyan('use 5')} to analyze again or {cyan('modules')} to see all tools.")
    p()


def launch_subdomain():
    p()
    header("TOOL 6 - SUBDOMAIN ENUMERATOR")
    p()
    p(f"  {dim('Discovers subdomains using DNS brute-force and certificate logs.')}")
    p(f"  {dim('Finds dev, staging, API, admin and other hidden subdomains.')}")
    p()

    p(f"  {white('Step 1 of 2')} - Enter the target domain")
    p(f"  {dim('Example: prymebay.com or drewstechconsult.com')}")
    p(f"  {dim('Do NOT include https:// or www.')}")
    domain = ask("Domain >")
    if not domain.strip():
        p(f"\n  {red('No domain entered. Going back.')}\n")
        return

    p()
    p(f"  {white('Step 2 of 2')} - Options")
    p(f"  {dim('Threads: how many to run at once (default 30, max 100)')}")
    threads = ask("Threads [30] >") or "30"

    p()
    p(f"  {dim('Use certificate transparency logs? (finds more subdomains)')}")
    use_crt = ask("Query crt.sh? [y/n] >").strip().lower()

    p()
    output = ask("Save to file? (Enter to skip) >")

    cmd = [sys.executable, "recon/subdomain_enum.py",
           "-d", domain.strip(),
           "-t", threads.strip()]

    if use_crt in ("y", "yes"):
        cmd.append("--crt")
    if output:
        cmd += ["-o", output]

    p()
    line()
    p(f"  {red('Target acquired - enumerating subdomains...')}")
    line()
    p()
    subprocess.run(cmd)
    p()
    line()
    p(f"  {green('Enumeration complete.')}")
    line()
    p()
    p(f"  Type {cyan('use 6')} to scan again or {cyan('modules')} to see all tools.")
    p()


def launch_portscan():
    p()
    header("TOOL 7 - PORT SCANNER")
    p()
    p(f"  {dim('Scans open ports, grabs service banners and rates risk.')}")
    p(f"  {dim('Finds exposed databases, dev servers and dangerous services.')}")
    p()

    p(f"  {white('Step 1 of 2')} - Enter the target host")
    p(f"  {dim('Example: prymebay.com or 192.168.1.1')}")
    p(f"  {dim('Do NOT include https:// or paths')}")
    target = ask("Host >")
    if not target.strip():
        p(f"\n  {red('No host entered. Going back.')}\n")
        return

    p()
    p(f"  {white('Step 2 of 2')} - Choose port set")
    p(f"  {dim('common   = 50 well-known ports (default, recommended)')}")
    p(f"  {dim('web      = HTTP/HTTPS ports only')}")
    p(f"  {dim('database = Database ports only')}")
    p(f"  {dim('dev      = Development server ports')}")
    p(f"  {dim('top100   = All ports 1-1024 (slower)')}")
    p(f"  {dim('custom   = Enter specific ports e.g: 80,443,3306')}")
    port_choice = ask("Port set [common] >") or "common"

    p()
    threads = ask("Threads [50] >") or "50"

    p()
    output = ask("Save to file? (Enter to skip) >")

    cmd = [sys.executable, "scanning/port_scanner.py",
           "-t", target.strip(),
           "--ports", port_choice.strip(),
           "--threads", threads.strip()]
    if output: cmd += ["-o", output]

    p()
    line()
    p(f"  {red('Target acquired - scanning ports...')}")
    line()
    p()
    subprocess.run(cmd)
    p()
    line()
    p(f"  {green('Scan complete.')}")
    line()
    p()
    p(f"  Type {cyan('use 7')} to scan again or {cyan('modules')} to see all tools.")
    p()

def launch_tool(tool):
    if tool["status"] != "ready":
        p(f"\n  {yellow(tool['name'] + ' is not available yet.')}\n")
        return
    if tool["id"] == 1:
        launch_sqli()
    elif tool["id"] == 2:
        launch_nosql()
    elif tool["id"] == 3:
        launch_xss()
    elif tool["id"] == 4:
        launch_firebase()
    elif tool["id"] == 5:
        launch_jwt()
    elif tool["id"] == 6:
        launch_subdomain()
    elif tool["id"] == 7:
        launch_portscan()

def find_tool(query):
    q = query.strip().lower()
    for t in ALL_TOOLS:
        if str(t["id"]) == q or q in t["name"].lower():
            return t
    return None

# ── Main loop ──────────────────────────────────────────────────────────────────

def main():
    show_banner()
    while True:
        try:
            sys.stdout.write(f"{BOLD}{RED}stryker{RST}{WHITE}@{RST}{CYAN}andrews{RST}{DIM} > {RST}")
            sys.stdout.flush()
            cmd = input().strip()
        except (KeyboardInterrupt, EOFError):
            p(f"\n  {dim('Type exit to quit.')}\n")
            continue

        if not cmd:
            continue

        parts  = cmd.split(maxsplit=1)
        action = parts[0].lower()
        arg    = parts[1].strip() if len(parts) > 1 else ""

        if action in ("exit", "quit", "q"):
            p()
            p(f"  {red('Strike terminated - STRYKER signing off.')}")
            p(f"  {dim(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}")
            p()
            break
        elif action == "help":           show_help()
        elif action in ("modules","tools","list"): show_modules()
        elif action == "banner":         show_banner()
        elif action == "clear":          clear()
        elif action == "info":
            if not arg: p(f"  {yellow('Usage: info <id>  eg: info 1')}\n")
            else:
                tool = find_tool(arg)
                if tool: show_info(tool)
                else:    p(f"  {red('Not found.')} Type {cyan('modules')} to see all.\n")
        elif action == "use":
            if not arg: p(f"  {yellow('Usage: use <id>  eg: use 1')}\n")
            else:
                tool = find_tool(arg)
                if tool: launch_tool(tool)
                else:    p(f"  {red('Not found.')} Type {cyan('modules')} to see all.\n")
        else:
            p(f"  {dim('Unknown:')} {red(cmd)}{dim('. Type')} {cyan('help')}{dim('.')}\n")

if __name__ == "__main__":
    main()