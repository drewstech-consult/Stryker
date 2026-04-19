#!/usr/bin/env python3
"""
workspace.py - STRYKER Workspace Manager
By Andrews | For authorized testing only

Manages client workspaces — each client gets their own isolated
environment with separate findings, scans, notes and reports.
"""

import os
import sys
import io
import json
import sqlite3
import shutil
import time
from pathlib import Path
from datetime import datetime

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)

if not sys.stdout.isatty() and os.name == "nt":
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

# ── Workspace paths ────────────────────────────────────────────────────────────

WORKSPACES_DIR  = Path("workspaces")
ACTIVE_FILE     = Path(".active_workspace")
GLOBAL_DB       = Path("stryker_data.db")


def get_active():
    """Get currently active workspace name."""
    if ACTIVE_FILE.exists():
        name = ACTIVE_FILE.read_text().strip()
        if name and (WORKSPACES_DIR / name).exists():
            return name
    return "default"


def set_active(name):
    """Set active workspace."""
    ACTIVE_FILE.write_text(name)


def workspace_path(name=None):
    """Get path to a workspace directory."""
    name = name or get_active()
    return WORKSPACES_DIR / name


def workspace_db(name=None):
    """Get path to workspace database."""
    return workspace_path(name) / "workspace.db"


def workspace_config(name=None):
    """Get path to workspace config."""
    return workspace_path(name) / "config.json"


# ── Database ───────────────────────────────────────────────────────────────────

def init_workspace_db(db_path):
    """Initialize a workspace database."""
    conn = sqlite3.connect(db_path)
    c    = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target      TEXT,
            started_at  TEXT,
            finished_at TEXT,
            status      TEXT,
            findings    INTEGER DEFAULT 0,
            notes       TEXT DEFAULT ''
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id    INTEGER,
            tool       TEXT,
            severity   TEXT,
            title      TEXT,
            target     TEXT,
            detail     TEXT,
            status     TEXT DEFAULT 'open',
            created_at TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            content    TEXT,
            created_at TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS targets (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            domain     TEXT UNIQUE,
            ip         TEXT,
            added_at   TEXT,
            notes      TEXT DEFAULT ''
        )
    """)
    conn.commit()
    conn.close()


# ── Workspace management ───────────────────────────────────────────────────────

def create_workspace(name, client_name="", domain="", notes=""):
    """Create a new workspace."""
    path = workspace_path(name)
    if path.exists():
        err(f"Workspace '{name}' already exists")
        return False

    path.mkdir(parents=True)
    (path / "scans").mkdir()
    (path / "reports").mkdir()

    # Config
    config = {
        "name":        name,
        "client":      client_name or name,
        "domain":      domain,
        "notes":       notes,
        "created_at":  datetime.now().isoformat(),
        "status":      "active",
    }
    workspace_config(name).write_text(json.dumps(config, indent=2))

    # Database
    init_workspace_db(workspace_db(name))

    success(f"Workspace '{name}' created")
    return True


def list_workspaces():
    """List all workspaces."""
    if not WORKSPACES_DIR.exists():
        return []

    workspaces = []
    for path in sorted(WORKSPACES_DIR.iterdir()):
        if path.is_dir():
            cfg_file = path / "config.json"
            db_file  = path / "workspace.db"

            config = {}
            if cfg_file.exists():
                try:
                    config = json.loads(cfg_file.read_text())
                except Exception:
                    pass

            # Count scans and findings
            scans = findings = 0
            if db_file.exists():
                try:
                    conn = sqlite3.connect(db_file)
                    c    = conn.cursor()
                    c.execute("SELECT COUNT(*) FROM scans")
                    scans = c.fetchone()[0]
                    c.execute("SELECT COUNT(*) FROM findings")
                    findings = c.fetchone()[0]
                    conn.close()
                except Exception:
                    pass

            workspaces.append({
                "name":     path.name,
                "client":   config.get("client", path.name),
                "domain":   config.get("domain", ""),
                "created":  config.get("created_at", "")[:10],
                "scans":    scans,
                "findings": findings,
                "active":   path.name == get_active(),
            })

    return workspaces


def delete_workspace(name):
    """Delete a workspace."""
    if name == "default":
        err("Cannot delete the default workspace")
        return False

    path = workspace_path(name)
    if not path.exists():
        err(f"Workspace '{name}' not found")
        return False

    shutil.rmtree(path)
    if get_active() == name:
        set_active("default")
    success(f"Workspace '{name}' deleted")
    return True


def add_note(content, name=None):
    """Add a note to the current workspace."""
    db = workspace_db(name)
    if not db.exists():
        err("Workspace database not found")
        return
    conn = sqlite3.connect(db)
    c    = conn.cursor()
    c.execute(
        "INSERT INTO notes (content, created_at) VALUES (?, ?)",
        (content, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()
    success("Note saved")


def show_notes(name=None):
    """Show notes in current workspace."""
    db = workspace_db(name)
    if not db.exists():
        warn("No notes yet")
        return
    conn = sqlite3.connect(db)
    c    = conn.cursor()
    c.execute("SELECT content, created_at FROM notes ORDER BY id DESC LIMIT 20")
    rows = c.fetchall()
    conn.close()

    p()
    header("WORKSPACE NOTES")
    if not rows:
        p(f"  {DIM}No notes yet. Use: note <text>{RST}")
        p()
        return
    for content, created in rows:
        date = created[:16].replace("T", " ")
        p(f"  {DIM}[{date}]{RST} {content}")
    p()


def add_target(domain, ip="", notes="", name=None):
    """Add a target to the workspace."""
    db = workspace_db(name)
    if not db.exists():
        err("Workspace database not found")
        return
    conn = sqlite3.connect(db)
    c    = conn.cursor()
    try:
        c.execute(
            "INSERT INTO targets (domain, ip, added_at, notes) VALUES (?, ?, ?, ?)",
            (domain, ip, datetime.now().isoformat(), notes)
        )
        conn.commit()
        success(f"Target '{domain}' added")
    except sqlite3.IntegrityError:
        warn(f"Target '{domain}' already exists")
    finally:
        conn.close()


def show_targets(name=None):
    """Show targets in workspace."""
    db = workspace_db(name)
    if not db.exists():
        warn("No targets yet")
        return
    conn = sqlite3.connect(db)
    c    = conn.cursor()
    c.execute("SELECT domain, ip, added_at, notes FROM targets ORDER BY id")
    rows = c.fetchall()
    conn.close()

    p()
    header("WORKSPACE TARGETS")
    if not rows:
        p(f"  {DIM}No targets yet. Use: target add <domain>{RST}")
        p()
        return
    for domain, ip, added, notes_text in rows:
        date = added[:10] if added else "—"
        p(f"  {CYAN}{domain:<35}{RST} {DIM}{ip or '':>16}{RST}  {DIM}Added: {date}{RST}")
        if notes_text:
            p(f"    {DIM}{notes_text}{RST}")
    p()


def show_workspace_findings(name=None):
    """Show all findings in workspace."""
    db = workspace_db(name)
    if not db.exists():
        warn("No findings yet")
        return

    conn = sqlite3.connect(db)
    c    = conn.cursor()
    c.execute("""
        SELECT f.severity, f.title, f.tool, f.target, f.status, s.target as scan_target
        FROM findings f
        JOIN scans s ON f.scan_id = s.id
        ORDER BY CASE f.severity
            WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
            WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'   THEN 4 ELSE 5
        END
        LIMIT 50
    """)
    rows = c.fetchall()
    conn.close()

    p()
    header("ALL FINDINGS")
    if not rows:
        p(f"  {DIM}No findings yet. Run a scan first.{RST}")
        p()
        return

    sev_colors = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN}
    for sev, title, tool, target, status, scan_target in rows:
        color = sev_colors.get(sev, DIM)
        status_c = GREEN if status == "fixed" else DIM
        p(f"  {color}[{sev:<8}]{RST} {title[:55]}")
        p(f"    {DIM}Tool: {tool}  |  {status_c}{status}{RST}")
    p()


def show_workspace_info(name=None):
    """Show current workspace info."""
    name = name or get_active()
    cfg_file = workspace_config(name)

    if not cfg_file.exists():
        warn(f"Workspace '{name}' not found")
        return

    config = json.loads(cfg_file.read_text())
    db     = workspace_db(name)

    scans = findings = open_findings = 0
    if db.exists():
        conn = sqlite3.connect(db)
        c    = conn.cursor()
        c.execute("SELECT COUNT(*) FROM scans")
        scans = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM findings")
        findings = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM findings WHERE status='open'")
        open_findings = c.fetchone()[0]
        conn.close()

    p()
    header(f"WORKSPACE: {name.upper()}")
    p()
    p(f"  {CYAN}Name       {RST}  {config.get('name', name)}")
    p(f"  {CYAN}Client     {RST}  {config.get('client', '—')}")
    p(f"  {CYAN}Domain     {RST}  {config.get('domain', '—')}")
    p(f"  {CYAN}Created    {RST}  {config.get('created_at', '—')[:10]}")
    p(f"  {CYAN}Scans      {RST}  {scans}")
    p(f"  {CYAN}Findings   {RST}  {findings} total, {RED}{open_findings}{RST} open")
    if config.get('notes'):
        p(f"  {CYAN}Notes      {RST}  {config['notes']}")
    p()
    line()
    p()


# ── Banner ─────────────────────────────────────────────────────────────────────

def show_banner():
    os.system("cls" if os.name == "nt" else "clear")
    active = get_active()
    p()
    p(f"{BOLD}{RED} _____ ___________ _   _____ ___________ {RST}")
    p(f"{BOLD}{RED}|  __ \\_   _| ___ \\ | / /  ___|_   _| ___ \\{RST}")
    p(f"{BOLD}{RED}| |  \\/ | | | |_/ / |/ /| |__   | | | |_/ /{RST}")
    p(f"{BOLD}{RED}| | __  | | |    /|    \\|  __|  | | |    / {RST}")
    p(f"{BOLD}{RED}| |_\\ \\_| |_| |\\ \\| |\\  \\ |___  | | | |\\ \\ {RST}")
    p(f"{BOLD}{RED} \\____/\\___/\\_| \\_\\_| \\_/\\____/ \\_/ \\_| \\_|{RST}")
    p(f"{BOLD}{RED}  __    __  ___    _   _   _    ___  ___ ___ {RST}")
    p(f"{BOLD}{RED} |  \\  /  |/ _ \\  | \\ | | /_\\  / __|/ __| __|{RST}")
    p(f"{BOLD}{RED} | |\\ \\/ /| (_) | |  \\| |/ _ \\ \\__ \\ (__| _| {RST}")
    p(f"{BOLD}{RED} |_| \\__/  \\___/  |_|\\__/_/ \\_\\|___/\\___|___|{RST}")
    p()
    p(f"{DIM}  Client Workspace Manager  |  by Andrews  |  v1.0.0{RST}")
    p()
    line()
    p(f"  {DIM}Active workspace:{RST} {GREEN}{active}{RST}")
    line()
    p()
    p(f"  {DIM}Commands:{RST}  "
      f"{CYAN}new{RST}  {CYAN}list{RST}  {CYAN}switch{RST}  {CYAN}info{RST}  "
      f"{CYAN}targets{RST}  {CYAN}findings{RST}  {CYAN}notes{RST}  {CYAN}note{RST}  "
      f"{CYAN}delete{RST}  {CYAN}exit{RST}")
    p()


# ── Main loop ──────────────────────────────────────────────────────────────────

def main():
    # Ensure default workspace exists
    WORKSPACES_DIR.mkdir(exist_ok=True)
    if not workspace_path("default").exists():
        create_workspace("default", "Default", "", "Default workspace")

    show_banner()

    while True:
        active = get_active()
        try:
            sys.stdout.write(
                f"{BOLD}{RED}stryker{RST}{WHITE}@{RST}"
                f"{CYAN}{active}{RST}{DIM} > {RST}"
            )
            sys.stdout.flush()
            cmd = input().strip()
        except (KeyboardInterrupt, EOFError):
            p(f"\n  {DIM}Type exit to quit.{RST}\n")
            continue

        if not cmd:
            continue

        parts  = cmd.split(maxsplit=2)
        action = parts[0].lower()
        arg1   = parts[1].strip() if len(parts) > 1 else ""
        arg2   = parts[2].strip() if len(parts) > 2 else ""

        if action in ("exit", "quit", "q"):
            p()
            p(f"  {RED}Workspace manager closed.{RST}")
            p(f"  {DIM}Active workspace: {get_active()}{RST}")
            p()
            break

        elif action == "new":
            p()
            header("CREATE NEW WORKSPACE")
            p()
            name   = ask("Workspace name (no spaces, use-hyphens) >")
            if not name:
                warn("Name required")
                continue
            name   = name.lower().replace(" ", "-")
            client = ask(f"Client name [{name}] >") or name
            domain = ask("Primary domain (e.g. client.com) >")
            notes  = ask("Notes (Enter to skip) >")
            p()
            if create_workspace(name, client, domain, notes):
                switch = ask(f"Switch to '{name}' now? [y/n] >").lower()
                if switch in ("y", "yes"):
                    set_active(name)
                    success(f"Switched to workspace '{name}'")
            p()

        elif action == "list":
            p()
            header("ALL WORKSPACES")
            workspaces = list_workspaces()
            if not workspaces:
                p(f"  {DIM}No workspaces yet. Use: new{RST}")
                p()
                continue
            p(f"  {'':2} {CYAN}{'Name':<20}{RST} {WHITE}{'Client':<25}{RST} "
              f"{DIM}{'Domain':<25}{RST} {'Scans':<7} {'Findings'}")
            p(f"  {'─'*2} {'─'*20} {'─'*25} {'─'*25} {'─'*7} {'─'*8}")
            for ws in workspaces:
                active_mark = f"{GREEN}*{RST}" if ws["active"] else " "
                p(f"  {active_mark} {CYAN}{ws['name']:<20}{RST} "
                  f"{ws['client']:<25} "
                  f"{DIM}{ws['domain']:<25}{RST} "
                  f"{ws['scans']:<7} "
                  f"{RED if ws['findings'] > 0 else GREEN}{ws['findings']}{RST}")
            p()
            p(f"  {GREEN}*{RST} = active workspace")
            p()

        elif action == "switch":
            if not arg1:
                p(f"  {YELLOW}Usage: switch <name>{RST}\n")
                continue
            if not workspace_path(arg1).exists():
                err(f"Workspace '{arg1}' not found. Use 'list' to see all.")
                p()
                continue
            set_active(arg1)
            success(f"Switched to workspace '{arg1}'")
            p()

        elif action == "info":
            show_workspace_info(arg1 or None)

        elif action in ("targets", "target"):
            if arg1 == "add":
                domain = arg2 or ask("Domain >")
                if domain:
                    add_target(domain)
            else:
                show_targets()

        elif action == "findings":
            show_workspace_findings()

        elif action == "notes":
            show_notes()

        elif action == "note":
            content = arg1 + (" " + arg2 if arg2 else "")
            if not content.strip():
                content = ask("Note >")
            if content.strip():
                add_note(content.strip())
            p()

        elif action == "delete":
            if not arg1:
                p(f"  {YELLOW}Usage: delete <name>{RST}\n")
                continue
            confirm = ask(f"Delete workspace '{arg1}'? This cannot be undone. [y/n] >").lower()
            if confirm in ("y", "yes"):
                delete_workspace(arg1)
            else:
                info("Cancelled")
            p()

        elif action == "banner":
            show_banner()

        else:
            p(f"  {DIM}Unknown: {RED}{cmd}{RST}{DIM}. Commands: "
              f"{CYAN}new list switch info targets findings notes note delete exit{RST}{DIM}.{RST}\n")


if __name__ == "__main__":
    main()