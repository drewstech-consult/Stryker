#!/usr/bin/env python3
"""
dashboard.py - STRYKER Web Dashboard
By Andrews | For authorized testing only

A local web dashboard to view scan results, findings and reports
in your browser while STRYKER runs in the terminal.
"""

import os
import sys
import io
import json
import sqlite3
import threading
import webbrowser
import time
from pathlib import Path
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)

os.environ["PYTHONUNBUFFERED"] = "1"

DB_PATH = Path("stryker_data.db")

RED   = "\033[91m"
CYAN  = "\033[96m"
GREEN = "\033[92m"
DIM   = "\033[2m"
BOLD  = "\033[1m"
RST   = "\033[0m"

def p(t=""):
    sys.stdout.write(str(t) + "\n")
    sys.stdout.flush()

# ── Data helpers ───────────────────────────────────────────────────────────────

def get_stats():
    try:
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute("SELECT COUNT(*) FROM scans")
        total_scans = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM scans WHERE status='complete'")
        complete = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM findings")
        total_findings = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM findings WHERE severity='CRITICAL'")
        critical = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM findings WHERE severity='HIGH'")
        high = c.fetchone()[0]
        conn.close()
        return {
            "total_scans": total_scans,
            "complete_scans": complete,
            "total_findings": total_findings,
            "critical": critical,
            "high": high,
        }
    except Exception:
        return {"total_scans": 0, "complete_scans": 0, "total_findings": 0, "critical": 0, "high": 0}


def get_scans():
    try:
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        c.execute("SELECT id, target, started_at, status, findings FROM scans ORDER BY id DESC LIMIT 20")
        rows = c.fetchall()
        conn.close()
        return [{"id": r[0], "target": r[1], "started_at": r[2], "status": r[3], "findings": r[4]} for r in rows]
    except Exception:
        return []


def get_findings(scan_id=None):
    try:
        conn = sqlite3.connect(DB_PATH)
        c    = conn.cursor()
        if scan_id:
            c.execute("""
                SELECT f.id, f.tool, f.severity, f.title, f.target, f.detail, s.target
                FROM findings f JOIN scans s ON f.scan_id = s.id
                WHERE f.scan_id=?
                ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END
            """, (scan_id,))
        else:
            c.execute("""
                SELECT f.id, f.tool, f.severity, f.title, f.target, f.detail, s.target
                FROM findings f JOIN scans s ON f.scan_id = s.id
                ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END
                LIMIT 100
            """)
        rows = c.fetchall()
        conn.close()
        return [{"id": r[0], "tool": r[1], "severity": r[2], "title": r[3],
                 "target": r[4], "detail": r[5], "scan_target": r[6]} for r in rows]
    except Exception:
        return []


# ── HTML Dashboard ─────────────────────────────────────────────────────────────

def build_html(stats, scans, findings, active_scan_id=None):
    sev_badge = {
        "CRITICAL": '<span style="background:#cc1111;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">CRITICAL</span>',
        "HIGH":     '<span style="background:#cc5500;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">HIGH</span>',
        "MEDIUM":   '<span style="background:#997700;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">MEDIUM</span>',
        "LOW":      '<span style="background:#1a6b1a;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">LOW</span>',
        "INFO":     '<span style="background:#444;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">INFO</span>',
    }

    scans_html = ""
    for s in scans:
        date     = s["started_at"][:16].replace("T", " ") if s["started_at"] else "—"
        active   = "background:#1a0000;" if str(s["id"]) == str(active_scan_id) else ""
        findings_badge = f'<span style="color:#cc1111;font-weight:700">{s["findings"]}</span>' if s["findings"] > 0 else f'<span style="color:#1a6b1a">{s["findings"]}</span>'
        scans_html += f'''
        <tr style="cursor:pointer;{active}" onclick="loadScan({s['id']})">
            <td style="padding:8px 12px;color:#96ccff">#{s['id']}</td>
            <td style="padding:8px 12px;color:#fff">{s['target']}</td>
            <td style="padding:8px 12px;color:#666">{date}</td>
            <td style="padding:8px 12px">{findings_badge}</td>
        </tr>'''

    findings_html = ""
    for f in findings:
        badge = sev_badge.get(f["severity"], sev_badge["INFO"])
        detail = (f["detail"] or "")[:120].replace("<", "&lt;").replace(">", "&gt;")
        findings_html += f'''
        <tr>
            <td style="padding:8px 12px">{badge}</td>
            <td style="padding:8px 12px;color:#96ccff;font-size:12px">{f['tool']}</td>
            <td style="padding:8px 12px;color:#fff">{f['title'][:70]}</td>
            <td style="padding:8px 12px;color:#666;font-size:11px">{detail}</td>
        </tr>'''

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>STRYKER Dashboard</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ background:#0a0a0a; color:#ccc; font-family:'Courier New',monospace; }}
  .header {{ background:#0f0f0f; border-bottom:2px solid #cc1111; padding:16px 24px; display:flex; align-items:center; justify-content:space-between; }}
  .logo {{ color:#cc1111; font-size:22px; font-weight:700; letter-spacing:4px; }}
  .subtitle {{ color:#444; font-size:11px; margin-top:2px; }}
  .timestamp {{ color:#333; font-size:11px; }}
  .stats {{ display:grid; grid-template-columns:repeat(5,1fr); gap:12px; padding:20px 24px; }}
  .stat {{ background:#111; border:1px solid #1a1a1a; border-radius:8px; padding:16px; text-align:center; }}
  .stat-val {{ font-size:28px; font-weight:700; color:#cc1111; }}
  .stat-val.green {{ color:#1a9b1a; }}
  .stat-label {{ font-size:10px; color:#555; margin-top:4px; letter-spacing:1px; text-transform:uppercase; }}
  .main {{ display:grid; grid-template-columns:300px 1fr; gap:0; height:calc(100vh - 160px); }}
  .sidebar {{ background:#0d0d0d; border-right:1px solid #1a1a1a; overflow-y:auto; }}
  .sidebar-title {{ padding:12px 16px; color:#cc1111; font-size:11px; letter-spacing:2px; border-bottom:1px solid #1a1a1a; }}
  .content {{ overflow-y:auto; padding:20px 24px; }}
  table {{ width:100%; border-collapse:collapse; }}
  tr:hover {{ background:#111; }}
  th {{ padding:8px 12px; text-align:left; color:#666; font-size:10px; letter-spacing:1px; border-bottom:1px solid #1a1a1a; }}
  .section-title {{ color:#cc1111; font-size:12px; letter-spacing:2px; margin-bottom:12px; padding-bottom:8px; border-bottom:1px solid #1a1a1a; }}
  .empty {{ color:#333; font-size:13px; padding:40px; text-align:center; }}
  ::-webkit-scrollbar {{ width:4px; }} ::-webkit-scrollbar-track {{ background:#0a0a0a; }} ::-webkit-scrollbar-thumb {{ background:#cc1111; }}
</style>
</head>
<body>
<div class="header">
  <div>
    <div class="logo">&#9651; STRYKER</div>
    <div class="subtitle">Penetration Testing Framework &mdash; by Andrews</div>
  </div>
  <div class="timestamp">Last updated: {now} &bull; Auto-refresh: 30s</div>
</div>

<div class="stats">
  <div class="stat"><div class="stat-val">{stats['total_scans']}</div><div class="stat-label">Total Scans</div></div>
  <div class="stat"><div class="stat-val green">{stats['complete_scans']}</div><div class="stat-label">Complete</div></div>
  <div class="stat"><div class="stat-val">{stats['total_findings']}</div><div class="stat-label">Findings</div></div>
  <div class="stat"><div class="stat-val">{stats['critical']}</div><div class="stat-label">Critical</div></div>
  <div class="stat"><div class="stat-val" style="color:#cc5500">{stats['high']}</div><div class="stat-label">High</div></div>
</div>

<div class="main">
  <div class="sidebar">
    <div class="sidebar-title">SCAN HISTORY</div>
    <table>
      <thead><tr>
        <th>ID</th><th>TARGET</th><th>DATE</th><th>FINDINGS</th>
      </tr></thead>
      <tbody>{scans_html if scans_html else '<tr><td colspan="4" class="empty">No scans yet.<br>Run autopilot.py</td></tr>'}</tbody>
    </table>
  </div>

  <div class="content">
    <div class="section-title">{'FINDINGS &mdash; SCAN #' + str(active_scan_id) if active_scan_id else 'ALL FINDINGS'}</div>
    <table>
      <thead><tr>
        <th>SEVERITY</th><th>TOOL</th><th>FINDING</th><th>DETAIL</th>
      </tr></thead>
      <tbody>{findings_html if findings_html else '<tr><td colspan="4" class="empty">No findings yet.<br>Run a scan to see results here.</td></tr>'}</tbody>
    </table>
  </div>
</div>

<script>
function loadScan(id) {{
  window.location.href = '/?scan=' + id;
}}
</script>
</body>
</html>'''


# ── HTTP Handler ───────────────────────────────────────────────────────────────

class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress access logs

    def do_GET(self):
        parsed   = urlparse(self.path)
        params   = parse_qs(parsed.query)
        scan_id  = params.get("scan", [None])[0]

        if parsed.path == "/api/stats":
            self.send_json(get_stats())
            return

        if parsed.path == "/api/scans":
            self.send_json(get_scans())
            return

        if parsed.path == "/api/findings":
            self.send_json(get_findings(scan_id))
            return

        # Main dashboard
        stats    = get_stats()
        scans    = get_scans()
        findings = get_findings(scan_id)
        html     = build_html(stats, scans, findings, scan_id)

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def send_json(self, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    port = 7474
    host = "127.0.0.1"

    os.system("cls" if os.name == "nt" else "clear")
    p()
    p(f"{BOLD}{RED} _____ _____ ____  _   _ ___  ___   _   ___ _  _ ___  _  _  _   ___ ___  {RST}")
    p(f"{BOLD}{RED}/ ____|_   _|  _ \\| \\ | |_ _|/ __| | | | __|  \\| |__  (_)| |  /_\\ |  \\ {RST}")
    p(f"{BOLD}{RED}\\____ \\ | | | |_) |  \\| || || (_   | |_| _|| .` |_| _| | |_| / _ \\|   /{RST}")
    p(f"{BOLD}{RED} ____/ / | | |  _ <| |\\  || | \\__| |___|___|_|\\_(_)_|  | |___/_/ \\_\\_|\\_\\{RST}")
    p(f"{BOLD}{RED}|_____/ |_| |_| \\_\\_| \\_|___||___| |___|___|_|  \\_|___|  |                {RST}")
    p()
    p(f"{DIM}  STRYKER Web Dashboard  |  by Andrews  |  v1.0.0{RST}")
    p()
    p(f"  {DIM}{'─' * 50}{RST}")
    p(f"  {DIM}Dashboard URL:{RST}  {CYAN}http://{host}:{port}{RST}")
    p(f"  {DIM}Auto-refresh:{RST}   every 30 seconds")
    p(f"  {DIM}Database:{RST}       {DB_PATH}")
    p(f"  {DIM}{'─' * 50}{RST}")
    p()
    p(f"  {GREEN}[+]{RST} Starting dashboard server...")

    server = HTTPServer((host, port), DashboardHandler)

    # Open browser after short delay
    def open_browser():
        time.sleep(1.2)
        webbrowser.open(f"http://{host}:{port}")

    browser_thread = threading.Thread(target=open_browser, daemon=True)
    browser_thread.start()

    p(f"  {GREEN}[+]{RST} Dashboard open at {CYAN}http://{host}:{port}{RST}")
    p()
    p(f"  {DIM}Press Ctrl+C to stop the dashboard.{RST}")
    p()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        p()
        p(f"  {RED}Dashboard stopped.{RST}")
        p()
        server.shutdown()


if __name__ == "__main__":
    main()