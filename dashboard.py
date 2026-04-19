#!/usr/bin/env python3
"""
dashboard.py - STRYKER Full Management Dashboard
By Andrews | For authorized testing only
"""

import os, sys, io, json, sqlite3, threading, webbrowser, time, shutil, subprocess
from pathlib import Path
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)

os.environ["PYTHONUNBUFFERED"] = "1"

DB_PATH        = Path("stryker_data.db")
WORKSPACES_DIR = Path("workspaces")
SCANS_DIR      = Path("scans")

RED  = "\033[91m"; CYAN = "\033[96m"; GREEN = "\033[92m"
DIM  = "\033[2m";  BOLD = "\033[1m";  RST   = "\033[0m"

def p(t=""): sys.stdout.write(str(t)+"\n"); sys.stdout.flush()

# ── DB helpers ─────────────────────────────────────────────────────────────────

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def ensure_db():
    conn = db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT,
        started_at TEXT, finished_at TEXT, status TEXT, findings INTEGER DEFAULT 0, notes TEXT DEFAULT '')""")
    c.execute("""CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER,
        tool TEXT, severity TEXT, title TEXT, target TEXT, detail TEXT,
        status TEXT DEFAULT 'open', recommendation TEXT DEFAULT '', created_at TEXT)""")
    conn.commit(); conn.close()

def q(sql, args=(), one=False):
    conn = db()
    c = conn.cursor(); c.execute(sql, args)
    rows = c.fetchone() if one else c.fetchall()
    conn.commit(); conn.close()
    return rows

def qw(sql, args=()):
    conn = db(); c = conn.cursor(); c.execute(sql, args)
    conn.commit(); conn.close()

# ── HTML ───────────────────────────────────────────────────────────────────────

CSS = """
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0a;color:#ccc;font-family:'Courier New',monospace;height:100vh;display:flex;flex-direction:column}
a{color:#96ccff;text-decoration:none}a:hover{color:#cc1111}
.topbar{background:#0d0d0d;border-bottom:2px solid #cc1111;padding:12px 20px;display:flex;align-items:center;gap:24px;flex-shrink:0}
.logo{color:#cc1111;font-size:18px;font-weight:700;letter-spacing:3px;margin-right:8px}
.nav a{padding:6px 14px;border-radius:4px;font-size:12px;letter-spacing:1px;transition:.15s}
.nav a:hover,.nav a.active{background:#cc1111;color:#fff}
.nav{display:flex;gap:4px}
.spacer{flex:1}
.badge{background:#cc1111;color:#fff;border-radius:10px;font-size:10px;padding:1px 7px;margin-left:5px;font-weight:700}
.badge.green{background:#1a6b1a}
.page{flex:1;overflow:hidden;display:none;flex-direction:column}
.page.active{display:flex}
.toolbar{background:#0f0f0f;border-bottom:1px solid #1a1a1a;padding:10px 20px;display:flex;align-items:center;gap:10px;flex-shrink:0}
.toolbar input,.toolbar select{background:#161616;border:1px solid #2a2a2a;color:#ccc;padding:6px 10px;border-radius:4px;font-family:inherit;font-size:12px}
.toolbar input:focus,.toolbar select:focus{outline:none;border-color:#cc1111}
.btn{padding:6px 14px;border-radius:4px;font-size:12px;cursor:pointer;border:none;font-family:inherit;letter-spacing:1px;transition:.15s}
.btn-red{background:#cc1111;color:#fff}.btn-red:hover{background:#aa0000}
.btn-ghost{background:transparent;border:1px solid #333;color:#888}.btn-ghost:hover{border-color:#cc1111;color:#cc1111}
.btn-green{background:#1a6b1a;color:#fff}.btn-green:hover{background:#145514}
.btn-sm{padding:3px 10px;font-size:11px}
.content{flex:1;overflow-y:auto;padding:20px}
table{width:100%;border-collapse:collapse}
th{padding:9px 12px;text-align:left;color:#555;font-size:10px;letter-spacing:1px;border-bottom:1px solid #1a1a1a;white-space:nowrap}
td{padding:9px 12px;border-bottom:1px solid #111;font-size:12px;vertical-align:middle}
tr:hover{background:#0e0e0e}
.sev{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.5px}
.sev-CRITICAL{background:#cc1111;color:#fff}.sev-HIGH{background:#cc5500;color:#fff}
.sev-MEDIUM{background:#997700;color:#fff}.sev-LOW{background:#1a6b1a;color:#fff}
.sev-INFO{background:#333;color:#aaa}
.status-open{color:#cc1111}.status-fixed{color:#1a9b1a}.status-wontfix{color:#666}
.stats-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:20px}
.stat{background:#111;border:1px solid #1a1a1a;border-radius:8px;padding:16px;text-align:center}
.stat-val{font-size:28px;font-weight:700;color:#cc1111}.stat-val.g{color:#1a9b1a}.stat-val.o{color:#cc5500}
.stat-lbl{font-size:9px;color:#444;margin-top:4px;letter-spacing:1px;text-transform:uppercase}
.card{background:#111;border:1px solid #1a1a1a;border-radius:8px;padding:16px;margin-bottom:12px}
.card-title{color:#cc1111;font-size:11px;letter-spacing:1px;margin-bottom:10px;text-transform:uppercase}
.form-group{margin-bottom:12px}
.form-group label{display:block;font-size:10px;color:#666;letter-spacing:1px;margin-bottom:4px;text-transform:uppercase}
.form-group input,.form-group select,.form-group textarea{width:100%;background:#161616;border:1px solid #2a2a2a;color:#ccc;padding:8px 10px;border-radius:4px;font-family:inherit;font-size:12px}
.form-group textarea{height:80px;resize:vertical}
.form-group input:focus,.form-group select:focus,.form-group textarea:focus{outline:none;border-color:#cc1111}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.85);z-index:100;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:#111;border:1px solid #cc1111;border-radius:8px;padding:24px;width:520px;max-height:80vh;overflow-y:auto}
.modal-title{color:#cc1111;font-size:13px;letter-spacing:2px;margin-bottom:16px;text-transform:uppercase}
.modal-footer{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}
.alert{padding:10px 14px;border-radius:4px;font-size:12px;margin-bottom:12px;display:none}
.alert.success{background:#0a1f0a;border:1px solid #1a6b1a;color:#4caf50}
.alert.error{background:#1f0a0a;border:1px solid #cc1111;color:#f44336}
.tag{display:inline-block;background:#1a1a1a;border:1px solid #2a2a2a;color:#888;padding:2px 8px;border-radius:10px;font-size:10px}
.detail-row{display:flex;gap:8px;margin-bottom:6px;font-size:12px}
.detail-lbl{color:#555;min-width:110px;flex-shrink:0}
.detail-val{color:#ccc;word-break:break-all}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-thumb{background:#cc1111}
"""

JS = """
let currentPage = 'dashboard';
let scanFilter = '';
let sevFilter = '';
let statusFilter = '';
let searchText = '';

function nav(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav a').forEach(a => a.classList.remove('active'));
  document.getElementById('page-' + page).classList.add('active');
  document.querySelector(`.nav a[onclick="nav('${page}')"]`).classList.add('active');
  currentPage = page;
}

function showAlert(msg, type='success') {
  const el = document.getElementById('alert');
  if (!el) return;
  el.textContent = msg; el.className = 'alert ' + type; el.style.display = 'block';
  setTimeout(() => el.style.display = 'none', 3000);
}

// Modal
function openModal(id) { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

// API helper
async function api(path, method='GET', body=null) {
  const opts = { method, headers: {'Content-Type':'application/json'} };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch('/api/' + path, opts);
  return res.json();
}

// Scan actions
async function deleteScan(id) {
  if (!confirm('Delete scan #' + id + '? This cannot be undone.')) return;
  await api('scans/' + id, 'DELETE');
  location.reload();
}

async function addNote(scanId) {
  const note = prompt('Add note to scan #' + scanId + ':');
  if (!note) return;
  await api('scans/' + scanId + '/note', 'POST', { note });
  location.reload();
}

async function runScan() {
  const target = document.getElementById('scan-target').value.trim();
  const cookie = document.getElementById('scan-cookie').value.trim();
  if (!target) { alert('Enter a target'); return; }
  closeModal('modal-scan');
  showAlert('Scan queued for ' + target + ' — check terminal for progress');
  await api('scans/run', 'POST', { target, cookie });
}

// Finding actions
async function updateFinding(id, status) {
  await api('findings/' + id + '/status', 'POST', { status });
  showAlert('Finding #' + id + ' marked as ' + status);
  setTimeout(() => location.reload(), 800);
}

async function deleteFinding(id) {
  if (!confirm('Delete this finding?')) return;
  await api('findings/' + id, 'DELETE');
  location.reload();
}

async function addFinding() {
  const data = {
    scan_id:        document.getElementById('f-scan').value,
    severity:       document.getElementById('f-sev').value,
    title:          document.getElementById('f-title').value,
    tool:           document.getElementById('f-tool').value,
    target:         document.getElementById('f-target').value,
    detail:         document.getElementById('f-detail').value,
    recommendation: document.getElementById('f-rec').value,
  };
  if (!data.title || !data.scan_id) { alert('Title and scan required'); return; }
  await api('findings', 'POST', data);
  closeModal('modal-finding');
  location.reload();
}

// Workspace actions
async function createWorkspace() {
  const data = {
    name:   document.getElementById('ws-name').value.trim().toLowerCase().replace(/ /g,'-'),
    client: document.getElementById('ws-client').value.trim(),
    domain: document.getElementById('ws-domain').value.trim(),
  };
  if (!data.name) { alert('Name required'); return; }
  await api('workspaces', 'POST', data);
  closeModal('modal-workspace');
  location.reload();
}

async function switchWorkspace(name) {
  await api('workspaces/switch', 'POST', { name });
  showAlert('Switched to workspace: ' + name);
  setTimeout(() => location.reload(), 800);
}

async function deleteWorkspace(name) {
  if (!confirm('Delete workspace ' + name + '?')) return;
  await api('workspaces/' + name, 'DELETE');
  location.reload();
}

// Filter findings
function filterFindings() {
  const rows = document.querySelectorAll('#findings-table tr.finding-row');
  const search = document.getElementById('search-findings')?.value.toLowerCase() || '';
  const sev = document.getElementById('filter-sev')?.value || '';
  const status = document.getElementById('filter-status')?.value || '';
  rows.forEach(row => {
    const text = row.textContent.toLowerCase();
    const rowSev = row.dataset.sev || '';
    const rowStatus = row.dataset.status || '';
    const show = (!search || text.includes(search)) &&
                 (!sev || rowSev === sev) &&
                 (!status || rowStatus === status);
    row.style.display = show ? '' : 'none';
  });
}

// Export
function exportFindings() {
  window.open('/api/findings/export', '_blank');
}

// Auto-refresh badge counts
async function refreshCounts() {
  const stats = await api('stats');
  document.getElementById('badge-findings').textContent = stats.total_findings;
  document.getElementById('badge-scans').textContent = stats.total_scans;
}

window.onload = () => {
  nav('dashboard');
  setInterval(refreshCounts, 15000);
};
"""

def render_sev(s):
    return f'<span class="sev sev-{s}">{s}</span>'

def render_status(s):
    return f'<span class="status-{s}">{s.upper()}</span>'

def build_page(stats, scans, findings, workspaces, active_ws):

    # Stats
    stats_html = f"""
    <div class="stats-grid">
      <div class="stat"><div class="stat-val">{stats['total_scans']}</div><div class="stat-lbl">Total Scans</div></div>
      <div class="stat"><div class="stat-val g">{stats['complete']}</div><div class="stat-lbl">Complete</div></div>
      <div class="stat"><div class="stat-val">{stats['total_findings']}</div><div class="stat-lbl">Findings</div></div>
      <div class="stat"><div class="stat-val">{stats['critical']}</div><div class="stat-lbl">Critical</div></div>
      <div class="stat"><div class="stat-val o">{stats['high']}</div><div class="stat-lbl">High</div></div>
    </div>"""

    # Scans table
    scans_rows = ""
    for s in scans:
        date  = (s["started_at"] or "")[:16].replace("T"," ")
        badge = f'<span style="color:{"#cc1111" if s["findings"]>0 else "#1a9b1a"};font-weight:700">{s["findings"]}</span>'
        note  = f'<span class="tag">{s["notes"][:30]}</span>' if s["notes"] else ""
        scans_rows += f"""
        <tr>
          <td style="color:#96ccff">#{s['id']}</td>
          <td style="color:#fff">{s['target']}</td>
          <td style="color:#555">{date}</td>
          <td><span class="tag">{s['status']}</span></td>
          <td>{badge}</td>
          <td>{note}</td>
          <td>
            <button class="btn btn-ghost btn-sm" onclick="addNote({s['id']})">note</button>
            <button class="btn btn-ghost btn-sm" style="margin-left:4px" onclick="deleteScan({s['id']})">delete</button>
            <a href="/api/scans/{s['id']}/report" class="btn btn-ghost btn-sm" style="margin-left:4px">report</a>
          </td>
        </tr>"""

    # Findings table
    findings_rows = ""
    for f in findings:
        findings_rows += f"""
        <tr class="finding-row" data-sev="{f['severity']}" data-status="{f['status']}">
          <td>{render_sev(f['severity'])}</td>
          <td style="color:#96ccff;font-size:11px">{f['tool']}</td>
          <td style="color:#fff">{f['title'][:65]}</td>
          <td style="color:#555;font-size:11px">{(f['target'] or '')[:30]}</td>
          <td>{render_status(f['status'])}</td>
          <td>
            <select onchange="updateFinding({f['id']},this.value)" style="background:#161616;border:1px solid #2a2a2a;color:#888;padding:2px 6px;border-radius:4px;font-size:11px;font-family:inherit">
              <option value="">action</option>
              <option value="open">mark open</option>
              <option value="fixed">mark fixed</option>
              <option value="wontfix">wont fix</option>
            </select>
            <button class="btn btn-ghost btn-sm" style="margin-left:4px" onclick="deleteFinding({f['id']})">del</button>
          </td>
        </tr>"""

    # Workspaces table
    ws_rows = ""
    for ws in workspaces:
        active_mark = '<span style="color:#1a9b1a;font-weight:700">● ACTIVE</span>' if ws["name"] == active_ws else ""
        ws_rows += f"""
        <tr>
          <td style="color:#96ccff">{ws['name']}</td>
          <td style="color:#fff">{ws.get('client','')}</td>
          <td style="color:#555">{ws.get('domain','')}</td>
          <td style="color:#555">{ws.get('created_at','')[:10]}</td>
          <td>{active_mark}</td>
          <td>
            <button class="btn btn-ghost btn-sm" onclick="switchWorkspace('{ws['name']}')">switch</button>
            <button class="btn btn-ghost btn-sm" style="margin-left:4px" onclick="deleteWorkspace('{ws['name']}')">delete</button>
          </td>
        </tr>"""

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><title>STRYKER Dashboard</title>
<style>{CSS}</style>
</head><body>

<div class="topbar">
  <span class="logo">▲ STRYKER</span>
  <nav class="nav">
    <a onclick="nav('dashboard')">Dashboard</a>
    <a onclick="nav('scans')">Scans <span class="badge" id="badge-scans">{stats['total_scans']}</span></a>
    <a onclick="nav('findings')">Findings <span class="badge" id="badge-findings">{stats['total_findings']}</span></a>
    <a onclick="nav('workspaces')">Workspaces</a>
    <a onclick="nav('tools')">Run Tools</a>
  </nav>
  <div class="spacer"></div>
  <span style="color:#333;font-size:10px">{now} &bull; workspace: <span style="color:#96ccff">{active_ws}</span></span>
</div>

<!-- DASHBOARD PAGE -->
<div class="page active" id="page-dashboard">
  <div class="content">
    <div id="alert" class="alert"></div>
    {stats_html}
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
      <div class="card">
        <div class="card-title">Recent Scans</div>
        <table><thead><tr><th>ID</th><th>TARGET</th><th>DATE</th><th>FINDINGS</th></tr></thead><tbody>
        {"".join(f'<tr><td style="color:#96ccff">#{s["id"]}</td><td style="color:#fff">{s["target"]}</td><td style="color:#555">{(s["started_at"] or "")[:10]}</td><td style="color:{"#cc1111" if s["findings"]>0 else "#1a9b1a"}">{s["findings"]}</td></tr>' for s in scans[:6])}
        </tbody></table>
      </div>
      <div class="card">
        <div class="card-title">Top Findings</div>
        <table><thead><tr><th>SEV</th><th>FINDING</th></tr></thead><tbody>
        {"".join(f'<tr><td>{render_sev(f["severity"])}</td><td style="color:#fff;font-size:11px">{f["title"][:55]}</td></tr>' for f in findings[:8])}
        </tbody></table>
      </div>
    </div>
  </div>
</div>

<!-- SCANS PAGE -->
<div class="page" id="page-scans">
  <div class="toolbar">
    <button class="btn btn-red" onclick="openModal('modal-scan')">+ New Scan</button>
    <div class="spacer"></div>
    <span style="color:#555;font-size:11px">{len(scans)} scan(s) total</span>
  </div>
  <div class="content">
    <table>
      <thead><tr><th>ID</th><th>TARGET</th><th>DATE</th><th>STATUS</th><th>FINDINGS</th><th>NOTE</th><th>ACTIONS</th></tr></thead>
      <tbody>{scans_rows if scans_rows else '<tr><td colspan="7" style="text-align:center;color:#333;padding:40px">No scans yet. Click + New Scan to start.</td></tr>'}</tbody>
    </table>
  </div>
</div>

<!-- FINDINGS PAGE -->
<div class="page" id="page-findings">
  <div class="toolbar">
    <input id="search-findings" placeholder="Search findings..." oninput="filterFindings()" style="width:200px">
    <select id="filter-sev" onchange="filterFindings()">
      <option value="">All severities</option>
      <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option>
    </select>
    <select id="filter-status" onchange="filterFindings()">
      <option value="">All statuses</option>
      <option>open</option><option>fixed</option><option>wontfix</option>
    </select>
    <div class="spacer"></div>
    <button class="btn btn-ghost" onclick="exportFindings()">Export JSON</button>
    <button class="btn btn-red" onclick="openModal('modal-finding')">+ Add Finding</button>
  </div>
  <div class="content">
    <table>
      <thead><tr><th>SEVERITY</th><th>TOOL</th><th>FINDING</th><th>TARGET</th><th>STATUS</th><th>ACTIONS</th></tr></thead>
      <tbody id="findings-table">{findings_rows if findings_rows else '<tr><td colspan="6" style="text-align:center;color:#333;padding:40px">No findings yet.</td></tr>'}</tbody>
    </table>
  </div>
</div>

<!-- WORKSPACES PAGE -->
<div class="page" id="page-workspaces">
  <div class="toolbar">
    <button class="btn btn-red" onclick="openModal('modal-workspace')">+ New Workspace</button>
    <div class="spacer"></div>
    <span style="color:#555;font-size:11px">Active: <span style="color:#96ccff">{active_ws}</span></span>
  </div>
  <div class="content">
    <table>
      <thead><tr><th>NAME</th><th>CLIENT</th><th>DOMAIN</th><th>CREATED</th><th>ACTIVE</th><th>ACTIONS</th></tr></thead>
      <tbody>{ws_rows if ws_rows else '<tr><td colspan="6" style="text-align:center;color:#333;padding:40px">No workspaces. Create one to organise clients.</td></tr>'}</tbody>
    </table>
  </div>
</div>

<!-- TOOLS PAGE -->
<div class="page" id="page-tools">
  <div class="content">
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px">
      {"".join(f'''<div class="card" style="cursor:pointer" onclick="document.getElementById('scan-target').value='';openModal('modal-scan')">
        <div class="card-title">{name}</div>
        <div style="color:#555;font-size:11px">{desc}</div>
        <div style="margin-top:10px"><span class="badge green">READY</span></div>
      </div>''' for name,desc in [
          ("SQLi Detector","SQL injection — error, boolean, time-based"),
          ("NoSQL Injector","MongoDB, Firebase, CouchDB"),
          ("XSS Scanner","Reflected, DOM, forms, headers"),
          ("Firebase Auditor","Firestore, RTDB, Storage, Auth"),
          ("JWT Analyzer","Algorithm, expiry, weak secrets"),
          ("Subdomain Enum","DNS brute-force + crt.sh"),
          ("Port Scanner","TCP, banner grab, risk rating"),
          ("Secrets Scanner","GitHub, URLs, local files"),
          ("CORS Exploiter","Arbitrary origin, wildcard, PoC"),
          ("Session Hijacker","Cookie flags, token reuse, logout"),
          ("Privesc Checker","Admin access, IDOR, bypass"),
          ("Autopilot","Full automated pipeline"),
      ])}
    </div>
    <div class="card" style="margin-top:16px">
      <div class="card-title">Quick Scan</div>
      <div class="form-group"><label>Target URL or domain</label>
        <input id="quick-target" placeholder="https://example.com or example.com"></div>
      <button class="btn btn-red" onclick="document.getElementById('scan-target').value=document.getElementById('quick-target').value;openModal('modal-scan')">Launch Autopilot</button>
    </div>
  </div>
</div>

<!-- MODAL: New Scan -->
<div class="modal-overlay" id="modal-scan">
  <div class="modal">
    <div class="modal-title">New Scan</div>
    <div class="form-group"><label>Target URL or domain</label>
      <input id="scan-target" placeholder="https://example.com or example.com"></div>
    <div class="form-group"><label>Session Cookie (optional)</label>
      <input id="scan-cookie" placeholder="session=abc123"></div>
    <div class="form-group"><label>Firebase Project ID (optional)</label>
      <input id="scan-firebase" placeholder="my-project-12345"></div>
    <div class="form-group"><label>Client Name (for report)</label>
      <input id="scan-client" placeholder="Acme Corp"></div>
    <div class="modal-footer">
      <button class="btn btn-ghost" onclick="closeModal('modal-scan')">Cancel</button>
      <button class="btn btn-red" onclick="runScan()">Launch Scan</button>
    </div>
  </div>
</div>

<!-- MODAL: Add Finding -->
<div class="modal-overlay" id="modal-finding">
  <div class="modal">
    <div class="modal-title">Add Finding</div>
    <div class="form-group"><label>Scan</label>
      <select id="f-scan">{"".join(f'<option value="{s["id"]}">#{s["id"]} {s["target"]}</option>' for s in scans)}</select></div>
    <div class="form-group"><label>Severity</label>
      <select id="f-sev"><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option></select></div>
    <div class="form-group"><label>Title</label><input id="f-title" placeholder="Short description of the finding"></div>
    <div class="form-group"><label>Tool</label><input id="f-tool" placeholder="e.g. XSS Scanner"></div>
    <div class="form-group"><label>Target URL</label><input id="f-target" placeholder="https://..."></div>
    <div class="form-group"><label>Detail / Evidence</label><textarea id="f-detail" placeholder="What was found..."></textarea></div>
    <div class="form-group"><label>Recommendation</label><textarea id="f-rec" placeholder="How to fix..."></textarea></div>
    <div class="modal-footer">
      <button class="btn btn-ghost" onclick="closeModal('modal-finding')">Cancel</button>
      <button class="btn btn-red" onclick="addFinding()">Add Finding</button>
    </div>
  </div>
</div>

<!-- MODAL: New Workspace -->
<div class="modal-overlay" id="modal-workspace">
  <div class="modal">
    <div class="modal-title">New Workspace</div>
    <div class="form-group"><label>Workspace Name (no spaces)</label>
      <input id="ws-name" placeholder="prymebay-audit"></div>
    <div class="form-group"><label>Client Name</label>
      <input id="ws-client" placeholder="PrymeBay Ghana"></div>
    <div class="form-group"><label>Primary Domain</label>
      <input id="ws-domain" placeholder="prymebay.com"></div>
    <div class="modal-footer">
      <button class="btn btn-ghost" onclick="closeModal('modal-workspace')">Cancel</button>
      <button class="btn btn-red" onclick="createWorkspace()">Create</button>
    </div>
  </div>
</div>

<script>{JS}</script>
</body></html>"""


# ── API Handler ────────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def send_json(self, data, status=200):
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html):
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type","text/html;charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path

        if path == "/api/stats":
            rows = q("SELECT COUNT(*) FROM scans")[0][0]
            comp = q("SELECT COUNT(*) FROM scans WHERE status='complete'")[0][0]
            find = q("SELECT COUNT(*) FROM findings")[0][0]
            crit = q("SELECT COUNT(*) FROM findings WHERE severity='CRITICAL'")[0][0]
            high = q("SELECT COUNT(*) FROM findings WHERE severity='HIGH'")[0][0]
            return self.send_json({"total_scans":rows,"complete":comp,"total_findings":find,"critical":crit,"high":high})

        if path == "/api/scans":
            rows = q("SELECT id,target,started_at,status,findings,notes FROM scans ORDER BY id DESC LIMIT 30")
            return self.send_json([dict(r) for r in rows])

        if path.startswith("/api/scans/") and path.endswith("/report"):
            sid = path.split("/")[3]
            finds = q("SELECT tool,severity,title,target,detail FROM findings WHERE scan_id=?", (sid,))
            data  = [{"severity":r[1],"title":r[2],"tool":r[0],"target":r[3],"description":r[4],"payload":"","evidence":r[4],"recommendation":""} for r in finds]
            body  = json.dumps(data, indent=2).encode()
            self.send_response(200)
            self.send_header("Content-Type","application/json")
            self.send_header("Content-Disposition",f"attachment;filename=findings_scan_{sid}.json")
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/api/findings":
            rows = q("""SELECT f.id,f.tool,f.severity,f.title,f.target,f.detail,f.status,f.recommendation,s.target
                        FROM findings f JOIN scans s ON f.scan_id=s.id
                        ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                        WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END LIMIT 200""")
            return self.send_json([dict(r) for r in rows])

        if path == "/api/findings/export":
            rows = q("""SELECT f.severity,f.title,f.tool,f.target,f.detail,f.recommendation,s.target as scan_target
                        FROM findings f JOIN scans s ON f.scan_id=s.id ORDER BY f.id""")
            data = [{"severity":r[0],"title":r[1],"tool":r[2],"target":r[3],"description":r[4],"recommendation":r[5],"scan_target":r[6]} for r in rows]
            body = json.dumps(data, indent=2).encode()
            self.send_response(200)
            self.send_header("Content-Type","application/json")
            self.send_header("Content-Disposition","attachment;filename=stryker_findings.json")
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/api/workspaces":
            wss = []
            if WORKSPACES_DIR.exists():
                for ws_path in sorted(WORKSPACES_DIR.iterdir()):
                    cfg_file = ws_path / "config.json"
                    if cfg_file.exists():
                        try: cfg = json.loads(cfg_file.read_text())
                        except: cfg = {}
                        wss.append(cfg)
            return self.send_json(wss)

        # Main dashboard
        ensure_db()
        stats     = {}
        scans_raw = q("SELECT id,target,started_at,status,findings,notes FROM scans ORDER BY id DESC LIMIT 30") or []
        finds_raw = q("""SELECT f.id,f.tool,f.severity,f.title,f.target,f.detail,f.status,f.recommendation,s.target
                         FROM findings f JOIN scans s ON f.scan_id=s.id
                         ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                         WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END LIMIT 200""") or []

        total_scans = q("SELECT COUNT(*) FROM scans")[0][0]
        complete    = q("SELECT COUNT(*) FROM scans WHERE status='complete'")[0][0]
        total_finds = q("SELECT COUNT(*) FROM findings")[0][0]
        critical    = q("SELECT COUNT(*) FROM findings WHERE severity='CRITICAL'")[0][0]
        high        = q("SELECT COUNT(*) FROM findings WHERE severity='HIGH'")[0][0]

        stats     = {"total_scans":total_scans,"complete":complete,"total_findings":total_finds,"critical":critical,"high":high}
        scans     = [dict(r) for r in scans_raw]
        findings  = [dict(r) for r in finds_raw]

        wss = []
        if WORKSPACES_DIR.exists():
            for ws_path in sorted(WORKSPACES_DIR.iterdir()):
                cfg_file = ws_path / "config.json"
                if cfg_file.exists():
                    try: wss.append(json.loads(cfg_file.read_text()))
                    except: pass

        active_ws = Path(".active_workspace").read_text().strip() if Path(".active_workspace").exists() else "default"
        self.send_html(build_page(stats, scans, findings, wss, active_ws))

    def do_POST(self):
        path = urlparse(self.path).path
        body = self.read_body()

        if path == "/api/scans/run":
            target = body.get("target","")
            cookie = body.get("cookie","")
            client = body.get("client","")
            firebase = body.get("firebase","")
            if target:
                def run():
                    cmd = [sys.executable, "autopilot.py"]
                    env = os.environ.copy()
                    env["STRYKER_TARGET"]   = target
                    env["STRYKER_COOKIE"]   = cookie
                    env["STRYKER_CLIENT"]   = client
                    env["STRYKER_FIREBASE"] = firebase
                    subprocess.Popen(cmd, env=env)
                threading.Thread(target=run, daemon=True).start()
            return self.send_json({"ok": True})

        if path.startswith("/api/scans/") and path.endswith("/note"):
            sid  = path.split("/")[3]
            note = body.get("note","")
            qw("UPDATE scans SET notes=? WHERE id=?", (note, sid))
            return self.send_json({"ok": True})

        if path.startswith("/api/findings/") and path.endswith("/status"):
            fid    = path.split("/")[3]
            status = body.get("status","open")
            qw("UPDATE findings SET status=? WHERE id=?", (status, fid))
            return self.send_json({"ok": True})

        if path == "/api/findings":
            qw("""INSERT INTO findings (scan_id,tool,severity,title,target,detail,recommendation,status,created_at)
                  VALUES (?,?,?,?,?,?,?,'open',?)""",
               (body.get("scan_id"),body.get("tool","Manual"),body.get("severity","INFO"),
                body.get("title"),body.get("target",""),body.get("detail",""),
                body.get("recommendation",""),datetime.now().isoformat()))
            return self.send_json({"ok": True})

        if path == "/api/workspaces":
            name   = body.get("name","")
            client = body.get("client","")
            domain = body.get("domain","")
            if name:
                ws_path = WORKSPACES_DIR / name
                ws_path.mkdir(parents=True, exist_ok=True)
                (ws_path/"scans").mkdir(exist_ok=True)
                (ws_path/"reports").mkdir(exist_ok=True)
                cfg = {"name":name,"client":client,"domain":domain,"created_at":datetime.now().isoformat()}
                (ws_path/"config.json").write_text(json.dumps(cfg,indent=2))
                conn = sqlite3.connect(ws_path/"workspace.db")
                conn.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, content TEXT, created_at TEXT)")
                conn.commit(); conn.close()
            return self.send_json({"ok": True})

        if path == "/api/workspaces/switch":
            name = body.get("name","default")
            Path(".active_workspace").write_text(name)
            return self.send_json({"ok": True})

        return self.send_json({"ok": False}, 404)

    def do_DELETE(self):
        path = urlparse(self.path).path

        if path.startswith("/api/scans/"):
            sid = path.split("/")[3]
            qw("DELETE FROM findings WHERE scan_id=?", (sid,))
            qw("DELETE FROM scans WHERE id=?", (sid,))
            return self.send_json({"ok": True})

        if path.startswith("/api/findings/"):
            fid = path.split("/")[3]
            qw("DELETE FROM findings WHERE id=?", (fid,))
            return self.send_json({"ok": True})

        if path.startswith("/api/workspaces/"):
            name = path.split("/")[3]
            ws_path = WORKSPACES_DIR / name
            if ws_path.exists():
                shutil.rmtree(ws_path)
            if Path(".active_workspace").exists():
                if Path(".active_workspace").read_text().strip() == name:
                    Path(".active_workspace").write_text("default")
            return self.send_json({"ok": True})

        return self.send_json({"ok": False}, 404)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    port = 7474
    ensure_db()

    os.system("cls" if os.name == "nt" else "clear")
    p(); p(f"{BOLD}{RED} ▲ STRYKER DASHBOARD{RST}")
    p(f"{DIM}   Full Management Interface  |  by Andrews{RST}"); p()
    p(f"  {DIM}URL:{RST}      {CYAN}http://127.0.0.1:{port}{RST}")
    p(f"  {DIM}Features:{RST} Scans, Findings, Workspaces, Tools, Export")
    p(f"  {DIM}Auto-opens browser in 1 second...{RST}"); p()
    p(f"  {DIM}Press Ctrl+C to stop.{RST}"); p()

    server = HTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=lambda: (time.sleep(1.2), webbrowser.open(f"http://127.0.0.1:{port}")), daemon=True).start()

    try:    server.serve_forever()
    except KeyboardInterrupt:
        p(f"\n  {RED}Dashboard stopped.{RST}\n")
        server.shutdown()

if __name__ == "__main__":
    main()