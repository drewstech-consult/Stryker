# STRYKER Usage Guide

## Getting Started

### Install

```bash
git clone https://github.com/drewstech-consult/stryker.git
cd stryker
pip install -r requirements.txt
```

### Launch

```bash
python stryker.py
```

You'll see the STRYKER banner load and drop into the console:

```
stryker@andrews >
```

---

## Console Commands

| Command     | What it does                |
| ----------- | --------------------------- |
| `modules`   | List all tools with status  |
| `use <id>`  | Launch a tool interactively |
| `info <id>` | Show details about a tool   |
| `clear`     | Clear the screen            |
| `banner`    | Redisplay the banner        |
| `exit`      | Exit STRYKER                |

---

## Running a Full Pentest with STRYKER

Here is a complete workflow from recon to report.

### Phase 1 — Recon

**Find subdomains:**

```
stryker@andrews > use 6
Domain  > target.com
crt.sh  > y
```

**Scan ports on found subdomains:**

```
stryker@andrews > use 7
Host    > api.target.com
Ports   > common
```

### Phase 2 — Web Vulnerability Scanning

**SQL injection:**

```
stryker@andrews > use 1
URL     > https://target.com/page?id=1
Checks  > all
```

**NoSQL injection (MongoDB/Firebase apps):**

```
stryker@andrews > use 2
URL     > https://target.com/api/users?id=1
Checks  > all
```

**XSS scanning:**

```
stryker@andrews > use 3
URL     > https://target.com/search?q=test
Checks  > all
```

### Phase 3 — Authentication & Config

**Firebase audit:**

```
stryker@andrews > use 4
Project > my-firebase-project-id
Checks  > all
```

**JWT token analysis:**

```
stryker@andrews > use 5
Token   > eyJhbGciOiJSUzI1NiIs...
Checks  > all
```

### Phase 4 — Reporting

**Generate PDF report:**

```
stryker@andrews > use 8
Target  > Client Name
File    > findings.json   (or press Enter for sample)
Output  > client_report.pdf
```

---

## Findings JSON Format

To generate a proper report from your scan results, save findings in this format:

```json
[
  {
    "severity": "CRITICAL",
    "title": "MongoDB exposed without authentication",
    "tool": "Port Scanner + NoSQL Injector",
    "target": "192.168.1.10:27017",
    "description": "MongoDB instance is accessible from the internet without authentication. Full database read and write access is possible.",
    "payload": "mongo 192.168.1.10 --port 27017",
    "evidence": "Connected to MongoDB shell without credentials. Found 3 databases.",
    "recommendation": "Bind MongoDB to localhost only. Enable authentication. Use a firewall to block port 27017 from public internet."
  },
  {
    "severity": "HIGH",
    "title": "Reflected XSS in search parameter",
    "tool": "XSS Scanner",
    "target": "https://site.com/search?q=",
    "description": "The q parameter reflects user input without HTML encoding.",
    "payload": "<script>alert(1)</script>",
    "evidence": "Script tag reflected in HTTP response body",
    "recommendation": "HTML-encode all user input before rendering. Add Content-Security-Policy header."
  }
]
```

Severity values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`

---

## Authenticated Scanning

For pages that require login, pass your session cookie or auth header:

```bash
# With cookie
python web/sqli_detector.py -u "https://site.com/profile?id=1" -c "session=abc123"

# With Bearer token
python web/xss_scanner.py -u "https://site.com/dashboard" -H "Authorization: Bearer eyJ..."

# With multiple headers
python web/nosql_injector.py -u "https://site.com/api?id=1" \
  -H "Authorization: Bearer eyJ..." \
  -H "X-API-Key: secret123"
```

**How to get your session cookie:**

1. Log into the target app in Chrome
2. Press F12 → Application tab → Cookies
3. Copy the session cookie value

---

## Port Sets Reference

| Set        | Ports included                                        |
| ---------- | ----------------------------------------------------- |
| `common`   | 50 well-known ports (default)                         |
| `web`      | 80, 443, 8000, 8080, 8443 and HTTP variants           |
| `database` | MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch etc. |
| `dev`      | Common dev server ports: 3000, 4200, 5000, 8080, 9000 |
| `top100`   | All ports 1–1024                                      |
| Custom     | `80,443,3306,27017` — comma separated                 |

---

## Risk Ratings (Port Scanner)

| Rating   | Meaning                               | Examples                                      |
| -------- | ------------------------------------- | --------------------------------------------- |
| CRITICAL | Immediate danger — likely exploitable | MongoDB no-auth, Redis exposed, Docker daemon |
| HIGH     | Serious risk — restrict immediately   | RDP open, MySQL exposed, SMB                  |
| MEDIUM   | Worth investigating                   | SSH, SMTP, VNC                                |
| LOW      | Informational                         | HTTP alt ports                                |

---

## Safe Practice Environments

Use these legal targets to practice before testing real clients:

```bash
# SQL injection practice
python web/sqli_detector.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1" --checks all

# Local DVWA (after setup)
python web/sqli_detector.py -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  -c "PHPSESSID=YOUR_SESSION;security=low" --checks all

# HackTheBox / TryHackMe machines — use their VPN + machine IPs
python scanning/port_scanner.py -t 10.10.10.1 --ports top100
```

---

## Troubleshooting

**`ModuleNotFoundError`**

```bash
pip install -r requirements.txt
```

**`python` not found on Windows**

```bash
python3 stryker.py
```

**No output in Git Bash desktop**
The toolkit auto-detects Git Bash and relaunches via `winpty`. If this fails:

```bash
winpty python stryker.py
```

Or use VS Code's integrated terminal — it works perfectly.

**SSL certificate errors**
All tools have `verify=False` for HTTPS — self-signed certs are handled automatically.

**Slow subdomain enumeration**
Increase threads:

```bash
python recon/subdomain_enum.py -d example.com -t 100 --no-http
```

---

## Output Files

All tools support saving results with `-o filename`:

```bash
python web/xss_scanner.py -u "https://site.com" -o xss_results.txt
python recon/subdomain_enum.py -d site.com -o subdomains.txt
python scanning/port_scanner.py -t site.com -o ports.txt
```

Collect all output files then feed them into the report generator:

```bash
python reporting/report_generator.py -f all_findings.json -t "Client" -o final_report.pdf
```
