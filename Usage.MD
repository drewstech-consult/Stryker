# STRYKER Usage Guide

## Installation

```bash
git clone https://github.com/drewstech-consult/stryker.git
cd stryker
pip install -r requirements.txt
python stryker.py
```

---

## Console Commands

```
modules          List all tools
use <id>         Launch a tool interactively
info <id>        Show tool details
clear            Clear the screen
banner           Show the banner again
exit             Exit STRYKER
```

---

## Complete Pentest Workflow

Use STRYKER to run a full engagement from start to finish.

### Phase 1 — Recon

Discover the attack surface before touching anything.

```
stryker@andrews > use 6
Domain  > target.com
crt.sh  > y
Output  > subs.txt
```

What to look for in results:

- `dev.` / `staging.` / `test.` — often less secure than production
- `api.` — API endpoints may have weaker auth
- `admin.` — admin panels
- `old.` / `backup.` — outdated servers with unpatched vulnerabilities

---

### Phase 2 — Port Scanning

Scan discovered subdomains for open ports.

```
stryker@andrews > use 7
Host    > api.target.com
Ports   > common
Threads > 50
Output  > ports.txt
```

**Critical ports to investigate immediately:**

| Port  | Service       | Risk                 |
| ----- | ------------- | -------------------- |
| 27017 | MongoDB       | No auth by default   |
| 6379  | Redis         | No auth by default   |
| 9200  | Elasticsearch | No auth by default   |
| 2375  | Docker        | Full server takeover |
| 3306  | MySQL         | Database exposed     |
| 5432  | PostgreSQL    | Database exposed     |
| 22    | SSH           | Brute force target   |
| 3389  | RDP           | Brute force target   |

---

### Phase 3 — Web Vulnerability Scanning

**SQL injection:**

```
stryker@andrews > use 1
URL     > https://target.com/products?id=1
Checks  > all
Output  > sqli.txt
```

**NoSQL injection (MongoDB / Firebase apps):**

```
stryker@andrews > use 2
URL     > https://target.com/api/users?id=1
Checks  > all
```

**XSS:**

```
stryker@andrews > use 3
URL     > https://target.com/search?q=test
Checks  > all
Output  > xss.txt
```

---

### Phase 4 — Auth & Config Auditing

**Firebase audit** (get project ID from Firebase Console → Project Settings):

```
stryker@andrews > use 4
Project > ghana-ecommerce-7f741
Checks  > all
Output  > firebase.txt
```

**JWT analysis** (get token from DevTools → Application → Cookies):

```
stryker@andrews > use 5
Token   > eyJhbGciOiJSUzI1NiIs...
Checks  > all
```

---

### Phase 5 — Post-Exploitation

Run these after finding vulnerabilities to prove real-world impact.

**Secrets scanner:**

```
stryker@andrews > use 9
Mode    > 2  (website)
URL     > https://target.com
```

**CORS exploiter:**

```
stryker@andrews > use 10
URL       > https://target.com
Endpoints > y
PoC       > y
```

**Session testing:**

```
stryker@andrews > use 11
Mode        > 2
URL         > https://target.com
Token       > eyJhbGci...
Token type  > bearer
Logout path > /api/auth/signout
```

**Privilege escalation:**

```
stryker@andrews > use 12
URL      > https://target.com
Token    > eyJhbGci...
User ID  > 42
```

---

### Phase 6 — Reporting

Compile all findings into a JSON file, then generate the PDF.

**findings.json:**

```json
[
  {
    "severity": "CRITICAL",
    "title": "MongoDB exposed without authentication",
    "tool": "Port Scanner",
    "target": "192.168.1.10:27017",
    "description": "MongoDB is accessible from the internet without authentication.",
    "payload": "mongo 192.168.1.10 --port 27017",
    "evidence": "Connected to MongoDB shell without credentials.",
    "recommendation": "Bind MongoDB to localhost. Enable authentication. Block port 27017."
  },
  {
    "severity": "HIGH",
    "title": "Reflected XSS in search parameter",
    "tool": "XSS Scanner",
    "target": "https://site.com/search?q=",
    "description": "The q parameter reflects user input without HTML encoding.",
    "payload": "<script>alert(1)</script>",
    "evidence": "Script tag reflected in HTTP response body.",
    "recommendation": "Encode all user input. Add Content-Security-Policy header."
  }
]
```

**Generate the report:**

```
stryker@andrews > use 8
Target  > Client Company Name
File    > findings.json
Output  > client_report.pdf
```

---

## Authenticated Scanning

Most interesting findings require authentication. Here's how to pass credentials.

**Get your session cookie:**

1. Log into the target app in Chrome
2. Press F12 → Application tab → Cookies
3. Copy the session/auth cookie value

**Pass cookie to any tool:**

```bash
python web/xss_scanner.py -u "https://site.com/profile" -c "session=eyJhbGci..."
```

**Pass Bearer token:**

```bash
python web/jwt_analyzer.py -t "eyJhbGci..." -u "https://api.site.com/user"
python web/sqli_detector.py -u "https://site.com/api?id=1" -H "Authorization: Bearer eyJ..."
```

---

## Port Sets

| Set        | What it scans                                    |
| ---------- | ------------------------------------------------ |
| `common`   | 50 well-known ports (default)                    |
| `web`      | HTTP/HTTPS ports only                            |
| `database` | MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch |
| `dev`      | Common dev server ports: 3000, 4200, 5000, 8080  |
| `top100`   | All ports 1-1024                                 |
| Custom     | `80,443,3306,27017` comma-separated              |

---

## Secrets Scanner Patterns

The secrets scanner detects 30+ pattern types:

| Category          | What it finds                              |
| ----------------- | ------------------------------------------ |
| Firebase          | API keys, service account JSON, DB URLs    |
| AWS               | Access keys, secret keys                   |
| Stripe / Paystack | Live and test API keys                     |
| GitHub            | Personal access tokens                     |
| Passwords         | Hardcoded passwords, DB connection strings |
| Private keys      | RSA, EC, PGP private keys                  |
| JWT               | Weak secrets, exposed tokens               |
| Env files         | `.env`, `.env.local`, `.env.production`    |
| Next.js           | `NEXT_PUBLIC_` variables                   |

---

## CORS Severity Guide

| Finding                         | Severity | Impact                                 |
| ------------------------------- | -------- | -------------------------------------- |
| Arbitrary origin + credentials  | CRITICAL | Can steal authenticated user data      |
| Wildcard `*` + credentials      | CRITICAL | Browsers block but server is broken    |
| Arbitrary origin no credentials | HIGH     | Can read public responses cross-origin |
| Wildcard `*` no credentials     | HIGH     | Any site can read your responses       |
| Null origin accepted            | MEDIUM   | Exploitable via sandboxed iframes      |

---

## Privilege Escalation Types

| Check             | What it tests                                                 |
| ----------------- | ------------------------------------------------------------- |
| Admin access      | 30+ admin panel URLs — `/admin`, `/api/admin` etc.            |
| IDOR              | Your ID ±1,2 and common IDs 1,2,3 — can you read other users? |
| Role manipulation | Mass assignment via PATCH, JWT role claim tampering           |
| Header bypass     | `X-Forwarded-For: 127.0.0.1`, `X-Original-URL: /admin`        |

---

## Saving and Combining Output

All tools support `-o filename` to save results:

```bash
python web/xss_scanner.py -u "https://site.com" -o xss_results.txt
python recon/subdomain_enum.py -d site.com -o subdomains.txt
python scanning/port_scanner.py -t site.com -o ports.txt
python post_exploit/secrets_scanner.py -u https://site.com -o secrets.txt
```

Compile all findings into one JSON, then generate a single PDF report.

---

## Troubleshooting

**`ModuleNotFoundError`**

```bash
pip install -r requirements.txt
```

**No output in Git Bash desktop**

```bash
winpty python stryker.py
```

Or use VS Code's integrated terminal.

**SSL certificate errors**
All tools use `verify=False` — self-signed certs handled automatically.

**Slow subdomain scan**

```bash
python recon/subdomain_enum.py -d example.com -t 100 --no-http
```

**GitHub API rate limit (secrets scanner)**

```bash
python post_exploit/secrets_scanner.py -r https://github.com/user/repo -g YOUR_TOKEN
```

Generate token at github.com/settings/tokens — check `repo` scope.

**Firebase project not found**
Find your project ID at Firebase Console → Project Settings → General → Project ID.
It looks like `my-app-12345` not `My App`.

---

## Practice Environment Setup

**DVWA (Damn Vulnerable Web App) on Windows:**

1. Download XAMPP from [apachefriends.org](https://apachefriends.org)
2. Download DVWA from [github.com/digininja/DVWA](https://github.com/digininja/DVWA)
3. Extract DVWA to `C:\xampp\htdocs\dvwa`
4. Start XAMPP → Start Apache + MySQL
5. Visit `http://localhost/dvwa/setup.php` → Create Database
6. Login: `admin` / `password` → Set Security to Low

**Test STRYKER against DVWA:**

```bash
python web/sqli_detector.py \
  -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  -c "PHPSESSID=YOUR_SESSION;security=low" \
  --checks all
```
