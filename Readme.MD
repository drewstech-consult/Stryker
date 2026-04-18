# STRYKER — Penetration Testing Framework

> A modular, Metasploit-style penetration testing toolkit built in Python.
> Built by Andrews Osei Agyemang | For authorized security testing only.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Tools](https://img.shields.io/badge/tools-12%20ready-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-red)

---

## Legal Notice

**This toolkit is for authorized penetration testing ONLY.**
Only use against systems you own or have explicit written permission to test.
Unauthorized use is illegal. See [LEGAL.md](./LEGAL.md) for full details.

---

## Overview

STRYKER is a complete penetration testing framework with an interactive
Metasploit-style terminal console and 12 ready-to-use security tools.
It covers the full pentest lifecycle — recon, scanning, exploitation,
post-exploitation and professional PDF reporting.

```bash
python stryker.py
```

```
          .                 .
       .node.             .node.
      (  o  )           (  o  )
   ____|___|_____________|___|____

 _____ _____________   ___   __ ___________
/  ___|_   _| ___ \ \ / / | / /|  ___| ___ \
...

  Penetration Testing Framework  |  by Andrews  |  v1.0.0

stryker@andrews >
```

---

## Tools

### Web (`/web`)

| ID  | Tool                  | Description                                     | Status |
| --- | --------------------- | ----------------------------------------------- | ------ |
| 1   | `sqli_detector.py`    | SQL injection — error, boolean, time-based      | Ready  |
| 2   | `nosql_injector.py`   | NoSQL injection — MongoDB, Firebase, CouchDB    | Ready  |
| 3   | `xss_scanner.py`      | XSS — reflected, DOM, forms, security headers   | Ready  |
| 4   | `firebase_auditor.py` | Firebase — Firestore, RTDB, Storage, Auth rules | Ready  |
| 5   | `jwt_analyzer.py`     | JWT — algorithm, expiry, weak secrets, endpoint | Ready  |

### Recon (`/recon`)

| ID  | Tool                | Description                                      | Status |
| --- | ------------------- | ------------------------------------------------ | ------ |
| 6   | `subdomain_enum.py` | Subdomain discovery via DNS brute-force + crt.sh | Ready  |

### Scanning (`/scanning`)

| ID  | Tool              | Description                                       | Status |
| --- | ----------------- | ------------------------------------------------- | ------ |
| 7   | `port_scanner.py` | Port scanner with banner grabbing and risk rating | Ready  |

### Reporting (`/reporting`)

| ID  | Tool                  | Description                      | Status |
| --- | --------------------- | -------------------------------- | ------ |
| 8   | `report_generator.py` | Professional PDF pentest reports | Ready  |

### Post-Exploitation (`/post_exploit`)

| ID  | Tool                  | Description                                            | Status |
| --- | --------------------- | ------------------------------------------------------ | ------ |
| 9   | `secrets_scanner.py`  | Find exposed API keys, .env files and credentials      | Ready  |
| 10  | `cors_exploiter.py`   | CORS misconfigurations with JavaScript PoC exploits    | Ready  |
| 11  | `session_hijacker.py` | Session token and cookie security testing              | Ready  |
| 12  | `privesc_checker.py`  | Privilege escalation — admin access, IDOR, role bypass | Ready  |

---

## Installation

**Requirements:** Python 3.10+

```bash
git clone https://github.com/drewstech-consult/stryker.git
cd stryker
pip install -r requirements.txt
```

---

## Quick Start

### Launch the console

```bash
python stryker.py
```

### Console commands

```
modules          List all 12 tools with status
use <id>         Launch a tool  (e.g. use 1)
info <id>        Show tool details
clear            Clear the screen
banner           Show the banner
exit             Exit STRYKER
```

### Run tools directly

```bash
python web/sqli_detector.py -u "https://site.com/page?id=1" --checks all
python web/nosql_injector.py -u "https://site.com/api/users?id=1"
python web/xss_scanner.py -u "https://site.com/search?q=test" --checks all
python web/firebase_auditor.py -p my-firebase-project-id
python web/jwt_analyzer.py -t "eyJhbGciOiJSUzI1NiIs..."
python recon/subdomain_enum.py -d example.com --crt
python scanning/port_scanner.py -t example.com --ports common
python reporting/report_generator.py -f findings.json -t "Client" -o report.pdf
python post_exploit/secrets_scanner.py -r https://github.com/user/repo
python post_exploit/cors_exploiter.py -u https://api.example.com --poc
python post_exploit/session_hijacker.py -u https://example.com --cookies-only
python post_exploit/privesc_checker.py -u https://example.com --checks all
```

---

## Tool Reference

### 1. SQLi Detector

Detects SQL injection vulnerabilities — error-based, boolean-based blind and time-based blind.

```bash
python web/sqli_detector.py -u "https://site.com/page?id=1"
python web/sqli_detector.py -u "https://site.com/page?id=1" --checks all
python web/sqli_detector.py -l urls.txt --checks error boolean -t 10
python web/sqli_detector.py -u "https://site.com/page?id=1" -c "session=abc" -o results.txt
```

| Flag       | Description                          |
| ---------- | ------------------------------------ |
| `-u`       | Target URL                           |
| `-l`       | File with list of URLs               |
| `--checks` | `error` / `boolean` / `time` / `all` |
| `-H`       | Custom header                        |
| `-c`       | Cookie                               |
| `-t`       | Threads (default: 5)                 |
| `-o`       | Output file                          |

---

### 2. NoSQL Injector

Tests MongoDB, Firebase and CouchDB applications for NoSQL injection.

```bash
python web/nosql_injector.py -u "https://site.com/api/users?id=1"
python web/nosql_injector.py -u "https://site.com/login" --checks post
python web/nosql_injector.py -u "https://project.firebaseio.com/users" --checks firebase
```

| Flag       | Description                         |
| ---------- | ----------------------------------- |
| `-u`       | Target URL                          |
| `--checks` | `get` / `post` / `firebase` / `all` |
| `-H`       | Custom header                       |
| `-c`       | Cookie                              |
| `-o`       | Output file                         |

---

### 3. XSS Scanner

Detects cross-site scripting — reflected, DOM-based, form inputs and missing security headers.

```bash
python web/xss_scanner.py -u "https://site.com/search?q=test"
python web/xss_scanner.py -u "https://site.com" --checks dom headers
python web/xss_scanner.py -u "https://site.com" --checks all -o xss.txt
```

| Flag       | Description                                       |
| ---------- | ------------------------------------------------- |
| `-u`       | Target URL                                        |
| `--checks` | `reflected` / `forms` / `dom` / `headers` / `all` |
| `-H`       | Custom header                                     |
| `-c`       | Cookie                                            |
| `-o`       | Output file                                       |

---

### 4. Firebase Auditor

Audits Firebase projects for security misconfigurations across all services.

```bash
python web/firebase_auditor.py -p my-project-id
python web/firebase_auditor.py -u https://myapp.web.app --checks all
python web/firebase_auditor.py -p my-project-id --checks firestore storage
```

| Flag       | Description                                                  |
| ---------- | ------------------------------------------------------------ |
| `-p`       | Firebase project ID                                          |
| `-u`       | App URL (project ID auto-extracted)                          |
| `--checks` | `firestore` / `rtdb` / `config` / `storage` / `auth` / `all` |
| `-o`       | Output file                                                  |

---

### 5. JWT Analyzer

Decodes and audits JWT tokens for security vulnerabilities.

```bash
python web/jwt_analyzer.py -t "eyJhbGciOiJSUzI1NiIs..."
python web/jwt_analyzer.py -t "eyJ..." --checks algorithm expiry sensitive
python web/jwt_analyzer.py -t "eyJ..." -u https://api.example.com/profile
```

| Flag       | Description                                                          |
| ---------- | -------------------------------------------------------------------- |
| `-t`       | JWT token                                                            |
| `--checks` | `algorithm` / `expiry` / `sensitive` / `secret` / `endpoint` / `all` |
| `-u`       | Endpoint to test token against                                       |
| `-o`       | Output file                                                          |

---

### 6. Subdomain Enumerator

Discovers subdomains using DNS brute-force and certificate transparency logs.

```bash
python recon/subdomain_enum.py -d example.com
python recon/subdomain_enum.py -d example.com --crt -t 50
python recon/subdomain_enum.py -d example.com -w wordlist.txt -o subs.txt
```

| Flag        | Description                   |
| ----------- | ----------------------------- |
| `-d`        | Target domain                 |
| `-t`        | Threads (default: 30)         |
| `--crt`     | Query crt.sh certificate logs |
| `-w`        | Custom wordlist               |
| `--no-http` | Skip HTTP probing (faster)    |
| `-o`        | Output file                   |

---

### 7. Port Scanner

Multi-threaded TCP port scanner with banner grabbing and automatic risk rating.

```bash
python scanning/port_scanner.py -t example.com
python scanning/port_scanner.py -t example.com --ports database
python scanning/port_scanner.py -t example.com --ports 80,443,3306,27017
python scanning/port_scanner.py -t example.com --ports top100 --threads 100
```

| Flag           | Description                                               |
| -------------- | --------------------------------------------------------- |
| `-t`           | Target host or IP                                         |
| `--ports`      | `common` / `web` / `database` / `dev` / `top100` / custom |
| `--threads`    | Threads (default: 50)                                     |
| `--timeout`    | Connection timeout (default: 1.0s)                        |
| `--no-banners` | Skip banner grabbing                                      |
| `-o`           | Output file                                               |

---

### 8. Report Generator

Generates professional PDF pentest reports with cover page, executive summary,
detailed findings and remediation table.

```bash
python reporting/report_generator.py -f findings.json -t "Client Name" -o report.pdf
python reporting/report_generator.py --sample -t "Demo" -o sample.pdf
```

**Findings JSON format:**

```json
[
  {
    "severity": "HIGH",
    "title": "Reflected XSS in search parameter",
    "tool": "XSS Scanner",
    "target": "https://site.com/search?q=",
    "description": "User input reflected without encoding.",
    "payload": "<script>alert(1)</script>",
    "evidence": "Script tag reflected in response",
    "recommendation": "Encode all user input before rendering in HTML."
  }
]
```

Severity values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`

---

### 9. Secrets Scanner

Scans GitHub repositories, websites and local folders for exposed secrets.
Detects 30+ pattern types including Firebase keys, AWS credentials, Stripe keys,
JWT secrets, private keys and .env file contents.

```bash
python post_exploit/secrets_scanner.py -r https://github.com/user/repo
python post_exploit/secrets_scanner.py -r https://github.com/user/repo -g ghp_token
python post_exploit/secrets_scanner.py -u https://example.com
python post_exploit/secrets_scanner.py -l ./my-project
```

| Flag          | Description                              |
| ------------- | ---------------------------------------- |
| `-r`          | GitHub repository URL                    |
| `-u`          | Website URL to probe                     |
| `-l`          | Local directory or file                  |
| `-g`          | GitHub personal access token             |
| `--max-files` | Max files to scan in repo (default: 200) |
| `-o`          | Output file                              |

---

### 10. CORS Exploiter

Tests for Cross-Origin Resource Sharing misconfigurations and generates
JavaScript proof-of-concept exploits to demonstrate impact to clients.

```bash
python post_exploit/cors_exploiter.py -u https://api.example.com
python post_exploit/cors_exploiter.py -u https://api.example.com --endpoints --poc
python post_exploit/cors_exploiter.py -u https://api.example.com -c "session=abc"
```

| Flag          | Description                     |
| ------------- | ------------------------------- |
| `-u`          | Target URL                      |
| `--endpoints` | Also test common API endpoints  |
| `--poc`       | Generate JavaScript PoC exploit |
| `-c`          | Cookie                          |
| `-H`          | Custom header                   |
| `-o`          | Output file                     |

---

### 11. Session Hijacker Tester

Tests session tokens and cookies for security weaknesses including missing
flags, token reuse, concurrent sessions and logout invalidation.

```bash
python post_exploit/session_hijacker.py -u https://example.com --cookies-only
python post_exploit/session_hijacker.py -u https://example.com -t "eyJhbGci..." --type bearer
python post_exploit/session_hijacker.py -u https://example.com -t "abc" --type cookie -n "session" --logout /api/logout
```

| Flag             | Description                    |
| ---------------- | ------------------------------ |
| `-u`             | Target URL                     |
| `-t`             | Session token or JWT           |
| `--type`         | `cookie` / `bearer` / `header` |
| `-n`             | Cookie or header name          |
| `--logout`       | Logout endpoint path           |
| `--cookies-only` | Only analyze cookie flags      |
| `-o`             | Output file                    |

---

### 12. Privilege Escalation Checker

Tests for vertical and horizontal privilege escalation — unauthorized admin
access, IDOR vulnerabilities, role manipulation and header-based bypasses.

```bash
python post_exploit/privesc_checker.py -u https://example.com
python post_exploit/privesc_checker.py -u https://example.com -t "eyJhbGci..." --user-id 42
python post_exploit/privesc_checker.py -u https://example.com -c "session=abc" --user-id 42 --checks admin idor
```

| Flag        | Description                                   |
| ----------- | --------------------------------------------- |
| `-u`        | Target URL                                    |
| `-t`        | JWT token                                     |
| `-c`        | Cookie                                        |
| `--user-id` | Your user ID for IDOR testing                 |
| `--checks`  | `admin` / `idor` / `roles` / `bypass` / `all` |
| `-o`        | Output file                                   |

---

## Full Pentest Workflow

```bash
# 1. Recon
python recon/subdomain_enum.py -d target.com --crt -o subs.txt

# 2. Port scan discovered subdomains
python scanning/port_scanner.py -t api.target.com --ports common -o ports.txt

# 3. Web vulnerability scanning
python web/sqli_detector.py -u "https://target.com/page?id=1" --checks all
python web/xss_scanner.py -u "https://target.com/search?q=test" --checks all
python web/nosql_injector.py -u "https://target.com/api/users?id=1"

# 4. Auth & config auditing
python web/firebase_auditor.py -p project-id --checks all
python web/jwt_analyzer.py -t "eyJhbGci..."

# 5. Post-exploitation
python post_exploit/secrets_scanner.py -u https://target.com
python post_exploit/cors_exploiter.py -u https://target.com --endpoints --poc
python post_exploit/session_hijacker.py -u https://target.com -t "eyJ..."
python post_exploit/privesc_checker.py -u https://target.com -t "eyJ..." --user-id 1

# 6. Generate report
python reporting/report_generator.py -f findings.json -t "Client Name" -o report.pdf
```

---

## Safe Practice Targets

| Lab                 | URL                                      | Good for               |
| ------------------- | ---------------------------------------- | ---------------------- |
| DVWA                | [dvwa.co.uk](https://dvwa.co.uk)         | SQLi, XSS, all basics  |
| HackTheBox          | [hackthebox.com](https://hackthebox.com) | Real pentest scenarios |
| TryHackMe           | [tryhackme.com](https://tryhackme.com)   | Guided learning paths  |
| testphp.vulnweb.com | Acunetix demo                            | Web vulnerabilities    |

---

## Project Structure

```
stryker/
├── stryker.py
├── requirements.txt
├── README.md
├── LEGAL.md
├── LICENSE
├── docs/
│   └── usage-guide.md
├── web/
│   ├── sqli_detector.py
│   ├── nosql_injector.py
│   ├── xss_scanner.py
│   ├── firebase_auditor.py
│   └── jwt_analyzer.py
├── recon/
│   └── subdomain_enum.py
├── scanning/
│   └── port_scanner.py
├── reporting/
│   └── report_generator.py
└── post_exploit/
    ├── secrets_scanner.py
    ├── cors_exploiter.py
    ├── session_hijacker.py
    └── privesc_checker.py
```

---

## Contributing

Pull requests welcome. Please:

1. Follow existing code style
2. Add docstring and usage example to every tool
3. Test against a legal target before submitting
4. Never include real target data in examples
5. Add tool to TOOLS registry in `stryker.py`

---

## Author

Built by **Andrews Osei Agyemang** — Software Engineer & Cybersecurity Expert
Ghana | [drewstechconsult.com](https://drewstechconsult.com) | [GitHub](https://github.com/drewstech-consult)

---

## License

MIT License — see [LICENSE](./LICENSE) for details.
