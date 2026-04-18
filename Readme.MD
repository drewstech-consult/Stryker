# STRYKER — Penetration Testing Framework

> A modular, Metasploit-style penetration testing toolkit built in Python.
> Built by Andrews | For authorized security testing only.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Tools](https://img.shields.io/badge/tools-8%20ready-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-red)

---

## Legal Notice

**This toolkit is for authorized penetration testing ONLY.**
Only use these tools against systems you own or have explicit written permission to test.
Unauthorized use is illegal and unethical. See [LEGAL.md](./LEGAL.md) for full details.

---

## Overview

STRYKER is a complete penetration testing framework with an interactive terminal console,
8 ready-to-use security tools, and a professional PDF report generator.
It covers the full pentest lifecycle — from recon to exploitation to reporting.

```
python stryker.py
```

```
          .                 .
       .node.             .node.
      (  o  )           (  o  )
   ____|___|_____________|___|____
  ...

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
| 4   | `firebase_auditor.py` | Firebase rules — Firestore, RTDB, Storage, Auth | Ready  |
| 5   | `jwt_analyzer.py`     | JWT tokens — algorithm, expiry, weak secrets    | Ready  |

### Recon (`/recon`)

| ID  | Tool                | Description                            | Status |
| --- | ------------------- | -------------------------------------- | ------ |
| 6   | `subdomain_enum.py` | Subdomain enumeration via DNS + crt.sh | Ready  |

### Scanning (`/scanning`)

| ID  | Tool              | Description                                       | Status |
| --- | ----------------- | ------------------------------------------------- | ------ |
| 7   | `port_scanner.py` | Port scanner with banner grabbing and risk rating | Ready  |

### Reporting (`/reporting`)

| ID  | Tool                  | Description                      | Status |
| --- | --------------------- | -------------------------------- | ------ |
| 8   | `report_generator.py` | Professional PDF pentest reports | Ready  |

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

### Launch the interactive console

```bash
python stryker.py
```

### Console commands

```
modules          List all tools
use 1            Launch SQLi Detector
use 2            Launch NoSQL Injector
use 3            Launch XSS Scanner
use 4            Launch Firebase Auditor
use 5            Launch JWT Analyzer
use 6            Launch Subdomain Enumerator
use 7            Launch Port Scanner
use 8            Launch Report Generator
info <id>        Show details about a tool
clear            Clear the screen
banner           Show the banner
exit             Exit STRYKER
```

### Run tools directly (without console)

```bash
# SQL injection scan
python web/sqli_detector.py -u "https://site.com/page?id=1" --checks all

# NoSQL injection scan
python web/nosql_injector.py -u "https://site.com/api/users?id=1" --checks all

# XSS scan
python web/xss_scanner.py -u "https://site.com/search?q=test" --checks all

# Firebase audit
python web/firebase_auditor.py -p my-firebase-project-id --checks all

# JWT analysis
python web/jwt_analyzer.py -t "eyJhbGciOiJSUzI1NiIs..."

# Subdomain enumeration
python recon/subdomain_enum.py -d example.com --crt

# Port scan
python scanning/port_scanner.py -t example.com --ports common

# Generate PDF report
python reporting/report_generator.py -f findings.json -t "Client Name" -o report.pdf

# Generate sample report
python reporting/report_generator.py --sample -t "Demo Client" -o sample.pdf
```

---

## Tool Reference

### 1. SQLi Detector

Detects SQL injection vulnerabilities in URL parameters.

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

Tests for NoSQL injection in MongoDB, Firebase and CouchDB applications.

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

Detects cross-site scripting vulnerabilities across reflected, DOM, forms and headers.

```bash
python web/xss_scanner.py -u "https://site.com/search?q=test"
python web/xss_scanner.py -u "https://site.com" --checks dom headers
python web/xss_scanner.py -u "https://site.com" --checks all -o xss_findings.txt
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

Audits Firebase projects for security misconfigurations.

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
| `-u`       | Endpoint URL to test token against                                   |
| `-o`       | Output file                                                          |

---

### 6. Subdomain Enumerator

Discovers subdomains using DNS brute-force and certificate transparency logs.

```bash
python recon/subdomain_enum.py -d example.com
python recon/subdomain_enum.py -d example.com --crt -t 50
python recon/subdomain_enum.py -d example.com -w custom_wordlist.txt -o subs.txt
```

| Flag        | Description                                |
| ----------- | ------------------------------------------ |
| `-d`        | Target domain                              |
| `-t`        | Threads (default: 30)                      |
| `--crt`     | Query crt.sh certificate transparency logs |
| `-w`        | Custom wordlist file                       |
| `--no-http` | Skip HTTP probing (faster)                 |
| `-o`        | Output file                                |

---

### 7. Port Scanner

Multi-threaded TCP port scanner with banner grabbing and risk assessment.

```bash
python scanning/port_scanner.py -t example.com
python scanning/port_scanner.py -t example.com --ports database
python scanning/port_scanner.py -t example.com --ports 80,443,3306,27017
python scanning/port_scanner.py -t example.com --ports top100 --threads 100
```

| Flag           | Description                                                    |
| -------------- | -------------------------------------------------------------- |
| `-t`           | Target host or IP                                              |
| `--ports`      | `common` / `web` / `database` / `dev` / `top100` / custom list |
| `--threads`    | Threads (default: 50)                                          |
| `--timeout`    | Connection timeout (default: 1.0s)                             |
| `--no-banners` | Skip banner grabbing                                           |
| `-o`           | Output file                                                    |

---

### 8. Report Generator

Generates professional PDF pentest reports with cover page, executive summary,
findings details and remediation table.

```bash
# From findings JSON file
python reporting/report_generator.py -f findings.json -t "Client Name" -o report.pdf

# Sample report
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

Severity levels: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`

---

## Safe Practice Targets

Never test against real systems without written permission. Use these instead:

| Lab                 | URL                                      | Good for               |
| ------------------- | ---------------------------------------- | ---------------------- |
| DVWA                | [dvwa.co.uk](https://dvwa.co.uk)         | SQLi, XSS, all basics  |
| HackTheBox          | [hackthebox.com](https://hackthebox.com) | Real pentest scenarios |
| TryHackMe           | [tryhackme.com](https://tryhackme.com)   | Guided learning        |
| testphp.vulnweb.com | Acunetix demo                            | Web vulnerabilities    |
| Your own apps       | localhost / staging                      | Real-world practice    |

---

## Project Structure

```
stryker/
├── stryker.py              Main console launcher
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
└── reporting/
    └── report_generator.py
```

---

## Contributing

Pull requests are welcome. Please:

1. Follow the existing code style
2. Add a docstring and usage example to every tool
3. Test against a legal target before submitting
4. Never include real target data in examples
5. Add the tool to the TOOLS registry in `stryker.py`

---

## Author

Built by **Andrews Osei Agyemang** — Software Engineer & Cybersecurity Expert
Ghana | [drewstechconsult.com](https://drewstechconsult.com) | [GitHub](https://github.com/drewstech-consult)

---

## License

MIT License — see [LICENSE](./LICENSE) for details.
