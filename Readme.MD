# 🛡️ pentest-toolkit

> A modular, well-documented penetration testing toolkit built in Python.  
> For authorized security testing only.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)

---

## ⚠️ Legal Notice

**This toolkit is for authorized penetration testing ONLY.**  
Only use these tools against systems you own or have explicit written permission to test.  
Unauthorized use is illegal. See [LEGAL.md](./LEGAL.md) for full details.

---

## Overview

`pentest-toolkit` is a growing collection of focused security tools organized around the penetration testing lifecycle. Each tool is:

- Standalone — works on its own
- Composable — output can feed into the next tool
- Documented — clear usage, examples, and explanations
- Readable — clean Python code you can learn from

---

## Tools

### 🌐 Web (`/web`)

| Tool               | Description                                                        | Status   |
| ------------------ | ------------------------------------------------------------------ | -------- |
| `sqli_detector.py` | Detects SQL injection vulnerabilities (error, boolean, time-based) | ✅ Ready |

### 🔍 Recon (`/recon`)

| Tool                | Description                              | Status    |
| ------------------- | ---------------------------------------- | --------- |
| `subdomain_enum.py` | Subdomain enumeration via wordlist + DNS | 🔜 Coming |

### 📡 Scanning (`/scanning`)

| Tool              | Description                                      | Status    |
| ----------------- | ------------------------------------------------ | --------- |
| `port_scanner.py` | Multi-threaded port scanner with banner grabbing | 🔜 Coming |

---

## Getting Started

### Requirements

- Python 3.10+
- pip

### Installation

```bash
git clone https://github.com/YOUR_USERNAME/pentest-toolkit.git
cd pentest-toolkit
pip install -r requirements.txt
```

---

## Usage

### SQLi Detector

Detect SQL injection vulnerabilities in web application parameters.

```bash
# Basic scan (error + boolean checks)
python web/sqli_detector.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1"

# Run all checks including time-based
python web/sqli_detector.py -u "http://example.com/page?id=1" --checks all

# Scan with custom headers (e.g. authenticated session)
python web/sqli_detector.py -u "http://example.com/page?id=1" -H "Authorization: Bearer <token>"

# Scan multiple URLs from a file
python web/sqli_detector.py -l urls.txt --checks error boolean

# Save findings to a file
python web/sqli_detector.py -u "http://example.com/page?id=1" -o findings.txt
```

**Options:**

| Flag       | Description                          |
| ---------- | ------------------------------------ |
| `-u`       | Single target URL                    |
| `-l`       | File with list of URLs               |
| `--checks` | `error`, `boolean`, `time`, or `all` |
| `-H`       | Custom request header                |
| `-c`       | Cookie string                        |
| `-t`       | Number of threads (default: 5)       |
| `-o`       | Output file for findings             |

**Detection types:**

- **Error-based** — Injects payloads that trigger database error messages
- **Boolean-based blind** — Compares responses to true/false conditions
- **Time-based blind** — Detects injection via deliberate response delays

---

## Lab Setup (Safe Testing)

Never test against real targets without permission. Use these instead:

| Lab                 | URL                                      | What to practice       |
| ------------------- | ---------------------------------------- | ---------------------- |
| DVWA                | [dvwa.co.uk](https://dvwa.co.uk)         | SQLi, XSS, more        |
| HackTheBox          | [hackthebox.com](https://hackthebox.com) | Full pentest scenarios |
| TryHackMe           | [tryhackme.com](https://tryhackme.com)   | Guided learning paths  |
| testphp.vulnweb.com | Acunetix demo site                       | Web vulnerabilities    |

---

## Project Structure

```
pentest-toolkit/
├── README.md
├── LEGAL.md
├── requirements.txt
├── web/
│   └── sqli_detector.py
├── recon/
│   └── (coming soon)
├── scanning/
│   └── (coming soon)
├── post_exploit/
│   └── (coming soon)
└── reporting/
    └── (coming soon)
```

---

## Contributing

Pull requests welcome. Please:

1. Follow the existing code style
2. Add a docstring and usage example to every tool
3. Test against a legal target before submitting
4. Never include real target data in examples

---

## Author

Built by **Andrews** — Software Engineer & Cybersecurity Expert  
🌍 Ghana | [LinkedIn](#) | [Twitter](#) | [Blog](#)

---

## License

MIT License — see [LICENSE](./LICENSE) for details.
