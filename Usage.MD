# Usage Guide

## Quick Start

```bash
pip install -r requirements.txt
python web/sqli_detector.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1"
```

## Understanding Output

The tool prints a results table with:

- **Type** — the injection technique that succeeded
- **Parameter** — which URL parameter is vulnerable
- **DB** — the database engine detected (MySQL, PostgreSQL, etc.)
- **Payload** — the exact string that triggered the finding
- **Evidence** — what indicated the vulnerability

## Check Types Explained

### Error-based

The fastest check. Injects strings like `'` or `' OR '1'='1` and looks for database
error messages in the response (e.g. "You have an error in your SQL syntax").

### Boolean-based blind

No error is shown, but the page content changes depending on whether the injected
condition is true or false. The tool sends a true-condition payload and a false-condition
payload and compares response lengths.

### Time-based blind

No visible difference in output at all. The tool injects `SLEEP()` / `WAITFOR DELAY`
commands and measures response time. A delayed response confirms injection.

## Multi-URL Scanning

Create a file `urls.txt`:

```
http://example.com/page?id=1
http://example.com/search?q=test
http://example.com/user?name=admin
```

Then run:

```bash
python web/sqli_detector.py -l urls.txt --checks all -t 10
```

## Authenticated Scanning

Pass session cookies or auth headers to test protected endpoints:

```bash
# Cookie auth
python web/sqli_detector.py -u "http://example.com/api?id=1" -c "session=abc123"

# Bearer token
python web/sqli_detector.py -u "http://example.com/api?id=1" -H "Authorization: Bearer eyJ..."

# Multiple headers
python web/sqli_detector.py -u "http://example.com/api?id=1" \
  -H "Authorization: Bearer eyJ..." \
  -H "X-API-Key: secret"
```

## Saving Reports

```bash
python web/sqli_detector.py -u "http://example.com/page?id=1" -o report.txt
```

## Safe Practice Targets

- `http://testphp.vulnweb.com/listproducts.php?cat=1` — Acunetix demo (intentionally vulnerable)
- DVWA running locally
- HackTheBox / TryHackMe machines
