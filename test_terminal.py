import os, sys
os.environ["PYTHONUNBUFFERED"] = "1"

RED  = "\033[91m"
CYAN = "\033[96m"
DIM  = "\033[2m"
BOLD = "\033[1m"
RST  = "\033[0m"

def p(t=""):
    sys.stdout.write(t + "\n")
    sys.stdout.flush()

p()
p(f"{BOLD}{RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RST}")
p(f"{BOLD}{RED}  STRYKER — PENETRATION TESTING FRAMEWORK{RST}")
p(f"{BOLD}{RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RST}")
p()
p(f"  Type {CYAN}help{RST} to see all commands.")
p()

while True:
    sys.stdout.write(f"{BOLD}{RED}stryker{RST}@{CYAN}andrews{RST} > ")
    sys.stdout.flush()
    try:
        cmd = input().strip().lower()
    except (KeyboardInterrupt, EOFError):
        break

    if cmd == "help":
        p()
        p(f"  {CYAN}modules{RST}          Show all available tools")
        p(f"  {CYAN}use 1{RST}            Launch SQLi Detector")
        p(f"  {CYAN}info 1{RST}           Show tool details")
        p(f"  {CYAN}clear{RST}            Clear the screen")
        p(f"  {CYAN}exit{RST}             Exit Stryker")
        p()
    elif cmd == "modules":
        p()
        p(f"  {RED}[ WEB ]{RST}")
        p(f"  {CYAN}1{RST}  SQLi Detector     {BOLD}READY{RST}")
        p()
        p(f"  {RED}[ RECON ]{RST}")
        p(f"  {CYAN}2{RST}  Subdomain Enum    {DIM}SOON{RST}")
        p()
    elif cmd in ("exit","quit"):
        p("  Goodbye.")
        break
    else:
        p(f"  Unknown command. Type {CYAN}help{RST}.")