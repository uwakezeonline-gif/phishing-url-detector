"""
main.py - Phishing URL Detection Tool
--------------------------------------
A command-line tool that analyzes URLs for phishing indicators
using a rule-based scoring system.

Usage:
    python main.py                  # Interactive mode
    python main.py --batch          # Analyze examples.txt
    python main.py --url <URL>      # Analyze a single URL
"""

import sys
import argparse
from utils import analyze_url

# ─── ANSI color codes for terminal output ───
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

BANNER = f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════╗
║       🛡  Phishing URL Detection Tool        ║
║         Rule-based URL Risk Analyzer         ║
╚══════════════════════════════════════════════╝{RESET}
"""


def colorize(level: str, text: str) -> str:
    """Apply color to text based on risk level."""
    if level == "safe":
        return f"{GREEN}{text}{RESET}"
    elif level == "suspicious":
        return f"{YELLOW}{text}{RESET}"
    else:  # phishing
        return f"{RED}{text}{RESET}"


def print_result(result: dict) -> None:
    """Pretty-print a single URL analysis result."""
    level  = result["level"]
    color  = {
        "safe": GREEN,
        "suspicious": YELLOW,
        "phishing": RED
    }[level]

    print(f"\n{DIM}{'─' * 50}{RESET}")
    print(f"  {BOLD}URL:{RESET}     {result['url']}")
    print(f"  {BOLD}Score:{RESET}   {result['score']}")
    print(f"  {BOLD}Verdict:{RESET} {color}{BOLD}{result['icon']}  {result['verdict'].upper()}{RESET}")
    print(f"\n  {BOLD}Findings:{RESET}")
    for flag in result["flags"]:
        bullet = colorize(level, "▸")
        print(f"    {bullet} {flag}")
    print(f"{DIM}{'─' * 50}{RESET}\n")


def interactive_mode() -> None:
    """Run the tool in interactive REPL mode."""
    print(BANNER)
    print(f"  {DIM}Type a URL to analyze. Enter 'quit' to exit.{RESET}\n")

    while True:
        try:
            url = input(f"  {CYAN}Enter URL:{RESET} ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n\n  {DIM}Exiting. Stay safe!{RESET}\n")
            break

        if url.lower() in ("quit", "exit", "q"):
            print(f"\n  {DIM}Exiting. Stay safe!{RESET}\n")
            break

        if not url:
            print(f"  {YELLOW}⚠  Please enter a URL.{RESET}")
            continue

        result = analyze_url(url)
        print_result(result)


def analyze_single(url: str) -> None:
    """Analyze one URL passed as a CLI argument."""
    print(BANNER)
    result = analyze_url(url)
    print_result(result)


def batch_mode(filepath: str = "examples.txt") -> None:
    """Read URLs from a file and analyze each one."""
    print(BANNER)
    print(f"  {CYAN}Batch analysis:{RESET} {filepath}\n")

    try:
        with open(filepath, "r") as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        print(f"  {RED}✗ File not found: {filepath}{RESET}\n")
        sys.exit(1)

    if not lines:
        print(f"  {YELLOW}No URLs found in {filepath}{RESET}\n")
        return

    safe = suspicious = phishing = 0

    for url in lines:
        result = analyze_url(url)
        print_result(result)
        if result["level"] == "safe":       safe += 1
        elif result["level"] == "suspicious": suspicious += 1
        else:                                 phishing += 1

    # Summary
    total = len(lines)
    print(f"\n  {BOLD}📊 Batch Summary ({total} URLs analyzed){RESET}")
    print(f"    {GREEN}✅ Safe:       {safe}{RESET}")
    print(f"    {YELLOW}⚠️  Suspicious: {suspicious}{RESET}")
    print(f"    {RED}❌ Phishing:   {phishing}{RESET}\n")


# ─── Entry point ───────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Phishing URL Detection Tool"
    )
    parser.add_argument(
        "--url", type=str, help="Analyze a single URL"
    )
    parser.add_argument(
        "--batch", action="store_true",
        help="Analyze all URLs in examples.txt"
    )
    args = parser.parse_args()

    if args.url:
        analyze_single(args.url)
    elif args.batch:
        batch_mode("examples.txt")
    else:
        interactive_mode()
