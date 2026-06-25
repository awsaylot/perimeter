#!/usr/bin/env python3
"""perimeter — passive external exposure scanner."""

from __future__ import annotations

import argparse
import sys
import textwrap

from perimeter.checks import (
    cookies, dns, dnssec, http, paths, robots, securitytxt, subdomains, tls, whois
)
from perimeter.models import ScanResult, Severity
from perimeter.output.html_output import write_report
from perimeter.output.json_output import to_json

CHECKS = [dns, dnssec, tls, http, cookies, paths, robots, subdomains, whois, securitytxt]

_COLORS = {
    Severity.HIGH:   "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW:    "\033[96m",
    Severity.INFO:   "\033[94m",
    Severity.PASS:   "\033[92m",
}
_RESET = "\033[0m"
_BOLD  = "\033[1m"
_DIM   = "\033[2m"

_LABEL_WIDTH = 8  # "[MEDIUM]" is 8 chars


def _badge(sev: Severity) -> str:
    label = f"[{sev.value.upper()}]"
    return f"{_COLORS[sev]}{label:<{_LABEL_WIDTH}}{_RESET}"


def _print_results(result: ScanResult) -> None:
    ts = result.scanned_at.strftime("%Y-%m-%d %H:%M UTC")
    print(f"\n{_BOLD}[perimeter]{_RESET} {result.domain}  {_DIM}({ts}){_RESET}")

    for cr in result.check_results:
        print(f"\n{_BOLD}{cr.check}{_RESET}")
        print("  " + "-" * 56)

        if cr.error:
            print(f"  {_COLORS[Severity.HIGH]}[ERROR]  {_RESET}{cr.error}")

        for f in cr.findings:
            print(f"  {_badge(f.severity)} {f.title}")
            if f.severity not in (Severity.PASS,):
                indent = " " * (2 + _LABEL_WIDTH + 1)
                for line in textwrap.wrap(f.summary, width=72):
                    print(f"{indent}{line}")
                if f.fix:
                    fix_text = textwrap.fill(
                        f"Fix: {f.fix}", width=72,
                        initial_indent=indent,
                        subsequent_indent=indent + "     ",
                    )
                    print(f"{_DIM}{fix_text}{_RESET}")

    actionable = result.actionable_findings
    total = len(result.all_findings)
    print(f"\n{'-' * 60}")

    if actionable:
        high   = sum(1 for f in actionable if f.severity == Severity.HIGH)
        medium = sum(1 for f in actionable if f.severity == Severity.MEDIUM)
        low    = sum(1 for f in actionable if f.severity == Severity.LOW)
        parts = []
        if high:
            parts.append(f"{_COLORS[Severity.HIGH]}{high} HIGH{_RESET}")
        if medium:
            parts.append(f"{_COLORS[Severity.MEDIUM]}{medium} MEDIUM{_RESET}")
        if low:
            parts.append(f"{_COLORS[Severity.LOW]}{low} LOW{_RESET}")
        print(f"  {len(actionable)}/{total} findings need attention  ({', '.join(parts)})")
    else:
        print(f"  {_COLORS[Severity.PASS]}All {total} checks passed.{_RESET}")

    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="perimeter",
        description="Passive external exposure scanner. Takes a domain and reports what's publicly visible.",
    )
    parser.add_argument("domain", help="Target domain to scan (e.g. example.com)")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit results as JSON to stdout instead of terminal output",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write an HTML report to FILE (e.g. report.html)",
    )


    args = parser.parse_args()
    result = ScanResult(domain=args.domain)

    if not args.json:
        print(f"[perimeter] scanning {result.domain}...")
    for check_module in CHECKS:
        cr = check_module.run(args.domain)
        result.check_results.append(cr)

    if args.json:
        sys.stdout.write(to_json(result) + "\n")
    elif args.output:
        write_report(result, args.output)
        print(f"[perimeter] report written to {args.output}")
    else:
        _print_results(result)


if __name__ == "__main__":
    main()
