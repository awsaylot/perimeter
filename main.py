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


def _print_history(domain: str) -> None:
    from perimeter.graph.connection import get_driver
    from perimeter.graph.reader import get_history, get_new_findings, get_resolved_findings

    driver = get_driver()
    scans = get_history(domain, driver)

    if not scans:
        print(f"[perimeter] no scan history found for {domain}")
        driver.close()
        return

    print(f"\n{_BOLD}[perimeter] scan history for {domain}{_RESET}")
    print("  " + "-" * 56)
    for s in scans:
        ts = s["scanned_at"].strftime("%Y-%m-%d %H:%M UTC") if hasattr(s["scanned_at"], "strftime") else str(s["scanned_at"])
        high_str   = f"{_COLORS[Severity.HIGH]}{s['high']}H{_RESET}"   if s["high"]   else ""
        medium_str = f"{_COLORS[Severity.MEDIUM]}{s['medium']}M{_RESET}" if s["medium"] else ""
        low_str    = f"{_COLORS[Severity.LOW]}{s['low']}L{_RESET}"     if s["low"]    else ""
        badge_str  = "  ".join(x for x in [high_str, medium_str, low_str] if x) or f"{_COLORS[Severity.PASS]}clean{_RESET}"
        print(f"  {_DIM}{ts}{_RESET}  {s['total']} findings  {badge_str}  {_DIM}{s['uuid'][:8]}{_RESET}")

    if len(scans) >= 2:
        new_findings      = get_new_findings(domain, driver)
        resolved_findings = get_resolved_findings(domain, driver)

        if new_findings:
            print(f"\n  {_COLORS[Severity.HIGH]}New since last scan:{_RESET}")
            for f in new_findings:
                print(f"    {_badge(Severity(f['severity']))} {f['check']} - {f['title']}")

        if resolved_findings:
            print(f"\n  {_COLORS[Severity.PASS]}Resolved since last scan:{_RESET}")
            for f in resolved_findings:
                print(f"    {_badge(Severity(f['severity']))} {f['check']} - {f['title']}")

        if not new_findings and not resolved_findings:
            print(f"\n  {_DIM}No changes since last scan.{_RESET}")

    print()
    driver.close()


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
    parser.add_argument(
        "--graph",
        action="store_true",
        help="Write scan results into Neo4j (requires NEO4J_PASSWORD in .env)",
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="Show scan history for the domain from Neo4j (no new scan is run)",
    )

    args = parser.parse_args()

    # --history is read-only — no scan needed
    if args.history:
        _print_history(args.domain)
        return

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

    if args.graph:
        from perimeter.graph.connection import get_driver
        from perimeter.graph.schema import apply_constraints
        from perimeter.graph.writer import write_scan
        driver = get_driver()
        apply_constraints(driver)
        write_scan(result, driver)
        driver.close()
        print(f"[perimeter] scan {result.uuid[:8]} written to Neo4j")


if __name__ == "__main__":
    main()
