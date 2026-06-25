#!/usr/bin/env python3
"""perimeter — passive external exposure scanner."""

import argparse

from perimeter.models import ScanResult


def main():
    parser = argparse.ArgumentParser(
        prog="perimeter",
        description="Passive external exposure scanner. Takes a domain and reports what's publicly visible.",
    )
    parser.add_argument("domain", help="Target domain to scan (e.g. example.com)")
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write the report to this file (default: <domain>-report.html)",
    )
    parser.add_argument(
        "--hibp-key",
        metavar="KEY",
        help="HaveIBeenPwned API key for breach check (or set HIBP_API_KEY env var)",
    )

    args = parser.parse_args()
    result = ScanResult(domain=args.domain)
    print(f"[perimeter] target: {result.domain}")
    print("(no checks implemented yet)")


if __name__ == "__main__":
    main()
