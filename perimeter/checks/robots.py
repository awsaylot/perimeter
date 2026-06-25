"""robots.txt audit — parses Disallow entries for sensitive path disclosure."""

from __future__ import annotations

import requests
from requests.exceptions import RequestException

from perimeter.models import CheckResult, Finding, Severity

CHECK_NAME = "robots.txt Audit"
TIMEOUT = 10

_SENSITIVE_KEYWORDS = [
    "admin", "administrator", "manage", "management", "portal",
    "api", "internal", "backend", "private",
    "staging", "stage", "stg", "dev", "development", "test", "sandbox", "uat",
    "config", "configuration", "settings",
    "backup", "archive", "export",
    "database", "db", "mysql", "phpmyadmin", "adminer",
    ".env", "env",
    "wp-admin", "wp-content/uploads",
    "cpanel", "plesk",
    "jenkins", "ci", "deploy",
    "secret", "credentials",
    "login", "auth", "sso",
]


def _is_sensitive(path: str) -> bool:
    lower = path.lower()
    return any(kw in lower for kw in _SENSITIVE_KEYWORDS)


def run(domain: str) -> CheckResult:
    result = CheckResult(check=CHECK_NAME)

    try:
        resp = requests.get(
            f"https://{domain}/robots.txt",
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "perimeter-scanner/1.0"},
        )
    except RequestException as exc:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title="robots.txt unreachable",
            severity=Severity.INFO,
            summary="Could not fetch robots.txt.",
            fix="",
            raw={"error": str(exc)},
        ))
        return result

    if resp.status_code == 404:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title="robots.txt not present",
            severity=Severity.PASS,
            summary="No robots.txt file exists — no path inventory is inadvertently disclosed.",
            fix="",
            raw={"status": 404},
        ))
        return result

    if resp.status_code != 200:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title=f"robots.txt returned HTTP {resp.status_code}",
            severity=Severity.INFO,
            summary="robots.txt returned an unexpected status code.",
            fix="",
            raw={"status": resp.status_code},
        ))
        return result

    # Collect all Disallow entries across all User-agent blocks
    disallowed: list[str] = []
    for line in resp.text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("disallow:"):
            path = stripped[9:].split("#")[0].strip()
            if path and path != "/":
                disallowed.append(path)

    if not disallowed:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title="robots.txt present but discloses no notable paths",
            severity=Severity.PASS,
            summary="robots.txt exists but contains no Disallow entries that reveal sensitive structure.",
            fix="",
            raw={"disallowed_entries": []},
        ))
        return result

    # Inventory finding — always emit this when there are any Disallow entries
    result.findings.append(Finding(
        check=CHECK_NAME,
        title=f"robots.txt discloses {len(disallowed)} Disallow path(s)",
        severity=Severity.INFO,
        summary=(
            "robots.txt lists paths intended to block crawlers. "
            "This file is publicly readable and commonly used by attackers during reconnaissance."
        ),
        fix="",
        raw={"disallowed_paths": disallowed},
    ))

    sensitive = [p for p in disallowed if _is_sensitive(p)]
    if sensitive:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title=f"{len(sensitive)} sensitive path(s) named in robots.txt",
            severity=Severity.MEDIUM,
            summary=(
                f"These Disallow entries suggest internal or sensitive paths: {', '.join(sensitive)}. "
                "Attackers routinely read robots.txt during recon — listing these paths advertises their existence."
            ),
            fix=(
                "Remove sensitive paths from robots.txt. "
                "Enforce access restrictions server-side; robots.txt is advisory only and not a security control."
            ),
            raw={"sensitive_paths": sensitive},
        ))

    return result
