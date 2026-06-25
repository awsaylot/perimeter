"""Subdomain enumeration via crt.sh certificate transparency logs."""

from __future__ import annotations

import re

import requests
from requests.exceptions import RequestException

from perimeter.models import CheckResult, Finding, Severity

CHECK_NAME = "Subdomain Enumeration"
TIMEOUT = 30  # crt.sh can be slow

# Keywords whose presence in the first label of a subdomain warrants attention.
# Match as whole word or prefix/suffix to avoid false positives (e.g. "stage" in "hostage").
_SENSITIVE = [
    "admin", "administrator", "portal", "manage", "management",
    "stage", "staging", "stg", "uat",
    "dev", "develop", "development", "sandbox",
    "test", "testing", "qa", "qc",
    "jenkins", "ci", "cd", "build", "deploy",
    "vpn", "remote", "access", "gateway",
    "internal", "intranet", "corp",
    "api", "backend", "service",
    "jira", "confluence", "gitlab", "bitbucket", "sonar",
    "mail", "smtp", "webmail", "owa",
    "ftp", "sftp", "files", "backup",
    "db", "database", "mysql", "postgres", "mongo", "redis",
    "old", "legacy", "archive",
    "demo", "preview", "beta",
    "login", "auth", "sso",
    "secure", "security",
]

# Pre-compiled: match a sensitive keyword as a standalone token within the label
_SENSITIVE_RE = re.compile(
    r"(?:^|[-_.])(" + "|".join(re.escape(k) for k in _SENSITIVE) + r")(?:$|[-_.])",
    re.IGNORECASE,
)


def _is_sensitive(subdomain: str) -> bool:
    first_label = subdomain.split(".")[0]
    return bool(_SENSITIVE_RE.search(first_label))


def _fetch_subdomains(domain: str) -> set[str]:
    """Query crt.sh and return unique subdomains of domain (wildcards excluded)."""
    resp = requests.get(
        "https://crt.sh/",
        params={"q": f"%.{domain}", "output": "json"},
        timeout=TIMEOUT,
        headers={"User-Agent": "perimeter-scanner/1.0"},
    )
    resp.raise_for_status()
    entries = resp.json()

    found: set[str] = set()
    for entry in entries:
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            # Keep only names that are proper subdomains of the target
            if name.endswith(f".{domain}") and name != domain:
                found.add(name)

    return found


def run(domain: str) -> CheckResult:
    result = CheckResult(check=CHECK_NAME)

    try:
        subdomains = _fetch_subdomains(domain)
    except RequestException as exc:
        result.error = str(exc)
        result.findings.append(Finding(
            check=CHECK_NAME,
            title="crt.sh lookup failed",
            severity=Severity.INFO,
            summary="Could not reach crt.sh to enumerate subdomains. Try again later.",
            fix="",
            raw={"error": str(exc)},
        ))
        return result

    if not subdomains:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title="No subdomains found in CT logs",
            severity=Severity.PASS,
            summary=f"No subdomains of {domain} appeared in certificate transparency logs.",
            fix="",
            raw={"subdomains": []},
        ))
        return result

    sorted_all = sorted(subdomains)
    sensitive = sorted([s for s in subdomains if _is_sensitive(s)])

    # Always emit an INFO finding with the full inventory
    result.findings.append(Finding(
        check=CHECK_NAME,
        title=f"{len(subdomains)} subdomain(s) visible in CT logs",
        severity=Severity.INFO,
        summary=(
            f"Certificate transparency logs reveal {len(subdomains)} subdomain(s) of {domain}. "
            "CT logs are public — this list is available to anyone."
        ),
        fix="",
        raw={"subdomains": sorted_all, "count": len(sorted_all)},
    ))

    if sensitive:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title=f"{len(sensitive)} sensitive-looking subdomain(s) found",
            severity=Severity.MEDIUM,
            summary=(
                f"The following subdomains have names suggesting development, internal, or "
                f"administrative infrastructure: {', '.join(sensitive)}. "
                "If these are unintended or forgotten, they may be less hardened than production."
            ),
            fix=(
                "Audit each sensitive subdomain. Decommission any that are no longer needed, "
                "and ensure development and staging environments are not publicly reachable."
            ),
            raw={"sensitive_subdomains": sensitive},
        ))

    return result
