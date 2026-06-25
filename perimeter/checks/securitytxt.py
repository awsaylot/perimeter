"""Security.txt check — RFC 9116 responsible disclosure policy."""

from __future__ import annotations

from datetime import datetime, timezone

import requests
from requests.exceptions import RequestException

from perimeter.models import CheckResult, Finding, Severity

CHECK_NAME = "Security Policy"
TIMEOUT = 10

# RFC 9116 canonical location first, legacy fallback second
_LOCATIONS = ["/.well-known/security.txt", "/security.txt"]


def _parse_expiry(content: str) -> datetime | None:
    for line in content.splitlines():
        if line.strip().lower().startswith("expires:"):
            date_str = line.split(":", 1)[1].strip()
            try:
                dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except ValueError:
                pass
    return None


def run(domain: str) -> CheckResult:
    result = CheckResult(check=CHECK_NAME)

    content: str | None = None
    found_url: str | None = None

    for path in _LOCATIONS:
        try:
            resp = requests.get(
                f"https://{domain}{path}",
                timeout=TIMEOUT,
                allow_redirects=False,
                headers={"User-Agent": "perimeter-scanner/1.0"},
            )
            if resp.status_code == 200 and "contact:" in resp.text.lower():
                content = resp.text
                found_url = f"https://{domain}{path}"
                break
        except RequestException:
            continue

    if not content:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title="security.txt not found",
            severity=Severity.LOW,
            summary=(
                f"{domain} does not publish a security.txt file (RFC 9116). "
                "Without it, security researchers have no official channel for reporting vulnerabilities, "
                "and reports may never reach the right team."
            ),
            fix=f"Create /.well-known/security.txt with at least a Contact field. Use the generator at https://securitytxt.org",
            raw={"checked_paths": _LOCATIONS},
        ))
        return result

    expiry = _parse_expiry(content)
    now = datetime.now(timezone.utc)
    is_expired = expiry is not None and expiry < now
    expiry_str = expiry.strftime("%Y-%m-%d") if expiry else None

    if is_expired:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title=f"security.txt is present but expired ({expiry_str})",
            severity=Severity.LOW,
            summary=(
                f"A security.txt file exists at {found_url} but its Expires field passed on {expiry_str}. "
                "An expired file signals to researchers that the disclosure process may be unmaintained."
            ),
            fix="Update the Expires field to a future date and review the other contact details.",
            raw={"url": found_url, "expired": True, "expiry": expiry_str},
        ))
    else:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title="security.txt is present and valid",
            severity=Severity.PASS,
            summary=(
                f"A valid security.txt was found at {found_url}"
                + (f", expires {expiry_str}." if expiry_str else ".")
            ),
            fix="",
            raw={"url": found_url, "expired": False, "expiry": expiry_str},
        ))

    return result
