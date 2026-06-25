"""Cookie security check — Secure, HttpOnly, and SameSite flags on Set-Cookie headers."""

from __future__ import annotations

import requests
from requests.exceptions import RequestException

from perimeter.models import CheckResult, Finding, Severity

CHECK_NAME = "Cookie Security"
TIMEOUT = 10


def _parse_set_cookie_headers(response: requests.Response) -> list[dict]:
    """
    Extract all Set-Cookie headers from the raw urllib3 response and parse each
    into a structured dict. requests merges duplicate headers by default, so we
    must go to the underlying response to get every cookie individually.
    """
    raw_values: list[str] = []
    for key, val in response.raw.headers.items():
        if key.lower() == "set-cookie":
            raw_values.append(val)

    cookies = []
    for raw in raw_values:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0].strip() if parts else "unknown"

        attr_keys = {p.split("=", 1)[0].strip().lower() for p in parts[1:]}
        samesite_val = ""
        for p in parts[1:]:
            k, _, v = p.partition("=")
            if k.strip().lower() == "samesite":
                samesite_val = v.strip().lower()
                break

        cookies.append({
            "name": name,
            "secure": "secure" in attr_keys,
            "httponly": "httponly" in attr_keys,
            "samesite": samesite_val,
            "raw": raw,
        })

    return cookies


def run(domain: str) -> CheckResult:
    result = CheckResult(check=CHECK_NAME)

    try:
        resp = requests.get(
            f"https://{domain}/",
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "perimeter-scanner/1.0"},
        )
    except RequestException as exc:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title="Could not fetch homepage for cookie inspection",
            severity=Severity.INFO,
            summary="The homepage was unreachable so cookies could not be inspected.",
            fix="",
            raw={"error": str(exc)},
        ))
        return result

    cookies = _parse_set_cookie_headers(resp)

    if not cookies:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title="No cookies set on homepage",
            severity=Severity.PASS,
            summary="The homepage response did not set any cookies.",
            fix="",
            raw={},
        ))
        return result

    missing_secure             = [c["name"] for c in cookies if not c["secure"]]
    missing_httponly           = [c["name"] for c in cookies if not c["httponly"]]
    missing_samesite           = [c["name"] for c in cookies if not c["samesite"]]
    samesite_none_no_secure    = [c["name"] for c in cookies if c["samesite"] == "none" and not c["secure"]]

    if not any([missing_secure, missing_httponly, missing_samesite, samesite_none_no_secure]):
        result.findings.append(Finding(
            check=CHECK_NAME,
            title=f"All {len(cookies)} cookie(s) correctly flagged",
            severity=Severity.PASS,
            summary="Every cookie on the homepage has Secure, HttpOnly, and SameSite set.",
            fix="",
            raw={"cookies": [c["name"] for c in cookies]},
        ))
        return result

    if missing_secure:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title=f"Cookie(s) missing Secure flag: {', '.join(missing_secure)}",
            severity=Severity.HIGH,
            summary=(
                "Cookies without the Secure flag can be transmitted over plain HTTP, "
                "exposing session tokens and other values to network interception."
            ),
            fix="Add the Secure attribute to all cookies: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Strict",
            raw={"cookies_missing_secure": missing_secure},
        ))

    if samesite_none_no_secure:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title=f"Cookie(s) with SameSite=None but no Secure flag: {', '.join(samesite_none_no_secure)}",
            severity=Severity.HIGH,
            summary=(
                "SameSite=None requires the Secure flag — without it, modern browsers reject the cookie entirely. "
                "This combination also allows the cookie to be sent in cross-site requests."
            ),
            fix="Add the Secure attribute alongside SameSite=None, or change SameSite to Strict or Lax.",
            raw={"cookies": samesite_none_no_secure},
        ))

    if missing_httponly:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title=f"Cookie(s) missing HttpOnly flag: {', '.join(missing_httponly)}",
            severity=Severity.LOW,
            summary=(
                "Cookies without HttpOnly are readable by JavaScript, "
                "making them vulnerable to theft via XSS attacks."
            ),
            fix="Add HttpOnly to any cookie that does not need to be accessed by client-side scripts.",
            raw={"cookies_missing_httponly": missing_httponly},
        ))

    if missing_samesite:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title=f"Cookie(s) missing SameSite attribute: {', '.join(missing_samesite)}",
            severity=Severity.LOW,
            summary=(
                "Cookies without SameSite default to Lax in modern browsers, but explicit configuration "
                "is best practice and provides consistent behavior across all browsers and versions."
            ),
            fix="Add SameSite=Strict or SameSite=Lax to all cookies.",
            raw={"cookies_missing_samesite": missing_samesite},
        ))

    return result
