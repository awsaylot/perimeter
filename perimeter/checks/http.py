"""HTTP security headers check — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy."""

from __future__ import annotations

import requests
from requests.exceptions import RequestException

from perimeter.models import CheckResult, Finding, Severity

CHECK_NAME = "HTTP Headers"
TIMEOUT = 10
ONE_YEAR = 31_536_000  # seconds


def _fetch_headers(domain: str) -> dict[str, str]:
    """GET https://{domain}/ following redirects; returns lowercased header dict."""
    resp = requests.get(
        f"https://{domain}/",
        timeout=TIMEOUT,
        allow_redirects=True,
        headers={"User-Agent": "perimeter-scanner/1.0"},
    )
    return {k.lower(): v for k, v in resp.headers.items()}


def _check_hsts(domain: str, headers: dict[str, str]) -> Finding:
    value = headers.get("strict-transport-security")

    if not value:
        return Finding(
            check=CHECK_NAME,
            title="HSTS header missing",
            severity=Severity.MEDIUM,
            summary=(
                f"No Strict-Transport-Security header was returned by {domain}. "
                "Without HSTS, browsers won't automatically upgrade future requests to HTTPS, "
                "leaving users exposed to SSL-stripping attacks on their first visit."
            ),
            fix='Add the response header: Strict-Transport-Security: max-age=31536000; includeSubDomains',
            raw={"strict-transport-security": None},
        )

    max_age: int | None = None
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1].strip())
            except ValueError:
                pass
            break

    if max_age is None:
        return Finding(
            check=CHECK_NAME,
            title="HSTS header is malformed (no max-age)",
            severity=Severity.LOW,
            summary=(
                "A Strict-Transport-Security header is present but has no valid max-age directive. "
                "Browsers may ignore it entirely."
            ),
            fix='Set a valid max-age, e.g.: Strict-Transport-Security: max-age=31536000; includeSubDomains',
            raw={"strict-transport-security": value},
        )

    if max_age < ONE_YEAR:
        days = max_age // 86400
        return Finding(
            check=CHECK_NAME,
            title=f"HSTS max-age is short ({days} days)",
            severity=Severity.LOW,
            summary=(
                f"HSTS is enabled but max-age is only {days} days. "
                "A value under one year means browsers stop enforcing HTTPS sooner than recommended."
            ),
            fix=f'Increase max-age to at least {ONE_YEAR} (one year): Strict-Transport-Security: max-age={ONE_YEAR}; includeSubDomains',
            raw={"strict-transport-security": value, "max_age_seconds": max_age},
        )

    return Finding(
        check=CHECK_NAME,
        title="HSTS is configured",
        severity=Severity.PASS,
        summary=f"Strict-Transport-Security is present with max-age={max_age // 86400} days.",
        fix="",
        raw={"strict-transport-security": value, "max_age_seconds": max_age},
    )


def _check_csp(domain: str, headers: dict[str, str]) -> Finding:
    value = headers.get("content-security-policy")
    report_only = headers.get("content-security-policy-report-only")

    if not value:
        if report_only:
            return Finding(
                check=CHECK_NAME,
                title="CSP is report-only (not enforced)",
                severity=Severity.LOW,
                summary=(
                    "A Content-Security-Policy-Report-Only header is present, but this does not "
                    "enforce any restrictions — it only logs violations. XSS and injection attacks "
                    "are not blocked by the policy."
                ),
                fix="Promote the policy from Content-Security-Policy-Report-Only to Content-Security-Policy once validated.",
                raw={"content-security-policy": None, "report-only": report_only},
            )
        return Finding(
            check=CHECK_NAME,
            title="Content-Security-Policy header missing",
            severity=Severity.MEDIUM,
            summary=(
                f"No Content-Security-Policy header was returned by {domain}. "
                "Without CSP, browsers apply no restrictions on resource loading, "
                "making XSS attacks easier to exploit."
            ),
            fix="Add a Content-Security-Policy header. Start with default-src 'self' and expand as needed.",
            raw={"content-security-policy": None},
        )

    issues: list[str] = []
    lower = value.lower()
    if "'unsafe-inline'" in lower:
        issues.append("'unsafe-inline'")
    if "'unsafe-eval'" in lower:
        issues.append("'unsafe-eval'")

    if issues:
        joined = " and ".join(issues)
        return Finding(
            check=CHECK_NAME,
            title=f"CSP contains {joined}",
            severity=Severity.LOW,
            summary=(
                f"The Content-Security-Policy includes {joined}, which significantly weakens "
                "the policy. These directives allow inline scripts and/or eval(), "
                "undermining XSS protection."
            ),
            fix=f"Remove {joined} from the CSP. Use nonces or hashes to allow specific inline scripts instead.",
            raw={"content-security-policy": value, "weak_directives": issues},
        )

    return Finding(
        check=CHECK_NAME,
        title="Content-Security-Policy is present",
        severity=Severity.PASS,
        summary="A Content-Security-Policy header is present without unsafe-inline or unsafe-eval.",
        fix="",
        raw={"content-security-policy": value},
    )


def _check_xfo(domain: str, headers: dict[str, str]) -> Finding:
    value = headers.get("x-frame-options")

    if not value:
        # CSP frame-ancestors supersedes X-Frame-Options; check for it
        csp = headers.get("content-security-policy", "")
        if "frame-ancestors" in csp.lower():
            return Finding(
                check=CHECK_NAME,
                title="X-Frame-Options absent but CSP frame-ancestors present",
                severity=Severity.PASS,
                summary="Framing is controlled via CSP frame-ancestors, which supersedes X-Frame-Options in modern browsers.",
                fix="",
                raw={"x-frame-options": None, "csp_frame_ancestors": True},
            )
        return Finding(
            check=CHECK_NAME,
            title="X-Frame-Options header missing",
            severity=Severity.MEDIUM,
            summary=(
                f"{domain} does not set X-Frame-Options or a CSP frame-ancestors directive. "
                "Without either, attackers can embed this site in an iframe to perform clickjacking attacks."
            ),
            fix="Add the response header: X-Frame-Options: DENY  (or SAMEORIGIN if the site embeds itself in frames).",
            raw={"x-frame-options": None},
        )

    upper = value.strip().upper()
    if upper in ("DENY", "SAMEORIGIN"):
        return Finding(
            check=CHECK_NAME,
            title=f"X-Frame-Options is set ({value.strip()})",
            severity=Severity.PASS,
            summary=f"Framing is restricted via X-Frame-Options: {value.strip()}.",
            fix="",
            raw={"x-frame-options": value},
        )

    return Finding(
        check=CHECK_NAME,
        title=f"X-Frame-Options has a weak or unrecognised value ({value.strip()})",
        severity=Severity.LOW,
        summary=(
            f"The X-Frame-Options header is set to '{value.strip()}', which may not provide "
            "clickjacking protection. Only DENY and SAMEORIGIN are recognised by all browsers."
        ),
        fix="Change X-Frame-Options to DENY or SAMEORIGIN.",
        raw={"x-frame-options": value},
    )


def _check_xcto(headers: dict[str, str]) -> Finding:
    value = headers.get("x-content-type-options")

    if not value or value.strip().lower() != "nosniff":
        return Finding(
            check=CHECK_NAME,
            title="X-Content-Type-Options: nosniff missing",
            severity=Severity.LOW,
            summary=(
                "Without X-Content-Type-Options: nosniff, older browsers may MIME-sniff "
                "responses and execute scripts served with the wrong content type, "
                "enabling drive-by download and XSS attacks."
            ),
            fix="Add the response header: X-Content-Type-Options: nosniff",
            raw={"x-content-type-options": value},
        )

    return Finding(
        check=CHECK_NAME,
        title="X-Content-Type-Options: nosniff is set",
        severity=Severity.PASS,
        summary="MIME-type sniffing is disabled.",
        fix="",
        raw={"x-content-type-options": value},
    )


_STRICT_REFERRER_VALUES = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "no-referrer-when-downgrade",
}

_LOOSE_REFERRER_VALUES = {
    "unsafe-url",
    "origin-when-cross-origin",
    "origin",
}


def _check_referrer_policy(headers: dict[str, str]) -> Finding:
    value = headers.get("referrer-policy")

    if not value:
        return Finding(
            check=CHECK_NAME,
            title="Referrer-Policy header missing",
            severity=Severity.LOW,
            summary=(
                "No Referrer-Policy header is set. Browsers fall back to their default, "
                "which for many is strict-origin-when-cross-origin, but setting it "
                "explicitly removes the ambiguity and prevents accidental referrer leakage."
            ),
            fix="Add the response header: Referrer-Policy: strict-origin-when-cross-origin",
            raw={"referrer-policy": None},
        )

    canonical = value.strip().lower()
    if canonical in _LOOSE_REFERRER_VALUES:
        return Finding(
            check=CHECK_NAME,
            title=f"Referrer-Policy is permissive ({value.strip()})",
            severity=Severity.LOW,
            summary=(
                f"The Referrer-Policy is set to '{value.strip()}', which may send the full URL "
                "(including query strings) to third-party sites, leaking sensitive path or parameter data."
            ),
            fix="Change to a stricter policy such as: Referrer-Policy: strict-origin-when-cross-origin",
            raw={"referrer-policy": value},
        )

    return Finding(
        check=CHECK_NAME,
        title=f"Referrer-Policy is set ({value.strip()})",
        severity=Severity.PASS,
        summary=f"Referrer leakage is controlled via Referrer-Policy: {value.strip()}.",
        fix="",
        raw={"referrer-policy": value},
    )


def _check_permissions_policy(headers: dict[str, str]) -> Finding:
    value = headers.get("permissions-policy")

    if not value:
        return Finding(
            check=CHECK_NAME,
            title="Permissions-Policy header missing",
            severity=Severity.INFO,
            summary=(
                "No Permissions-Policy header is set. Without it, the browser applies "
                "its defaults for powerful features (camera, microphone, geolocation). "
                "Explicitly restricting unused features reduces the attack surface."
            ),
            fix="Add a Permissions-Policy header to restrict features this site doesn't use, e.g.: Permissions-Policy: geolocation=(), camera=(), microphone=()",
            raw={"permissions-policy": None},
        )

    return Finding(
        check=CHECK_NAME,
        title="Permissions-Policy is set",
        severity=Severity.PASS,
        summary="Browser feature access is explicitly controlled via Permissions-Policy.",
        fix="",
        raw={"permissions-policy": value},
    )


def run(domain: str) -> CheckResult:
    result = CheckResult(check=CHECK_NAME)

    try:
        headers = _fetch_headers(domain)
    except RequestException as exc:
        result.error = str(exc)
        result.findings.append(Finding(
            check=CHECK_NAME,
            title="Could not retrieve HTTP headers",
            severity=Severity.HIGH,
            summary=f"An error occurred while fetching https://{domain}/. Headers could not be inspected.",
            fix="Ensure the domain is reachable over HTTPS and returns a valid response.",
            raw={"error": str(exc)},
        ))
        return result

    errors: list[str] = []
    for fn, args in [
        (_check_hsts,               (domain, headers)),
        (_check_csp,                (domain, headers)),
        (_check_xfo,                (domain, headers)),
        (_check_xcto,               (headers,)),
        (_check_referrer_policy,    (headers,)),
        (_check_permissions_policy, (headers,)),
    ]:
        try:
            result.findings.append(fn(*args))
        except Exception as exc:
            errors.append(f"{fn.__name__}: {exc}")

    if errors:
        result.error = "; ".join(errors)

    return result
