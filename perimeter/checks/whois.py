"""Domain registration check via RDAP — expiry date and domain age."""

from __future__ import annotations

from datetime import datetime, timezone

import requests
from requests.exceptions import RequestException

from perimeter.models import CheckResult, Finding, Severity

CHECK_NAME = "Domain Registration"
TIMEOUT = 15


def _fetch_rdap(domain: str) -> dict:
    resp = requests.get(
        f"https://rdap.org/domain/{domain}",
        timeout=TIMEOUT,
        allow_redirects=True,
        headers={
            "User-Agent": "perimeter-scanner/1.0",
            "Accept": "application/rdap+json, application/json",
        },
    )
    resp.raise_for_status()
    return resp.json()


def _parse_event_date(data: dict, action: str) -> datetime | None:
    for event in data.get("events", []):
        if event.get("eventAction", "").lower() == action:
            date_str = event.get("eventDate", "")
            try:
                dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except (ValueError, AttributeError):
                pass
    return None


def run(domain: str) -> CheckResult:
    result = CheckResult(check=CHECK_NAME)

    try:
        data = _fetch_rdap(domain)
    except RequestException as exc:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title="RDAP lookup unavailable",
            severity=Severity.INFO,
            summary=(
                "Could not retrieve domain registration data from RDAP. "
                "The TLD may not support RDAP, or the service is temporarily unavailable."
            ),
            fix="Check your registrar's portal directly for registration and expiry details.",
            raw={"error": str(exc)},
        ))
        return result

    now = datetime.now(timezone.utc)

    # --- Expiry ---
    expiry = _parse_event_date(data, "expiration")
    if expiry:
        days_left = (expiry - now).days
        expiry_str = expiry.strftime("%Y-%m-%d")

        if days_left < 0:
            result.findings.append(Finding(
                check=CHECK_NAME,
                title="Domain registration has expired",
                severity=Severity.HIGH,
                summary=f"The domain expired {abs(days_left)} day(s) ago ({expiry_str}). It may be suspended or at risk of being registered by someone else.",
                fix="Renew the domain immediately through your registrar.",
                raw={"expiry": expiry.isoformat(), "days_remaining": days_left},
            ))
        elif days_left < 30:
            result.findings.append(Finding(
                check=CHECK_NAME,
                title=f"Domain expires in {days_left} days ({expiry_str})",
                severity=Severity.HIGH,
                summary=f"Domain registration expires {expiry_str}. If not renewed, the domain will be suspended and could be registered by an attacker.",
                fix="Renew the domain now and enable auto-renew to prevent future lapses.",
                raw={"expiry": expiry.isoformat(), "days_remaining": days_left},
            ))
        elif days_left < 60:
            result.findings.append(Finding(
                check=CHECK_NAME,
                title=f"Domain expires in {days_left} days ({expiry_str})",
                severity=Severity.MEDIUM,
                summary=f"Domain registration expires {expiry_str}. Renewal should be prioritized.",
                fix="Renew the domain and confirm auto-renew is enabled with your registrar.",
                raw={"expiry": expiry.isoformat(), "days_remaining": days_left},
            ))
        elif days_left < 90:
            result.findings.append(Finding(
                check=CHECK_NAME,
                title=f"Domain expires in {days_left} days ({expiry_str})",
                severity=Severity.LOW,
                summary=f"Domain registration expires {expiry_str}. No immediate action needed, but schedule renewal soon.",
                fix="Confirm auto-renew is enabled with your registrar.",
                raw={"expiry": expiry.isoformat(), "days_remaining": days_left},
            ))
        else:
            result.findings.append(Finding(
                check=CHECK_NAME,
                title=f"Domain registration is current ({days_left} days remaining)",
                severity=Severity.PASS,
                summary=f"Domain registration is active and does not expire until {expiry_str}.",
                fix="",
                raw={"expiry": expiry.isoformat(), "days_remaining": days_left},
            ))
    else:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title="Domain expiry date not available via RDAP",
            severity=Severity.INFO,
            summary="The registrar did not include an expiry date in the RDAP response. Verify renewal status directly in your registrar's portal.",
            fix="",
            raw={"events": data.get("events", [])},
        ))

    # --- Registration age ---
    registered = _parse_event_date(data, "registration")
    if registered:
        age_days = (now - registered).days
        registered_str = registered.strftime("%Y-%m-%d")

        if age_days < 30:
            result.findings.append(Finding(
                check=CHECK_NAME,
                title=f"Domain registered only {age_days} days ago",
                severity=Severity.MEDIUM,
                summary=(
                    f"The domain was registered on {registered_str} — {age_days} day(s) ago. "
                    "Very recently registered domains are a common indicator of phishing infrastructure."
                ),
                fix="If this is your domain, no action needed. If scanning a third-party, treat this as a risk signal.",
                raw={"registered": registered.isoformat(), "age_days": age_days},
            ))
        else:
            result.findings.append(Finding(
                check=CHECK_NAME,
                title=f"Domain registered {age_days} days ago ({registered_str})",
                severity=Severity.PASS,
                summary=f"Domain has been registered since {registered_str} — an established domain.",
                fix="",
                raw={"registered": registered.isoformat(), "age_days": age_days},
            ))

    return result
