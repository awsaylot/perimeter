"""DNS posture check — MX, SPF, DMARC, DKIM."""

from __future__ import annotations

import dns.exception
import dns.resolver

from perimeter.models import CheckResult, Finding, Severity

CHECK_NAME = "DNS Posture"

# Common DKIM selectors to probe. Covers Google Workspace, Microsoft 365,
# SendGrid, Klaviyo, and generic provider defaults.
DKIM_SELECTORS = [
    "default", "google", "google2", "mail", "mail2",
    "k1", "k2", "s1", "s2", "selector1", "selector2",
    "dkim", "email", "smtp",
]


def _query(qname: str, rtype: str) -> list[str]:
    """DNS lookup — returns string records; empty list on any DNS failure."""
    try:
        answers = dns.resolver.resolve(qname, rtype)
        return [r.to_text() for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return []


def _check_mx(domain: str) -> Finding:
    records = _query(domain, "MX")
    if not records:
        return Finding(
            check=CHECK_NAME,
            title="No MX records found",
            severity=Severity.LOW,
            summary=(
                f"No mail exchange records are configured for {domain}. "
                "If this domain sends or receives email, missing MX records indicate a misconfiguration."
            ),
            fix="Add MX records pointing to your mail provider, or publish a null MX (0 .) to explicitly signal that this domain accepts no mail.",
            raw={"mx_records": []},
        )
    return Finding(
        check=CHECK_NAME,
        title="MX records present",
        severity=Severity.PASS,
        summary="Mail exchange records are configured.",
        fix="",
        raw={"mx_records": records},
    )


def _check_spf(domain: str) -> Finding:
    txt_records = _query(domain, "TXT")
    spf_records = [r.strip('"') for r in txt_records if "v=spf1" in r]

    if not spf_records:
        return Finding(
            check=CHECK_NAME,
            title="SPF record missing",
            severity=Severity.MEDIUM,
            summary=(
                f"No SPF record found for {domain}. Without SPF, any server on the internet can "
                "send email claiming to be from this domain, making it trivial to spoof in phishing campaigns."
            ),
            fix=f'Publish a TXT record at {domain}: "v=spf1 include:<your-mail-provider> -all"',
            raw={"spf_record": None, "txt_records": txt_records},
        )

    record = spf_records[0]

    if "+all" in record:
        return Finding(
            check=CHECK_NAME,
            title="SPF record uses +all (any sender permitted)",
            severity=Severity.HIGH,
            summary=(
                "The SPF record contains +all, which explicitly authorizes every server on the internet "
                "to send email as this domain. This completely defeats the purpose of SPF."
            ),
            fix="Replace +all with -all in the SPF record to reject unauthorized senders.",
            raw={"spf_record": record},
        )

    if "~all" in record or "?all" in record:
        qualifier = "~all" if "~all" in record else "?all"
        return Finding(
            check=CHECK_NAME,
            title=f"SPF record uses {qualifier} (not enforcing)",
            severity=Severity.LOW,
            summary=(
                f"The SPF record uses {qualifier}, which flags unauthorized senders but does not reject them. "
                "Most mail providers will still deliver soft-fail messages, so spoofed email may get through."
            ),
            fix="Change to -all once all legitimate senders are listed in the SPF record.",
            raw={"spf_record": record},
        )

    return Finding(
        check=CHECK_NAME,
        title="SPF record present and enforcing",
        severity=Severity.PASS,
        summary="SPF is configured and uses -all, rejecting unauthorized senders.",
        fix="",
        raw={"spf_record": record},
    )


def _check_dmarc(domain: str) -> Finding:
    records = _query(f"_dmarc.{domain}", "TXT")
    dmarc_records = [r.strip('"') for r in records if "v=DMARC1" in r]

    if not dmarc_records:
        return Finding(
            check=CHECK_NAME,
            title="DMARC record missing",
            severity=Severity.MEDIUM,
            summary=(
                f"No DMARC record found at _dmarc.{domain}. Without DMARC, receiving servers have "
                "no policy guidance for messages that fail SPF or DKIM, so spoofed mail may be delivered."
            ),
            fix=f'Publish a TXT record at _dmarc.{domain}: "v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}"',
            raw={"dmarc_record": None},
        )

    record = dmarc_records[0]

    policy: str | None = None
    for part in record.split(";"):
        part = part.strip()
        if part.startswith("p="):
            policy = part[2:].strip().lower()
            break

    if policy == "none":
        return Finding(
            check=CHECK_NAME,
            title="DMARC policy is p=none (monitor only, not enforcing)",
            severity=Severity.LOW,
            summary=(
                "DMARC is present but set to p=none — messages that fail authentication are only "
                "reported, not quarantined or rejected. This gives visibility without any enforcement."
            ),
            fix="Escalate to p=quarantine or p=reject to actively block spoofed email.",
            raw={"dmarc_record": record, "policy": policy},
        )

    if policy == "quarantine":
        return Finding(
            check=CHECK_NAME,
            title="DMARC policy is p=quarantine",
            severity=Severity.INFO,
            summary=(
                "DMARC is configured with p=quarantine — failing messages are sent to spam rather than "
                "rejected outright. Consider upgrading to p=reject for maximum enforcement."
            ),
            fix="Upgrade to p=reject once confident that all legitimate mail passes DMARC.",
            raw={"dmarc_record": record, "policy": policy},
        )

    return Finding(
        check=CHECK_NAME,
        title="DMARC policy is enforcing",
        severity=Severity.PASS,
        summary=f"DMARC is configured with p={policy}, providing strong protection against email spoofing.",
        fix="",
        raw={"dmarc_record": record, "policy": policy},
    )


def _check_dkim(domain: str) -> Finding:
    found: list[dict] = []
    for selector in DKIM_SELECTORS:
        records = _query(f"{selector}._domainkey.{domain}", "TXT")
        if records:
            found.append({"selector": selector, "record": records[0]})

    if not found:
        return Finding(
            check=CHECK_NAME,
            title="DKIM not detected at common selectors",
            severity=Severity.LOW,
            summary=(
                "No DKIM public key was found at any of the common selectors checked. DKIM may be "
                "configured under a non-standard selector, but if it is absent, receiving servers "
                "cannot verify that messages from this domain were not tampered with in transit."
            ),
            fix="Configure DKIM signing in your mail provider and publish the public key as a DNS TXT record.",
            raw={"selectors_checked": DKIM_SELECTORS, "selectors_found": []},
        )

    return Finding(
        check=CHECK_NAME,
        title="DKIM record found",
        severity=Severity.PASS,
        summary=f"DKIM public key detected at selector(s): {', '.join(f['selector'] for f in found)}.",
        fix="",
        raw={"selectors_found": found},
    )


def run(domain: str) -> CheckResult:
    result = CheckResult(check=CHECK_NAME)
    errors: list[str] = []

    for fn in [_check_mx, _check_spf, _check_dmarc, _check_dkim]:
        try:
            result.findings.append(fn(domain))
        except Exception as exc:
            errors.append(f"{fn.__name__}: {exc}")

    if errors:
        result.error = "; ".join(errors)

    return result
