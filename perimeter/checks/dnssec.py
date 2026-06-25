"""DNSSEC check — verifies the DNS zone is signed and records are authenticated."""

from __future__ import annotations

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver

from perimeter.models import CheckResult, Finding, Severity

CHECK_NAME = "DNSSEC"

# Use public DNSSEC-aware resolvers rather than the system resolver,
# which may strip RRSIG records before they reach us.
_RESOLVER = dns.resolver.Resolver()
_RESOLVER.nameservers = ["8.8.8.8", "1.1.1.1"]


def _has_dnskey(domain: str) -> bool:
    try:
        _RESOLVER.resolve(domain, "DNSKEY")
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return False


def _has_rrsig(domain: str) -> bool:
    """Send a SOA query with the EDNS DO bit set; True if the response contains RRSIG records."""
    try:
        qname = dns.name.from_text(domain)
        request = dns.message.make_query(qname, dns.rdatatype.SOA)
        request.use_edns(ednsflags=dns.flags.DO)
        response = dns.query.udp(request, "8.8.8.8", timeout=5)
        return any(
            rrset.rdtype == dns.rdatatype.RRSIG
            for rrset in response.answer
        )
    except Exception:
        return False


def run(domain: str) -> CheckResult:
    result = CheckResult(check=CHECK_NAME)

    dnskey = _has_dnskey(domain)
    rrsig = _has_rrsig(domain)

    if dnskey and rrsig:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title="DNSSEC is enabled and signing",
            severity=Severity.PASS,
            summary="DNSKEY records are published and SOA responses include RRSIG signatures.",
            fix="",
            raw={"dnskey": True, "rrsig": True},
        ))
    elif dnskey:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title="DNSKEY published but zone does not appear to be actively signing",
            severity=Severity.LOW,
            summary=(
                "DNSKEY records exist but the SOA query did not return RRSIG records. "
                "DNSSEC may be partially configured — DS records may not be published in the parent zone."
            ),
            fix="Verify zone signing is active and that DS records have been submitted to your registrar.",
            raw={"dnskey": True, "rrsig": False},
        ))
    else:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title="DNSSEC is not enabled",
            severity=Severity.MEDIUM,
            summary=(
                f"{domain} has not enabled DNSSEC. Without it, DNS responses can be spoofed "
                "via cache poisoning, silently redirecting users to attacker-controlled servers."
            ),
            fix="Enable DNSSEC through your DNS provider or registrar. Most major providers support it at no extra cost.",
            raw={"dnskey": False, "rrsig": False},
        ))

    return result
