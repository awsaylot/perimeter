"""TLS posture check — cert expiry, chain validity, protocol version."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509

from perimeter.models import CheckResult, Finding, Severity

CHECK_NAME = "TLS / Certificate"
PORT = 443
TIMEOUT = 10


def _get_cert_raw(domain: str, verify: bool = True) -> tuple[x509.Certificate, str]:
    """
    Open a TLS connection to domain:443.
    With verify=False, skips hostname and chain checks so we can inspect even
    broken certs (expired, self-signed, hostname mismatch).
    Returns (certificate, negotiated_version_string).
    """
    if verify:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((domain, PORT), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            cert_der = ssock.getpeercert(binary_form=True)
            version = ssock.version() or "unknown"

    return x509.load_der_x509_certificate(cert_der), version


def _check_cert_expiry(domain: str, cert: x509.Certificate) -> Finding:
    now = datetime.now(timezone.utc)
    expiry = cert.not_valid_after_utc
    days_left = (expiry - now).days
    expiry_str = expiry.strftime("%Y-%m-%d")

    if days_left < 0:
        return Finding(
            check=CHECK_NAME,
            title="TLS certificate is expired",
            severity=Severity.HIGH,
            summary=(
                f"The certificate for {domain} expired {abs(days_left)} day(s) ago "
                f"({expiry_str}). Browsers show a hard error and block all access."
            ),
            fix="Renew the certificate immediately. If using Let's Encrypt, check that auto-renewal is functioning.",
            raw={"expires": expiry.isoformat(), "days_remaining": days_left},
        )
    if days_left < 14:
        return Finding(
            check=CHECK_NAME,
            title=f"TLS certificate expires in {days_left} days",
            severity=Severity.HIGH,
            summary=(
                f"The certificate expires on {expiry_str} — less than two weeks away. "
                "Browsers will show errors for all visitors the moment it expires."
            ),
            fix="Renew the certificate now. If using Let's Encrypt, verify auto-renewal is running.",
            raw={"expires": expiry.isoformat(), "days_remaining": days_left},
        )
    if days_left < 30:
        return Finding(
            check=CHECK_NAME,
            title=f"TLS certificate expires in {days_left} days",
            severity=Severity.MEDIUM,
            summary=(
                f"The certificate expires on {expiry_str}. Renewal should be "
                "prioritized to avoid a browser warning before the month is out."
            ),
            fix="Renew the certificate now and verify any auto-renewal process is working.",
            raw={"expires": expiry.isoformat(), "days_remaining": days_left},
        )
    if days_left < 60:
        return Finding(
            check=CHECK_NAME,
            title=f"TLS certificate expires in {days_left} days",
            severity=Severity.LOW,
            summary=(
                f"The certificate expires on {expiry_str}. No immediate action needed, "
                "but renewal should be scheduled within the next few weeks."
            ),
            fix="Schedule certificate renewal and confirm auto-renewal is configured.",
            raw={"expires": expiry.isoformat(), "days_remaining": days_left},
        )
    return Finding(
        check=CHECK_NAME,
        title=f"TLS certificate valid for {days_left} more days",
        severity=Severity.PASS,
        summary=f"Certificate expires {expiry_str} — well within the validity window.",
        fix="",
        raw={"expires": expiry.isoformat(), "days_remaining": days_left},
    )


def _check_chain_validity(domain: str) -> Finding:
    try:
        _get_cert_raw(domain, verify=True)
        return Finding(
            check=CHECK_NAME,
            title="Certificate chain is valid",
            severity=Severity.PASS,
            summary="The certificate chain is trusted by the system root store and the hostname matches.",
            fix="",
            raw={},
        )
    except ssl.SSLCertVerificationError as exc:
        msg = str(exc).lower()
        if "self-signed" in msg or "self signed" in msg:
            title = "Self-signed certificate"
            summary = (
                f"The certificate for {domain} is self-signed — it was not issued by a "
                "trusted CA. Every browser will show a security warning to visitors."
            )
            fix = "Replace with a certificate from a trusted CA. Let's Encrypt provides free, auto-renewing certificates."
        elif "hostname" in msg or "host name" in msg:
            title = "Certificate hostname mismatch"
            summary = (
                f"The certificate presented by {domain} is issued for a different hostname. "
                "This causes a hard browser error and suggests a misconfiguration."
            )
            fix = "Ensure the certificate includes this hostname as a Subject Alternative Name (SAN)."
        elif "expired" in msg:
            title = "Certificate chain failed (expired)"
            summary = "Chain validation failed because the certificate has expired."
            fix = "Renew the certificate immediately."
        else:
            title = "Certificate chain validation failed"
            summary = (
                f"The TLS certificate chain for {domain} could not be verified against a trusted root. "
                "Browsers will block access with a security warning."
            )
            fix = "Ensure the server sends the full chain including all intermediate certificates."
        return Finding(
            check=CHECK_NAME,
            title=title,
            severity=Severity.HIGH,
            summary=summary,
            fix=fix,
            raw={"ssl_error": str(exc)},
        )


def _try_legacy_version(domain: str, version_attr: str) -> bool:
    """Attempt a handshake capped at version_attr (e.g. 'TLSv1'). Returns True if accepted."""
    version = getattr(ssl.TLSVersion, version_attr, None)
    if version is None:
        return False
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.maximum_version = version
        with socket.create_connection((domain, PORT), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain):
                return True
    except (ssl.SSLError, OSError):
        return False


def _check_tls_version(domain: str, negotiated: str) -> Finding:
    tls10 = _try_legacy_version(domain, "TLSv1")
    tls11 = _try_legacy_version(domain, "TLSv1_1")

    if tls10:
        return Finding(
            check=CHECK_NAME,
            title="Server accepts TLS 1.0 (deprecated)",
            severity=Severity.HIGH,
            summary=(
                "The server accepts TLS 1.0 connections. TLS 1.0 was deprecated in 2021 "
                "(RFC 8996) and has known weaknesses including BEAST and POODLE."
            ),
            fix="Disable TLS 1.0 and 1.1 in the server TLS configuration. Allow only TLS 1.2 and 1.3.",
            raw={"negotiated": negotiated, "tls10_accepted": True, "tls11_accepted": tls11},
        )
    if tls11:
        return Finding(
            check=CHECK_NAME,
            title="Server accepts TLS 1.1 (deprecated)",
            severity=Severity.MEDIUM,
            summary=(
                "The server accepts TLS 1.1 connections. TLS 1.1 was deprecated in 2021 "
                "(RFC 8996) and lacks the forward secrecy guarantees of TLS 1.2+."
            ),
            fix="Disable TLS 1.1 in the server TLS configuration. Allow only TLS 1.2 and 1.3.",
            raw={"negotiated": negotiated, "tls10_accepted": False, "tls11_accepted": True},
        )
    return Finding(
        check=CHECK_NAME,
        title=f"TLS protocol is current ({negotiated})",
        severity=Severity.PASS,
        summary=f"The server negotiated {negotiated}. Legacy protocol versions (TLS 1.0 / 1.1) were not accepted.",
        fix="",
        raw={"negotiated": negotiated, "tls10_accepted": False, "tls11_accepted": False},
    )


def run(domain: str) -> CheckResult:
    result = CheckResult(check=CHECK_NAME)

    # One unverified connection to get the cert and negotiated version.
    # If this fails, port 443 is unreachable and all sub-checks are moot.
    try:
        cert, negotiated = _get_cert_raw(domain, verify=False)
    except OSError as exc:
        result.findings.append(Finding(
            check=CHECK_NAME,
            title="Port 443 is not reachable",
            severity=Severity.HIGH,
            summary=(
                f"Could not connect to {domain}:443. "
                "HTTPS may not be configured or the port is blocked."
            ),
            fix="Ensure the server is configured to serve HTTPS on port 443.",
            raw={"error": str(exc)},
        ))
        return result

    errors: list[str] = []
    for fn, args in [
        (_check_cert_expiry,   (domain, cert)),
        (_check_chain_validity, (domain,)),
        (_check_tls_version,   (domain, negotiated)),
    ]:
        try:
            result.findings.append(fn(*args))
        except Exception as exc:
            errors.append(f"{fn.__name__}: {exc}")

    if errors:
        result.error = "; ".join(errors)

    return result
