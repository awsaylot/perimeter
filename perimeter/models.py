"""Shared data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    PASS = "pass"


@dataclass
class Finding:
    """A single observation from a check."""

    check: str        # e.g. "DNS Posture"
    title: str        # e.g. "DMARC record missing"
    severity: Severity
    summary: str      # plain-English: what it is and why it matters
    fix: str          # one-line suggested remediation
    raw: dict[str, Any] = field(default_factory=dict)  # technical detail for appendix


@dataclass
class CheckResult:
    """Output of one check module."""

    check: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None  # set if the check itself failed


@dataclass
class ScanResult:
    """Aggregate result for a full domain scan."""

    domain: str
    check_results: list[CheckResult] = field(default_factory=list)

    @property
    def all_findings(self) -> list[Finding]:
        return [f for cr in self.check_results for f in cr.findings]

    @property
    def actionable_findings(self) -> list[Finding]:
        """Everything except PASS and INFO."""
        return [f for f in self.all_findings if f.severity not in (Severity.PASS, Severity.INFO)]
