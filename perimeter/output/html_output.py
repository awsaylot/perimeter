"""HTML report renderer using Jinja2."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from perimeter.models import ScanResult, Severity

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


def _counts(result: ScanResult) -> dict:
    findings = result.all_findings
    return {
        "total": len(findings),
        "high":   sum(1 for f in findings if f.severity == Severity.HIGH),
        "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
        "low":    sum(1 for f in findings if f.severity == Severity.LOW),
        "info":   sum(1 for f in findings if f.severity == Severity.INFO),
        "passed": sum(1 for f in findings if f.severity == Severity.PASS),
    }


def to_html(result: ScanResult) -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["tojson"] = __import__("json").dumps
    template = env.get_template("report.html")
    return template.render(result=result, counts=_counts(result))


def write_report(result: ScanResult, path: str) -> None:
    Path(path).write_text(to_html(result), encoding="utf-8")
