from __future__ import annotations

from datetime import UTC, datetime

from audit_agent.report.markdown import render_markdown
from audit_agent.schemas import (
    AuditReport,
    Evidence,
    Finding,
    RunMetrics,
    ToolCallTrace,
)


def _finding(severity: str, *tools: str) -> Finding:
    now = datetime.now(UTC)
    return Finding(
        id="f",
        title="t",
        category="security",
        severity=severity,
        explanation="e",
        recommendation="r",
        effort="quick",
        evidence=[Evidence(tool=t, raw={}, captured_at=now) for t in tools],
    )


def _report(findings: list[Finding], ran: list[str]) -> AuditReport:
    trace = [
        ToolCallTrace(
            iteration=0, tool=t, args={}, reasoning="r", latency_ms=1.0, result_summary="s"
        )
        for t in ran
    ]
    run = RunMetrics(
        cost_usd=0,
        input_tokens=0,
        output_tokens=0,
        iterations=0,
        tool_calls=0,
        duration_s=0,
        trace=trace,
    )
    return AuditReport(url="https://x", status="complete", findings=findings, run=run)


def test_info_finding_is_not_reported_as_a_hit() -> None:
    report = _report([_finding("info", "tls_check")], ran=["tls_check"])

    rows = {code: status for code, _, status in report.owasp_coverage()}

    assert rows["A04:2025"] == "probe available, no findings (ran: tls_check)"


def test_no_findings_says_when_the_probe_never_ran() -> None:
    report = _report([], ran=[])

    rows = {code: status for code, _, status in report.owasp_coverage()}

    assert rows["A02:2025"] == "probe available, no findings (not run in this audit)"


def test_finding_serializes_owasp_in_json() -> None:
    report = _report([_finding("low", "tls_check")], ran=["tls_check"])

    assert '"owasp":["A04:2025"]' in report.model_dump_json()
    assert "**OWASP:** A04:2025" in render_markdown(report)


def test_a_probe_that_skipped_is_not_counted_as_having_run() -> None:
    """vuln_check without a feed returns skipped; "ran: vuln_check" would read
    as "checked and clean" for A03 when nothing was checked."""
    trace = [
        ToolCallTrace(
            iteration=1,
            tool="vuln_check",
            args={},
            reasoning="r",
            latency_ms=0.0,
            result_summary="skipped",
            ok=False,
        )
    ]
    run = RunMetrics(
        cost_usd=0,
        input_tokens=0,
        output_tokens=0,
        iterations=1,
        tool_calls=1,
        duration_s=0,
        trace=trace,
    )
    report = AuditReport(url="https://x", status="complete", findings=[], run=run)

    rows = {code: status for code, _, status in report.owasp_coverage()}

    assert rows["A03:2025"] == "probe available, no findings (not run in this audit)"


def test_every_tool_in_the_owasp_map_exists_in_the_registry() -> None:
    """The map is keyed by strings: a renamed tool would silently stop tagging."""
    from audit_agent.agent import build_registry
    from audit_agent.config import load_settings
    from audit_agent.owasp import TOOL_TO_OWASP

    names = {s["name"] for s in build_registry(load_settings(), active=True).schemas()}
    names |= {"wordpress_probe", "vuln_check"}  # registered once WordPress is detected

    assert set(TOOL_TO_OWASP) <= names
