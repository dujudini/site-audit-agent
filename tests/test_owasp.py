from __future__ import annotations

from datetime import UTC, datetime

from audit_agent.report.markdown import render_markdown
from audit_agent.schemas import AuditReport, Evidence, Finding, RunMetrics


def _finding(category: str, *tools: str) -> Finding:
    now = datetime.now(UTC)
    return Finding(
        id="f",
        title="t",
        category=category,
        severity="low",
        explanation="e",
        recommendation="r",
        effort="quick",
        evidence=[Evidence(tool=t, raw={}, captured_at=now) for t in tools],
    )


def test_owasp_derived_from_evidence_tools_for_security_only() -> None:
    assert _finding("security", "tls_check", "headers_audit", "tls_check").owasp == [
        "A02:2025",
        "A04:2025",
    ]
    assert _finding("security", "http_probe").owasp == []
    assert _finding("performance", "tls_check").owasp == []


def test_markdown_lists_probed_and_unprobed_categories() -> None:
    run = RunMetrics(
        cost_usd=0,
        input_tokens=0,
        output_tokens=0,
        iterations=0,
        tool_calls=0,
        duration_s=0,
    )
    report = AuditReport(
        url="https://x",
        status="complete",
        findings=[_finding("security", "tls_check")],
        run=run,
    )
    md = render_markdown(report)
    assert "A04:2025 Cryptographic Failures: findings above" in md
    assert "A02:2025 Security Misconfiguration: probe available, no findings" in md
    assert "A05:2025 Injection: probe available, no findings (not run in this audit)" in md
    assert "A09:2025 Security Logging and Alerting Failures: no passive probe, not assessed" in md
