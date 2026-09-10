"""Render an AuditReport as human-readable Markdown, findings sorted by
severity, each one showing which tool grounds it."""

from __future__ import annotations

from audit_agent.schemas import AuditReport, Severity

SEVERITY_ORDER = {
    Severity.critical: 0, Severity.high: 1, Severity.medium: 2,
    Severity.low: 3, Severity.info: 4,
}

SEVERITY_LABEL = {
    Severity.critical: "CRITICAL", Severity.high: "HIGH",
    Severity.medium: "MEDIUM", Severity.low: "LOW", Severity.info: "INFO",
}


def render_markdown(report: AuditReport) -> str:
    lines = [f"# Audit report — {report.url}", "", f"Status: `{report.status}`", ""]

    findings = sorted(report.findings, key=lambda f: SEVERITY_ORDER[f.severity])
    if not findings:
        lines.append("No findings. Nothing in the collected data warranted flagging.")
    for f in findings:
        lines.append(f"## {SEVERITY_LABEL[f.severity]} — {f.title}")
        lines.append(f"**Category:** {f.category.value} · **Effort:** {f.effort}")
        lines.append("")
        lines.append(f.explanation)
        lines.append("")
        lines.append(f"**Recommendation:** {f.recommendation}")
        lines.append("")
        tools = ", ".join(sorted({e.tool for e in f.evidence}))
        lines.append(f"_Evidence: {tools}_")
        lines.append("")

    run = report.run
    lines.append("---")
    lines.append("## Run metrics")
    lines.append(f"- Cost: ${run.cost_usd:.4f}")
    lines.append(f"- Tokens: {run.input_tokens} in / {run.output_tokens} out")
    lines.append(f"- Iterations: {run.iterations} · Tool calls: {run.tool_calls}")
    lines.append(f"- Duration: {run.duration_s:.1f}s")
    lines.append("")
    lines.append("### Decision trace")
    for t in run.trace:
        lines.append(f"- **it.{t.iteration}** `{t.tool}` ({t.latency_ms:.0f}ms) — {t.reasoning}")

    return "\n".join(lines)
