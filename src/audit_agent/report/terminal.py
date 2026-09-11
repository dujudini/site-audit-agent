"""Rich-native rendering for what a person watches scroll by in a terminal:
one colored panel per finding, sorted by severity, plus a metrics table and
the decision trace. Markdown (markdown.py) and JSON (json_out.py) stay the
portable formats for --out / --json-out; this is terminal-only."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from audit_agent.schemas import AuditReport, Finding, Severity

# The model writes free-text (title, explanation, reasoning) and naturally
# uses typographic Unicode punctuation. Rich's legacy Windows console
# renderer encodes as cp1252 and silently mangles characters outside it
# (e.g. em-dash) into "?" instead of raising, so sanitize before printing.
# Files (markdown.py, json_out.py) keep the original Unicode; this is
# terminal-display-only.
_ASCII_SAFE = str.maketrans({
    "—": "-", "–": "-",  # em dash, en dash
    "‘": "'", "’": "'",  # curly single quotes
    "“": '"', "”": '"',  # curly double quotes
    "…": "...",  # ellipsis
    "·": "*",  # middle dot
})


def _safe(text: str) -> str:
    return text.translate(_ASCII_SAFE)


SEVERITY_ORDER = {s: i for i, s in enumerate(Severity)}

SEVERITY_BORDER = {
    Severity.critical: "red",
    Severity.high: "red",
    Severity.medium: "yellow",
    Severity.low: "blue",
    Severity.info: "grey50",
}

SEVERITY_TITLE_STYLE = {
    Severity.critical: "bold white on red",
    Severity.high: "bold red",
    Severity.medium: "bold yellow",
    Severity.low: "bold blue",
    Severity.info: "dim",
}


def _finding_panel(finding: Finding) -> Panel:
    title = Text(f" {finding.severity.value.upper()}  {_safe(finding.title)} ")
    title.stylize(SEVERITY_TITLE_STYLE[finding.severity])

    body = Text()
    body.append(f"{finding.category.value} | {finding.effort}\n\n", style="dim")
    body.append(_safe(finding.explanation) + "\n\n")
    body.append("Recommendation: ", style="bold")
    body.append(_safe(finding.recommendation) + "\n\n")
    tools = ", ".join(sorted({e.tool for e in finding.evidence}))
    body.append(f"Evidence: {tools}", style="italic dim")

    return Panel(
        body, title=title, title_align="left",
        border_style=SEVERITY_BORDER[finding.severity], expand=True,
    )


def render_terminal(console: Console, report: AuditReport) -> None:
    console.print(f"[bold]Audit report[/bold]  {report.url}")
    console.print(f"Status: [bold]{report.status}[/bold]\n")

    findings = sorted(report.findings, key=lambda f: SEVERITY_ORDER[f.severity])
    if not findings:
        console.print("No findings. Nothing in the collected data warranted flagging.\n")
    for f in findings:
        console.print(_finding_panel(f))

    run = report.run
    table = Table(title="Run metrics", show_header=False, box=None, padding=(0, 2, 0, 0))
    table.add_row("Cost", f"${run.cost_usd:.4f}")
    table.add_row("Tokens", f"{run.input_tokens} in / {run.output_tokens} out")
    table.add_row("Iterations", str(run.iterations))
    table.add_row("Tool calls", str(run.tool_calls))
    table.add_row("Duration", f"{run.duration_s:.1f}s")
    console.print(table)

    console.print("\n[bold]Decision trace[/bold]")
    for t in run.trace:
        console.print(
            f"  it.{t.iteration} [cyan]{t.tool}[/cyan] "
            f"({t.latency_ms:.0f}ms): {_safe(t.reasoning)}"
        )
