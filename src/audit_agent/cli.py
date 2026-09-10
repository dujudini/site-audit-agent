"""Typer entrypoint."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import typer
from rich.console import Console
from rich.json import JSON

from audit_agent.agent import run_agent
from audit_agent.config import load_settings
from audit_agent.findings import generate_findings
from audit_agent.report.json_out import render_json
from audit_agent.report.markdown import render_markdown
from audit_agent.schemas import AuditReport, RunMetrics, ToolCallTrace
from audit_agent.tools.dns_check import dns_check
from audit_agent.tools.http_probe import http_probe
from audit_agent.tools.tls_check import tls_check

app = typer.Typer(add_completion=False)
console = Console()


async def _probe(url: str) -> dict[str, Any]:
    domain = urlparse(url).netloc or url

    async with httpx.AsyncClient(timeout=15) as client:
        http_result, dns_result, tls_result = await asyncio.gather(
            http_probe(url, client),
            dns_check(domain, client),
            tls_check(domain),
        )

    return {"http_probe": http_result, "dns_check": dns_result, "tls_check": tls_result}


@app.command()
def probe(url: str) -> None:
    """Run the Phase 1 foundation tools (http_probe, dns_check, tls_check) against URL, no agent."""
    result = asyncio.run(_probe(url))
    console.print(JSON.from_data(result))


async def _audit(url: str) -> tuple[AuditReport, list[dict[str, Any]]]:
    settings = load_settings()
    result = await run_agent(url, settings)
    findings, dropped = await generate_findings(result["state"], settings)

    run_data = result["run"]
    report = AuditReport(
        url=result["state"]["url"],
        status=run_data["status"],
        findings=findings,
        run=RunMetrics(
            cost_usd=run_data["cost_usd"],
            input_tokens=run_data["input_tokens"],
            output_tokens=run_data["output_tokens"],
            iterations=run_data["iterations"],
            tool_calls=run_data["tool_calls"],
            duration_s=run_data["duration_s"],
            trace=[ToolCallTrace(**t) for t in run_data["trace"]],
        ),
    )
    return report, dropped


@app.command()
def audit(
    url: str,
    out: Path | None = typer.Option(None, help="Write Markdown report to this file."),
    json_out: Path | None = typer.Option(
        None, "--json-out", help="Write JSON report to this file."
    ),
) -> None:
    """Run the full pipeline: loop + finding generation + report. Needs ANTHROPIC_API_KEY."""
    report, dropped = asyncio.run(_audit(url))

    markdown = render_markdown(report)
    console.print(markdown)
    if dropped:
        console.print(
            f"\n[yellow]{len(dropped)} finding(s) dropped for missing/invalid evidence.[/yellow]"
        )

    if out is not None:
        out.write_text(markdown, encoding="utf-8")
    if json_out is not None:
        json_out.write_text(render_json(report), encoding="utf-8")


if __name__ == "__main__":
    app()
