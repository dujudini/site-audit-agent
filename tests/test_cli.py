from typing import Any

import pytest
from typer.testing import CliRunner

from audit_agent import cli as cli_mod
from audit_agent.schemas import AuditReport, RunMetrics

runner = CliRunner()


def _empty_report(url: str) -> AuditReport:
    return AuditReport(
        url=url,
        status="complete",
        findings=[],
        run=RunMetrics(
            cost_usd=0.0,
            input_tokens=0,
            output_tokens=0,
            iterations=0,
            tool_calls=0,
            duration_s=0.0,
        ),
    )


def test_audit_refuses_without_authorization_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    async def fake_audit(url: str) -> Any:
        nonlocal called
        called = True
        return _empty_report(url), []

    monkeypatch.setattr(cli_mod, "_audit", fake_audit)

    result = runner.invoke(cli_mod.app, ["audit", "https://example.com"])

    assert result.exit_code == 2
    assert "--i-am-authorized" in result.output
    assert called is False, "no request may be made before the gate is passed"


def test_audit_runs_with_authorization_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_audit(url: str) -> Any:
        return _empty_report(url), []

    monkeypatch.setattr(cli_mod, "_audit", fake_audit)

    result = runner.invoke(cli_mod.app, ["audit", "https://example.com", "--i-am-authorized"])

    assert result.exit_code == 0
    assert "example.com" in result.output
