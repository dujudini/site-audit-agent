from datetime import UTC, datetime, timedelta

import pytest

from audit_agent.tools import tls_check as tls_check_mod
from audit_agent.tools.tls_check import tls_check


def _fake_fetch_cert_factory(days_left: int):
    def _fake_fetch_cert(domain: str, port: int, timeout: float) -> dict:
        now = datetime.now(UTC)
        not_after = now + timedelta(days=days_left)
        return {
            "domain": domain,
            "reachable": True,
            "issuer": "Let's Encrypt",
            "not_before": (now - timedelta(days=60)).isoformat(),
            "not_after": not_after.isoformat(),
            "days_left": days_left,
            "protocol": "TLSv1.3",
        }

    return _fake_fetch_cert


@pytest.mark.asyncio
async def test_tls_check_reports_days_left(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tls_check_mod, "_fetch_cert", _fake_fetch_cert_factory(45))

    result = await tls_check("example.com")

    assert result["reachable"] is True
    assert result["days_left"] == 45
    assert result["issuer"] == "Let's Encrypt"


@pytest.mark.asyncio
async def test_tls_check_handles_connection_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fail(domain: str, port: int, timeout: float) -> dict:
        raise OSError("connection refused")

    monkeypatch.setattr(tls_check_mod, "_fetch_cert", _fail)

    result = await tls_check("down.example.com")

    assert result["reachable"] is False
    assert "error" in result
