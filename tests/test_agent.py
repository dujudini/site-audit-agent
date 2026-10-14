"""Loop mechanics, with the Anthropic API and the network both faked — this
tests decision-conditioning, guardrails and instrumentation, not live model
behavior (that's what a manual `audit-agent` run and, later, evals are for)."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import respx

from audit_agent import agent as agent_mod
from audit_agent.config import Settings


@dataclass
class TextBlock:
    text: str
    type: str = "text"


@dataclass
class ToolUseBlock:
    name: str
    input: dict[str, Any]
    id: str
    type: str = "tool_use"


@dataclass
class FakeResponse:
    content: list[Any]
    usage: SimpleNamespace = field(
        default_factory=lambda: SimpleNamespace(input_tokens=100, output_tokens=50)
    )


class FakeMessages:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self._responses = iter(responses)
        self.calls: list[dict[str, Any]] = []

    async def create(self, **kwargs: Any) -> FakeResponse:
        self.calls.append(kwargs)
        return next(self._responses)


class FakeAnthropic:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.messages = FakeMessages(responses)

    def __call__(self, api_key: str) -> FakeAnthropic:
        return self


def _settings(**overrides: Any) -> Settings:
    base = dict(
        anthropic_api_key="test-key",
        model_decision="claude-sonnet-5",
        google_pagespeed_key="",
        wordfence_feed_path="nonexistent.json",
        max_iterations=5,
        max_cost_usd=1.0,
        max_tool_calls=10,
        timeout_global_s=30,
        timeout_tool_s=5,
    )
    base.update(overrides)
    return Settings(**base)


def _mock_base_collection() -> None:
    respx.route(host="example.com").mock(return_value=httpx.Response(200, headers={}))
    respx.get("https://cloudflare-dns.com/dns-query").mock(
        return_value=httpx.Response(200, json={})
    )


@pytest.mark.asyncio
@respx.mock
async def test_agent_conditions_decision_on_prior_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The model's second call must be informed by the tls_check result from
    the first — this is the one behavior the whole project exists to prove."""
    _mock_base_collection()

    async def fake_tls_check(domain: str, port: int = 443, timeout: float = 10.0) -> dict:
        return {"domain": domain, "reachable": True, "days_left": 3, "issuer": "Let's Encrypt"}

    import audit_agent.tools.tls_check as tls_mod

    monkeypatch.setattr(tls_mod, "tls_check", fake_tls_check)

    responses = [
        FakeResponse(
            content=[
                TextBlock(text="Certificate expires in 3 days, that's the highest-severity lead."),
                ToolUseBlock(name="dns_check", input={"domain": "example.com"}, id="call_1"),
            ]
        ),
        FakeResponse(
            content=[TextBlock(text="Certificate near expiry confirmed and well-evidenced. Done.")]
        ),
    ]
    monkeypatch.setattr(agent_mod, "AsyncAnthropic", FakeAnthropic(responses))

    result = await agent_mod.run_agent("https://example.com", settings=_settings())

    assert result["run"]["status"] == "complete"
    trace = result["run"]["trace"]
    conditioned = [t for t in trace if "3 days" in t["reasoning"]]
    assert conditioned, "expected a trace entry whose reasoning cites the prior tls_check result"
    assert result["run"]["iterations"] == 2
    assert result["run"]["cost_usd"] > 0


@pytest.mark.asyncio
@respx.mock
async def test_agent_stops_at_max_iterations(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_base_collection()

    async def fake_tls_check(domain: str, port: int = 443, timeout: float = 10.0) -> dict:
        return {"domain": domain, "reachable": True, "days_left": 200, "issuer": "Let's Encrypt"}

    import audit_agent.tools.tls_check as tls_mod

    monkeypatch.setattr(tls_mod, "tls_check", fake_tls_check)

    def _always_wants_another_tool() -> FakeResponse:
        return FakeResponse(
            content=[
                TextBlock(text="Still digging."),
                ToolUseBlock(name="dns_check", input={"domain": "example.com"}, id="call_x"),
            ]
        )

    responses = [_always_wants_another_tool() for _ in range(10)]
    fake = FakeAnthropic(responses)
    monkeypatch.setattr(agent_mod, "AsyncAnthropic", fake)

    result = await agent_mod.run_agent("https://example.com", settings=_settings(max_iterations=2))

    assert result["run"]["status"] == "partial"
    assert result["state"]["stopped_reason"].startswith("max_iterations")
    assert result["run"]["iterations"] == 2
    assert len(fake.messages.calls) == 2, "max_iterations=2 must allow exactly 2 model calls"


def _registry_with(fn: Any, name: str = "t") -> Any:
    from audit_agent.tools import ToolRegistry, ToolSpec

    registry = ToolRegistry()
    registry.register(ToolSpec(name=name, description="", parameters={}, fn=fn))
    return registry


@pytest.mark.asyncio
async def test_a_tool_that_raises_becomes_an_error_result_not_a_crash() -> None:
    """Seen for real: a DoH resolver behind a proxy answered 200 with HTML and
    resp.json() raised, which used to kill the whole paid-for audit."""

    async def boom(url: str) -> dict[str, Any]:
        raise ValueError("Expecting value: line 1 column 1")

    async with httpx.AsyncClient() as client:
        result = await agent_mod._run_tool_with_timeout(
            _registry_with(boom), "t", {"url": "x"}, client, 5
        )

    assert "ValueError" in result["error"]


@pytest.mark.asyncio
async def test_a_wrong_argument_name_from_the_model_is_an_error_result() -> None:
    async def takes_url(url: str) -> dict[str, Any]:
        return {"ok": True}

    async with httpx.AsyncClient() as client:
        result = await agent_mod._run_tool_with_timeout(
            _registry_with(takes_url), "t", {"domain": "x"}, client, 5
        )

    assert "TypeError" in result["error"]


def test_normalize_url_adds_a_scheme_only_when_missing() -> None:
    assert agent_mod.normalize_url("dujudini.com.br") == "https://dujudini.com.br"
    assert agent_mod.normalize_url("http://example.com") == "http://example.com"


def test_succeeded_rejects_skipped_errored_and_unreachable_results() -> None:
    ok = agent_mod._succeeded
    assert ok({"exposed": []}) is True
    assert ok({"skipped": True, "reason": "feed not found"}) is False
    assert ok({"error": "tool x exceeded 15s timeout"}) is False
    assert ok({"reachable": False}) is False


@pytest.mark.asyncio
async def test_unknown_model_fails_before_spending_anything() -> None:
    with pytest.raises(ValueError, match="no pricing entry"):
        await agent_mod.run_agent(
            "https://example.com", settings=_settings(model_decision="not-a-priced-model")
        )


@pytest.mark.asyncio
@respx.mock
async def test_security_probes_run_in_the_base_collection_without_the_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The model concludes immediately and calls nothing, yet every probe that
    feeds the OWASP coverage has already run."""
    _mock_base_collection()
    import audit_agent.tools.tls_check as tls_mod

    async def fake_tls_check(domain: str, port: int = 443, timeout: float = 10.0) -> dict:
        return {"domain": domain, "reachable": True, "days_left": 90, "issuer": "x"}

    monkeypatch.setattr(tls_mod, "tls_check", fake_tls_check)
    done = FakeResponse(content=[TextBlock(text="Nothing more to check.")])
    monkeypatch.setattr(agent_mod, "AsyncAnthropic", FakeAnthropic([done]))

    result = await agent_mod.run_agent("https://example.com", settings=_settings())

    ran_at_start = {t["tool"] for t in result["run"]["trace"] if t["iteration"] == 0}
    assert {"headers_audit", "exposure_probe", "integrity_probe", "auth_probe"} <= ran_at_start
