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
        model_cheap="claude-haiku-4-5-20251001",
        google_pagespeed_key="", wordfence_feed_path="nonexistent.json",
        max_iterations=5,
        max_cost_usd=1.0,
        max_tool_calls=10,
        timeout_global_s=30,
        timeout_tool_s=5,
    )
    base.update(overrides)
    return Settings(**base)


def _mock_base_collection() -> None:
    respx.get("https://example.com/").mock(return_value=httpx.Response(200, headers={}))
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
    monkeypatch.setattr(agent_mod, "AsyncAnthropic", FakeAnthropic(responses))

    result = await agent_mod.run_agent(
        "https://example.com", settings=_settings(max_iterations=2)
    )

    assert result["run"]["status"] == "partial"
    assert result["state"]["stopped_reason"].startswith("max_iterations")
    assert result["run"]["iterations"] <= 2
