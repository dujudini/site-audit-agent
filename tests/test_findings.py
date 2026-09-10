"""Finding generation is a separate phase from the loop (CLAUDE.md 3.2 and
section 8): the model names which collected tool backs a finding, and this
module is the one place that decides whether that evidence is real."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from audit_agent.config import Settings
from audit_agent.findings import generate_findings


@dataclass
class ToolUseBlock:
    input: dict[str, Any]
    type: str = "tool_use"


@dataclass
class FakeResponse:
    content: list[Any]


class FakeMessages:
    def __init__(self, response: FakeResponse) -> None:
        self._response = response

    async def create(self, **kwargs: Any) -> FakeResponse:
        return self._response


class FakeAnthropic:
    def __init__(self, response: FakeResponse) -> None:
        self.messages = FakeMessages(response)


def _settings() -> Settings:
    return Settings(
        anthropic_api_key="test-key",
        model_decision="claude-sonnet-5",
        model_cheap="claude-haiku-4-5-20251001",
        google_pagespeed_key="",
        wordfence_feed_path="nonexistent.json",
        max_iterations=5,
        max_cost_usd=1.0,
        max_tool_calls=10,
        timeout_global_s=30,
        timeout_tool_s=5,
    )


@pytest.mark.asyncio
async def test_finding_with_real_evidence_is_kept() -> None:
    state = {
        "url": "https://example.com",
        "collected": {"tls_check": {"domain": "example.com", "days_left": 3}},
    }
    response = FakeResponse(
        content=[
            ToolUseBlock(
                input={
                    "findings": [
                        {
                            "id": "tls-expiry",
                            "title": "Certificate expires in 3 days",
                            "category": "security",
                            "severity": "critical",
                            "explanation": "Cert about to expire.",
                            "recommendation": "Renew now.",
                            "effort": "quick",
                            "evidence_tools": ["tls_check"],
                        }
                    ]
                }
            )
        ]
    )

    findings, dropped = await generate_findings(
        state, _settings(), anthropic=FakeAnthropic(response)
    )

    assert len(findings) == 1
    assert dropped == []
    assert findings[0].evidence[0].raw == {"domain": "example.com", "days_left": 3}


@pytest.mark.asyncio
async def test_finding_citing_uncollected_tool_is_dropped() -> None:
    """The model claims a finding is backed by a tool that never ran — this
    must be discarded, not flagged, per CLAUDE.md 3.2."""
    state = {"url": "https://example.com", "collected": {"tls_check": {"days_left": 90}}}
    response = FakeResponse(
        content=[
            ToolUseBlock(
                input={
                    "findings": [
                        {
                            "id": "phantom",
                            "title": "Made-up finding",
                            "category": "security",
                            "severity": "high",
                            "explanation": "x",
                            "recommendation": "y",
                            "effort": "quick",
                            "evidence_tools": ["wordpress_probe"],
                        }
                    ]
                }
            )
        ]
    )

    findings, dropped = await generate_findings(
        state, _settings(), anthropic=FakeAnthropic(response)
    )

    assert findings == []
    assert len(dropped) == 1
    assert "no collected result" in dropped[0]["reason"]


@pytest.mark.asyncio
async def test_empty_findings_list_is_valid() -> None:
    state = {"url": "https://healthy.example.com", "collected": {"tls_check": {"days_left": 90}}}
    response = FakeResponse(content=[ToolUseBlock(input={"findings": []})])

    findings, dropped = await generate_findings(
        state, _settings(), anthropic=FakeAnthropic(response)
    )

    assert findings == []
    assert dropped == []
