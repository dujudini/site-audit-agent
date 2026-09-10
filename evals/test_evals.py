"""Runs the agent's finding-generation stage against 8 fixtures with known
answers, replaying pre-recorded model responses (evals/record_cassettes.py)
— no network, no API cost on a normal `pytest` run.

The healthy_site case is the one that matters most: `must_not_find_any`
means no finding above `info` severity — CLAUDE.md 10 says an agent that
always finds something is a useless agent, and info-severity is precisely
the schema's slot for "checked, nothing wrong" (CLAUDE.md 7 defines it that
way), so a healthy site returning one info-level summary is correct, not a
false positive.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml

from audit_agent.config import Settings
from audit_agent.findings import generate_findings
from audit_agent.schemas import Finding

EVALS_DIR = Path(__file__).parent
CASES = yaml.safe_load((EVALS_DIR / "cases.yaml").read_text(encoding="utf-8"))


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
        anthropic_api_key="cassette-replay-needs-no-real-key",
        model_decision="claude-sonnet-5", model_cheap="claude-haiku-4-5-20251001",
        google_pagespeed_key="", max_iterations=12, max_cost_usd=0.50,
        max_tool_calls=30, timeout_global_s=180, timeout_tool_s=15,
    )


def _load_case(case: dict) -> tuple[dict, dict]:
    fixture_dir = EVALS_DIR / case["fixture"]
    collected = json.loads((fixture_dir / "collected.json").read_text(encoding="utf-8"))
    cassette_path = fixture_dir / "cassette.json"
    if not cassette_path.exists():
        pytest.skip(f"no cassette for {case['name']}; run evals/record_cassettes.py")
    cassette = json.loads(cassette_path.read_text(encoding="utf-8"))
    return collected, cassette


async def _run_case(case: dict) -> tuple[list[Finding], list[dict]]:
    collected, cassette = _load_case(case)
    url = collected.get("http_probe", {}).get("url", f"https://{case['name']}.example.com")
    state = {"url": url, "collected": collected, "conclusion": "(recorded eval)"}

    response = FakeResponse(content=[ToolUseBlock(input=cassette["tool_use_input"])])
    return await generate_findings(state, _settings(), anthropic=FakeAnthropic(response))


def _matches_spec(finding: Finding, spec: dict) -> bool:
    if "category" in spec and finding.category.value != spec["category"]:
        return False
    if "severity" in spec and finding.severity.value != spec["severity"]:
        return False
    if "matches" in spec:
        haystack = f"{finding.title} {finding.explanation}".lower()
        if spec["matches"].lower() not in haystack:
            return False
    return True


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
async def test_eval_case(case: dict) -> None:
    findings, dropped = await _run_case(case)
    assert dropped == [], f"{case['name']}: findings dropped for invalid evidence: {dropped}"

    if case.get("must_not_find_any"):
        non_info = [f for f in findings if f.severity.value != "info"]
        assert non_info == [], (
            f"{case['name']}: healthy fixture produced non-info finding(s): "
            f"{[f.title for f in non_info]}"
        )
        return

    for spec in case.get("must_find", []):
        assert any(_matches_spec(f, spec) for f in findings), (
            f"{case['name']}: no finding matched {spec}; got "
            f"{[(f.category.value, f.severity.value, f.title) for f in findings]}"
        )

    for spec in case.get("must_not_find", []):
        # info severity is "checked, all good" (see module docstring) — it
        # isn't a reported problem, so it doesn't violate a must_not_find.
        matching = [
            f for f in findings if f.severity.value != "info" and _matches_spec(f, spec)
        ]
        assert matching == [], f"{case['name']}: unexpected finding(s) matching {spec}: {matching}"


@pytest.mark.asyncio
async def test_eval_recall_and_precision_summary() -> None:
    """Aggregate numbers, printed for the README (CLAUDE.md 10 and 11)."""
    total_must_find = 0
    matched_must_find = 0
    total_findings = 0

    for case in CASES:
        findings, _ = await _run_case(case)
        total_findings += len(findings)
        for spec in case.get("must_find", []):
            total_must_find += 1
            if any(_matches_spec(f, spec) for f in findings):
                matched_must_find += 1

    recall = matched_must_find / total_must_find if total_must_find else 1.0
    precision = matched_must_find / total_findings if total_findings else 1.0

    print(
        f"\nrecall={recall:.2f} ({matched_must_find}/{total_must_find} planted issues found) "
        f"precision~={precision:.2f} ({matched_must_find}/{total_findings} findings were expected)"
    )
    assert recall == 1.0, "every planted problem across the 8 cases must be found"
