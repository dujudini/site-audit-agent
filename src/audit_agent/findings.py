"""Finding generation — a phase distinct from the investigation loop
(CLAUDE.md section 8). Takes the fully collected state and turns it into
validated Finding objects.

The model never writes `evidence.raw` itself: it only names which already-
collected tool result(s) support each finding, and this module looks that
data up from `state["collected"]`. A finding that cites a tool with no
collected result is invalid and gets dropped, not just flagged — same rule
as an empty evidence list (CLAUDE.md 3.2).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from anthropic import AsyncAnthropic
from pydantic import ValidationError

from audit_agent.config import Settings
from audit_agent.schemas import Evidence, Finding

REPORT_PROMPT = (Path(__file__).parent / "prompts" / "report.md").read_text(encoding="utf-8")

EMIT_FINDINGS_TOOL = {
    "name": "emit_findings",
    "description": "Emit the final list of audit findings derived from the collected data.",
    "input_schema": {
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "title": {"type": "string"},
                        "category": {
                            "type": "string",
                            "enum": [
                                "security", "performance", "seo",
                                "availability", "maintenance",
                            ],
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                        },
                        "explanation": {"type": "string"},
                        "recommendation": {"type": "string"},
                        "effort": {"type": "string", "enum": ["quick", "moderate", "involved"]},
                        "evidence_tools": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Names of collected tools this finding is grounded in.",
                        },
                    },
                    "required": [
                        "id", "title", "category", "severity", "explanation",
                        "recommendation", "effort", "evidence_tools",
                    ],
                },
            },
        },
        "required": ["findings"],
    },
}


def _build_evidence(
    collected: dict[str, Any], tool_names: list[str], captured_at: datetime
) -> list[Evidence] | None:
    """None means at least one cited tool has no collected data — the whole
    finding is invalid, not partially evidenced."""
    evidence = []
    for name in tool_names:
        if name not in collected:
            return None
        evidence.append(Evidence(tool=name, raw=collected[name], captured_at=captured_at))
    return evidence


async def generate_findings(
    state: dict[str, Any], settings: Settings, anthropic: AsyncAnthropic | None = None,
) -> tuple[list[Finding], list[dict[str, Any]]]:
    """Returns (valid findings, dropped) — dropped entries carry the raw model
    output plus why they were rejected, for debugging, never silently lost."""
    anthropic = anthropic or AsyncAnthropic(api_key=settings.anthropic_api_key)
    collected = state["collected"]
    captured_at = datetime.now(UTC)

    # Raw dicts, not the SDK's TypedDicts — same rationale as agent.py.
    response = await anthropic.messages.create(  # type: ignore[call-overload]
        model=settings.model_decision,
        max_tokens=4096,
        system=REPORT_PROMPT,
        tools=[EMIT_FINDINGS_TOOL],
        tool_choice={"type": "tool", "name": "emit_findings"},
        messages=[
            {
                "role": "user",
                "content": (
                    f"Collected data for {state['url']}:\n\n"
                    f"{_dump(collected)}\n\n"
                    "Investigation conclusion: "
                    f"{state.get('conclusion', '(none, run stopped early)')}\n\n"
                    "Emit the findings."
                ),
            }
        ],
    )

    tool_use = next(b for b in response.content if b.type == "tool_use")
    raw_findings = tool_use.input.get("findings", [])

    valid: list[Finding] = []
    dropped: list[dict[str, Any]] = []
    for raw in raw_findings:
        evidence_tools = raw.pop("evidence_tools", [])
        evidence = _build_evidence(collected, evidence_tools, captured_at)
        if evidence is None:
            dropped.append({"raw": raw, "reason": "cited tool has no collected result"})
            continue
        try:
            valid.append(Finding(**raw, evidence=evidence))
        except ValidationError as exc:
            dropped.append({"raw": raw, "reason": str(exc)})

    return valid, dropped


def _dump(collected: dict[str, Any]) -> str:
    return json.dumps(collected, default=str, indent=2)
