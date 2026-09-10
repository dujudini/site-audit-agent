"""Dev-only utility, not a test. Calls the real Anthropic API once per case
in cases.yaml and saves the raw `emit_findings` tool input as a cassette.
test_evals.py replays these cassettes — no network, no API cost, on every
regular test run. Re-run this manually after changing prompts/report.md or
a fixture, and re-review the diff before committing new cassettes.

Usage: python evals/record_cassettes.py
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import yaml
from anthropic import AsyncAnthropic

from audit_agent.config import load_settings
from audit_agent.findings import EMIT_FINDINGS_TOOL, REPORT_PROMPT

EVALS_DIR = Path(__file__).parent


async def record_case(case: dict, settings, anthropic: AsyncAnthropic) -> None:
    fixture_dir = EVALS_DIR / case["fixture"]
    collected = json.loads((fixture_dir / "collected.json").read_text(encoding="utf-8"))
    url = collected.get("http_probe", {}).get("url", f"https://{case['name']}.example.com")

    response = await anthropic.messages.create(
        model=settings.model_decision,
        max_tokens=4096,
        system=REPORT_PROMPT,
        tools=[EMIT_FINDINGS_TOOL],
        tool_choice={"type": "tool", "name": "emit_findings"},
        messages=[
            {
                "role": "user",
                "content": (
                    f"Collected data for {url}:\n\n{json.dumps(collected, indent=2)}\n\n"
                    "Investigation conclusion: (recorded eval, no live loop)\n\n"
                    "Emit the findings."
                ),
            }
        ],
    )
    tool_use = next(b for b in response.content if b.type == "tool_use")

    cassette = {
        "model": settings.model_decision,
        "input_tokens": response.usage.input_tokens,
        "output_tokens": response.usage.output_tokens,
        "tool_use_input": tool_use.input,
    }
    (fixture_dir / "cassette.json").write_text(
        json.dumps(cassette, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"recorded {case['name']}: {len(tool_use.input.get('findings', []))} finding(s)")


async def main() -> None:
    settings = load_settings()
    if not settings.anthropic_api_key:
        raise SystemExit("ANTHROPIC_API_KEY not set — needed once, to record cassettes")

    cases = yaml.safe_load((EVALS_DIR / "cases.yaml").read_text(encoding="utf-8"))
    anthropic = AsyncAnthropic(api_key=settings.anthropic_api_key)
    for case in cases:
        await record_case(case, settings, anthropic)


if __name__ == "__main__":
    asyncio.run(main())
