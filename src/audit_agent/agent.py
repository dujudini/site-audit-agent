"""The loop, written by hand. Read top to bottom:

1. Run the fixed base collection (http_probe, dns_check, tls_check,
   tech_detect) — always, unconditionally, it's the starting point.
2. Enter the decision loop: send accumulated state + available tools to the
   model, ask what to call next and why.
3. Execute the chosen tool, record latency and result, append to state.
4. Record the decision and its justification in the trace.
5. Repeat until the model says it's done, or a guardrail trips.
6. Finding generation (findings.py) is a separate phase, called after this
   loop returns — this module only produces raw collected state + a decision
   trace, not a report.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from anthropic import AsyncAnthropic

from audit_agent.config import Settings, load_settings
from audit_agent.instrumentation import RunRecorder
from audit_agent.tools import ToolRegistry
from audit_agent.tools.content_probe import spec as content_probe_spec
from audit_agent.tools.dns_check import spec as dns_check_spec
from audit_agent.tools.headers_audit import spec as headers_audit_spec
from audit_agent.tools.http_probe import spec as http_probe_spec
from audit_agent.tools.perf_probe import spec as perf_probe_spec
from audit_agent.tools.tech_detect import spec as tech_detect_spec
from audit_agent.tools.tls_check import spec as tls_check_spec
from audit_agent.tools.wordpress_probe import spec as wordpress_probe_spec

SYSTEM_PROMPT = (Path(__file__).parent / "prompts" / "system.md").read_text(encoding="utf-8")

BASE_COLLECTION_TOOLS = ("http_probe", "dns_check", "tls_check", "tech_detect")


def build_registry(settings: Settings) -> ToolRegistry:
    """Always-available tools. wordpress_probe is added on top of this,
    conditionally, once tech_detect confirms WordPress — see run_agent."""
    registry = ToolRegistry()
    for make_spec in (
        http_probe_spec, dns_check_spec, tls_check_spec, tech_detect_spec,
        headers_audit_spec, content_probe_spec,
    ):
        registry.register(make_spec())
    registry.register(perf_probe_spec(settings.google_pagespeed_key))
    return registry


class GuardrailStop(Exception):
    """Raised internally when a budget trips; caught once, turns into status=partial."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _check_guardrails(recorder: RunRecorder, settings: Settings) -> None:
    if recorder.iterations >= settings.max_iterations:
        raise GuardrailStop(f"max_iterations ({settings.max_iterations}) reached")
    if recorder.tool_calls >= settings.max_tool_calls:
        raise GuardrailStop(f"max_tool_calls ({settings.max_tool_calls}) reached")
    if recorder.cost_usd >= settings.max_cost_usd:
        raise GuardrailStop(f"max_cost_usd (${settings.max_cost_usd}) reached")
    if recorder.elapsed_s() >= settings.timeout_global_s:
        raise GuardrailStop(f"timeout_global_s ({settings.timeout_global_s}) reached")


def _merge_collected(collected: dict[str, Any], tool_name: str, result: dict[str, Any]) -> None:
    """First call for a tool stores the bare result; a repeat call (same tool,
    different args — e.g. dns_check on a second subdomain) turns it into a list
    so nothing gets silently overwritten."""
    existing = collected.get(tool_name)
    if existing is None:
        collected[tool_name] = result
    elif isinstance(existing, list):
        existing.append(result)
    else:
        collected[tool_name] = [existing, result]


def _summarize(result: dict[str, Any], limit: int = 300) -> str:
    text = json.dumps(result, default=str)
    return text if len(text) <= limit else text[:limit] + "…"


async def _run_tool_with_timeout(
    registry: ToolRegistry, name: str, args: dict[str, Any],
    client: httpx.AsyncClient, timeout_s: int,
) -> dict[str, Any]:
    spec = registry.get(name)
    fn_kwargs = dict(args)
    if "client" in spec.fn.__code__.co_varnames:
        fn_kwargs["client"] = client
    try:
        return await asyncio.wait_for(spec.fn(**fn_kwargs), timeout=timeout_s)
    except TimeoutError:
        return {"error": f"tool {name} exceeded {timeout_s}s timeout"}


async def run_agent(url: str, settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or load_settings()
    domain = urlparse(url).netloc or url
    recorder = RunRecorder()
    registry = build_registry(settings)
    anthropic = AsyncAnthropic(api_key=settings.anthropic_api_key)

    async with httpx.AsyncClient(
        timeout=settings.timeout_tool_s, headers={"User-Agent": settings.user_agent}
    ) as client:
        # Step 1 — fixed base collection, always these four, unconditionally.
        state: dict[str, Any] = {"url": url, "domain": domain, "collected": {}}
        base_args = {
            "http_probe": {"url": url},
            "dns_check": {"domain": domain},
            "tls_check": {"domain": domain},
            "tech_detect": {"url": url},
        }
        for tool_name in BASE_COLLECTION_TOOLS:
            args = base_args[tool_name]
            t0 = time.monotonic()
            result = await _run_tool_with_timeout(
                registry, tool_name, args, client, settings.timeout_tool_s
            )
            latency_ms = (time.monotonic() - t0) * 1000
            state["collected"][tool_name] = result
            recorder.record_tool_call(
                iteration=0, tool=tool_name, args=args,
                reasoning="base collection, always run first",
                latency_ms=round(latency_ms, 1), result_summary=_summarize(result),
            )

        # Dynamic registry: wordpress_probe only exists for the model to call
        # once tech_detect actually found WordPress signals. An irrelevant
        # tool must not appear as an option (CLAUDE.md section 9).
        if state["collected"].get("tech_detect", {}).get("is_wordpress"):
            registry.register(wordpress_probe_spec())

        # Steps 2-5 — the decision loop.
        messages: list[dict[str, Any]] = [
            {
                "role": "user",
                "content": (
                    f"Auditing {url}. Base collection result:\n\n"
                    f"{json.dumps(state['collected'], default=str, indent=2)}\n\n"
                    "Decide the next step."
                ),
            }
        ]
        status = "complete"

        try:
            while True:
                recorder.iterations += 1
                _check_guardrails(recorder, settings)

                # Raw dicts, not the SDK's TypedDicts: messages/tools are
                # built dynamically across loop iterations and the registry.
                response = await anthropic.messages.create(
                    model=settings.model_decision,
                    max_tokens=1024,
                    system=SYSTEM_PROMPT,
                    tools=registry.schemas(),  # type: ignore[arg-type]
                    messages=messages,  # type: ignore[arg-type]
                )
                recorder.record_model_usage(
                    settings.model_decision,
                    response.usage.input_tokens,
                    response.usage.output_tokens,
                )

                tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
                text_blocks = [b for b in response.content if b.type == "text"]

                if not tool_use_blocks:
                    reasoning = " ".join(b.text for b in text_blocks)
                    state["conclusion"] = reasoning
                    break

                messages.append({"role": "assistant", "content": response.content})
                reasoning = " ".join(b.text for b in text_blocks) or "(no stated reasoning)"

                tool_results = []
                for block in tool_use_blocks:
                    _check_guardrails(recorder, settings)
                    t0 = time.monotonic()
                    result = await _run_tool_with_timeout(
                        registry, block.name, block.input, client, settings.timeout_tool_s
                    )
                    latency_ms = (time.monotonic() - t0) * 1000
                    _merge_collected(state["collected"], block.name, result)

                    recorder.record_tool_call(
                        iteration=recorder.iterations, tool=block.name, args=block.input,
                        reasoning=reasoning, latency_ms=round(latency_ms, 1),
                        result_summary=_summarize(result),
                    )
                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": json.dumps(result, default=str),
                        }
                    )

                messages.append({"role": "user", "content": tool_results})
        except GuardrailStop as stop:
            status = "partial"
            state["stopped_reason"] = stop.reason

    return {"state": state, "run": recorder.as_metrics_dict(status)}
