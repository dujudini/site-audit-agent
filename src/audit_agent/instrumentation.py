"""Cost, token, and latency accounting. Every run reports real numbers —
nothing in the eventual README is an estimate.

Pricing confirmed via Anthropic's public pricing page, Sep 2026. Re-check
before trusting this for a cost-sensitive decision; prices change.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

# USD per token (list price / 1_000_000).
PRICING_PER_TOKEN: dict[str, dict[str, float]] = {
    "claude-sonnet-5": {"input": 2.00 / 1_000_000, "output": 10.00 / 1_000_000},
    "claude-haiku-4-5-20251001": {"input": 1.00 / 1_000_000, "output": 5.00 / 1_000_000},
}


def estimate_cost_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    rates = PRICING_PER_TOKEN.get(model)
    if rates is None:
        raise ValueError(
            f"no pricing entry for model {model!r}; add it to PRICING_PER_TOKEN "
            "after confirming the rate, don't silently guess"
        )
    return input_tokens * rates["input"] + output_tokens * rates["output"]


@dataclass
class ToolCallRecord:
    iteration: int
    tool: str
    args: dict[str, Any]
    reasoning: str
    latency_ms: float
    result_summary: str


@dataclass
class RunRecorder:
    """Accumulates everything the final RunMetrics needs, iteration by iteration."""

    _start: float = field(default_factory=time.monotonic)
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    iterations: int = 0
    tool_calls: int = 0
    trace: list[ToolCallRecord] = field(default_factory=list)

    def record_model_usage(self, model: str, input_tokens: int, output_tokens: int) -> None:
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens
        self.cost_usd += estimate_cost_usd(model, input_tokens, output_tokens)

    def record_tool_call(
        self, iteration: int, tool: str, args: dict[str, Any], reasoning: str,
        latency_ms: float, result_summary: str,
    ) -> None:
        self.tool_calls += 1
        self.trace.append(
            ToolCallRecord(
                iteration=iteration, tool=tool, args=args, reasoning=reasoning,
                latency_ms=latency_ms, result_summary=result_summary,
            )
        )

    def elapsed_s(self) -> float:
        return time.monotonic() - self._start

    def as_metrics_dict(self, status: str) -> dict[str, Any]:
        return {
            "status": status,
            "cost_usd": round(self.cost_usd, 6),
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "iterations": self.iterations,
            "tool_calls": self.tool_calls,
            "duration_s": round(self.elapsed_s(), 2),
            "trace": [vars(t) for t in self.trace],
        }
