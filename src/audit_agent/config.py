"""Guardrails, model identifiers, and defaults. Everything reads from the
environment (via .env in development); nothing is hardcoded mid-code."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


def _env_str(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


def _env_float(name: str, default: float) -> float:
    return float(os.environ.get(name, default))


@dataclass(frozen=True)
class Settings:
    anthropic_api_key: str
    model_decision: str
    model_cheap: str
    google_pagespeed_key: str
    wordfence_feed_path: str

    max_iterations: int
    max_cost_usd: float
    max_tool_calls: int
    timeout_global_s: int
    timeout_tool_s: int

    user_agent: str = (
        "audit-agent/0.1 (+https://github.com/dujudini/site-audit-agent; "
        "passive collection only, respects robots.txt)"
    )
    rate_limit_per_host_s: float = 1.0


def load_settings() -> Settings:
    return Settings(
        anthropic_api_key=_env_str("ANTHROPIC_API_KEY", ""),
        model_decision=_env_str("AUDIT_AGENT_MODEL_DECISION", "claude-sonnet-5"),
        model_cheap=_env_str("AUDIT_AGENT_MODEL_CHEAP", "claude-haiku-4-5-20251001"),
        google_pagespeed_key=_env_str("GOOGLE_PAGESPEED_KEY", ""),
        wordfence_feed_path=_env_str("WORDFENCE_FEED_PATH", "wordfence_feed.json"),
        max_iterations=_env_int("AUDIT_AGENT_MAX_ITERATIONS", 12),
        max_cost_usd=_env_float("AUDIT_AGENT_MAX_COST_USD", 0.50),
        max_tool_calls=_env_int("AUDIT_AGENT_MAX_TOOL_CALLS", 30),
        timeout_global_s=_env_int("AUDIT_AGENT_TIMEOUT_GLOBAL_S", 180),
        timeout_tool_s=_env_int("AUDIT_AGENT_TIMEOUT_TOOL_S", 15),
    )
