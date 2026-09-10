"""Contract for the whole system. `explanation` and `recommendation` are the
only fields the LLM writes freely; everything else is derived from a tool
call or a fixed rule."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Category(StrEnum):
    security = "security"
    performance = "performance"
    seo = "seo"
    availability = "availability"
    maintenance = "maintenance"


class Evidence(BaseModel):
    tool: str
    # dict for a tool called once; list[dict] when the model called the same
    # tool again with different args (e.g. dns_check on a second subdomain).
    raw: dict[str, Any] | list[dict[str, Any]]
    captured_at: datetime


class Finding(BaseModel):
    id: str
    title: str
    category: Category
    severity: Severity
    explanation: str
    recommendation: str
    effort: Literal["quick", "moderate", "involved"]
    evidence: list[Evidence]

    @field_validator("evidence")
    @classmethod
    def evidence_required(cls, v: list[Evidence]) -> list[Evidence]:
        if not v:
            raise ValueError("a Finding without evidence is invalid, not just unverified")
        return v


class ToolCallTrace(BaseModel):
    iteration: int
    tool: str
    args: dict[str, Any]
    reasoning: str
    latency_ms: float
    result_summary: str


class RunMetrics(BaseModel):
    cost_usd: float
    input_tokens: int
    output_tokens: int
    iterations: int
    tool_calls: int
    duration_s: float
    trace: list[ToolCallTrace] = Field(default_factory=list)


class AuditReport(BaseModel):
    url: str
    status: Literal["complete", "partial"]
    findings: list[Finding]
    run: RunMetrics
