"""Performance via Google PageSpeed Insights (free, quota-limited). Needs
GOOGLE_PAGESPEED_KEY — degrades to an explicit note instead of failing the
whole audit when the key is missing, since perf is one signal among many."""

from __future__ import annotations

from typing import Any

import httpx

from audit_agent.tools import ToolSpec

SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "Target URL, including scheme."},
    },
    "required": ["url"],
}

PAGESPEED_ENDPOINT = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"


async def perf_probe(url: str, client: httpx.AsyncClient, api_key: str) -> dict[str, Any]:
    if not api_key:
        return {
            "url": url,
            "skipped": True,
            "reason": "GOOGLE_PAGESPEED_KEY not set",
        }

    try:
        resp = await client.get(
            PAGESPEED_ENDPOINT,
            params={"url": url, "key": api_key, "category": "PERFORMANCE", "strategy": "mobile"},
            timeout=30,
        )
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        return {"url": url, "skipped": True, "reason": str(exc)}

    data = resp.json()
    lighthouse = data.get("lighthouseResult", {})
    categories = lighthouse.get("categories", {})
    audits = lighthouse.get("audits", {})

    def metric(audit_id: str, ndigits: int) -> float | None:
        value = audits.get(audit_id, {}).get("numericValue")
        return round(value, ndigits) if value is not None else None

    return {
        "url": url,
        "skipped": False,
        "performance_score": categories.get("performance", {}).get("score"),
        "lcp_ms": metric("largest-contentful-paint", 1),
        "cls": metric("cumulative-layout-shift", 3),
        "tbt_ms": metric("total-blocking-time", 1),
        "fcp_ms": metric("first-contentful-paint", 1),
    }


def spec(api_key: str) -> ToolSpec:
    async def bound(url: str, client: httpx.AsyncClient) -> dict[str, Any]:
        return await perf_probe(url, client, api_key)

    return ToolSpec(
        name="perf_probe",
        description=(
            "Run Google PageSpeed Insights (mobile) and report LCP, CLS, "
            "TBT, FCP, and the performance score."
        ),
        parameters=SCHEMA,
        fn=bound,
    )
