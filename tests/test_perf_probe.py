import httpx
import pytest
import respx

from audit_agent.tools.perf_probe import perf_probe

LIGHTHOUSE_RESPONSE = {
    "lighthouseResult": {
        "categories": {"performance": {"score": 0.42}},
        "audits": {
            "largest-contentful-paint": {"numericValue": 4200.5},
            "cumulative-layout-shift": {"numericValue": 0.15},
            "total-blocking-time": {"numericValue": 800.0},
            "first-contentful-paint": {"numericValue": 1800.0},
        },
    }
}


@pytest.mark.asyncio
async def test_perf_probe_skips_without_api_key() -> None:
    async with httpx.AsyncClient() as client:
        result = await perf_probe("https://example.com", client, api_key="")

    assert result["skipped"] is True
    assert "GOOGLE_PAGESPEED_KEY" in result["reason"]


@pytest.mark.asyncio
@respx.mock
async def test_perf_probe_extracts_core_web_vitals() -> None:
    respx.get("https://www.googleapis.com/pagespeedonline/v5/runPagespeed").mock(
        return_value=httpx.Response(200, json=LIGHTHOUSE_RESPONSE)
    )

    async with httpx.AsyncClient() as client:
        result = await perf_probe("https://example.com", client, api_key="fake-key")

    assert result["skipped"] is False
    assert result["performance_score"] == 0.42
    assert result["lcp_ms"] == 4200.5
    assert result["cls"] == 0.15
