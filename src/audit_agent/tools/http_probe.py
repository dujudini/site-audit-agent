"""Status, headers, redirect chain, TTFB, and body size for one URL. Pure
function: takes a URL and an httpx.AsyncClient, returns a plain dict."""

from __future__ import annotations

import time
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


async def http_probe(url: str, client: httpx.AsyncClient) -> dict[str, Any]:
    start = time.monotonic()
    try:
        resp = await client.get(url, follow_redirects=True)
    except httpx.HTTPError as exc:
        return {"url": url, "error": str(exc), "reachable": False}

    ttfb_ms = (time.monotonic() - start) * 1000
    redirects = [str(r.url) for r in resp.history]

    return {
        "url": url,
        "reachable": True,
        "final_url": str(resp.url),
        "status_code": resp.status_code,
        "redirect_chain": redirects,
        "redirect_count": len(redirects),
        "headers": dict(resp.headers),
        "ttfb_ms": round(ttfb_ms, 1),
        "content_length": len(resp.content),
    }


def spec() -> ToolSpec:
    return ToolSpec(
        name="http_probe",
        description="Fetch a URL and report status, headers, redirect chain, TTFB, and body size.",
        parameters=SCHEMA,
        fn=http_probe,
    )
