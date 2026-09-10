"""CMS, framework, server, analytics, and versions exposed in HTML/headers.
Drives the dynamic registry: run_agent registers wordpress_probe only after
this tool reports is_wordpress=True."""

from __future__ import annotations

import re
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

GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
WP_CONTENT_RE = re.compile(r"/wp-content/", re.I)
WP_JSON_RE = re.compile(r"/wp-json/", re.I)

ANALYTICS_SIGNALS = {
    "gtag(": "Google Analytics (gtag.js)",
    "googletagmanager.com": "Google Tag Manager",
    "google-analytics.com": "Google Analytics (legacy)",
    "connect.facebook.net": "Meta Pixel",
    "hotjar.com": "Hotjar",
}

FRAMEWORK_SIGNALS = {
    "cdn.shopify.com": "Shopify",
    "_next/static": "Next.js",
    "__NUXT__": "Nuxt.js",
    "wp-content": "WordPress",
    "sites/default/files": "Drupal",
    "joomla": "Joomla",
    "squarespace.com": "Squarespace",
    "wixstatic.com": "Wix",
}


async def tech_detect(url: str, client: httpx.AsyncClient) -> dict[str, Any]:
    try:
        resp = await client.get(url, follow_redirects=True)
    except httpx.HTTPError as exc:
        return {"url": url, "error": str(exc), "reachable": False}

    html = resp.text
    headers = {k.lower(): v for k, v in resp.headers.items()}

    generator_match = GENERATOR_RE.search(html)
    generator = generator_match.group(1) if generator_match else None

    is_wordpress = bool(
        WP_CONTENT_RE.search(html)
        or WP_JSON_RE.search(html)
        or (generator and "wordpress" in generator.lower())
    )

    frameworks = sorted({name for sig, name in FRAMEWORK_SIGNALS.items() if sig in html})
    analytics = sorted({name for sig, name in ANALYTICS_SIGNALS.items() if sig in html})

    return {
        "url": url,
        "reachable": True,
        "server_header": headers.get("server"),
        "x_powered_by": headers.get("x-powered-by"),
        "generator_meta": generator,
        "is_wordpress": is_wordpress,
        "frameworks_detected": frameworks,
        "analytics_detected": analytics,
    }


def spec() -> ToolSpec:
    return ToolSpec(
        name="tech_detect",
        description=(
            "Detect CMS/framework/server/analytics from HTML and headers; "
            "flags WordPress for wordpress_probe."
        ),
        parameters=SCHEMA,
        fn=tech_detect,
    )
