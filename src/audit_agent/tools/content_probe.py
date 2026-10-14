"""title, meta description, headings, robots.txt, sitemap, canonical — the
minimum SEO/content hygiene signals a maintenance client cares about."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin

import httpx

from audit_agent.tools import ToolSpec

SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "Target URL, including scheme."},
    },
    "required": ["url"],
}

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
META_DESC_RE = re.compile(
    r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']*)', re.I
)
CANONICAL_RE = re.compile(r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)', re.I)
HEADING_RE = re.compile(r"<h([1-6])\b", re.I)


# /wp-sitemap.xml is what WordPress core serves by default since 5.5, so
# checking only /sitemap.xml would flag a stock WordPress site as having none.
SITEMAP_PATHS = ("/sitemap.xml", "/sitemap_index.xml", "/wp-sitemap.xml")


_HTML_START = re.compile(r"\s*<(!doctype|html)", re.I)
_SITEMAP = re.compile(r"<(urlset|sitemapindex)\b", re.I)


async def _exists(
    client: httpx.AsyncClient, url: str, looks_right: Callable[[str], bool]
) -> bool:
    """A 200 alone proves nothing: a single-page app answers 200 with its HTML
    shell for every path. shortcut: downloads the whole file, fine up to a few
    MB of sitemap; stream it if a site ever ships a huge one."""
    try:
        resp = await client.get(url, follow_redirects=True)
    except httpx.HTTPError:
        return False
    return resp.status_code == 200 and looks_right(resp.text[:4096])


async def content_probe(url: str, client: httpx.AsyncClient) -> dict[str, Any]:
    try:
        resp = await client.get(url, follow_redirects=True)
    except httpx.HTTPError as exc:
        return {"url": url, "error": str(exc), "reachable": False}

    html = resp.text
    title_match = TITLE_RE.search(html)
    desc_match = META_DESC_RE.search(html)
    canonical_match = CANONICAL_RE.search(html)
    heading_counts: dict[str, int] = {}
    for level in HEADING_RE.findall(html):
        key = f"h{level}"
        heading_counts[key] = heading_counts.get(key, 0) + 1

    base = str(resp.url)
    has_robots = await _exists(
        client, urljoin(base, "/robots.txt"), lambda text: not _HTML_START.match(text)
    )
    # Independent of robots.txt: a site can have a sitemap and no robots.txt.
    has_sitemap = False
    for path in SITEMAP_PATHS:
        if await _exists(client, urljoin(base, path), lambda text: bool(_SITEMAP.search(text))):
            has_sitemap = True
            break

    return {
        "url": url,
        "reachable": True,
        "title": title_match.group(1).strip() if title_match else None,
        "meta_description": desc_match.group(1).strip() if desc_match else None,
        "canonical": canonical_match.group(1) if canonical_match else None,
        "heading_counts": heading_counts,
        "has_robots_txt": has_robots,
        "has_sitemap_xml": has_sitemap,
    }


def spec() -> ToolSpec:
    return ToolSpec(
        name="content_probe",
        description=(
            "Report title, meta description, canonical, heading structure, "
            "robots.txt and sitemap.xml presence."
        ),
        parameters=SCHEMA,
        fn=content_probe,
    )
