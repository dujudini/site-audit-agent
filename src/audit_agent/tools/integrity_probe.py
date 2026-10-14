"""Third-party scripts and stylesheets loaded without Subresource Integrity
(OWASP A08, software or data integrity failures). Reads the page HTML only.

Hosts that change their content without notice (tag managers, analytics, web
fonts) cannot use a pinned hash: it would break the page on the next update.
Those are listed separately instead of being reported as a gap, so the report
never recommends a fix that cannot work."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from audit_agent.tools import ToolSpec

SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "Target URL, including scheme."},
    },
    "required": ["url"],
}

MAX_LISTED = 25

DYNAMIC_HOSTS = (
    "googletagmanager.com",
    "google-analytics.com",
    "fonts.googleapis.com",
    "connect.facebook.net",
    "static.hotjar.com",
    # Cloudflare Turnstile: the vendor updates api.js in place and says it
    # must always be loaded from this origin, so a pinned hash breaks it.
    "challenges.cloudflare.com",
)

_TAG = re.compile(r"<(script|link)\b([^>]*)>", re.I)
_URL_ATTR = {
    "script": re.compile(r"""(?<![\w-])src\s*=\s*["']([^"']+)["']""", re.I),
    "link": re.compile(r"""(?<![\w-])href\s*=\s*["']([^"']+)["']""", re.I),
}
_STYLESHEET = re.compile(r"""(?<![\w-])rel\s*=\s*["']?[^"'>]*stylesheet""", re.I)
_INTEGRITY = re.compile(r"(?<![\w-])integrity\s*=", re.I)


def _is_dynamic(host: str) -> bool:
    return any(host == h or host.endswith("." + h) for h in DYNAMIC_HOSTS)


async def integrity_probe(url: str, client: httpx.AsyncClient) -> dict[str, Any]:
    try:
        resp = await client.get(url, follow_redirects=True)
    except httpx.HTTPError as exc:
        return {"url": url, "error": str(exc), "reachable": False}

    page_url = str(resp.url)
    page_host = (urlparse(page_url).hostname or "").lower()
    # blog.site.com, www.site.com and cdn.site.com are all the owner's; only
    # other domains are third parties.
    # shortcut: last two labels, wrong for suffixes like .com.br (treats the
    # whole suffix as the owner); upgrade with a public-suffix list.
    own_base = ".".join(page_host.split(".")[-2:])

    third_party = 0
    missing: list[dict[str, str]] = []
    dynamic_hosts: set[str] = set()

    for match in _TAG.finditer(resp.text):
        kind, attrs = match.group(1).lower(), match.group(2)
        if kind == "link" and not _STYLESHEET.search(attrs):
            continue
        url_match = _URL_ATTR[kind].search(attrs)
        if url_match is None:
            continue
        asset_url = urljoin(page_url, url_match.group(1))
        host = (urlparse(asset_url).hostname or "").lower()
        if not host or host == page_host or host.endswith("." + own_base):
            continue

        third_party += 1
        if _is_dynamic(host):
            dynamic_hosts.add(host)
        elif not _INTEGRITY.search(attrs):
            missing.append(
                {"type": "script" if kind == "script" else "stylesheet", "url": asset_url}
            )

    return {
        "url": url,
        "reachable": True,
        "third_party_assets": third_party,
        "without_integrity_count": len(missing),
        "without_integrity": missing[:MAX_LISTED],
        "dynamic_third_party_hosts": sorted(dynamic_hosts),
    }


def spec() -> ToolSpec:
    return ToolSpec(
        name="integrity_probe",
        description=(
            "List third-party scripts and stylesheets loaded without a "
            "Subresource Integrity (integrity) attribute. Hosts where SRI cannot "
            "be applied (tag managers, analytics, web fonts) are listed apart."
        ),
        parameters=SCHEMA,
        fn=integrity_probe,
    )
