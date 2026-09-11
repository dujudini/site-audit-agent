"""WordPress-specific inventory: exposed core version, REST user enumeration,
XML-RPC, and plugins/themes visible in HTML asset paths. Passive only — no
brute force, no exploitation, per CLAUDE.md 3.3. Only registered once
tech_detect confirms WordPress."""

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

# Requires a dotted major.minor so "released under GPL version 2" (real
# text in modern readme.html files) can't be mistaken for the WP version,
# which appears there as plain text without a dot in some GPL mentions.
README_VERSION_RE = re.compile(r"Version\s+(\d+\.\d+(?:\.\d+)?)", re.I)
ASSET_VERSION_RE = re.compile(r"[?&]ver=([\d.]+)")
# Captures the whole asset URL (up to the closing quote/space/paren), not
# just the slug, so the version query string further along the same URL
# can be pulled from the match text afterward.
ASSET_RE = re.compile(r"/wp-content/(plugins|themes)/([a-z0-9\-_]+)/[^\"'\s>)]*", re.I)


async def _get(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
    try:
        return await client.get(url)
    except httpx.HTTPError:
        return None


def _detect_assets(html: str) -> tuple[dict[str, str], dict[str, str]]:
    """slug -> version (empty string if the asset URL carried no ?ver=)."""
    plugins: dict[str, str] = {}
    themes: dict[str, str] = {}
    for m in ASSET_RE.finditer(html):
        target = plugins if m.group(1).lower() == "plugins" else themes
        slug = m.group(2)
        ver_match = ASSET_VERSION_RE.search(m.group(0))
        version = ver_match.group(1) if ver_match else ""
        if not target.get(slug):
            target[slug] = version
    return plugins, themes


async def wordpress_probe(url: str, client: httpx.AsyncClient) -> dict[str, Any]:
    base = url.rstrip("/")

    home = await _get(client, base + "/")
    html = home.text if home is not None else ""

    plugins, themes = _detect_assets(html)

    readme = await _get(client, base + "/readme.html")
    core_version = None
    if readme is not None and readme.status_code == 200:
        match = README_VERSION_RE.search(readme.text)
        core_version = match.group(1) if match else None

    users_resp = await _get(client, base + "/wp-json/wp/v2/users")
    users_exposed = 0
    if users_resp is not None and users_resp.status_code == 200:
        try:
            body = users_resp.json()
            if isinstance(body, list):
                users_exposed = len(body)
        except ValueError:
            pass

    xmlrpc_resp = await _get(client, base + "/xmlrpc.php")
    xmlrpc_enabled = bool(
        xmlrpc_resp is not None and "XML-RPC server accepts POST" in xmlrpc_resp.text
    )

    return {
        "url": url,
        "core_version_exposed": core_version,
        "plugins_detected": plugins,
        "themes_detected": themes,
        "rest_users_exposed_count": users_exposed,
        "xmlrpc_enabled": xmlrpc_enabled,
        "readme_html_public": readme is not None and readme.status_code == 200,
    }


def spec() -> ToolSpec:
    return ToolSpec(
        name="wordpress_probe",
        description=(
            "WordPress-specific passive checks: exposed core version, REST user "
            "enumeration, XML-RPC, plugins/themes visible in HTML."
        ),
        parameters=SCHEMA,
        fn=wordpress_probe,
    )
