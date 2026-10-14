"""Sensitive files and open directory listings that should never be public
(OWASP A02, security misconfiguration). One GET per well-known path, the same
request a crawler makes.

A 200 alone proves nothing: many sites answer every path with an HTML page.
Each path therefore carries a content signature and only a match is reported.
File contents are never returned, because a real hit may hold credentials."""

from __future__ import annotations

import re
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

MAX_BYTES = 2048

_WP_CONFIG = re.compile(r"DB_NAME|DB_PASSWORD|<\?php", re.I)
_LOG = re.compile(
    r"PHP (Warning|Notice|Fatal error|Deprecated)|Stack trace|\[\d{2}-[A-Za-z]{3}-\d{4}"
)

SENSITIVE_PATHS: dict[str, tuple[str, re.Pattern[str]]] = {
    "/.git/config": ("Git repository metadata", re.compile(r"\[core\]")),
    "/.env": ("Environment file", re.compile(r"^[A-Z][A-Z0-9_]*\s*=", re.M)),
    "/wp-config.php.bak": ("wp-config.php backup", _WP_CONFIG),
    "/wp-config.php~": ("wp-config.php backup", _WP_CONFIG),
    "/wp-config.php.old": ("wp-config.php backup", _WP_CONFIG),
    "/wp-content/debug.log": ("WordPress debug log", _LOG),
    "/debug.log": ("Debug log", _LOG),
}

LISTING_PATH = "/wp-content/uploads/"
_LISTING = re.compile(r"<title>Index of /|<h1>Index of /", re.I)


async def _fetch_start(client: httpx.AsyncClient, url: str) -> tuple[int, str] | None:
    """Status plus the first MAX_BYTES of the body. Streams and stops early so
    a hit on a large backup never downloads the whole file. Redirects are not
    followed: a 301 to a login page is not an exposure."""
    try:
        async with client.stream("GET", url) as resp:
            body = b""
            async for chunk in resp.aiter_bytes():
                body += chunk
                if len(body) >= MAX_BYTES:
                    break
            return resp.status_code, body[:MAX_BYTES].decode("utf-8", errors="replace")
    except httpx.HTTPError:
        return None


async def _resolve_origin(client: httpx.AsyncClient, url: str) -> str:
    """Where the site actually lives after redirects. Paths are not followed,
    so probing an apex that 301s to www would find nothing and report a clean
    site without ever looking at the server that holds the files."""
    try:
        resp = await client.get(url, follow_redirects=True)
    except httpx.HTTPError:
        return url
    return str(resp.url)


async def exposure_probe(url: str, client: httpx.AsyncClient) -> dict[str, Any]:
    base = await _resolve_origin(client, url)
    exposed: list[dict[str, str]] = []
    answered = 0
    for path, (description, signature) in SENSITIVE_PATHS.items():
        fetched = await _fetch_start(client, urljoin(base, path))
        if fetched is None:
            continue
        status, body = fetched
        # A rate-limit or server error says nothing about the path.
        if status != 429 and status < 500:
            answered += 1
        if status == 200 and signature.search(body):
            exposed.append({"path": path, "description": description})

    listing_open: list[str] = []
    fetched = await _fetch_start(client, urljoin(base, LISTING_PATH))
    if fetched is not None:
        if fetched[0] != 429 and fetched[0] < 500:
            answered += 1
        if fetched[0] == 200 and _LISTING.search(fetched[1]):
            listing_open.append(LISTING_PATH)

    return {
        "url": url,
        # "Nothing exposed" only means something if the server answered.
        "reachable": answered > 0,
        "paths_checked": len(SENSITIVE_PATHS) + 1,
        "paths_answered": answered,
        "exposed": exposed,
        "directory_listing_open": listing_open,
    }


def spec() -> ToolSpec:
    return ToolSpec(
        name="exposure_probe",
        description=(
            "Check a short list of well-known sensitive paths (.env, .git/config, "
            "wp-config backups, debug logs) and the uploads directory listing. "
            "Reports only that a file matched its signature, never its contents."
        ),
        parameters=SCHEMA,
        fn=exposure_probe,
        # Up to 10 sequential requests; the default 15s cuts a slow site short.
        timeout_s=60,
    )
