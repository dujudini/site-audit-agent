"""Verbose-error disclosure check (OWASP A10, mishandling of exceptional
conditions). Requests a path guaranteed not to exist and a malformed path,
and checks whether the error response leaks a stack trace, file path or
framework version instead of a generic error page.

GET only. Only runs in `--active` mode: an unusual path is closer to probing
than the passive base collection, even though it changes nothing on the
server."""

from __future__ import annotations

import re
import uuid
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

_LEAK = re.compile(
    r"Stack trace|Traceback \(most recent|at System\.|"
    r"PHP (Warning|Notice|Fatal error|Deprecated)|"
    r"Exception in thread|in <module>|"
    r"[A-Za-z]:\\[\w\\]+\.(php|py|java|rb)|/(var|home|usr)/[\w/]+\.(php|py|rb)",
)


async def _fetch(client: httpx.AsyncClient, url: str) -> tuple[int, str] | None:
    try:
        resp = await client.get(url, follow_redirects=True)
    except httpx.HTTPError:
        return None
    return resp.status_code, resp.text


async def error_handling_probe(url: str, client: httpx.AsyncClient) -> dict[str, Any]:
    marker = uuid.uuid4().hex[:12]
    missing = await _fetch(client, urljoin(url, f"/this-path-does-not-exist-{marker}"))
    # A malformed, overlong path segment is a cheap way to trip a framework's
    # own router/validation error instead of its normal 404 handler.
    malformed = await _fetch(client, urljoin(url, f"/%ff%fe{'a' * 200}"))

    if missing is None and malformed is None:
        return {"url": url, "error": "host unreachable", "reachable": False}

    leaks: list[str] = []
    for name, fetched in (("missing_path", missing), ("malformed_path", malformed)):
        if fetched is not None and _LEAK.search(fetched[1]):
            leaks.append(name)

    return {
        "url": url,
        "reachable": True,
        "missing_path_status": missing[0] if missing else None,
        "malformed_path_status": malformed[0] if malformed else None,
        "verbose_error_leaked": leaks,
    }


def spec() -> ToolSpec:
    return ToolSpec(
        name="error_handling_probe",
        description=(
            "Active probe (--active only): requests a nonexistent path and a "
            "malformed path, and checks whether the error response leaks a "
            "stack trace, file path or framework internals. GET only."
        ),
        parameters=SCHEMA,
        fn=error_handling_probe,
    )
