"""Unauthenticated access to admin paths (OWASP A01, partial: this checks
only whether a generic admin path is reachable without a login challenge,
never whether a specific user's data is exposed, which would need an account
on the target).

GET only. Only runs in `--active` mode: hitting /admin-style paths is closer
to probing than the passive base collection."""

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

ADMIN_PATHS = ("/admin", "/administrator", "/manage", "/dashboard", "/phpmyadmin")

# A login form, or a redirect to one, means the path is protected. Matching
# against the body (not just the status) catches an SPA that returns 200 for
# every route and renders the login screen client-side instead of redirecting.
_LOGIN_FORM = re.compile(
    r"""<input\b[^>]*type\s*=\s*["']?password|name=["']?(user(name)?|login|email)["']?""",
    re.I,
)


async def access_probe(url: str, client: httpx.AsyncClient) -> dict[str, Any]:
    open_paths: list[str] = []
    checked = 0
    for path in ADMIN_PATHS:
        try:
            resp = await client.get(urljoin(url, path), follow_redirects=True)
        except httpx.HTTPError:
            continue
        checked += 1
        if resp.status_code != 200:
            continue
        if not _LOGIN_FORM.search(resp.text):
            open_paths.append(path)

    return {
        "url": url,
        "reachable": checked > 0,
        "paths_checked": len(ADMIN_PATHS),
        "paths_answered": checked,
        "open_admin_paths": open_paths,
    }


def spec() -> ToolSpec:
    return ToolSpec(
        name="access_probe",
        description=(
            "Active probe (--active only): requests common admin paths "
            "(/admin, /dashboard, ...) and reports which ones return content "
            "without a login form. Partial OWASP A01 coverage: it cannot tell "
            "whether a reachable path exposes another user's data. GET only."
        ),
        parameters=SCHEMA,
        fn=access_probe,
    )
