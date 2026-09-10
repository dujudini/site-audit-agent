"""CSP, HSTS, X-Frame-Options, cookie flags, referrer policy — the security
header posture of one URL."""

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

SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security (HSTS)",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def _cookie_flags(set_cookie_headers: list[str]) -> list[dict[str, Any]]:
    flagged = []
    for raw in set_cookie_headers:
        name = raw.split("=", 1)[0].strip()
        lower = raw.lower()
        flagged.append(
            {
                "name": name,
                "secure": "secure" in lower,
                "httponly": "httponly" in lower,
                "samesite": "samesite" in lower,
            }
        )
    return flagged


async def headers_audit(url: str, client: httpx.AsyncClient) -> dict[str, Any]:
    try:
        resp = await client.get(url, follow_redirects=True)
    except httpx.HTTPError as exc:
        return {"url": url, "error": str(exc), "reachable": False}

    present = {k.lower() for k in resp.headers}
    missing = [name for hdr, name in SECURITY_HEADERS.items() if hdr not in present]

    set_cookie = resp.headers.get_list("set-cookie")

    return {
        "url": url,
        "reachable": True,
        "missing_security_headers": missing,
        "present_security_headers": [
            name for hdr, name in SECURITY_HEADERS.items() if hdr in present
        ],
        "cookies": _cookie_flags(set_cookie),
    }


def spec() -> ToolSpec:
    return ToolSpec(
        name="headers_audit",
        description=(
            "Report missing/present security headers (CSP, HSTS, "
            "X-Frame-Options, etc.) and cookie flags."
        ),
        parameters=SCHEMA,
        fn=headers_audit,
    )
