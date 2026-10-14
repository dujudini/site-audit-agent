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


def cookie_flags(set_cookie_headers: list[str]) -> list[dict[str, Any]]:
    flagged = []
    for raw in set_cookie_headers:
        name_value, *attributes = raw.split(";")
        # Only attributes after the first ";" count: matching the whole string
        # would read a cookie *named* "secure_id" as having the Secure flag.
        attr_names = {a.split("=", 1)[0].strip().lower() for a in attributes}
        flagged.append(
            {
                "name": name_value.split("=", 1)[0].strip(),
                "secure": "secure" in attr_names,
                "httponly": "httponly" in attr_names,
                "samesite": "samesite" in attr_names,
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
        "cookies": cookie_flags(set_cookie),
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
