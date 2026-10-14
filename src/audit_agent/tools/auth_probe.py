"""Authentication hygiene visible from the outside (OWASP A07): cookies set
without Secure/HttpOnly/SameSite, and password forms that submit over plain
HTTP. It does not try to log in or guess anything."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from audit_agent.tools import ToolSpec
from audit_agent.tools.headers_audit import cookie_flags

SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "Target URL, including scheme."},
    },
    "required": ["url"],
}

_SESSION_LIKE = re.compile(r"sess|sid|token|auth|login|logged_in|jwt", re.I)
_FORM = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_PASSWORD_INPUT = re.compile(r"""<input\b[^>]*type\s*=\s*["']?password""", re.I)
_ACTION = re.compile(r"""(?<![\w-])action\s*=\s*["']([^"']*)["']""", re.I)


async def auth_probe(url: str, client: httpx.AsyncClient) -> dict[str, Any]:
    try:
        resp = await client.get(url, follow_redirects=True)
    except httpx.HTTPError as exc:
        return {"url": url, "error": str(exc), "reachable": False}

    final_url = str(resp.url)

    cookies_missing_flags = []
    for cookie in cookie_flags(resp.headers.get_list("set-cookie")):
        # A language or consent cookie without HttpOnly is not an auth failure.
        if not _SESSION_LIKE.search(cookie["name"]):
            continue
        missing = [flag for flag in ("secure", "httponly", "samesite") if not cookie[flag]]
        if missing:
            cookies_missing_flags.append({"name": cookie["name"], "missing": missing})

    password_forms: list[dict[str, Any]] = []
    for form in _FORM.finditer(resp.text):
        if not _PASSWORD_INPUT.search(form.group(2)):
            continue
        action = _ACTION.search(form.group(1))
        # An empty or missing action submits back to the page itself.
        target = urljoin(final_url, action.group(1)) if action and action.group(1) else final_url
        password_forms.append({"action": target, "https": urlparse(target).scheme == "https"})

    return {
        "url": url,
        "reachable": True,
        "cookies_missing_flags": cookies_missing_flags,
        "password_forms": password_forms,
        "password_forms_over_http": [f for f in password_forms if not f["https"]],
    }


def spec() -> ToolSpec:
    return ToolSpec(
        name="auth_probe",
        description=(
            "Check cookies set by the page for missing Secure/HttpOnly/SameSite "
            "flags, and password forms that submit over plain HTTP."
        ),
        parameters=SCHEMA,
        fn=auth_probe,
    )
