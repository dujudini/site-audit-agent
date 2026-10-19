"""Reflected-injection smoke test (OWASP A05). Active, not passive: it sends
a harmless marker in a query string and checks whether the page reflects it
unescaped (indicates reflected XSS) or whether a database driver's own error
text leaks back (indicates unsanitized input reaching a query).

GET only, same as every other tool. The marker never executes anything: no
browser renders this response, so an unescaped `<script>` here is evidence,
not an attack. Only runs in `--active` mode."""

from __future__ import annotations

import re
import uuid
from typing import Any
from urllib.parse import urlencode

import httpx

from audit_agent.tools import ToolSpec

SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "Target URL, including scheme."},
    },
    "required": ["url"],
}

_DB_ERROR = re.compile(
    r"SQL syntax|mysql_fetch|unclosed quotation mark|ORA-\d{5}|"
    r"PostgreSQL.*ERROR|SQLite3::|Microsoft OLE DB Provider",
    re.I,
)


async def injection_probe(url: str, client: httpx.AsyncClient) -> dict[str, Any]:
    # Unique per run so a reflection can't be confused with static page text.
    marker = f"ov{uuid.uuid4().hex[:8]}"
    xss_payload = f"<{marker}>'\"</{marker}>"
    sql_payload = f"{marker}'"
    probe_url = f"{url}?{urlencode({'q': xss_payload, 'id': sql_payload})}"

    try:
        resp = await client.get(probe_url, follow_redirects=True)
    except httpx.HTTPError as exc:
        return {"url": url, "error": str(exc), "reachable": False}

    return {
        "url": url,
        "reachable": True,
        # Unescaped in the body means the marker's own <> survived verbatim;
        # a sanitizing app would emit &lt;ov.../&gt; instead.
        "reflected_unescaped": xss_payload in resp.text,
        "database_error_leaked": bool(_DB_ERROR.search(resp.text)),
    }


def spec() -> ToolSpec:
    return ToolSpec(
        name="injection_probe",
        description=(
            "Active probe (--active only): sends a harmless marker in a query "
            "string and checks whether the page reflects it unescaped (reflected "
            "XSS) or leaks a database error (unsanitized input). GET only."
        ),
        parameters=SCHEMA,
        fn=injection_probe,
    )
