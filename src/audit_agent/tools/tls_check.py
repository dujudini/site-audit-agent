"""Certificate issuer, validity window, days-to-expiry, and negotiated
protocol version for one domain. Stdlib ssl/socket only — no HTTP involved,
so it runs even when the site returns non-200 for every path."""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import UTC, datetime
from typing import Any

from audit_agent.tools import ToolSpec

SCHEMA = {
    "type": "object",
    "properties": {
        "domain": {"type": "string", "description": "Bare domain, no scheme."},
        "port": {"type": "integer", "default": 443},
    },
    "required": ["domain"],
}

CERT_DATE_FMT = "%b %d %H:%M:%S %Y %Z"


def _fetch_cert(domain: str, port: int, timeout: float) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as tls_sock:
            cert = tls_sock.getpeercert()
            protocol = tls_sock.version()

    if cert is None:
        raise ssl.SSLError("no peer certificate returned")

    not_after_str = str(cert["notAfter"])
    not_before_str = str(cert["notBefore"])
    not_after = datetime.strptime(not_after_str, CERT_DATE_FMT).replace(tzinfo=UTC)
    not_before = datetime.strptime(not_before_str, CERT_DATE_FMT).replace(tzinfo=UTC)
    days_left = (not_after - datetime.now(UTC)).days

    issuer_pairs: list[tuple[str, str]] = [
        (str(pair[0]), str(pair[1]))
        for group in cert.get("issuer", ())
        for pair in group
    ]
    issuer = dict(issuer_pairs)

    return {
        "domain": domain,
        "reachable": True,
        "issuer": issuer.get("organizationName", issuer.get("commonName", "unknown")),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_left": days_left,
        "protocol": protocol,
    }


async def tls_check(domain: str, port: int = 443, timeout: float = 10.0) -> dict[str, Any]:
    try:
        return await asyncio.to_thread(_fetch_cert, domain, port, timeout)
    except (ssl.SSLError, OSError, TimeoutError) as exc:
        return {"domain": domain, "reachable": False, "error": str(exc)}


def spec() -> ToolSpec:
    return ToolSpec(
        name="tls_check",
        description=(
            "Report TLS certificate issuer, validity window, days left, "
            "and protocol version."
        ),
        parameters=SCHEMA,
        fn=tls_check,
    )
