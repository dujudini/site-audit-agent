"""A, AAAA, MX, TXT, NS records and a basic CDN guess for one domain.

Uses DNS-over-HTTPS (Cloudflare's resolver, port 443) instead of raw UDP:
many sandboxed/CI environments block outbound UDP:53, and httpx is already
a project dependency, so this avoids pulling in dnspython for four lookups.
"""

from __future__ import annotations

from typing import Any

import httpx

from audit_agent.tools import ToolSpec

SCHEMA = {
    "type": "object",
    "properties": {
        "domain": {"type": "string", "description": "Bare domain, no scheme (e.g. example.com)."},
    },
    "required": ["domain"],
}

DOH_URL = "https://cloudflare-dns.com/dns-query"
RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS")

CDN_HINTS = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "cloudfront": "Amazon CloudFront",
}


async def _query(client: httpx.AsyncClient, domain: str, rtype: str) -> list[str]:
    resp = await client.get(
        DOH_URL,
        params={"name": domain, "type": rtype},
        headers={"accept": "application/dns-json"},
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    return [a["data"] for a in data.get("Answer", [])]


def _guess_cdn(ns_records: list[str], a_records: list[str]) -> str | None:
    haystack = " ".join(ns_records + a_records).lower()
    for hint, name in CDN_HINTS.items():
        if hint in haystack:
            return name
    return None


async def dns_check(domain: str, client: httpx.AsyncClient) -> dict[str, Any]:
    records: dict[str, list[str]] = {}
    for rtype in RECORD_TYPES:
        try:
            records[rtype] = await _query(client, domain, rtype)
        except httpx.HTTPError:
            records[rtype] = []

    return {
        "domain": domain,
        "a": records["A"],
        "aaaa": records["AAAA"],
        "mx": records["MX"],
        "txt": records["TXT"],
        "ns": records["NS"],
        "cdn_guess": _guess_cdn(records["NS"], records["A"]),
        "has_spf": any("v=spf1" in t for t in records["TXT"]),
        "has_dmarc": any("v=DMARC1" in t for t in records["TXT"]),
    }


def spec() -> ToolSpec:
    return ToolSpec(
        name="dns_check",
        description="Resolve A/AAAA/MX/TXT/NS for a domain and guess CDN from NS/A records.",
        parameters=SCHEMA,
        fn=dns_check,
    )
