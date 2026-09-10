"""Cross-references WordPress core/plugin/theme versions against the
Wordfence Intelligence vulnerability feed (free, downloaded separately —
see scripts/download_wordfence_feed.py). Pure lookup, no network, no LLM.

Ported from an earlier project's passive audit script. Only registered once
tech_detect confirms WordPress, same as wordpress_probe, and takes the exact
version data wordpress_probe already reported (the model reads that result
and passes it in) rather than re-detecting anything itself.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from audit_agent.tools import ToolSpec

SCHEMA = {
    "type": "object",
    "properties": {
        "core_version": {
            "type": "string",
            "description": "WordPress core version, from wordpress_probe.",
        },
        "plugins": {
            "type": "object",
            "description": "slug -> version, from wordpress_probe's plugins_detected.",
            "additionalProperties": {"type": "string"},
        },
        "themes": {
            "type": "object",
            "description": "slug -> version, from wordpress_probe's themes_detected.",
            "additionalProperties": {"type": "string"},
        },
    },
    "required": [],
}

_VER_RE = re.compile(r"(\d+(?:\.\d+)*)")


def _ver_tuple(v: str) -> tuple[int, ...]:
    m = _VER_RE.search(v or "")
    if not m:
        return (0,)
    return tuple(int(p) for p in m.group(1).split("."))


@lru_cache(maxsize=1)
def _load_feed(path: str) -> dict[tuple[str, str], list[dict[str, Any]]]:
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)

    index: dict[tuple[str, str], list[dict[str, Any]]] = {}
    items = raw.values() if isinstance(raw, dict) else raw
    for vuln in items:
        title = vuln.get("title", "")
        cve = vuln.get("cve") or ""
        cvss = vuln.get("cvss") or {}
        severity = str(cvss.get("rating") or "") if isinstance(cvss, dict) else ""

        for sw in vuln.get("software", []):
            slug = sw.get("slug", "")
            sw_type = sw.get("type", "")
            if not slug:
                continue
            ranges = []
            for spec in (sw.get("affected_versions") or {}).values():
                ranges.append({
                    "from": spec.get("from_version", "*"),
                    "from_inc": spec.get("from_inclusive", True),
                    "to": spec.get("to_version", "*"),
                    "to_inc": spec.get("to_inclusive", True),
                })
            index.setdefault((sw_type, slug), []).append({
                "title": title, "cve": cve, "severity": severity, "ranges": ranges,
            })
    return index


def _version_in_range(version: str, r: dict[str, Any]) -> bool:
    if not version:
        return False
    vt = _ver_tuple(version)
    lo, hi = r["from"], r["to"]
    if lo != "*":
        lt = _ver_tuple(lo)
        if vt < lt or (vt == lt and not r["from_inc"]):
            return False
    if hi != "*":
        ht = _ver_tuple(hi)
        if vt > ht or (vt == ht and not r["to_inc"]):
            return False
    return True


def _match(
    sw_type: str, slug: str, version: str,
    index: dict[tuple[str, str], list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    return [
        entry for entry in index.get((sw_type, slug), [])
        if any(_version_in_range(version, rg) for rg in entry["ranges"])
    ]


async def vuln_check(
    feed_path: str,
    core_version: str = "",
    plugins: dict[str, str] | None = None,
    themes: dict[str, str] | None = None,
) -> dict[str, Any]:
    if not Path(feed_path).is_file():
        return {
            "skipped": True,
            "reason": (
                f"feed not found at {feed_path}; run "
                "scripts/download_wordfence_feed.py once (needs WORDFENCE_API_KEY)"
            ),
        }

    index = _load_feed(feed_path)
    vulns: list[dict[str, Any]] = []

    if core_version:
        for hit in _match("core", "wordpress", core_version, index):
            vulns.append({"component": "core", "slug": "wordpress", "version": core_version, **hit})
    for slug, version in (plugins or {}).items():
        for hit in _match("plugin", slug, version, index):
            vulns.append({"component": "plugin", "slug": slug, "version": version, **hit})
    for slug, version in (themes or {}).items():
        for hit in _match("theme", slug, version, index):
            vulns.append({"component": "theme", "slug": slug, "version": version, **hit})

    return {"skipped": False, "vulnerabilities": vulns}


def spec(feed_path: str) -> ToolSpec:
    async def bound(
        core_version: str = "", plugins: dict[str, str] | None = None,
        themes: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        return await vuln_check(feed_path, core_version, plugins, themes)

    return ToolSpec(
        name="vuln_check",
        description=(
            "Cross-reference WordPress core/plugin/theme versions (from "
            "wordpress_probe) against the Wordfence vulnerability feed for "
            "known CVEs. Pass the exact values wordpress_probe reported."
        ),
        parameters=SCHEMA,
        fn=bound,
    )
