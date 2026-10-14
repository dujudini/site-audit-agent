"""OWASP Top 10:2025 mapping. Deterministic and tool-based: a finding is
tagged from the tools its evidence came from, never from model output, so
the "LLM never invents data" rule holds here too.

The map is deliberately narrow. A tool is listed only for a category it can
actually produce evidence for; every other category is reported as not
assessed instead of being implied as covered."""

from __future__ import annotations

from collections.abc import Iterable

OWASP_2025: dict[str, str] = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Security Logging and Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}

TOOL_TO_OWASP: dict[str, tuple[str, ...]] = {
    "tls_check": ("A04:2025",),
    "headers_audit": ("A02:2025",),
    "wordpress_probe": ("A02:2025",),
    "exposure_probe": ("A02:2025",),
    "vuln_check": ("A03:2025",),
    "auth_probe": ("A07:2025",),
    "integrity_probe": ("A08:2025",),
}


def owasp_for(category: str, evidence_tools: Iterable[str]) -> list[str]:
    """Only security findings carry OWASP tags; a slow TTFB is not an OWASP risk."""
    if category != "security":
        return []
    return sorted({code for tool in evidence_tools for code in TOOL_TO_OWASP.get(tool, ())})


def coverage(found: set[str], ran_tools: set[str]) -> list[tuple[str, str, str]]:
    """One row per category: (code, name, status).

    `found` must hold only codes of findings that report a problem. An
    info-severity finding means "checked, nothing wrong" in this project, so
    counting it would make a clean category read as if it had an issue.
    "no findings" is also qualified by whether a probe actually ran, because
    a probe that never ran proves nothing."""
    rows: list[tuple[str, str, str]] = []
    for code, name in OWASP_2025.items():
        probes = sorted(tool for tool, codes in TOOL_TO_OWASP.items() if code in codes)
        if code in found:
            status = "findings above"
        elif probes:
            ran = [tool for tool in probes if tool in ran_tools]
            note = f"ran: {', '.join(ran)}" if ran else "not run in this audit"
            status = f"probe available, no findings ({note})"
        else:
            status = "no passive probe, not assessed"
        rows.append((code, name, status))
    return rows
