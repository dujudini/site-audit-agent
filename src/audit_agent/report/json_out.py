"""Serialize an AuditReport to JSON — the machine-readable counterpart to
markdown.py, same data, no interpretation added."""

from __future__ import annotations

from audit_agent.schemas import AuditReport


def render_json(report: AuditReport) -> str:
    return report.model_dump_json(indent=2)
