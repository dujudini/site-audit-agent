import json
from pathlib import Path

import pytest

from audit_agent.tools.vuln_check import _load_feed, vuln_check

FEED = {
    "848ccbdc-c6f1-480f-a272-cd459e706713": {
        "title": "Contact Form 7 < 5.9 - SQL Injection",
        "cve": "CVE-2024-00000",
        "cvss": {"rating": "High"},
        "software": [
            {
                "type": "plugin",
                "slug": "contact-form-7",
                "affected_versions": {
                    "* - 5.8.9": {"from_version": "*", "to_version": "5.8.9", "to_inclusive": True},
                },
            }
        ],
    },
    "aaaaaaaa-0000-0000-0000-000000000000": {
        "title": "WordPress Core < 6.3 - Some Issue",
        "cve": "CVE-2023-99999",
        "cvss": {"rating": "Critical"},
        "software": [
            {
                "type": "core",
                "slug": "wordpress",
                "affected_versions": {
                    "* - 6.2.9": {"from_version": "*", "to_version": "6.2.9", "to_inclusive": True},
                },
            }
        ],
    },
}


@pytest.fixture
def feed_path(tmp_path: Path) -> str:
    path = tmp_path / "feed.json"
    path.write_text(json.dumps(FEED), encoding="utf-8")
    _load_feed.cache_clear()
    return str(path)


@pytest.mark.asyncio
async def test_vuln_check_flags_outdated_plugin(feed_path: str) -> None:
    result = await vuln_check(feed_path, plugins={"contact-form-7": "5.8.5"})

    assert result["skipped"] is False
    assert len(result["vulnerabilities"]) == 1
    assert result["vulnerabilities"][0]["cve"] == "CVE-2024-00000"


@pytest.mark.asyncio
async def test_vuln_check_ignores_patched_plugin(feed_path: str) -> None:
    result = await vuln_check(feed_path, plugins={"contact-form-7": "5.9.1"})

    assert result["vulnerabilities"] == []


@pytest.mark.asyncio
async def test_vuln_check_flags_outdated_core(feed_path: str) -> None:
    result = await vuln_check(feed_path, core_version="6.1")

    assert len(result["vulnerabilities"]) == 1
    assert result["vulnerabilities"][0]["component"] == "core"


@pytest.mark.asyncio
async def test_vuln_check_skips_without_feed_file() -> None:
    result = await vuln_check("does-not-exist.json", core_version="6.1")

    assert result["skipped"] is True
    assert "not found" in result["reason"]
