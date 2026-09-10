"""Downloads the free Wordfence Intelligence vulnerability feed, used by
audit_agent.tools.vuln_check for passive CVE cross-referencing.

v3 of the feed requires an API key (Bearer auth). Generate one at
wordfence.com > account > Integrations, then either export it or put it in
.env as WORDFENCE_API_KEY. Re-run this occasionally to refresh the feed;
vuln_check reads whatever is on disk, it doesn't auto-update.

Usage:
    python scripts/download_wordfence_feed.py [--out wordfence_feed.json]
"""

from __future__ import annotations

import argparse
import os
import sys

import httpx
from dotenv import load_dotenv

FEED_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"
USER_AGENT = "audit-agent/0.1 (+https://github.com/dujudini/site-audit-agent)"


def main() -> None:
    load_dotenv()
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="wordfence_feed.json")
    args = ap.parse_args()

    api_key = os.environ.get("WORDFENCE_API_KEY")
    if not api_key:
        print("set WORDFENCE_API_KEY (wordfence.com > account > Integrations)", file=sys.stderr)
        raise SystemExit(2)

    print(f"downloading {FEED_URL} ...", file=sys.stderr)
    resp = httpx.get(
        FEED_URL,
        headers={"User-Agent": USER_AGENT, "Authorization": f"Bearer {api_key}"},
        timeout=120,
    )
    resp.raise_for_status()

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(resp.text)
    print(f"saved {args.out} ({len(resp.content) // 1024} KB)", file=sys.stderr)


if __name__ == "__main__":
    main()
