import httpx
import pytest
import respx

from audit_agent.tools.tech_detect import tech_detect

WP_HTML = """
<html><head>
<meta name="generator" content="WordPress 6.4" />
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css" />
</head><body>
<script src="https://www.googletagmanager.com/gtag/js"></script>
</body></html>
"""


@pytest.mark.asyncio
@respx.mock
async def test_tech_detect_flags_wordpress_and_analytics() -> None:
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(200, headers={"server": "nginx"}, text=WP_HTML)
    )

    async with httpx.AsyncClient() as client:
        result = await tech_detect("https://example.com/", client)

    assert result["is_wordpress"] is True
    assert result["generator_meta"] == "WordPress 6.4"
    assert "Google Tag Manager" in result["analytics_detected"]


@pytest.mark.asyncio
@respx.mock
async def test_tech_detect_no_signals_on_plain_html() -> None:
    respx.get("https://plain.example.com/").mock(
        return_value=httpx.Response(200, text="<html><body>hi</body></html>")
    )

    async with httpx.AsyncClient() as client:
        result = await tech_detect("https://plain.example.com/", client)

    assert result["is_wordpress"] is False
    assert result["frameworks_detected"] == []
