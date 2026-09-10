import httpx
import pytest
import respx

from audit_agent.tools.content_probe import content_probe

HTML = """
<html><head>
<title>Acme Dental — Home</title>
<meta name="description" content="Family dentistry in Tulsa." />
<link rel="canonical" href="https://acmedental.example.com/" />
</head><body>
<h1>Welcome</h1><h2>Services</h2><h2>Contact</h2>
</body></html>
"""


@pytest.mark.asyncio
@respx.mock
async def test_content_probe_extracts_seo_signals() -> None:
    respx.get("https://acmedental.example.com/").mock(return_value=httpx.Response(200, text=HTML))
    respx.get("https://acmedental.example.com/robots.txt").mock(return_value=httpx.Response(200))
    respx.get("https://acmedental.example.com/sitemap.xml").mock(return_value=httpx.Response(404))

    async with httpx.AsyncClient() as client:
        result = await content_probe("https://acmedental.example.com/", client)

    assert result["title"] == "Acme Dental — Home"
    assert result["meta_description"] == "Family dentistry in Tulsa."
    assert result["heading_counts"] == {"h1": 1, "h2": 2}
    assert result["has_robots_txt"] is True
    assert result["has_sitemap_xml"] is False


@pytest.mark.asyncio
@respx.mock
async def test_content_probe_handles_missing_metadata() -> None:
    respx.get("https://bare.example.com/").mock(
        return_value=httpx.Response(200, text="<html><body>no head tags here</body></html>")
    )
    respx.get("https://bare.example.com/robots.txt").mock(return_value=httpx.Response(404))

    async with httpx.AsyncClient() as client:
        result = await content_probe("https://bare.example.com/", client)

    assert result["title"] is None
    assert result["meta_description"] is None
    assert result["has_robots_txt"] is False
    assert result["has_sitemap_xml"] is False
