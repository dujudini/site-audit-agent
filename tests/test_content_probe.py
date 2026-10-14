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
    for path in ("/sitemap.xml", "/sitemap_index.xml", "/wp-sitemap.xml"):
        respx.get(f"https://acmedental.example.com{path}").mock(return_value=httpx.Response(404))

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
    for path in ("/sitemap.xml", "/sitemap_index.xml", "/wp-sitemap.xml"):
        respx.get(f"https://bare.example.com{path}").mock(return_value=httpx.Response(404))

    async with httpx.AsyncClient() as client:
        result = await content_probe("https://bare.example.com/", client)

    assert result["title"] is None
    assert result["meta_description"] is None
    assert result["has_robots_txt"] is False
    assert result["has_sitemap_xml"] is False


@pytest.mark.asyncio
@respx.mock
async def test_sitemap_is_checked_even_when_robots_txt_is_missing() -> None:
    """Found on a real site: no robots.txt but a working sitemap.xml. The old
    code only looked for the sitemap when robots.txt existed, and reported
    "no sitemap" without having looked."""
    respx.get("https://nosrobots.example.com/").mock(
        return_value=httpx.Response(200, text="<html></html>")
    )
    respx.get("https://nosrobots.example.com/robots.txt").mock(return_value=httpx.Response(404))
    respx.get("https://nosrobots.example.com/sitemap.xml").mock(
        return_value=httpx.Response(200, text="<urlset></urlset>")
    )

    async with httpx.AsyncClient() as client:
        result = await content_probe("https://nosrobots.example.com/", client)

    assert result["has_robots_txt"] is False
    assert result["has_sitemap_xml"] is True


@pytest.mark.asyncio
@respx.mock
async def test_wordpress_core_sitemap_counts() -> None:
    respx.get("https://wp.example.com/").mock(
        return_value=httpx.Response(200, text="<html></html>")
    )
    respx.get("https://wp.example.com/robots.txt").mock(return_value=httpx.Response(404))
    respx.get("https://wp.example.com/sitemap.xml").mock(return_value=httpx.Response(404))
    respx.get("https://wp.example.com/sitemap_index.xml").mock(return_value=httpx.Response(404))
    respx.get("https://wp.example.com/wp-sitemap.xml").mock(
        return_value=httpx.Response(200, text="<sitemapindex></sitemapindex>")
    )

    async with httpx.AsyncClient() as client:
        result = await content_probe("https://wp.example.com/", client)

    assert result["has_sitemap_xml"] is True


@pytest.mark.asyncio
@respx.mock
async def test_single_page_app_answering_200_everywhere_has_no_robots_or_sitemap() -> None:
    """A SPA returns its HTML shell with 200 for any path. That is not a
    robots.txt or a sitemap, and counting it hides a real SEO gap."""
    shell = "<!doctype html><html><div id='app'></div></html>"
    respx.route(host="spa.example.com").mock(return_value=httpx.Response(200, text=shell))

    async with httpx.AsyncClient() as client:
        result = await content_probe("https://spa.example.com/", client)

    assert result["has_robots_txt"] is False
    assert result["has_sitemap_xml"] is False
