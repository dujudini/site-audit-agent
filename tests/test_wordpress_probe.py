import httpx
import pytest
import respx

from audit_agent.tools.wordpress_probe import wordpress_probe

HOME_HTML = """
<html><body>
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css?ver=1.2" />
<script src="/wp-content/plugins/contact-form-7/js/scripts.js?ver=5.9.8"></script>
<script src="/wp-content/plugins/contact-form-7/js/scripts.js?ver=5.9.8"></script>
</body></html>
"""


@pytest.mark.asyncio
@respx.mock
async def test_wordpress_probe_detects_plugins_and_exposed_users() -> None:
    respx.get("https://wp.example.com/").mock(return_value=httpx.Response(200, text=HOME_HTML))
    respx.get("https://wp.example.com/readme.html").mock(
        return_value=httpx.Response(200, text="WordPress Version 6.2")
    )
    respx.get("https://wp.example.com/wp-json/wp/v2/users").mock(
        return_value=httpx.Response(200, json=[{"id": 1, "name": "admin"}])
    )
    respx.get("https://wp.example.com/xmlrpc.php").mock(
        return_value=httpx.Response(200, text="XML-RPC server accepts POST requests only.")
    )

    async with httpx.AsyncClient() as client:
        result = await wordpress_probe("https://wp.example.com", client)

    assert result["plugins_detected"] == {"contact-form-7": "5.9.8"}
    assert result["themes_detected"] == {"twentytwentyfour": "1.2"}
    assert result["core_version_exposed"] == "6.2"
    assert result["rest_users_exposed_count"] == 1
    assert result["xmlrpc_enabled"] is True


@pytest.mark.asyncio
@respx.mock
async def test_wordpress_probe_ignores_gpl_version_mention() -> None:
    """Modern readme.html wraps the core version requirement in HTML tags
    (breaking a naive "Version X" match) but states the GPL license version
    as plain text ("...version 2 or..."). A real audit against a live site
    hit this: the old regex reported core_version_exposed="2"."""
    respx.get("https://gplmention.example.com/").mock(
        return_value=httpx.Response(200, text="<html></html>")
    )
    respx.get("https://gplmention.example.com/readme.html").mock(
        return_value=httpx.Response(
            200,
            text=(
                "<li>PHP version <strong>7.4</strong> or greater.</li>"
                "<p>WordPress is free software, released under the terms of "
                "the GPL (GNU General Public License) version 2 or later.</p>"
            ),
        )
    )
    respx.get("https://gplmention.example.com/wp-json/wp/v2/users").mock(
        return_value=httpx.Response(401)
    )
    respx.get("https://gplmention.example.com/xmlrpc.php").mock(return_value=httpx.Response(403))

    async with httpx.AsyncClient() as client:
        result = await wordpress_probe("https://gplmention.example.com", client)

    assert result["core_version_exposed"] is None
    assert result["readme_html_public"] is True


@pytest.mark.asyncio
@respx.mock
async def test_wordpress_probe_reports_empty_version_when_asset_has_no_query_string() -> None:
    """A real audit hit a site whose plugin/theme asset URLs carried no
    ?ver= at all, so vuln_check had nothing to cross-reference even though
    the plugin/theme itself was correctly detected."""
    respx.get("https://noquery.example.com/").mock(
        return_value=httpx.Response(
            200,
            text=(
                '<script src="/wp-content/plugins/ewww-image-optimizer/js/a.js"></script>'
                '<link href="/wp-content/themes/mvf-20/style.css" />'
            ),
        )
    )
    respx.get("https://noquery.example.com/readme.html").mock(return_value=httpx.Response(404))
    respx.get("https://noquery.example.com/wp-json/wp/v2/users").mock(
        return_value=httpx.Response(401)
    )
    respx.get("https://noquery.example.com/xmlrpc.php").mock(return_value=httpx.Response(403))

    async with httpx.AsyncClient() as client:
        result = await wordpress_probe("https://noquery.example.com", client)

    assert result["plugins_detected"] == {"ewww-image-optimizer": ""}
    assert result["themes_detected"] == {"mvf-20": ""}


@pytest.mark.asyncio
@respx.mock
async def test_wordpress_probe_reports_hardened_site() -> None:
    respx.get("https://hardened.example.com/").mock(
        return_value=httpx.Response(200, text="<html></html>")
    )
    respx.get("https://hardened.example.com/readme.html").mock(return_value=httpx.Response(404))
    respx.get("https://hardened.example.com/wp-json/wp/v2/users").mock(
        return_value=httpx.Response(401)
    )
    respx.get("https://hardened.example.com/xmlrpc.php").mock(return_value=httpx.Response(403))

    async with httpx.AsyncClient() as client:
        result = await wordpress_probe("https://hardened.example.com", client)

    assert result["core_version_exposed"] is None
    assert result["rest_users_exposed_count"] == 0
    assert result["xmlrpc_enabled"] is False
    assert result["readme_html_public"] is False


@pytest.mark.asyncio
@respx.mock
async def test_wordpress_probe_follows_an_apex_redirect() -> None:
    """Without following the 301, every probe below read as "nothing there"."""

    def apex(request: httpx.Request) -> httpx.Response:
        target = f"https://www.example.com{request.url.path}"
        return httpx.Response(301, headers={"location": target})

    respx.route(host="example.com").mock(side_effect=apex)

    def www(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/wp-json/wp/v2/users":
            return httpx.Response(200, json=[{"id": 1}, {"id": 2}])
        if request.url.path == "/xmlrpc.php":
            return httpx.Response(200, text="XML-RPC server accepts POST requests only.")
        if request.url.path == "/readme.html":
            return httpx.Response(200, text="readme")
        return httpx.Response(
            200, text='<script src="/wp-content/plugins/akismet/a.js?ver=5.3"></script>'
        )

    respx.route(host="www.example.com").mock(side_effect=www)

    async with httpx.AsyncClient() as client:
        result = await wordpress_probe("https://example.com", client)

    assert result["plugins_detected"] == {"akismet": "5.3"}
    assert result["rest_users_exposed_count"] == 2
    assert result["xmlrpc_enabled"] is True
    assert result["readme_html_public"] is True


@pytest.mark.asyncio
@respx.mock
async def test_ver_equal_to_core_version_is_not_taken_as_the_theme_version() -> None:
    """Real site: the theme's CSS carried ?ver=<WordPress version>, and its
    style.css carried the real theme version further down the page."""
    html = (
        '<meta name="generator" content="WordPress 7.0.7" />'
        '<link href="/wp-content/themes/mvf-20/css/bootstrap.min.css?ver=7.0.7">'
        '<link href="/wp-content/themes/mvf-20/style.css?ver=2.0">'
        '<script src="/wp-content/plugins/ewww/a.js?ver=7.0.7"></script>'
    )
    respx.get("https://v.example.com/").mock(return_value=httpx.Response(200, text=html))
    for path in ("/readme.html", "/wp-json/wp/v2/users", "/xmlrpc.php"):
        respx.get(f"https://v.example.com{path}").mock(return_value=httpx.Response(404))

    async with httpx.AsyncClient() as client:
        result = await wordpress_probe("https://v.example.com", client)

    assert result["themes_detected"] == {"mvf-20": "2.0"}
    assert result["plugins_detected"] == {"ewww": ""}
