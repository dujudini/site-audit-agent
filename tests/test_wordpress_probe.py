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

    assert result["plugins_detected"] == ["contact-form-7"]
    assert result["themes_detected"] == ["twentytwentyfour"]
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
async def test_wordpress_probe_reports_hardened_site() -> None:
    respx.get("https://hardened.example.com/").mock(
        return_value=httpx.Response(200, text="<html></html>")
    )
    respx.get("https://hardened.example.com/readme.html").mock(return_value=httpx.Response(404))
    respx.get("https://hardened.example.com/wp-json/wp/v2/users").mock(return_value=httpx.Response(401))
    respx.get("https://hardened.example.com/xmlrpc.php").mock(return_value=httpx.Response(403))

    async with httpx.AsyncClient() as client:
        result = await wordpress_probe("https://hardened.example.com", client)

    assert result["core_version_exposed"] is None
    assert result["rest_users_exposed_count"] == 0
    assert result["xmlrpc_enabled"] is False
    assert result["readme_html_public"] is False
