from collections.abc import Callable

import httpx
import pytest
import respx

from audit_agent.tools.exposure_probe import exposure_probe

HOST = "site.example.com"
URL = f"https://{HOST}/"


def _site(files: dict[str, str]) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        body = files.get(request.url.path)
        if body is None:
            return httpx.Response(404)
        return httpx.Response(200, text=body)

    return handler


@pytest.mark.asyncio
@respx.mock
async def test_reports_env_file_without_leaking_its_contents() -> None:
    respx.route(host=HOST).mock(
        side_effect=_site({"/.env": "DB_PASSWORD=hunter2\nAPP_KEY=base64:abc"})
    )

    async with httpx.AsyncClient() as client:
        result = await exposure_probe(URL, client)

    assert result["exposed"] == [{"path": "/.env", "description": "Environment file"}]
    assert "hunter2" not in repr(result)


@pytest.mark.asyncio
@respx.mock
async def test_reports_exposed_git_config() -> None:
    respx.route(host=HOST).mock(
        side_effect=_site({"/.git/config": "[core]\n\trepositoryformatversion = 0\n"})
    )

    async with httpx.AsyncClient() as client:
        result = await exposure_probe(URL, client)

    assert [e["path"] for e in result["exposed"]] == ["/.git/config"]


@pytest.mark.asyncio
@respx.mock
async def test_soft_404_page_is_not_an_exposure() -> None:
    """A site that answers 200 with its HTML shell for every path must not be
    reported as leaking .env or .git, or the report would be wrong and loud."""

    def catch_all(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<!doctype html><html><body>Welcome</body></html>")

    respx.route(host=HOST).mock(side_effect=catch_all)

    async with httpx.AsyncClient() as client:
        result = await exposure_probe(URL, client)

    assert result["exposed"] == []
    assert result["directory_listing_open"] == []


@pytest.mark.asyncio
@respx.mock
async def test_redirect_is_not_an_exposure() -> None:
    def redirect_all(request: httpx.Request) -> httpx.Response:
        return httpx.Response(301, headers={"location": "https://site.example.com/login"})

    respx.route(host=HOST).mock(side_effect=redirect_all)

    async with httpx.AsyncClient() as client:
        result = await exposure_probe(URL, client)

    assert result["exposed"] == []


@pytest.mark.asyncio
@respx.mock
async def test_probes_the_host_the_apex_redirects_to() -> None:
    """Without resolving the redirect first, every path on the apex 301s and
    the probe would report a clean site without looking at the real server."""
    respx.route(host="site.example.com").mock(
        return_value=httpx.Response(301, headers={"location": "https://www.site.example.com/"})
    )
    respx.route(host="www.site.example.com").mock(
        side_effect=_site({"/": "<html>home</html>", "/.env": "APP_KEY=base64:abc"})
    )

    async with httpx.AsyncClient() as client:
        result = await exposure_probe("https://site.example.com/", client)

    assert [e["path"] for e in result["exposed"]] == ["/.env"]


@pytest.mark.asyncio
@respx.mock
async def test_reports_open_directory_listing() -> None:
    respx.route(host=HOST).mock(
        side_effect=_site(
            {"/wp-content/uploads/": "<html><head><title>Index of /wp-content/uploads</title>"}
        )
    )

    async with httpx.AsyncClient() as client:
        result = await exposure_probe(URL, client)

    assert result["directory_listing_open"] == ["/wp-content/uploads/"]


@pytest.mark.asyncio
async def test_rate_limited_server_is_not_reported_as_clean() -> None:
    def limited(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429)

    async with httpx.AsyncClient(transport=httpx.MockTransport(limited)) as client:
        result = await exposure_probe(URL, client)

    assert result["reachable"] is False
    assert result["paths_answered"] == 0


@pytest.mark.asyncio
async def test_unreachable_server_is_not_reported_as_clean() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route")

    async with httpx.AsyncClient(transport=httpx.MockTransport(boom)) as client:
        result = await exposure_probe(URL, client)

    assert result["reachable"] is False
    assert result["paths_answered"] == 0
