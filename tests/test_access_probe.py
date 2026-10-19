import httpx
import pytest
import respx

from audit_agent.tools.access_probe import access_probe

HOST = "site.example.com"
URL = f"https://{HOST}/"


@pytest.mark.asyncio
@respx.mock
async def test_admin_path_without_a_login_form_is_flagged() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/admin":
            return httpx.Response(200, text="<h1>Dashboard</h1><p>Welcome back</p>")
        return httpx.Response(404)

    respx.route(host=HOST).mock(side_effect=handler)

    async with httpx.AsyncClient() as client:
        result = await access_probe(URL, client)

    assert result["open_admin_paths"] == ["/admin"]


@pytest.mark.asyncio
@respx.mock
async def test_admin_path_with_a_login_form_is_not_flagged() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/admin":
            return httpx.Response(
                200,
                text='<form><input type="password" name="pwd"></form>',
            )
        return httpx.Response(404)

    respx.route(host=HOST).mock(side_effect=handler)

    async with httpx.AsyncClient() as client:
        result = await access_probe(URL, client)

    assert result["open_admin_paths"] == []


@pytest.mark.asyncio
async def test_unreachable_server_is_not_reported_as_clean() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route")

    async with httpx.AsyncClient(transport=httpx.MockTransport(boom)) as client:
        result = await access_probe(URL, client)

    assert result["reachable"] is False
