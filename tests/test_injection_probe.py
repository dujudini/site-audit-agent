import httpx
import pytest
import respx

from audit_agent.tools.injection_probe import injection_probe

URL = "https://site.example.com/"


@pytest.mark.asyncio
@respx.mock
async def test_flags_unescaped_reflection_of_the_marker() -> None:
    def echo(request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("q", "")
        return httpx.Response(200, text=f"<html><body>results for {q}</body></html>")

    respx.get(url__startswith=URL).mock(side_effect=echo)

    async with httpx.AsyncClient() as client:
        result = await injection_probe(URL, client)

    assert result["reflected_unescaped"] is True
    assert result["database_error_leaked"] is False


@pytest.mark.asyncio
@respx.mock
async def test_escaped_reflection_is_not_flagged() -> None:
    def echo(request: httpx.Request) -> httpx.Response:
        q = request.url.params.get("q", "")
        escaped = q.replace("<", "&lt;").replace(">", "&gt;")
        return httpx.Response(200, text=f"<html><body>results for {escaped}</body></html>")

    respx.get(url__startswith=URL).mock(side_effect=echo)

    async with httpx.AsyncClient() as client:
        result = await injection_probe(URL, client)

    assert result["reflected_unescaped"] is False


@pytest.mark.asyncio
@respx.mock
async def test_leaked_database_error_is_flagged() -> None:
    respx.get(url__startswith=URL).mock(
        return_value=httpx.Response(500, text="You have an error in your SQL syntax; check...")
    )

    async with httpx.AsyncClient() as client:
        result = await injection_probe(URL, client)

    assert result["database_error_leaked"] is True


@pytest.mark.asyncio
async def test_unreachable_server_reports_unreachable() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route")

    async with httpx.AsyncClient(transport=httpx.MockTransport(boom)) as client:
        result = await injection_probe(URL, client)

    assert result["reachable"] is False
