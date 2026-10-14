import asyncio

import httpx
import pytest
import respx

from audit_agent.tools.http_probe import http_probe


@pytest.mark.asyncio
@respx.mock
async def test_http_probe_reports_status_and_headers() -> None:
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(200, headers={"server": "nginx"}, content=b"hello")
    )

    async with httpx.AsyncClient() as client:
        result = await http_probe("https://example.com/", client)

    assert result["reachable"] is True
    assert result["status_code"] == 200
    assert result["headers"]["server"] == "nginx"
    assert result["content_length"] == 5
    assert result["redirect_count"] == 0


@pytest.mark.asyncio
@respx.mock
async def test_http_probe_follows_redirects() -> None:
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(301, headers={"location": "https://example.com/final"})
    )
    respx.get("https://example.com/final").mock(return_value=httpx.Response(200))

    async with httpx.AsyncClient() as client:
        result = await http_probe("https://example.com/", client)

    assert result["redirect_count"] == 1
    assert result["final_url"] == "https://example.com/final"


@pytest.mark.asyncio
@respx.mock
async def test_http_probe_reports_unreachable_without_raising() -> None:
    respx.get("https://down.example.com/").mock(side_effect=httpx.ConnectError("refused"))

    async with httpx.AsyncClient() as client:
        result = await http_probe("https://down.example.com/", client)

    assert result["reachable"] is False
    assert "error" in result


@pytest.mark.asyncio
async def test_ttfb_stops_at_the_headers_not_at_the_end_of_the_body() -> None:
    async def slow_body():
        yield b"a"
        await asyncio.sleep(0.4)
        yield b"b"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=slow_body())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await http_probe("https://slow-body.example.com/", client)

    assert result["content_length"] == 2
    assert result["ttfb_ms"] < 300, "TTFB must not include the 400ms body download"
