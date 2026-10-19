import httpx
import pytest
import respx

from audit_agent.tools.error_handling_probe import error_handling_probe

HOST = "site.example.com"
URL = f"https://{HOST}/"


@pytest.mark.asyncio
@respx.mock
async def test_flags_a_stack_trace_in_a_404_page() -> None:
    respx.route(host=HOST).mock(
        return_value=httpx.Response(
            500, text="PHP Fatal error: Uncaught Exception in /var/www/html/index.php:42"
        )
    )

    async with httpx.AsyncClient() as client:
        result = await error_handling_probe(URL, client)

    assert result["verbose_error_leaked"] == ["missing_path", "malformed_path"]


@pytest.mark.asyncio
@respx.mock
async def test_a_generic_404_page_is_not_flagged() -> None:
    respx.route(host=HOST).mock(return_value=httpx.Response(404, text="<h1>Not Found</h1>"))

    async with httpx.AsyncClient() as client:
        result = await error_handling_probe(URL, client)

    assert result["verbose_error_leaked"] == []
    assert result["missing_path_status"] == 404


@pytest.mark.asyncio
async def test_unreachable_server_reports_unreachable() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route")

    async with httpx.AsyncClient(transport=httpx.MockTransport(boom)) as client:
        result = await error_handling_probe(URL, client)

    assert result["reachable"] is False
