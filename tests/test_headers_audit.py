import httpx
import pytest
import respx

from audit_agent.tools.headers_audit import headers_audit


@pytest.mark.asyncio
@respx.mock
async def test_headers_audit_reports_missing_headers() -> None:
    respx.get("https://bare.example.com/").mock(
        return_value=httpx.Response(200, headers={"content-type": "text/html"})
    )

    async with httpx.AsyncClient() as client:
        result = await headers_audit("https://bare.example.com/", client)

    assert "Content-Security-Policy" in result["missing_security_headers"]
    assert "Strict-Transport-Security (HSTS)" in result["missing_security_headers"]
    assert result["present_security_headers"] == []


@pytest.mark.asyncio
@respx.mock
async def test_headers_audit_flags_insecure_cookies() -> None:
    respx.get("https://cookies.example.com/").mock(
        return_value=httpx.Response(
            200,
            headers=[
                ("strict-transport-security", "max-age=31536000"),
                ("set-cookie", "sessionid=abc123; Path=/"),
            ],
        )
    )

    async with httpx.AsyncClient() as client:
        result = await headers_audit("https://cookies.example.com/", client)

    assert "Strict-Transport-Security (HSTS)" in result["present_security_headers"]
    assert result["cookies"] == [
        {"name": "sessionid", "secure": False, "httponly": False, "samesite": False}
    ]
