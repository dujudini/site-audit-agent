import httpx
import pytest
import respx

from audit_agent.tools.auth_probe import auth_probe


@pytest.mark.asyncio
@respx.mock
async def test_lists_cookies_missing_flags_and_ignores_complete_ones() -> None:
    respx.get("https://site.example.com/").mock(
        return_value=httpx.Response(
            200,
            headers=[
                ("set-cookie", "sid=abc; Path=/; HttpOnly"),
                ("set-cookie", "pref=1; Secure; HttpOnly; SameSite=Lax"),
                # A cookie *named* secure_session must not count as having Secure.
                ("set-cookie", "secure_session=9; Path=/"),
                # Not an auth cookie: a language preference is not an A07 issue.
                ("set-cookie", "pll_language=en; Path=/"),
            ],
            text="<html></html>",
        )
    )

    async with httpx.AsyncClient() as client:
        result = await auth_probe("https://site.example.com/", client)

    assert result["cookies_missing_flags"] == [
        {"name": "sid", "missing": ["secure", "samesite"]},
        {"name": "secure_session", "missing": ["secure", "httponly", "samesite"]},
    ]


@pytest.mark.asyncio
@respx.mock
async def test_flags_password_form_that_submits_over_http() -> None:
    html = (
        '<form action="http://site.example.com/login" method="post">'
        '<input type="password" name="pw"></form>'
        '<form action="/secure-login" method="post">'
        '<input type="password" name="pw"></form>'
        '<form action="/search"><input type="text" name="q"></form>'
    )
    respx.get("https://site.example.com/").mock(return_value=httpx.Response(200, text=html))

    async with httpx.AsyncClient() as client:
        result = await auth_probe("https://site.example.com/", client)

    assert len(result["password_forms"]) == 2
    assert result["password_forms_over_http"] == [
        {"action": "http://site.example.com/login", "https": False}
    ]


@pytest.mark.asyncio
@respx.mock
async def test_page_without_cookies_or_forms_reports_nothing() -> None:
    respx.get("https://quiet.example.com/").mock(
        return_value=httpx.Response(200, text="<html><body>hi</body></html>")
    )

    async with httpx.AsyncClient() as client:
        result = await auth_probe("https://quiet.example.com/", client)

    assert result["cookies_missing_flags"] == []
    assert result["password_forms"] == []
