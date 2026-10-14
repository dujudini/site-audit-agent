import httpx
import pytest
import respx

from audit_agent.tools.integrity_probe import integrity_probe

HTML = """
<html><head>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>
<script src="https://cdn.example.org/lib.js" integrity="sha384-abc"></script>
<script src="/local.js"></script>
<script src="https://cdn.site.example.com/own.js"></script>
<script src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>
<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto">
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap.min.css">
<link rel="icon" href="https://other.example.net/favicon.ico">
</head></html>
"""


@pytest.mark.asyncio
@respx.mock
async def test_flags_only_third_party_assets_without_integrity() -> None:
    respx.get("https://www.site.example.com/").mock(return_value=httpx.Response(200, text=HTML))

    async with httpx.AsyncClient() as client:
        result = await integrity_probe("https://www.site.example.com/", client)

    assert [a["url"] for a in result["without_integrity"]] == [
        "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js",
        "https://stackpath.bootstrapcdn.com/bootstrap.min.css",
    ]
    assert result["without_integrity_count"] == 2
    # cdnjs, cdn.example.org, gtm, fonts, bootstrapcdn; own subdomain and icon excluded.
    assert result["third_party_assets"] == 5


@pytest.mark.asyncio
@respx.mock
async def test_sibling_subdomains_of_a_subdomain_page_are_own_assets() -> None:
    html = '<script src="https://cdn.example.com/a.js"></script>'
    respx.get("https://blog.example.com/").mock(return_value=httpx.Response(200, text=html))

    async with httpx.AsyncClient() as client:
        result = await integrity_probe("https://blog.example.com/", client)

    assert result["third_party_assets"] == 0


@pytest.mark.asyncio
@respx.mock
async def test_dynamic_hosts_are_listed_apart_not_reported_as_a_gap() -> None:
    respx.get("https://www.site.example.com/").mock(return_value=httpx.Response(200, text=HTML))

    async with httpx.AsyncClient() as client:
        result = await integrity_probe("https://www.site.example.com/", client)

    assert result["dynamic_third_party_hosts"] == [
        "fonts.googleapis.com",
        "www.googletagmanager.com",
    ]
    reported = {a["url"] for a in result["without_integrity"]}
    assert not any("googletagmanager" in u or "googleapis" in u for u in reported)


@pytest.mark.asyncio
@respx.mock
async def test_cloudflare_turnstile_is_not_reported_as_missing_sri() -> None:
    """Found on a real site: Turnstile's api.js is updated in place by the
    vendor, so recommending a pinned hash would break the captcha."""
    html = '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>'
    respx.get("https://site.example.com/").mock(return_value=httpx.Response(200, text=html))

    async with httpx.AsyncClient() as client:
        result = await integrity_probe("https://site.example.com/", client)

    assert result["without_integrity"] == []
    assert result["dynamic_third_party_hosts"] == ["challenges.cloudflare.com"]


@pytest.mark.asyncio
@respx.mock
async def test_page_without_third_party_assets_reports_none() -> None:
    respx.get("https://plain.example.com/").mock(
        return_value=httpx.Response(200, text='<script src="/app.js"></script>')
    )

    async with httpx.AsyncClient() as client:
        result = await integrity_probe("https://plain.example.com/", client)

    assert result["third_party_assets"] == 0
    assert result["without_integrity"] == []
