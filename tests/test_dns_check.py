import httpx
import pytest
import respx

from audit_agent.tools.dns_check import dns_check


def _doh_response(rtype: str, answers: list[str]) -> httpx.Response:
    return httpx.Response(200, json={"Answer": [{"data": a} for a in answers]} if answers else {})


@pytest.mark.asyncio
@respx.mock
async def test_dns_check_aggregates_record_types_and_guesses_cdn() -> None:
    route = respx.get("https://cloudflare-dns.com/dns-query")

    def side_effect(request: httpx.Request) -> httpx.Response:
        rtype = request.url.params["type"]
        data = {
            "A": ["104.16.1.1"],
            "AAAA": [],
            "MX": ["10 mail.example.com."],
            "TXT": ['"v=spf1 include:_spf.example.com ~all"', '"v=DMARC1; p=quarantine"'],
            "NS": ["ns1.cloudflare.com.", "ns2.cloudflare.com."],
        }[rtype]
        return _doh_response(rtype, data)

    route.mock(side_effect=side_effect)

    async with httpx.AsyncClient() as client:
        result = await dns_check("example.com", client)

    assert result["a"] == ["104.16.1.1"]
    assert result["cdn_guess"] == "Cloudflare"
    assert result["has_spf"] is True
    assert result["has_dmarc"] is True


@pytest.mark.asyncio
@respx.mock
async def test_dns_check_handles_empty_records() -> None:
    respx.get("https://cloudflare-dns.com/dns-query").mock(
        return_value=httpx.Response(200, json={})
    )

    async with httpx.AsyncClient() as client:
        result = await dns_check("noreply.invalid", client)

    assert result["a"] == []
    assert result["cdn_guess"] is None
    assert result["has_spf"] is False


def _dns_by_name(zone: dict[tuple[str, str], list[str]]):
    def handler(request: httpx.Request) -> httpx.Response:
        key = (request.url.params["name"], request.url.params["type"])
        answers = zone.get(key, [])
        return httpx.Response(
            200, json={"Answer": [{"data": a} for a in answers]} if answers else {}
        )

    return handler


@pytest.mark.asyncio
@respx.mock
async def test_dmarc_is_read_from_the_underscore_name_not_the_apex_txt() -> None:
    """Found on a real site: DMARC sat at _dmarc.<domain> and the apex TXT had
    only SPF, so the old check reported "no DMARC" for a domain that had it."""
    zone = {
        ("example.com", "TXT"): ['"v=spf1 -all"'],
        ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=quarantine"'],
    }
    respx.get("https://cloudflare-dns.com/dns-query").mock(side_effect=_dns_by_name(zone))

    async with httpx.AsyncClient() as client:
        result = await dns_check("example.com", client)

    assert result["has_dmarc"] is True
    assert result["dmarc_record"] == '"v=DMARC1; p=quarantine"'


@pytest.mark.asyncio
@respx.mock
async def test_dmarc_on_the_parent_domain_covers_a_www_host() -> None:
    zone = {("_dmarc.example.com.br", "TXT"): ['"v=DMARC1; p=none"']}
    respx.get("https://cloudflare-dns.com/dns-query").mock(side_effect=_dns_by_name(zone))

    async with httpx.AsyncClient() as client:
        result = await dns_check("www.example.com.br", client)

    assert result["has_dmarc"] is True


@pytest.mark.asyncio
@respx.mock
async def test_dmarc_text_in_the_apex_txt_does_not_count() -> None:
    zone = {("example.com", "TXT"): ['"v=DMARC1; p=reject"']}
    respx.get("https://cloudflare-dns.com/dns-query").mock(side_effect=_dns_by_name(zone))

    async with httpx.AsyncClient() as client:
        result = await dns_check("example.com", client)

    assert result["has_dmarc"] is False
