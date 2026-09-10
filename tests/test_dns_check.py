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
