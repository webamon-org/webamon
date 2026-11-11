"""Unit tests for enrichment (GeoIP readers stubbed — no .mmdb needed)."""
import asyncio

import pytest

from sandbox.config import Settings
from sandbox.enrich import Enrichment, Technology


def _settings(**kw):
    kw.setdefault("dns", "NONE")
    return Settings(save_elastic=False, **kw)


async def _fake_resolve(domain, record_type, sem):
    """Stand-in for a live resolver: A answers, everything else empty."""
    return record_type.lower(), (["1.2.3.4"] if record_type == "A" else [])


class _StubEnrichment(Enrichment):
    """Enrichment with GeoIP lookups stubbed so domain_info can be tested
    without the MaxMind databases present."""

    def ip2country(self, ip):  # type: ignore[override]
        return {"name": "United States", "iso": "US"}

    def ip2asn(self, ip):  # type: ignore[override]
        return {"number": 16509, "name": "Amazon.com, Inc.", "network": "1.2.3.0/24"}


def _raw_report():
    return {
        "request": [{
            "request": {"url": "https://a.com/x.js"},
            "response": {
                "url": "https://a.com/x.js", "mime_type": "application/javascript",
                "ip": "1.2.3.4", "status": 200, "encoded_data_length": 100,
                "headers": [{"name": "Server", "value": "nginx"}],
            },
        }],
        "resource": [{"sha256": "abc", "url": "https://a.com/x.js",
                      "mime_type": "application/javascript"}],
        "certificate": [],
    }


class TestDomainInfo:
    def test_populates_country_and_asn_when_geoip_available(self):
        e = _StubEnrichment(_settings())
        info = e.domain_info("a.com", _raw_report())
        # Proves the country/asn code path is correct; absence in a local run
        # is purely a missing .mmdb file, not a logic gap.
        assert info["country"] == {"name": "United States", "iso": "US"}
        assert info["asn"]["number"] == 16509

    def test_core_fields(self):
        e = _StubEnrichment(_settings())
        info = e.domain_info("a.com", _raw_report())
        assert info["name"] == "a.com"
        assert info["ip"] == "1.2.3.4"
        assert info["request_count"] == 1
        assert info["hosting_scripts"] is True   # javascript mime
        assert info["server"] == "nginx"
        assert info["total_response_size"] == 100.0
        assert info["response_code"] == [200]

    def test_resource_deduped_by_sha256(self):
        e = _StubEnrichment(_settings())
        raw = _raw_report()
        raw["resource"].append({"sha256": "abc", "url": "https://a.com/x.js",
                                "mime_type": "application/javascript"})
        info = e.domain_info("a.com", raw)
        assert len(info["resource"]) == 1

    def test_domain_info_no_longer_resolves_dns_itself(self):
        # DNS moved to third_parties() so every domain resolves concurrently
        # instead of one-at-a-time inside this synchronous function.
        e = _StubEnrichment(_settings())
        assert "dns" not in e.domain_info("a.com", _raw_report())


class TestDnsResolution:
    """DNS is ON by default (v2 production reports contain a populated `dns`
    block), so the implementation has to be affordable rather than optional."""

    @pytest.mark.asyncio
    async def test_disabled_returns_empty(self):
        e = _StubEnrichment(_settings(dns="NONE"))
        assert await e.get_dns_info("a.com") == {}

    @pytest.mark.asyncio
    async def test_main_mode_skips_third_parties(self):
        e = _StubEnrichment(_settings(dns="MAIN"))
        e._resolve_one = _fake_resolve
        assert await e.get_dns_info("cdn.example", is_root=False) == {}
        root = await e.get_dns_info("a.com", is_root=True)
        assert root["a"] == ["1.2.3.4"]

    @pytest.mark.asyncio
    async def test_all_record_types_present_and_shape_stable(self):
        e = _StubEnrichment(_settings(dns="ALL"))
        e._resolve_one = _fake_resolve
        out = await e.get_dns_info("a.com")
        # Every key present even when empty: strict OpenSearch mappings need a
        # stable field shape.
        assert set(out) == {t.lower() for t in e.dns_record_types}
        assert out["mx"] == []

    @pytest.mark.asyncio
    async def test_nxdomain_reports_error(self):
        async def nx(domain, rt, sem):
            return "__nxdomain__", []
        e = _StubEnrichment(_settings(dns="ALL"))
        e._resolve_one = nx
        assert await e.get_dns_info("nope.invalid") == {"error": "Domain does not exist"}

    @pytest.mark.asyncio
    async def test_repeat_lookups_are_cached(self):
        calls = {"n": 0}

        async def counting(domain, rt, sem):
            calls["n"] += 1
            return rt.lower(), []
        e = _StubEnrichment(_settings(dns="ALL"))
        e._resolve_one = counting
        await e.get_dns_info("a.com")
        first = calls["n"]
        await e.get_dns_info("a.com")
        assert calls["n"] == first, "second lookup should be served from cache"

    @pytest.mark.asyncio
    async def test_concurrent_lookups_of_same_domain_collapse(self):
        """The same CDN domain appears on nearly every page; N in-flight
        lookups for it must not become N sets of queries."""
        calls = {"n": 0}

        async def slow(domain, rt, sem):
            calls["n"] += 1
            await asyncio.sleep(0.02)
            return rt.lower(), []
        e = _StubEnrichment(_settings(dns="ALL"))
        e._resolve_one = slow
        await asyncio.gather(*(e.get_dns_info("a.com") for _ in range(5)))
        assert calls["n"] == len(e.dns_record_types), (
            f"expected one round of {len(e.dns_record_types)} queries, got {calls['n']}")

    @pytest.mark.asyncio
    async def test_resolver_failure_never_fails_the_scan(self):
        async def boom(domain, rt, sem):
            raise RuntimeError("resolver down")
        e = _StubEnrichment(_settings(dns="ALL"))
        e._resolve_one = boom
        out = await e.get_dns_info("a.com")
        assert "error" in out


class TestServerData:
    def test_aggregates_domains_by_ip(self):
        report = {"domain": [
            {"name": "a.com", "ip": "1.1.1.1", "hosting_scripts": True,
             "response_code": [200], "mime_type": ["text/html"], "resource": [],
             "total_response_size": 10.0, "server": "nginx",
             "country": {"iso": "US"}, "asn": {"number": 1}},
            {"name": "b.com", "ip": "1.1.1.1", "hosting_scripts": False,
             "response_code": [404], "mime_type": ["text/css"], "resource": [],
             "total_response_size": 5.0, "server": "nginx",
             "country": {"iso": "US"}, "asn": {"number": 1}},
        ]}
        servers = Enrichment.server_data(report)
        assert len(servers) == 1
        s = servers[0]
        assert sorted(s["domain"]) == ["a.com", "b.com"]
        assert s["total_response_size"] == 15.0
        assert s["hosting_scripts"] is True
        assert s["server"] == ["nginx"]
        assert sorted(s["response_code"]) == [200, 404]


class TestDomainExtract:
    def test_basic(self):
        e = _StubEnrichment(_settings())
        assert e.domain_extract("https://www.bbc.co.uk/news") == ("bbc.co.uk", "www", "co.uk")

    def test_no_subdomain(self):
        e = _StubEnrichment(_settings())
        domain, sub, tld = e.domain_extract("http://example.com/")
        assert domain == "example.com"
        assert sub == ""

    def test_with_port(self):
        e = _StubEnrichment(_settings())
        assert e.domain_extract("https://a.example.com:6524/x")[0] == "example.com"


class TestTechnology:
    def test_detects_and_dedupes(self, tmp_path):
        p = tmp_path / "patterns.txt"
        p.write_text("# comment\njquery,jQuery\nreact\\.js,React\n", encoding="utf-8")
        t = Technology(str(p))
        found = t.detect(["https://cdn/jquery.min.js", "https://cdn/jquery-3.js"], [], [])
        assert [f["name"] for f in found] == ["jQuery"]   # deduped by name

    def test_missing_file_is_safe(self):
        t = Technology("does_not_exist.txt")
        assert t.detect(["https://x/jquery.js"], [], []) == []


class TestDnsRecordTypeTuning:
    """Resolver load is (domains x record types), so the type list is a direct
    multiplier. It must be tunable at runtime, not baked into the image."""

    def test_ptr_is_not_queried_by_default(self):
        from sandbox.config import Settings
        from sandbox.enrich import Enrichment
        types = Enrichment(Settings(save_elastic=False)).dns_record_types
        assert "PTR" not in types, (
            "PTR is the reverse lookup for an IP; asking for the PTR of a domain "
            "name always NXDOMAINs. It was 1/8 of DNS traffic returning nothing.")

    def test_settings_override_is_honoured(self):
        from sandbox.config import Settings
        from sandbox.enrich import Enrichment
        e = Enrichment(Settings(save_elastic=False, dns_record_types="A,MX"))
        assert e.dns_record_types == ("A", "MX")

    def test_empty_falls_back_rather_than_disabling_dns(self):
        from sandbox.config import Settings
        from sandbox.enrich import Enrichment
        e = Enrichment(Settings(save_elastic=False, dns_record_types=""))
        assert e.dns_record_types == e.DNS_RECORD_TYPES,             "an empty list must not silently mean 'no DNS' - use dns=NONE for that"


class TestDnsOffSwitch:
    """Turning DNS off must actually turn it off.

    dns_enabled() used an exact-string test, so "none", "off" and " NONE " all
    left DNS fully ON - an operator disabling it to relieve a saturated resolver
    would have seen no change and no error.
    """

    @pytest.mark.parametrize("value", ["NONE", "none", "None", " NONE ", "off",
                                       "OFF", "no", "0", "False", ""])
    def test_off_words_disable_dns(self, value):
        from sandbox.config import Settings
        assert Settings(save_elastic=False, dns=value).dns_enabled() is False

    @pytest.mark.parametrize("value", ["ALL", "all", "MAIN", "main", " MAIN "])
    def test_on_values_stay_enabled(self, value):
        from sandbox.config import Settings
        assert Settings(save_elastic=False, dns=value).dns_enabled() is True
