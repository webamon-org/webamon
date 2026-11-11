"""Unit tests for the threat-intel fingerprint extensions."""
import pytest

from sandbox import fingerprints, fpx


class TestCertificates:
    def test_split_pivots_are_independent(self):
        """Two certs from one issuer for different names must share the issuer
        hash but not the SAN hash - that separation is the whole point."""
        a = [{"issuer": "R3", "san_list": ["a.com"], "protocol": "TLS 1.3",
              "cipher": "AES_128_GCM", "valid_to": "2026-01-01"}]
        b = [{"issuer": "R3", "san_list": ["b.com"], "protocol": "TLS 1.3",
              "cipher": "AES_128_GCM", "valid_to": "2027-06-06"}]
        fa, fb = fpx.cert_fingerprints(a), fpx.cert_fingerprints(b)
        assert fa["cert_issuer"] == fb["cert_issuer"]
        assert fa["cert_config"] == fb["cert_config"]
        assert fa["cert_san"] != fb["cert_san"]

    def test_renewal_does_not_change_any_split_hash(self):
        """The existing ssl hash breaks on renewal because it includes the
        validity dates; these must not."""
        old = [{"issuer": "R3", "san_list": ["a.com"], "protocol": "TLS 1.3",
                "cipher": "AES_128_GCM", "valid_from": "2025-01-01", "valid_to": "2025-04-01"}]
        new = [{"issuer": "R3", "san_list": ["a.com"], "protocol": "TLS 1.3",
                "cipher": "AES_128_GCM", "valid_from": "2025-04-01", "valid_to": "2025-07-01"}]
        assert fpx.cert_fingerprints(old) == fpx.cert_fingerprints(new)

    def test_san_order_and_case_do_not_matter(self):
        a = [{"issuer": "x", "san_list": ["B.com", "a.com."]}]
        b = [{"issuer": "x", "san_list": ["a.com", "b.com"]}]
        assert fpx.cert_fingerprints(a)["cert_san"] == fpx.cert_fingerprints(b)["cert_san"]

    def test_empty_input_is_empty_not_a_hash_of_nothing(self):
        assert fpx.cert_fingerprints([])["cert_issuer"] == ""


class TestHeaderOrder:
    def _req(self, names, url="https://x.com/"):
        return [{"response": {"url": url,
                              "headers": [{"name": n, "value": "v"} for n in names]}}]

    def test_order_is_significant(self):
        a = fpx.header_order_fingerprint(self._req(["Server", "Date"]), "https://x.com/")
        b = fpx.header_order_fingerprint(self._req(["Date", "Server"]), "https://x.com/")
        assert a != b, "header ORDER is the signal - sorting would destroy it"

    def test_values_are_ignored(self):
        r = [{"response": {"url": "https://x.com/", "headers": [
            {"name": "Set-Cookie", "value": "session=abc123"}]}}]
        r2 = [{"response": {"url": "https://x.com/", "headers": [
            {"name": "Set-Cookie", "value": "session=zzz999"}]}}]
        assert (fpx.header_order_fingerprint(r, "https://x.com/")
                == fpx.header_order_fingerprint(r2, "https://x.com/"))

    def test_picks_the_main_document_not_a_subresource(self):
        reqs = [
            {"response": {"url": "https://cdn.x.com/a.js", "headers": [{"name": "X-CDN"}]}},
            {"response": {"url": "https://x.com/", "headers": [{"name": "Server"}]}},
        ]
        only_main = [{"response": {"url": "https://x.com/",
                                   "headers": [{"name": "Server"}]}}]
        assert (fpx.header_order_fingerprint(reqs, "https://x.com/")
                == fpx.header_order_fingerprint(only_main, "https://x.com/"))


class TestCookieNames:
    def test_values_excluded_so_sessions_still_match(self):
        a = [{"name": "PHPSESSID", "value": "aaa"}, {"name": "csrf", "value": "1"}]
        b = [{"name": "csrf", "value": "2"}, {"name": "PHPSESSID", "value": "bbb"}]
        assert fpx.cookie_name_fingerprint(a) == fpx.cookie_name_fingerprint(b)
        assert fingerprints.hash_data(a) != fingerprints.hash_data(b), \
            "the existing cookies hash should differ - that is why this exists"


class TestDomSimilarity:
    KIT = "<html><body><div><form><input><input><button></button></form></div></body></html>"

    def test_rebrand_keeps_structure_hash(self):
        """Same markup, different copy - the case the existing dom hash misses."""
        a = self.KIT.replace("<button>", "<button>Sign in")
        b = self.KIT.replace("<button>", "<button>Anmelden")
        assert fpx.dom_similarity(a)["dom_structure"] == fpx.dom_similarity(b)["dom_structure"]
        assert fingerprints.hash_data(a) != fingerprints.hash_data(b)

    def test_attribute_values_do_not_change_structure(self):
        a = '<div class="a" id="x"><p>hi</p></div>'
        b = '<div class="totally-different" id="y"><p>bye</p></div>'
        assert fpx.dom_similarity(a)["dom_structure"] == fpx.dom_similarity(b)["dom_structure"]

    def test_different_structure_differs(self):
        a = "<html><body><div><span></span></div></body></html>"
        b = "<html><body><table><tr><td></td></tr></table></body></html>"
        assert fpx.dom_similarity(a)["dom_structure"] != fpx.dom_similarity(b)["dom_structure"]

    def test_near_duplicate_shares_a_band(self):
        """A page with one extra element must still be findable."""
        base = "<html><body>" + "<div><p></p></div>" * 40 + "</body></html>"
        tweak = base.replace("</body>", "<span></span></body>")
        ba = set(fpx.dom_similarity(base)["dom_band"])
        bb = set(fpx.dom_similarity(tweak)["dom_band"])
        assert ba & bb, "LSH bands must overlap for a near-duplicate"

    def test_bands_are_index_prefixed(self):
        dom = "<html><body>" + "<div></div>" * 30 + "</body></html>"
        bands = fpx.dom_similarity(dom)["dom_band"]
        assert all(b.split(":")[0] == str(i) for i, b in enumerate(bands)), \
            "without the band index, band 0 could match band 2 spuriously"

    def test_empty_dom_is_empty(self):
        assert fpx.dom_similarity("") == {"dom_structure": "", "dom_band": []}


class TestDnsSets:
    def test_mx_priority_is_stripped(self):
        a = [{"name": "x.com", "dns": {"mx": ["10 mail.x.com.", "20 alt.x.com."]}}]
        b = [{"name": "x.com", "dns": {"mx": ["5 mail.x.com", "30 alt.x.com"]}}]
        assert (fpx.dns_set_fingerprints(a, "x.com")["mx_set"]
                == fpx.dns_set_fingerprints(b, "x.com")["mx_set"]), \
            "a provider reweighting MX must not change the fingerprint"

    def test_ns_order_and_trailing_dot_normalised(self):
        a = [{"name": "x.com", "dns": {"ns": ["NS2.h.com.", "ns1.h.com"]}}]
        b = [{"name": "x.com", "dns": {"ns": ["ns1.h.com.", "ns2.h.com"]}}]
        assert (fpx.dns_set_fingerprints(a, "x.com")["ns_set"]
                == fpx.dns_set_fingerprints(b, "x.com")["ns_set"])

    def test_shared_hosting_clusters(self):
        a = [{"name": "evil1.com", "dns": {"ns": ["ns1.bullet.ru"]}}]
        b = [{"name": "evil2.com", "dns": {"ns": ["ns1.bullet.ru"]}}]
        assert (fpx.dns_set_fingerprints(a, "evil1.com")["ns_set"]
                == fpx.dns_set_fingerprints(b, "evil2.com")["ns_set"])


class TestLexical:
    def test_brand_impersonation_detected(self):
        f = fpx.lexical_features("paypa1", "")
        assert f["brand_match"] == "paypal"
        assert f["brand_distance"] == 1

    def test_brand_as_substring_is_distance_zero(self):
        assert fpx.lexical_features("paypal-secure-login.tk", "")["brand_match"] == "paypal"

    def test_unrelated_domain_has_no_brand(self):
        assert fpx.lexical_features("kzqxvwmt", "")["brand_match"] is None

    def test_punycode_flagged(self):
        assert fpx.lexical_features("xn--pypal-4ve.com", "")["has_punycode"] is True

    def test_dga_style_domain_has_high_entropy(self):
        low = fpx.lexical_features("aaaaaaaaaa", "")["entropy"]
        high = fpx.lexical_features("x7q2zk9mfp", "")["entropy"]
        assert high > low + 1.5

    def test_digit_ratio(self):
        assert fpx.lexical_features("abc123", "")["digit_ratio"] == 0.5

    def test_empty_domain_returns_empty(self):
        assert fpx.lexical_features("", "") == {}


class TestFaviconDhash:
    def test_survives_recompression(self):
        pytest.importorskip("PIL")
        import io

        from PIL import Image
        im = Image.new("RGB", (32, 32))
        for x in range(32):
            for y in range(32):
                im.putpixel((x, y), (x * 8 % 256, y * 8 % 256, 0))
        a, b = io.BytesIO(), io.BytesIO()
        im.save(a, "PNG")
        im.resize((64, 64)).save(b, "PNG")
        assert fpx.favicon_dhash(a.getvalue()) == fpx.favicon_dhash(b.getvalue()), \
            "dhash must survive a resize - that is the point over mmh3"

    def test_garbage_returns_none_not_an_exception(self):
        assert fpx.favicon_dhash(b"this is not an image") is None


class TestBackwardCompatibility:
    def test_original_nine_are_unchanged(self):
        scan = {"certificate": [], "technology": ["a"], "cookie": [],
                "server": [], "page_scripts": [], "page_links": [],
                "domain": [], "dom": "<html></html>", "resolved_url": ""}
        fp = fingerprints.generate_fingerprints(scan)
        for key in ("ssl", "tech", "cookies", "asn",
                    "scripts", "links", "domains", "dom"):
            assert key in fp
        assert fp["tech"] == fingerprints.hash_data(["a"])
        assert fp["dom"] == fingerprints.hash_data("<html></html>")

    def test_new_fields_present(self):
        fp = fingerprints.generate_fingerprints({"dom": "<html><body></body></html>"})
        for key in ("cert_issuer", "cert_san", "cert_config", "header_order",
                    "cookie_names", "dom_structure", "dom_band", "ns_set", "mx_set"):
            assert key in fp, f"{key} missing"

    def test_no_crash_on_empty_report(self):
        assert fingerprints.generate_fingerprints({})
        assert fingerprints.generate_lexical({}) == {}
