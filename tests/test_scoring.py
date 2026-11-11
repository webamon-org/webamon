"""Unit tests for risk scoring — behaviour-parity with v2 threat_score."""
import time

from sandbox import scoring


class TestSslChecks:
    def test_expired_cert(self):
        assert scoring.ssl_checks([{"valid_to": int(time.time()) - 100}]) == 5

    def test_weak_protocol_tls12(self):
        # v2 quirk retained: TLS 1.2 counts as weak (+3).
        assert scoring.ssl_checks([{"protocol": "TLS 1.2"}]) == 3

    def test_wildcard_subject(self):
        assert scoring.ssl_checks([{"subject_name": "*.evil.com"}]) == 2

    def test_letsencrypt_issuer_flagged(self):
        # v2 quirk retained: any issuer starting with 'R' gets +1.
        assert scoring.ssl_checks([{"issuer": "R3"}]) == 1

    def test_capped_at_max(self):
        cert = {"valid_to": 1, "protocol": "TLS 1.0", "cipher": "RC4",
                "valid_from": 0, "subject_name": "*.x", "issuer": "R3"}
        assert scoring.ssl_checks([cert]) == scoring.SSL_MAX

    def test_empty(self):
        assert scoring.ssl_checks([]) == 0


class TestRequestCheck:
    def test_cleartext_http(self):
        assert scoring.request_check([{"request": {"url": "http://x.com"}}]) == 7

    def test_post(self):
        assert scoring.request_check([{"request": {"method": "POST", "url": "https://x"}}]) == 3

    def test_capped(self):
        reqs = [{"request": {"method": "POST", "url": "http://x"}} for _ in range(5)]
        assert scoring.request_check(reqs) == scoring.REQUEST_MAX


class TestMetaCheck:
    def test_over_20(self):
        assert scoring.meta_check({"script_count": 25}) == 4

    def test_over_40(self):
        assert scoring.meta_check({"script_count": 45}) == 10  # 4 + 6

    def test_low(self):
        assert scoring.meta_check({"script_count": 5}) == 0


class TestDomainCheck:
    def test_risky_tld(self):
        assert scoring.domain_check([{"tld": "xyz"}]) == 5

    def test_risky_country(self):
        assert scoring.domain_check([{"country": {"iso": "RU"}}]) == 5

    def test_risky_asn(self):
        assert scoring.domain_check([{"asn": {"number": 4134}}]) == 5

    def test_none_country_safe(self):
        assert scoring.domain_check([{"country": None, "asn": None}]) == 0

    def test_capped(self):
        domains = [{"tld": "xyz", "country": {"iso": "RU"}, "asn": {"number": 4134}} for _ in range(3)]
        assert scoring.domain_check(domains) == scoring.DOMAIN_MAX


class TestCookieCheck:
    def test_insecure_cookie(self):
        assert scoring.cookie_check([{"secure": False, "httpOnly": False}]) == 6

    def test_secure_httponly(self):
        assert scoring.cookie_check([{"secure": True, "httpOnly": True}]) == 0

    def test_snake_case_httponly(self):
        assert scoring.cookie_check([{"secure": True, "http_only": True}]) == 0


class TestTechnologyCheck:
    def test_risky_tech(self):
        assert scoring.technology_check([{"name": "jQuery", "version": "1.8"}]) == 5

    def test_safe_tech(self):
        assert scoring.technology_check([{"name": "React", "version": "18"}]) == 0


class TestGenerate:
    def test_empty_report_zero(self):
        assert scoring.generate({}) == 0

    def test_normalized_range(self):
        report = {
            "certificate": [{"valid_to": 1, "protocol": "TLS 1.0"}],
            "request": [{"request": {"url": "http://x"}}],
            "domain": [{"tld": "xyz"}],
        }
        score = scoring.generate(report)
        assert 0 <= score <= 100

    def test_max_possible_is_70(self):
        assert scoring.MAX_POSSIBLE == 70
