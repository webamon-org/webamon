"""Unit tests for typed config."""
import pytest

from sandbox.config import Settings


class TestSettings:
    def test_defaults(self):
        s = Settings()
        assert s.threads == 4
        assert s.save_elastic is True

    def test_bool_from_v2_string(self, monkeypatch):
        monkeypatch.setenv("save_screenshot", "True")
        monkeypatch.setenv("skip_if_exists", "False")
        s = Settings()
        assert s.save_screenshot is True
        assert s.skip_if_exists is False

    def test_invalid_resources_rejected(self, monkeypatch):
        monkeypatch.setenv("resources", "bogus")
        with pytest.raises(Exception):
            Settings()

    def test_invalid_log_level_rejected(self, monkeypatch):
        monkeypatch.setenv("log_level", "NOPE")
        with pytest.raises(Exception):
            Settings()

    def test_cookies_dict_valid(self, monkeypatch):
        monkeypatch.setenv("set_cookies", '{"a": "b"}')
        assert Settings().cookies_dict() == {"a": "b"}

    def test_cookies_dict_invalid_json_safe(self, monkeypatch):
        monkeypatch.setenv("set_cookies", "not json")
        assert Settings().cookies_dict() == {}

    def test_dns_enabled(self, monkeypatch):
        monkeypatch.setenv("dns", "ALL")
        assert Settings().dns_enabled() is True
        monkeypatch.setenv("dns", "NONE")
        assert Settings().dns_enabled() is False

    def test_dns_defaults_to_all_matching_v2(self):
        """REGRESSION GUARD - do not relax this.

        Reports carry a populated `dns` block. Defaulting to MAIN or NONE
        silently drops that field from every scan, which is a data regression
        rather than a performance setting. If DNS cost becomes
        a problem the fix is in the resolver, not the default.
        """
        s = Settings()
        assert s.dns == "ALL"
        assert s.dns_enabled() is True

    def test_dns_resolver_timeouts_are_pinned(self):
        """dnspython's defaults (2s/5s) mean 8 record types can stall a domain
        for 40s, and scan_timeout does not cover enrichment."""
        s = Settings()
        assert 0 < s.dns_timeout <= 5
        assert 0 < s.dns_lifetime <= 10
        assert s.dns_concurrency >= len(("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR")) // 2

    def test_post_load_dwell_off_by_default(self):
        assert Settings().post_load_dwell_ms == 0

    def test_post_load_dwell_from_env(self, monkeypatch):
        monkeypatch.setenv("post_load_dwell_ms", "2500")
        assert Settings().post_load_dwell_ms == 2500

