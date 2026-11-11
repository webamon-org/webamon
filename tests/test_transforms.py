"""Unit tests for report-shaping transforms (no network, no browser)."""
from sandbox.transforms import (
    normalize_private_tags, clean_data, transform_headers, format_errors,
    normalize_cookies,
)


class TestNormalizeCookies:
    """v2/Selenium wrote `expiry` (int, omitted for session cookies);
    Playwright emits `expires` (float, -1 for session)."""

    def test_expires_renamed_to_expiry_int(self):
        out = normalize_cookies([{"name": "a", "expires": 1817231894.0}])
        assert out[0]["expiry"] == 1817231894
        assert isinstance(out[0]["expiry"], int)
        assert "expires" not in out[0]

    def test_session_cookie_has_no_expiry(self):
        out = normalize_cookies([{"name": "s", "expires": -1}])
        assert "expiry" not in out[0]
        assert "expires" not in out[0]

    def test_other_fields_untouched(self):
        out = normalize_cookies([{"name": "a", "value": "b", "secure": True,
                                  "httpOnly": False, "expires": -1}])
        assert out[0]["name"] == "a"
        assert out[0]["secure"] is True

    def test_no_expires_key_safe(self):
        assert normalize_cookies([{"name": "a"}]) == [{"name": "a"}]

    def test_does_not_mutate_input(self):
        original = [{"name": "a", "expires": 123.0}]
        normalize_cookies(original)
        assert "expires" in original[0]

    def test_garbage_expires_treated_as_session(self):
        out = normalize_cookies([{"name": "a", "expires": "bogus"}])
        assert "expiry" not in out[0]


class TestNormalizePrivateTags:
    def test_none(self):
        assert normalize_private_tags(None) == []

    def test_empty_string(self):
        assert normalize_private_tags("") == []

    def test_plain_list(self):
        assert normalize_private_tags(["a", "b"]) == ["a", "b"]

    def test_comma_string(self):
        assert normalize_private_tags("a,b") == ["a", "b"]

    def test_python_list_string(self):
        assert normalize_private_tags("['a','b']") == ["a", "b"]

    def test_json_list_string(self):
        assert normalize_private_tags('["a","b"]') == ["a", "b"]

    def test_strips_whitespace_and_quotes(self):
        assert normalize_private_tags(' "a" , b ') == ["a", "b"]

    def test_nested_stringified_list_element(self):
        assert normalize_private_tags(["['x','y']"]) == ["x", "y"]

    def test_tuple_input(self):
        assert normalize_private_tags(("a", "b")) == ["a", "b"]


class TestCleanData:
    def test_renames_response_camelcase(self):
        report = {"request": [{"response": {"mimeType": "text/html", "remoteIPAddress": "1.2.3.4",
                                            "encodedDataLength": 42}}]}
        clean_data(report)
        resp = report["request"][0]["response"]
        assert resp["mime_type"] == "text/html"
        assert resp["ip"] == "1.2.3.4"
        assert resp["encoded_data_length"] == 42
        assert "mimeType" not in resp

    def test_drops_noise_fields(self):
        report = {"request": [{"response": {"fromDiskCache": True, "connectionId": 7, "mimeType": "x"}}]}
        clean_data(report)
        resp = report["request"][0]["response"]
        assert "fromDiskCache" not in resp
        assert "connectionId" not in resp

    def test_cert_rename(self):
        report = {"certificate": [{"subjectName": "a.com", "validFrom": 1, "validTo": 2, "sanList": []}]}
        clean_data(report)
        cert = report["certificate"][0]
        assert cert["subject_name"] == "a.com"
        assert cert["valid_from"] == 1
        assert cert["san_list"] == []

    def test_cookie_rename(self):
        report = {"cookie": [{"httpOnly": True, "sameSite": "Lax"}]}
        clean_data(report)
        assert report["cookie"][0]["http_only"] is True
        assert report["cookie"][0]["same_site"] == "Lax"

    def test_empty_report_safe(self):
        assert clean_data({}) == {}


class TestTransformHeaders:
    def test_dict_to_namevalue_list(self):
        report = {"request": [{"request": {"headers": {"Host": "a.com", "Accept": "*/*"}},
                               "response": {"headers": {"Server": "nginx"}}}]}
        transform_headers(report)
        req_headers = report["request"][0]["request"]["headers"]
        assert {"name": "Host", "value": "a.com"} in req_headers
        assert report["request"][0]["response"]["headers"] == [{"name": "Server", "value": "nginx"}]


def test_format_errors_groups_by_error():
    log = [{"error": "timeout", "url": "a"}, {"error": "timeout", "url": "b"},
           {"error": "refused", "url": "c"}]
    assert format_errors(log) == {"timeout": ["a", "b"], "refused": ["c"]}
