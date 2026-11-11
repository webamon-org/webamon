"""Unit tests for network capture logic (no live browser — CDP payloads faked)."""
import pytest

from sandbox import capture


def _domain_extract(url):
    """Minimal stand-in for Enrichment.domain_extract."""
    from urllib.parse import urlparse
    host = urlparse(url).netloc
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:]), ".".join(parts[:-2]), parts[-1]
    return host, "", ""


class TestNetworkCapture:
    def test_request_then_response_pairs(self):
        cap = capture.NetworkCapture()
        cap._on_request({"requestId": "1", "request": {"url": "http://a.com/"}})
        cap._on_response({"requestId": "1", "response": {"url": "http://a.com/", "status": 200}})
        assert cap.requests["1"]["request"]["url"] == "http://a.com/"
        assert cap.requests["1"]["response"]["status"] == 200

    def test_redirect_chain_captured(self):
        cap = capture.NetworkCapture()
        cap._on_request({
            "requestId": "1",
            "request": {"url": "http://final.com/"},
            "redirectResponse": {"url": "http://start.com/", "status": 302, "remoteIPAddress": "1.1.1.1"},
        })
        assert cap.redirect_chain == [
            {"url": "http://start.com/", "status": 302, "ip": "1.1.1.1", "location": "http://final.com/"}
        ]

    def test_response_without_request_ignored(self):
        cap = capture.NetworkCapture()
        cap._on_response({"requestId": "ghost", "response": {"status": 200}})
        assert "ghost" not in cap.requests


class TestBuildResources:
    def test_hashes_and_dedupes(self):
        requests = {
            "1": {"request": {"url": "http://a/x.js"}, "response": {"mimeType": "application/javascript", "url": "http://a/x.js"}},
        }
        bodies = {"1": {"body": "console.log(1)"}}
        mapping, master = capture.build_resources(requests, bodies, "rid", "http://a", "2026-01-01T00:00:00Z")
        assert len(mapping) == 1
        sha = mapping[0]["sha256"]
        assert master[sha]["resource"] == "console.log(1)"
        assert master[sha]["mime_type"] == "application/javascript"

    def test_skips_requests_without_body(self):
        requests = {"1": {"request": {"url": "http://a/x"}, "response": {"mimeType": "text/html", "url": "http://a/x"}}}
        mapping, master = capture.build_resources(requests, {}, "rid", "http://a", "t")
        assert mapping == []
        assert master == {}


class TestCaptureBodies:
    """Regression: requests arriving DURING body fetching must still get bodies.

    The original code snapshotted body ids once, then assigned report["request"]
    the live dict by reference, so late arrivals appeared in request[] with no
    resource - producing resource counts lower than request counts.
    """

    class _FakeCDP:
        def __init__(self, net, inject_on_call=None):
            self.net = net
            self.inject_on_call = inject_on_call or {}
            self.calls = 0

        async def send(self, method, params):
            self.calls += 1
            rid = params["requestId"]
            # Simulate new requests landing while the first fetch is in flight.
            for at_call, entries in list(self.inject_on_call.items()):
                if self.calls >= at_call:
                    self.net.requests.update(entries)
                    del self.inject_on_call[at_call]
            return {"body": f"body-{rid}", "base64Encoded": False}

    @pytest.mark.asyncio
    async def test_late_arrivals_get_bodies(self):
        net = capture.NetworkCapture()
        net.requests = {
            "1": {"request": {"url": "https://a/1"}, "response": {"url": "https://a/1"}},
            "2": {"request": {"url": "https://a/2"}, "response": {"url": "https://a/2"}},
        }
        late = {"3": {"request": {"url": "https://a/3"}, "response": {"url": "https://a/3"}}}
        cdp = self._FakeCDP(net, inject_on_call={1: late})

        snapshot, bodies = await capture.capture_bodies(cdp, net, concurrency=2)

        assert set(snapshot) == {"1", "2", "3"}
        assert set(bodies) == {"1", "2", "3"}, "late arrival must not be left body-less"

    @pytest.mark.asyncio
    async def test_snapshot_is_frozen_copy(self):
        net = capture.NetworkCapture()
        net.requests = {"1": {"request": {"url": "https://a/1"},
                              "response": {"url": "https://a/1"}}}
        cdp = self._FakeCDP(net)
        snapshot, _ = await capture.capture_bodies(cdp, net, concurrency=2)
        # Mutating the live map afterwards must not change what we reported.
        net.requests["99"] = {"request": {"url": "x"}, "response": {}}
        assert "99" not in snapshot

    @pytest.mark.asyncio
    async def test_bounded_passes_on_endless_stream(self):
        """A page streaming requests forever must not hang the scan."""
        net = capture.NetworkCapture()
        net.requests = {"1": {"request": {"url": "https://a/1"},
                              "response": {"url": "https://a/1"}}}

        class _Endless(self._FakeCDP):
            async def send(self, method, params):
                self.calls += 1
                self.net.requests[f"new{self.calls}"] = {
                    "request": {"url": "https://a/n"}, "response": {"url": "https://a/n"}}
                return {"body": "x"}

        snapshot, bodies = await capture.capture_bodies(
            _Endless(net), net, concurrency=1, max_passes=2)
        assert len(bodies) >= 1   # terminated rather than looping forever


class TestFinalizeNetwork:
    def test_filters_blob_and_data_urls(self):
        sec = {"subjectName": "a.com", "validFrom": 0, "validTo": 100}
        network = {"request": {
            "1": {"request": {"url": "data:text/html,x"}, "response": {"url": "data:text/html,x", "securityDetails": dict(sec)}},
            "2": {"request": {"url": "https://a.com/"}, "response": {"url": "https://a.com/", "securityDetails": dict(sec)}},
        }}
        capture.finalize_network(network, _domain_extract)
        urls = [r["request"]["url"] for r in network["request"]]
        assert "https://a.com/" in urls
        assert all(not u.startswith("data:") for u in urls)

    def test_plain_http_request_is_kept(self):
        """v3 diverges from v2: cleartext HTTP requests must survive.

        v2 dropped anything without TLS securityDetails, so HTTP-only hosts
        were invisible in request[], domain[] and the risk score.
        """
        network = {"request": {"1": {"request": {"url": "http://a.com/"},
                                     "response": {"url": "http://a.com/"}}}}
        capture.finalize_network(network, _domain_extract)
        assert len(network["request"]) == 1
        assert network["request"][0]["request"]["url"] == "http://a.com/"
        assert network["certificate"] == []   # no cert harvested from plain HTTP

    def test_mixed_http_and_https_both_kept_certs_only_from_tls(self):
        sec = {"subjectName": "s.com", "validFrom": 0, "validTo": 100}
        network = {"request": {
            "1": {"request": {"url": "http://plain.com/"}, "response": {"url": "http://plain.com/"}},
            "2": {"request": {"url": "https://s.com/"}, "response": {"url": "https://s.com/", "securityDetails": dict(sec)}},
        }}
        capture.finalize_network(network, _domain_extract)
        assert len(network["request"]) == 2
        assert len(network["certificate"]) == 1
        assert network["certificate"][0]["subject_name" if "subject_name" in network["certificate"][0] else "subjectName"] == "s.com"

    def test_request_without_response_still_skipped(self):
        """Dangling requests have no URL to attribute and would create
        empty-string domain buckets downstream."""
        network = {"request": {"1": {"request": {"url": "http://a.com/"}}}}
        capture.finalize_network(network, _domain_extract)
        assert network["request"] == []

    def test_dedupes_certificates_by_subject(self):
        sec = {"subjectName": "a.com", "validFrom": 0, "validTo": 100}
        network = {"request": {
            "1": {"request": {"url": "https://a.com/1"}, "response": {"url": "https://a.com/1", "securityDetails": dict(sec)}},
            "2": {"request": {"url": "https://a.com/2"}, "response": {"url": "https://a.com/2", "securityDetails": dict(sec)}},
        }}
        capture.finalize_network(network, _domain_extract)
        assert len(network["certificate"]) == 1
        assert "valid_from_utc" in network["certificate"][0]

    def test_request_becomes_list(self):
        sec = {"subjectName": "a.com", "validFrom": 0, "validTo": 100}
        network = {"request": {"1": {"request": {"url": "https://a.com/"}, "response": {"url": "https://a.com/", "securityDetails": dict(sec)}}}}
        capture.finalize_network(network, _domain_extract)
        assert isinstance(network["request"], list)
