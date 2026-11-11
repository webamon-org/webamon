"""Unit tests for fingerprinting + monitor change detection."""
import pytest

from sandbox import fingerprints


class TestHashData:
    def test_stable_across_dict_ordering(self):
        a = {"x": 1, "y": 2}
        b = {"y": 2, "x": 1}
        assert fingerprints.hash_data(a) == fingerprints.hash_data(b)

    def test_stable_across_list_ordering(self):
        assert fingerprints.hash_data([3, 1, 2]) == fingerprints.hash_data([1, 2, 3])

    def test_different_data_differs(self):
        assert fingerprints.hash_data({"a": 1}) != fingerprints.hash_data({"a": 2})

    def test_nested_heterogeneous_list(self):
        # deep_sort must not raise on mixed-type list content.
        data = [{"z": 1}, {"a": 2}, "string", 42]
        assert isinstance(fingerprints.hash_data(data), str)


class TestGenerateFingerprints:
    ORIGINAL_KEYS = {"ssl", "tech", "cookies", "asn",
                     "scripts", "links", "domains", "dom"}

    def test_all_keys_present(self):
        # The original eight must always be present. Asserting an EXACT set
        # would make every future fingerprint a breaking change; the contract
        # that matters is that these eight never disappear or change meaning,
        # because saved queries and dashboards are built on them.
        scan = {"certificate": [], "technology": [], "cookie": [], "server": [],
                "page_scripts": [], "page_links": [], "domain": [], "dom": "<html>"}
        fp = fingerprints.generate_fingerprints(scan)
        assert self.ORIGINAL_KEYS <= set(fp)

    def test_extension_keys_present(self):
        scan = {"certificate": [], "technology": [], "cookie": [], "server": [],
                "page_scripts": [], "page_links": [], "domain": [], "dom": "<html>"}
        fp = fingerprints.generate_fingerprints(scan)
        assert {"cert_issuer", "cert_san", "cert_config", "header_order",
                "cookie_names", "dom_structure", "dom_band",
                "ns_set", "mx_set"} <= set(fp)

    def test_missing_optional_fields_safe(self):
        # generate_fingerprints must not KeyError on a minimal scan.
        fp = fingerprints.generate_fingerprints({})
        assert "dom" in fp

    def test_scan_fingerprint_is_gone(self):
        # Removed deliberately: unique per scan by construction (0.646
        # cardinality, largest cluster 1 doc) for 133.9 ms per page.
        fp = fingerprints.generate_fingerprints({"dom": "<html>"})
        assert "scan_fingerprint" not in fp

    def test_asn_extraction(self):
        scan = {"server": [{"asn": {"number": 123}}, {"asn": {"number": 456}}]}
        fp1 = fingerprints.generate_fingerprints(scan)
        fp2 = fingerprints.generate_fingerprints({"server": [{"asn": {"number": 456}}, {"asn": {"number": 123}}]})
        assert fp1["asn"] == fp2["asn"]  # order-independent


class TestCompareFingerprints:
    def test_detects_changed_keys(self):
        old = {"ssl": "a", "tech": "b", "dom": "c"}
        new = {"ssl": "a", "tech": "X", "dom": "c"}
        assert fingerprints.compare_fingerprints(old, new) == ["tech"]

    def test_no_change(self):
        fp = {k: "same" for k in ("asn", "cookies", "domains", "links", "scripts", "ssl", "tech", "dom")}
        assert fingerprints.compare_fingerprints(fp, fp) == []


class TestDetectChanges:
    """Regression for v2 bug: set.update('page_title') exploded into characters."""

    class _FakeClient:
        def __init__(self, previous):
            self._previous = previous

        async def search(self, index, body):
            if self._previous is None:
                return {"hits": {"hits": []}}
            return {"hits": {"hits": [{"_source": self._previous}]}}

    @pytest.mark.asyncio
    async def test_page_title_change_is_whole_word(self):
        previous = {"fingerprint": {}, "page_title": "Old", "resolved_url": "http://x/"}
        scan = {"submission_url": "http://x", "fingerprint": {}, "page_title": "New", "resolved_url": "http://x/"}
        changes = await fingerprints.detect_changes(scan, self._FakeClient(previous))
        assert changes == ["page_title"]  # NOT ['p','a','g','e',...]

    @pytest.mark.asyncio
    async def test_no_previous_returns_empty(self):
        scan = {"submission_url": "http://x", "fingerprint": {}, "page_title": "", "resolved_url": ""}
        assert await fingerprints.detect_changes(scan, self._FakeClient(None)) == []

    @pytest.mark.asyncio
    async def test_resolved_url_and_fingerprint_change(self):
        previous = {"fingerprint": {"dom": "a"}, "page_title": "T", "resolved_url": "http://x/"}
        scan = {"submission_url": "http://x", "fingerprint": {"dom": "b"},
                "page_title": "T", "resolved_url": "http://y/"}
        changes = await fingerprints.detect_changes(scan, self._FakeClient(previous))
        assert "resolved_url" in changes
        assert "dom" in changes
