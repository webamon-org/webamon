"""Unit tests for pipeline job parsing, tenant validation, counters."""
import pytest

from sandbox.pipeline import ScanJob, Counters, _safe_tenant


class TestScanJob:
    def test_from_submission_url(self):
        job = ScanJob.from_payload({"submission_url": "example.com"})
        assert job.url == "example.com"

    def test_from_url_fallback(self):
        job = ScanJob.from_payload({"url": "example.com"})
        assert job.url == "example.com"

    def test_missing_url_returns_none(self):
        assert ScanJob.from_payload({"tag": "x"}) is None

    def test_non_string_url_returns_none(self):
        assert ScanJob.from_payload({"url": 123}) is None

    def test_private_tag_normalized(self):
        job = ScanJob.from_payload({"url": "x", "private": True, "private_tag": "a,b"})
        assert job.private is True
        assert job.private_tag == ["a", "b"]


class TestSafeTenant:
    def test_valid_slug(self):
        assert _safe_tenant("acme-corp") == "acme-corp"

    def test_lowercased(self):
        assert _safe_tenant("AcmeCorp") == "acmecorp"

    def test_rejects_path_traversal(self):
        assert _safe_tenant("../etc") is None

    def test_rejects_wildcard(self):
        assert _safe_tenant("scans*") is None

    def test_rejects_comma(self):
        assert _safe_tenant("a,b") is None

    def test_none(self):
        assert _safe_tenant(None) is None


class TestCounters:
    @pytest.mark.asyncio
    async def test_records_statuses(self):
        c = Counters()
        await c.record("success")
        await c.record("failed")
        await c.record("skipped")
        await c.record("blocked")
        await c.record("success")
        assert c.total == 5
        assert c.success == 2
        assert c.failed == 1
        assert c.skipped == 1
        assert c.blocked == 1
