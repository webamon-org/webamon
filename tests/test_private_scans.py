"""Private scans must land in the tenant's own index.

The v3 rebuild dropped this: pipeline.py called

    index_report(report if not job.private else report)

with both branches the same object, so every private scan went to the shared
scans-YYYY.MM.DD index carrying `private: true` while the tenant's
private-scans-<tenant> index stopped growing entirely. Nothing failed, nothing
logged, and the data was in the wrong place from the moment v3 went live.
"""
import asyncio
import json

import pytest

from sandbox.config import Settings
from sandbox.persist import BulkWriter
from sandbox.pipeline import ScanJob, ScanPipeline


class FakeOS:
    def __init__(self, settings):
        self.settings = settings
        self.sent = []

    def dated(self, base):
        return f"{base}-2026.08.06"

    async def bulk(self, ndjson):
        self.sent.append(ndjson)
        return {"errors": False, "items": []}


async def _index_written(payload):
    settings = Settings(save_elastic=False)
    os_ = FakeOS(settings)
    writer = BulkWriter(os_, settings)
    job = ScanJob.from_payload(payload)
    await writer.index_report({"report_id": "r1"},
                              index_override=ScanPipeline._private_index(job))
    writer.start()
    await writer.stop()
    return json.loads(os_.sent[0].split("\n")[0])["index"]["_index"]


class TestPrivateRouting:
    def test_private_scan_goes_to_the_tenant_index(self):
        idx = asyncio.run(_index_written(
            {"url": "http://x.com", "private": True, "tenant": "acme-corp"}))
        assert idx == "private-scans-acme-corp"

    def test_tenant_index_is_not_date_suffixed(self):
        """v2 does `index_override or get_current_index('scans')`, so the
        override is verbatim. Dating it would scatter a tenant's history across
        daily indices their saved queries do not match."""
        idx = asyncio.run(_index_written(
            {"url": "http://x.com", "private": True, "tenant": "acme"}))
        assert idx == "private-scans-acme"
        assert "2026" not in idx

    def test_public_scan_still_goes_to_the_dated_index(self):
        idx = asyncio.run(_index_written({"url": "http://x.com"}))
        assert idx == "scans-2026.08.06"

    def test_private_without_tenant_falls_back_to_public(self):
        """Safer than composing an index name from nothing - and it is logged."""
        idx = asyncio.run(_index_written({"url": "http://x.com", "private": True}))
        assert idx == "scans-2026.08.06"

    @pytest.mark.parametrize("tenant", [
        "../../etc", "acme corp", "acme/../other", "a" * 41, "acme*", "",
    ])
    def test_injection_attempts_never_reach_an_index_name(self, tenant):
        idx = asyncio.run(_index_written(
            {"url": "http://x.com", "private": True, "tenant": tenant}))
        assert idx == "scans-2026.08.06", f"{tenant!r} must not build an index name"

    def test_tenant_is_lowercased(self):
        idx = asyncio.run(_index_written(
            {"url": "http://x.com", "private": True, "tenant": "AcmeCorp"}))
        assert idx == "private-scans-acmecorp"


class TestPrivateIndexHelper:
    def test_public_job_returns_none(self):
        assert ScanPipeline._private_index(ScanJob(url="http://x.com")) is None

    def test_private_job_returns_the_tenant_index(self):
        job = ScanJob.from_payload(
            {"url": "http://x.com", "private": True, "tenant": "acme"})
        assert ScanPipeline._private_index(job) == "private-scans-acme"

    def test_index_report_defaults_to_public_when_override_is_none(self):
        """The override must be opt-in - a None must never be stringified into
        the index name."""
        idx = asyncio.run(_index_written({"url": "http://x.com"}))
        assert "None" not in idx
