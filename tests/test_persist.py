"""Unit tests for the batched persistence layer.

Verifies the NDJSON actions the BulkWriter emits WITHOUT a live cluster: a fake
OpenSearchClient captures flushed bodies so we can assert op-types and that
domains/servers use scripted upserts on non-dated indices (the v2 fix).
"""
import asyncio
import json

import pytest

from sandbox.persist import BulkWriter, _b64_id


class _FakeOS:
    def __init__(self):
        self.flushed = []

    def dated(self, base):
        return f"{base}-2026.01.01"

    async def bulk(self, ndjson):
        self.flushed.append(ndjson)
        return {"errors": False, "items": []}


class _Settings:
    bulk_max_actions = 500
    bulk_flush_interval = 0.05
    domains_index = "domains"
    servers_index = "servers"
    # v3's intended model: a single, non-dated entity index.
    entity_dated_indices = False
    bulk_queue_maxsize = 10000
    bulk_put_timeout = 0.0


class _SlowOS(_FakeOS):
    """OpenSearch that never completes a flush — simulates an outage."""

    def __init__(self, block: asyncio.Event):
        super().__init__()
        self._block = block

    async def bulk(self, ndjson):
        await self._block.wait()
        return {"errors": False, "items": []}


def _parse(ndjson):
    """Return list of (action_dict, doc_dict) pairs from NDJSON."""
    lines = [l for l in ndjson.split("\n") if l]
    return [(json.loads(lines[i]), json.loads(lines[i + 1])) for i in range(0, len(lines), 2)]


@pytest.mark.asyncio
async def test_resource_uses_create_op():
    os = _FakeOS()
    writer = BulkWriter(os, _Settings())
    await writer.create_resource("sha-1", {"sha256": "sha-1", "resource": "x"})
    writer.start()
    await writer.stop()
    action, doc = _parse(os.flushed[0])[0]
    assert "create" in action  # create op → dedupe via 409, no existence read
    assert action["create"]["_id"] == "sha-1"
    assert action["create"]["_index"] == "resources-2026.01.01"


@pytest.mark.asyncio
async def test_domain_upsert_is_scripted_on_nondated_index():
    os = _FakeOS()
    writer = BulkWriter(os, _Settings())
    await writer.upsert_domain({"name": "evil.com", "sub_domain": ["www"], "resource": [], "request": [1]})
    writer.start()
    await writer.stop()
    action, doc = _parse(os.flushed[0])[0]
    assert "update" in action
    assert action["update"]["_index"] == "domains"        # NOT dated (v2 reset bug fixed)
    assert action["update"]["_id"] == _b64_id("evil.com")
    assert action["update"]["retry_on_conflict"] == 3     # race-safe
    assert doc["scripted_upsert"] is True
    assert "request" not in doc["script"]["params"]["doc"]  # stripped field


@pytest.mark.asyncio
async def test_server_upsert_strips_volatile_fields():
    os = _FakeOS()
    writer = BulkWriter(os, _Settings())
    await writer.upsert_server({"ip": "1.2.3.4", "domain": ["a.com"], "total_response_size": 99,
                                "mime_type": ["x"], "response_code": [200], "resource": []})
    writer.start()
    await writer.stop()
    _, doc = _parse(os.flushed[0])[0]
    params_doc = doc["script"]["params"]["doc"]
    assert "total_response_size" not in params_doc
    assert "mime_type" not in params_doc
    assert params_doc["domain"] == ["a.com"]


@pytest.mark.asyncio
async def test_report_indexed_on_dated_index():
    os = _FakeOS()
    writer = BulkWriter(os, _Settings())
    await writer.index_report({"report_id": "rid-1", "scan_status": "success"})
    writer.start()
    await writer.stop()
    action, doc = _parse(os.flushed[0])[0]
    assert action["index"]["_index"] == "scans-2026.01.01"
    assert action["index"]["_id"] == "rid-1"


class TestEntityIndexMode:
    """v2 compatibility: entity docs can be written to dated indices so a v3
    deploy changes nothing downstream, or to a single index (v3's model)."""

    @pytest.mark.asyncio
    async def test_dated_mode_matches_v2_layout(self):
        s = _Settings()
        s.entity_dated_indices = True
        os = _FakeOS()
        writer = BulkWriter(os, s)
        await writer.upsert_domain({"name": "a.com"})
        await writer.upsert_server({"ip": "1.2.3.4"})
        writer.start()
        await writer.stop()
        idx = [a["update"]["_index"] for a, _ in _parse(os.flushed[0])]
        assert idx == ["domains-2026.01.01", "servers-2026.01.01"]

    @pytest.mark.asyncio
    async def test_single_index_mode_is_undated(self):
        s = _Settings()
        s.entity_dated_indices = False
        os = _FakeOS()
        writer = BulkWriter(os, s)
        await writer.upsert_domain({"name": "a.com"})
        writer.start()
        await writer.stop()
        assert _parse(os.flushed[0])[0][0]["update"]["_index"] == "domains"

    @pytest.mark.asyncio
    async def test_custom_entity_index_names_respected(self):
        s = _Settings()
        s.domains_index = "domains-v3"
        s.servers_index = "servers-v3"
        os = _FakeOS()
        writer = BulkWriter(os, s)
        await writer.upsert_domain({"name": "a.com"})
        await writer.upsert_server({"ip": "1.2.3.4"})
        writer.start()
        await writer.stop()
        idx = [a["update"]["_index"] for a, _ in _parse(os.flushed[0])]
        assert idx == ["domains-v3", "servers-v3"]


class TestBackpressure:
    """A bounded queue is the difference between throttling and an OOM."""

    @pytest.mark.asyncio
    async def test_queue_is_bounded_from_settings(self):
        s = _Settings()
        s.bulk_queue_maxsize = 5
        writer = BulkWriter(_FakeOS(), s)
        assert writer.queue_maxsize == 5

    @pytest.mark.asyncio
    async def test_zero_maxsize_means_unbounded(self):
        s = _Settings()
        s.bulk_queue_maxsize = 0
        writer = BulkWriter(_FakeOS(), s)
        assert writer.queue_maxsize == 0   # asyncio semantics: 0 == unbounded

    @pytest.mark.asyncio
    async def test_put_blocks_when_full_rather_than_growing(self):
        s = _Settings()
        s.bulk_queue_maxsize = 2
        writer = BulkWriter(_FakeOS(), s)          # writer NOT started: nothing drains
        await writer.index_report({"report_id": "a"})
        await writer.index_report({"report_id": "b"})
        assert writer.queue_depth == 2

        # Third put must block, not silently grow the queue.
        task = asyncio.create_task(writer.index_report({"report_id": "c"}))
        await asyncio.sleep(0.05)
        assert not task.done(), "put should be blocked on a full queue"
        assert writer.queue_depth == 2
        assert writer.stats["backpressure_waits"] == 1

        writer._queue.get_nowait()                 # simulate a drain
        await asyncio.wait_for(task, timeout=1)
        assert writer.queue_depth == 2

    @pytest.mark.asyncio
    async def test_timeout_drops_and_records_rather_than_hanging(self):
        s = _Settings()
        s.bulk_queue_maxsize = 1
        s.bulk_put_timeout = 0.1
        writer = BulkWriter(_FakeOS(), s)
        await writer.index_report({"report_id": "a"})
        await writer.index_report({"report_id": "b"})   # times out -> dropped
        assert writer.stats["dropped"] == 1
        assert writer.queue_depth == 1

    @pytest.mark.asyncio
    async def test_stats_track_queued_and_flushed(self):
        os = _FakeOS()
        writer = BulkWriter(os, _Settings())
        await writer.index_report({"report_id": "a"})
        await writer.create_resource("s1", {"sha256": "s1"})
        writer.start()
        await writer.stop()
        assert writer.stats["queued"] == 2
        assert writer.stats["flushed"] == 2
        assert writer.stats["flush_errors"] == 0

    @pytest.mark.asyncio
    async def test_flush_error_is_counted_not_raised(self):
        class _BrokenOS(_FakeOS):
            async def bulk(self, ndjson):
                raise RuntimeError("opensearch down")

        writer = BulkWriter(_BrokenOS(), _Settings())
        await writer.index_report({"report_id": "a"})
        writer.start()
        await writer.stop()          # must not raise
        assert writer.stats["flush_errors"] == 1

    @pytest.mark.asyncio
    async def test_shutdown_completes_even_when_queue_was_full(self):
        """Regression guard: a bounded queue must not deadlock stop()."""
        s = _Settings()
        s.bulk_queue_maxsize = 3
        writer = BulkWriter(_FakeOS(), s)
        for i in range(3):
            await writer.index_report({"report_id": f"r{i}"})
        writer.start()
        await asyncio.wait_for(writer.stop(), timeout=5)
        assert writer.queue_depth == 0
        assert writer.stats["flushed"] == 3


@pytest.mark.asyncio
async def test_multiple_actions_coalesce_into_one_flush():
    os = _FakeOS()
    writer = BulkWriter(os, _Settings())
    await writer.index_report({"report_id": "r1"})
    await writer.create_resource("s1", {"sha256": "s1"})
    await writer.upsert_domain({"name": "a.com"})
    writer.start()
    await writer.stop()
    # All three ride in a single _bulk request — the whole point of batching.
    total_pairs = sum(len(_parse(f)) for f in os.flushed)
    assert total_pairs == 3
    assert len(os.flushed) == 1
