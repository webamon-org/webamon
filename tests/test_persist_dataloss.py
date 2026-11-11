"""Regressions for the three ways the writer silently lost documents."""
import asyncio
import pytest

from sandbox.config import Settings
from sandbox.persist import BulkWriter, _b64_id, _strip_empty_ips


class FakeOS:
    def __init__(self, st):
        self.settings = st
        self.sent = []

    def dated(self, b):
        return f"{b}-2026.08.04"

    async def bulk(self, ndjson):
        self.sent.append(ndjson)
        return {"errors": False, "items": []}


def _writer():
    st = Settings(save_elastic=False)
    os_ = FakeOS(st)
    return BulkWriter(os_, st), os_


def test_empty_string_b64_id_is_empty():
    """The root cause: an empty name yields an empty _id, not a valid one."""
    assert _b64_id("") == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["", "   "])
async def test_empty_key_never_reaches_the_batch(bad):
    """One empty _id used to fail the WHOLE bulk request, losing every good
    document batched alongside it."""
    w, os_ = _writer()
    await w.upsert_domain({"name": bad, "ip": "1.2.3.4"})
    await w.upsert_domain({"name": "good.com", "ip": "1.2.3.4"})
    w.start()
    await w.stop()

    body = "".join(os_.sent)
    assert '"_id": ""' not in body
    assert _b64_id("good.com") in body, "the valid document was lost too"
    assert w.stats.get("dropped_blank_key") == 1


@pytest.mark.asyncio
async def test_empty_ip_is_removed_not_written():
    """`''` is not an IP string literal - it fails the entire document."""
    w, os_ = _writer()
    await w.index_report({
        "report_id": "r1",
        "ip": "",
        "domain": [{"name": "a.com", "ip": "", "request": {"ip": ""}},
                   {"name": "b.com", "ip": "9.9.9.9"}],
    })
    w.start()
    await w.stop()

    body = "".join(os_.sent)
    assert '"ip": ""' not in body
    assert '"9.9.9.9"' in body, "a real IP must survive"
    assert '"b.com"' in body


def test_strip_empty_ips_leaves_everything_else_alone():
    doc = {"ip": "", "name": "x", "empty_but_not_ip": "",
           "nested": [{"ip": " "}, {"ip": "8.8.8.8"}]}
    out = _strip_empty_ips(doc)
    assert "ip" not in out
    assert out["name"] == "x"
    assert out["empty_but_not_ip"] == "", "only ip fields should be stripped"
    assert "ip" not in out["nested"][0]
    assert out["nested"][1]["ip"] == "8.8.8.8"


@pytest.mark.asyncio
async def test_rejected_items_are_counted():
    """Rejections are permanent - the count must be visible."""
    w, os_ = _writer()

    async def failing_bulk(ndjson):
        return {"errors": True, "items": [
            {"index": {"status": 400, "_index": "scans-x",
                       "error": {"type": "mapper_parsing_exception", "reason": "nope"}}},
            {"index": {"status": 409, "_index": "resources-x"}},   # dedupe, not loss
            {"index": {"status": 201, "_index": "scans-x"}},
        ]}

    os_.bulk = failing_bulk
    await w.index_report({"report_id": "r1"})
    w.start()
    await w.stop()

    assert w.stats["item_errors"] == 1, "409 dedupe must not count as loss"
