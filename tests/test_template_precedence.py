"""v3 must not install a template that would lose to an incumbent.

On a cluster shared with v2 the sandbox_*_v1 templates sit at priority 200.
A losing template does nothing today and silently takes over if the incumbent
is ever removed.
"""
import pytest
from sandbox.mappings import _put_if_not_outranked, _SCANS_TEMPLATE


class _Indices:
    def __init__(self, existing):
        self.existing = existing
        self.put = []

    async def get_index_template(self):
        return {"index_templates": self.existing}

    async def put_index_template(self, name, body):
        self.put.append(name)


class Idx:
    """Stands in for the OpenSearch client: templates live under .indices."""

    def __init__(self, existing):
        self.indices = _Indices(existing)

    @property
    def put(self):
        return self.indices.put


def _tpl(name, patterns, priority=None):
    it = {"index_patterns": patterns}
    if priority is not None:
        it["priority"] = priority
    return {"name": name, "index_template": it}


@pytest.mark.asyncio
async def test_skips_when_outranked():
    c = Idx([_tpl("sandbox_scans_v1", ["scans-*"], 200)])
    await _put_if_not_outranked(c, "webamon-scans", _SCANS_TEMPLATE)
    assert c.put == [], "installed a template that would never apply"


@pytest.mark.asyncio
async def test_installs_on_a_clean_cluster():
    c = Idx([])
    await _put_if_not_outranked(c, "webamon-scans", _SCANS_TEMPLATE)
    assert c.put == ["webamon-scans"]


@pytest.mark.asyncio
async def test_ignores_templates_for_other_patterns():
    c = Idx([_tpl("other", ["logs-*"], 500)])
    await _put_if_not_outranked(c, "webamon-scans", _SCANS_TEMPLATE)
    assert c.put == ["webamon-scans"]


@pytest.mark.asyncio
async def test_equal_priority_is_treated_as_losing():
    # Same priority + overlapping patterns is an ambiguity OpenSearch rejects.
    c = Idx([_tpl("rival", ["scans-*"], 0)])
    await _put_if_not_outranked(c, "webamon-scans", _SCANS_TEMPLATE)
    assert c.put == []


@pytest.mark.asyncio
async def test_updating_our_own_template_is_not_blocked():
    c = Idx([_tpl("webamon-scans", ["scans-*"], 0)])
    await _put_if_not_outranked(c, "webamon-scans", _SCANS_TEMPLATE)
    assert c.put == ["webamon-scans"]
