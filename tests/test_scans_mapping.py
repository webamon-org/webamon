"""The scans template must be installable: OpenSearch rejects the whole
template if the mapping references an analysis component it does not define."""
from sandbox.mappings import _SCANS_TEMPLATE


def _referenced(node, key):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key and isinstance(v, str):
                yield v
            else:
                yield from _referenced(v, key)
    elif isinstance(node, list):
        for item in node:
            yield from _referenced(item, key)


def test_every_normalizer_is_defined():
    defined = set(_SCANS_TEMPLATE["template"]["settings"].get("analysis", {}).get("normalizer", {}))
    used = set(_referenced(_SCANS_TEMPLATE["template"]["mappings"], "normalizer"))
    assert used <= defined, f"undefined normalizers: {sorted(used - defined)}"


def test_scans_mapping_is_strict():
    # Dynamic mapping lets the first report fix a field's type and rejects the
    # rest; every field the scanner writes must be declared instead.
    assert _SCANS_TEMPLATE["template"]["mappings"]["dynamic"] == "strict"
