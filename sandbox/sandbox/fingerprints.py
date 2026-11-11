"""Fingerprint generation + change monitoring (port of v2 monitoring.py).

Fixes over v2: ``set.add`` instead of ``set.update`` (which exploded strings
into characters), and previous-scan lookup goes through the configured
persistence client instead of a hardcoded host.
"""
from __future__ import annotations

import hashlib

from . import fpx
import json
import logging

logger = logging.getLogger(__name__)

_FINGERPRINT_KEYS = ("asn", "cookies", "domains", "links", "scripts", "ssl", "tech", "dom")


def deep_sort(obj):
    if isinstance(obj, dict):
        return {k: deep_sort(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return sorted([deep_sort(v) for v in obj], key=lambda x: json.dumps(x, sort_keys=True))
    return obj


def normalize_for_hashing(data) -> str:
    return json.dumps(deep_sort(data), sort_keys=True, separators=(",", ":"))


def hash_data(data) -> str:
    return hashlib.sha256(normalize_for_hashing(data).encode()).hexdigest()


def generate_fingerprints(scan: dict) -> dict:
    # The original eight, byte-for-byte unchanged - existing dashboards and
    # saved queries depend on these exact values.
    #
    # scan_fingerprint was REMOVED deliberately. It hashed the entire report,
    # including report_id, timestamps and response times, so it was unique per
    # scan by construction: measured cardinality 0.646 over 539,692 production
    # documents, and its LARGEST cluster was a single document. It grouped
    # nothing, while costing 133.9 ms on a 1.5 MB page - 74% of the whole
    # fingerprint stage. This is a deliberate divergence from the v2 schema.
    fp = {
        "ssl": hash_data(scan.get("certificate", [])),
        "tech": hash_data(scan.get("technology", [])),
        "cookies": hash_data(scan.get("cookie", [])),
        "asn": hash_data([
            d["asn"]["number"] for d in scan.get("server", [])
            if isinstance(d.get("asn"), dict) and "number" in d["asn"]
        ]),
        "scripts": hash_data(scan.get("page_scripts", [])),
        "links": hash_data(scan.get("page_links", [])),
        "domains": hash_data([d["name"] for d in scan.get("domain", []) if "name" in d]),
        "dom": hash_data(scan.get("dom", "")),
    }
    # Threat-intel extensions. Each is a pivot the originals cannot express:
    # the originals are exact-match over volatile content, these are stable
    # across the things a campaign actually changes between victims.
    fp.update(fpx.cert_fingerprints(scan.get("certificate", [])))
    fp["header_order"] = fpx.header_order_fingerprint(
        scan.get("request", []), scan.get("resolved_url", ""))
    fp["cookie_names"] = fpx.cookie_name_fingerprint(scan.get("cookie", []))
    fp.update(fpx.dom_similarity(scan.get("dom", "")))
    fp.update(fpx.dns_set_fingerprints(
        scan.get("domain", []), scan.get("resolved_domain", "")))
    return fp


def generate_lexical(scan: dict) -> dict:
    """Lexical features of the scanned domain. Separate top-level block: these
    are numeric attributes to range-query on, not hashes to aggregate on."""
    return fpx.lexical_features(
        scan.get("resolved_domain") or scan.get("domain_name") or "",
        scan.get("resolved_sub_domain") or scan.get("sub_domain") or "",
    )


def compare_fingerprints(old: dict, new: dict) -> list[str]:
    return [key for key in _FINGERPRINT_KEYS if old.get(key) != new.get(key)]


async def detect_changes(scan: dict, os_client, index_pattern: str = "scans*") -> list[str]:
    """Diff this scan against the most recent previous scan of the same URL."""
    query = {
        "size": 1,
        "query": {"term": {"submission_url": scan["submission_url"]}},
        "sort": [{"submission_utc": "desc"}],
        "_source": ["fingerprint", "page_title", "resolved_url"],
    }
    try:
        response = await os_client.search(index=index_pattern, body=query)
        hits = response.get("hits", {}).get("hits", [])
    except Exception as e:
        logger.error("monitor: previous-scan lookup failed: %s", e)
        return []
    if not hits:
        return []
    previous = hits[0]["_source"]
    changes = set(compare_fingerprints(previous.get("fingerprint", {}), scan.get("fingerprint", {})))
    if scan.get("page_title") != previous.get("page_title"):
        changes.add("page_title")
    if scan.get("resolved_url") != previous.get("resolved_url"):
        changes.add("resolved_url")
    return sorted(changes)
