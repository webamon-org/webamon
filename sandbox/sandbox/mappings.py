"""Explicit index templates + entity index setup.

The scans mapping (``scans_mapping.json``) is complete and ``dynamic: strict``:
every field the scanner writes is declared with its type. Leaving scans to
dynamic mapping is not safe: some fields hold different types in different
reports (``request.response.security_details.value`` is a date for one
certificate field and text for the next), so whichever report arrives first
fixes the type and later reports are rejected.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_SCANS_MAPPING = json.loads((Path(__file__).with_name("scans_mapping.json")).read_text(encoding="utf-8"))

_SCANS_TEMPLATE = {
    "index_patterns": ["scans-*"],
    "template": {
        # A short refresh interval on a busy scans index creates a large segment
        # merge backlog. Reading one report back is a realtime GET by _id, which
        # bypasses refresh entirely, so 30s costs nothing on the submit->read path.
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "refresh_interval": "30s",
            "codec": "best_compression",
            "mapping": {"total_fields": {"limit": 2000}},
        },
        "mappings": _SCANS_MAPPING,
    },
}

_RESOURCES_TEMPLATE = {
    "index_patterns": ["resources-*"],
    "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "sha256": {"type": "keyword"},
                "mime_type": {"type": "keyword"},
                "report_id": {"type": "keyword"},
                "submission_url": {"type": "keyword"},
                "resource_url": {"type": "keyword"},
                "first_seen_utc": {"type": "date"},
                "last_seen_utc": {"type": "date"},
            }
        },
    },
}

_ENTITY_MAPPING = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "name": {"type": "keyword"},
            "ip": {"type": "keyword"},
            "tld": {"type": "keyword"},
            "first_seen_utc": {"type": "date"},
            "last_seen_utc": {"type": "date"},
            "last_seen": {"type": "date", "format": "yyyy-MM-dd"},
        }
    },
}


async def _put_if_not_outranked(client, name: str, body: dict) -> None:
    """Install a template only if it would actually win.

    v3 may share a cluster with v2, whose templates sit at priority 200. With
    composable templates the highest priority wins OUTRIGHT - no merging - so
    installing ours at the default 0 achieves nothing except leaving a live
    landmine: delete the incumbent later and ours silently takes over, turning
    a strict mapping into a dynamic one on the next index roll.

    Refuse to be that landmine. Log what won instead.
    """
    patterns = body["index_patterns"]
    ours = body.get("priority", 0)
    try:
        existing = (await client.indices.get_index_template()).get("index_templates", [])
    except Exception:
        existing = []

    for entry in existing:
        if entry.get("name") == name:
            continue
        tpl = entry.get("index_template", {})
        theirs = tpl.get("priority", 0)
        if theirs >= ours and set(tpl.get("index_patterns", [])) & set(patterns):
            logger.warning(
                "not installing template %r (priority %s): %r already matches %s at "
                "priority %s and would win. v3 will use the existing mapping. Remove "
                "%r or raise ours deliberately if v3 should own these indices.",
                name, ours, entry["name"], patterns, theirs, entry["name"],
            )
            return
    await client.indices.put_index_template(name=name, body=body)
    logger.info("installed index template %r for %s", name, patterns)


async def ensure_templates(os_client) -> None:
    """Idempotently install index templates + the non-dated entity indices.

    What needs creating depends on ``entity_dated_indices``, and conflating the
    two modes produces a false alarm that costs real time to chase:

    dated (the v2-compatible default)
        Writes go to ``domains-YYYY.MM.DD``, never to bare ``domains``. The
        bare name being an alias is then EXPECTED - it is how v2 exposes the
        rollup - and is not a conflict. Only the template matters here; the
        dated index is created on first write.

    non-dated
        The bare name IS the write target, so an alias there is fatal: a write
        to a multi-index alias with no ``is_write_index`` is rejected.
    """
    client = os_client.client
    settings = os_client.settings
    entities = (settings.domains_index, settings.servers_index)
    try:
        await _put_if_not_outranked(client, "webamon-scans", _SCANS_TEMPLATE)
        await _put_if_not_outranked(client, "webamon-resources", _RESOURCES_TEMPLATE)

        # Covers the dated write targets. Without this they are dynamic-mapped
        # on first write and `name`/`ip` land as text+keyword multifields
        # rather than plain keywords.
        await client.indices.put_index_template(
            name="webamon-entities",
            body={
                "index_patterns": [f"{e}-*" for e in entities],
                "template": _ENTITY_MAPPING,
            },
        )

        if settings.entity_dated_indices:
            logger.info(
                "index templates ensured; entity writes go to dated indices (%s)",
                ", ".join(os_client.dated(e) for e in entities),
            )
            return

        for entity in entities:
            if await client.indices.exists_alias(name=entity):
                logger.error(
                    "%s is an ALIAS (v2 owns it) and entity_dated_indices is off, so v3 "
                    "would write to it directly - that is rejected unless one backing index "
                    "is is_write_index. Either set entity_dated_indices=true (v2 behaviour) "
                    "or point domains_index/servers_index at unused names.",
                    entity,
                )
                continue
            if not await client.indices.exists(index=entity):
                await client.indices.create(index=entity, body=_ENTITY_MAPPING)
        logger.info("index templates + entity indices ensured")
    except Exception as e:
        logger.error("failed to ensure templates: %s", e)
