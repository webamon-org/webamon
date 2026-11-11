"""Batch mode: scan a fixed set of URLs once, then exit.

Sources (``source`` setting): ``url`` (the ``url`` setting), ``mass_scan``
(one URL per line in ``mass_scan_file``), ``openphish`` (the public OpenPhish
feed) or ``query`` (URLs returned by an OpenSearch query).
"""
from __future__ import annotations

import asyncio
import logging

from .pipeline import ScanJob

logger = logging.getLogger(__name__)


async def run_batch(settings, pipeline) -> None:
    """Run-once producers: url | mass_scan | openphish | query."""
    urls = await _load_batch_urls(settings, pipeline)
    logger.info("batch: queued %d urls from source=%s", len(urls), settings.source)
    await asyncio.gather(*(pipeline.process(ScanJob.from_payload({"url": u})) for u in urls))


async def _load_batch_urls(settings, pipeline) -> list[str]:
    if settings.source == "url" and settings.url:
        return [settings.url]
    if settings.source == "mass_scan":
        try:
            with open(settings.mass_scan_file, "r", encoding="utf-8") as fh:
                return [line.strip() for line in fh if line.strip()]
        except FileNotFoundError:
            logger.error("mass_scan file not found: %s", settings.mass_scan_file)
            return []
    if settings.source == "openphish":
        import httpx
        async with httpx.AsyncClient() as client:
            resp = await client.get("https://www.openphish.com/feed.txt", timeout=30)
            return resp.text.splitlines() if resp.status_code == 200 else []
    if settings.source == "query":
        body = {"query": {"query_string": {"query": settings.elastic_query}}, "size": settings.elastic_size}
        resp = await pipeline.os.search(pipeline.os.dated(settings.elastic_query_index), body)
        out = []
        for hit in resp.get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            u = src.get("url") or src.get("domain")
            if isinstance(u, list):
                u = u[0] if u else None
            if u:
                out.append(u)
        return out
    return []
