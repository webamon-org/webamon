"""Composition root: build all components, wire them, own lifecycle.

This is the ONLY place that instantiates concrete resources (browser pool,
GeoIP readers, OpenSearch client). Every other module takes its dependencies
as arguments, so they import cleanly under test with no side effects.
"""
from __future__ import annotations

import asyncio
import datetime
import logging
from datetime import timezone

import httpx

from .browser import BrowserPool
from .memguard import MemoryGuard
from .config import Settings, configure_logging, make_engine_id
from .engine import ScanEngine
from .enrich import Enrichment, Technology
from .mappings import ensure_templates
from .persist import BulkWriter, OpenSearchClient
from .pipeline import ScanPipeline

logger = logging.getLogger(__name__)


class Application:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.engine_id = make_engine_id()
        self.started_utc = datetime.datetime.now(timezone.utc)
        self.pool: BrowserPool | None = None
        self.memguard: MemoryGuard | None = None
        self.os: OpenSearchClient | None = None
        self.writer: BulkWriter | None = None
        self.pipeline: ScanPipeline | None = None
        self.http: httpx.AsyncClient | None = None

    async def start(self) -> None:
        self.http = httpx.AsyncClient(verify=False)
        self.pool = BrowserPool(self.settings)
        await self.pool.start()
        self.memguard = MemoryGuard(self.settings)
        self.memguard.start()

        enrichment = Enrichment(self.settings)
        technology = Technology(self.settings.technology_patterns_path)
        engine = ScanEngine(self.settings, self.pool, enrichment, technology,
                            self.http, engine_id=self.engine_id)

        if self.settings.save_elastic:
            self.os = OpenSearchClient(self.settings)
            await ensure_templates(self.os)
            self.writer = BulkWriter(self.os, self.settings)
            self.writer.start()

        self.pipeline = ScanPipeline(self.settings, engine, self.writer, self.os)

    async def stop(self) -> None:
        if self.writer:
            await self.writer.stop()
        if self.memguard:
            await self.memguard.stop()
        if self.pool:
            await self.pool.stop()
        if self.os:
            await self.os.close()
        if self.http:
            await self.http.aclose()
        await self._save_engine_log()

    async def _save_engine_log(self) -> None:
        if not self.settings.save_elastic or not self.os:
            return
        c = self.pipeline.counters
        engine_log = {
            "engine_id": self.engine_id,
            "start_utc": self.started_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "completion_utc": datetime.datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "date": self.started_utc.strftime("%Y-%m-%d"),
            "total": c.total, "success": c.success, "failed": c.failed,
            "skipped": c.skipped, "blocked": c.blocked,
            "version": "3.0.0",
        }
        try:
            index = self.os.dated("engine_log")
            await self.os.client.index(index=index, id=self.engine_id, body=engine_log)
        except Exception as e:
            logger.error("failed to save engine_log: %s", e)


async def run() -> None:
    settings = Settings()
    configure_logging(settings)
    app = Application(settings)
    await app.start()

    try:
        if settings.queue_worker:
            import uvicorn
            from .api import build_app
            api = build_app(settings, app.pipeline)
            config = uvicorn.Config(api, host=settings.api_host, port=settings.api_port, log_level="info")
            server = uvicorn.Server(config)
            await server.serve()
        else:
            from .batch import run_batch
            await run_batch(settings, app.pipeline)
            c = app.pipeline.counters
            logger.info("batch complete: total=%d success=%d failed=%d skipped=%d blocked=%d",
                        c.total, c.success, c.failed, c.skipped, c.blocked)
    finally:
        await app.stop()
