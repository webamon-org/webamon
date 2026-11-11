"""FastAPI async scan endpoint (replaces v2's blocking Flask /scan).

Scans run on the shared pipeline (bounded concurrency, batched persistence).
Optional API-key auth; strict input validation; tenant slug validated in
ScanJob. Unlike v2, this path shares the exact same persistence code as the
queue workers.
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from .pipeline import ScanJob

logger = logging.getLogger(__name__)


class ScanRequest(BaseModel):
    submission_url: str
    report_id: str | None = None
    tag: object = None
    private: bool = False
    private_tag: object = None
    tenant: str | None = None


def build_app(settings, pipeline) -> FastAPI:
    app = FastAPI(title="Webamon Sandbox v3", version="3.0.0")

    def _check_auth(x_api_key: str | None) -> None:
        if settings.api_key and x_api_key != settings.api_key:
            raise HTTPException(status_code=401, detail="invalid api key")

    @app.get("/healthz")
    async def healthz() -> dict:
        c = pipeline.counters
        body = {"status": "ok", "engine": getattr(pipeline.engine.pool, "engine_name", "?"),
                "scans": {"total": c.total, "success": c.success, "failed": c.failed,
                          "skipped": c.skipped, "blocked": c.blocked}}
        writer = getattr(pipeline, "writer", None)
        if writer is not None:
            body["writer"] = {**writer.stats, "queue_depth": writer.queue_depth,
                              "queue_maxsize": writer.queue_maxsize}
            # Sustained backpressure means OpenSearch is the constraint.
            if writer.stats.get("dropped"):
                body["status"] = "degraded"
        return body

    @app.post("/scan")
    async def scan(req: ScanRequest, x_api_key: str | None = Header(default=None)) -> dict:
        _check_auth(x_api_key)
        job = ScanJob.from_payload(req.model_dump())
        if job is None:
            raise HTTPException(status_code=400, detail="missing submission_url")
        report = await pipeline.process(job)
        return {"scan_status": report.get("scan_status"),
                "data": {"submission_url": job.url, "report_id": report.get("report_id")}}

    return app
