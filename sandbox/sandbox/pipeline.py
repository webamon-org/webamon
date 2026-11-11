"""Scan pipeline: bounded-concurrency orchestration + persistence dispatch.

One ``ScanPipeline`` owns the engine, the bulk writer and a semaphore that
caps concurrent scans at ``settings.threads``. ``process(job)`` runs a scan and
enqueues all resulting docs onto the bulk writer — workers never write to
OpenSearch directly, so all persistence is batched.
"""
from __future__ import annotations

import asyncio
import datetime
import logging
import uuid
from dataclasses import dataclass, field
from datetime import timezone

from . import capture, fingerprints
from .transforms import clean_data, normalize_private_tags, format_utc_datetime

logger = logging.getLogger(__name__)


@dataclass
class ScanJob:
    url: str
    report_id: str = ""
    tag: object = None
    private: bool = False
    private_tag: list[str] | None = None
    tenant: str | None = None

    @classmethod
    def from_payload(cls, payload: dict) -> "ScanJob | None":
        url = payload.get("submission_url") or payload.get("url")
        if not url or not isinstance(url, str):
            return None
        return cls(
            url=url,
            report_id=str(payload.get("report_id", "") or ""),
            tag=payload.get("tag"),
            private=bool(payload.get("private")),
            private_tag=normalize_private_tags(payload.get("private_tag")),
            tenant=_safe_tenant(payload.get("tenant")),
        )


@dataclass
class Counters:
    total: int = 0
    success: int = 0
    failed: int = 0
    skipped: int = 0
    blocked: int = 0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def record(self, status: str) -> None:
        async with self.lock:
            self.total += 1
            if status == "success":
                self.success += 1
            elif status == "skipped":
                self.skipped += 1
            elif status == "blocked":
                self.blocked += 1
            else:
                self.failed += 1


_TENANT_RE = None


def _safe_tenant(tenant) -> str | None:
    """Whitelist-validate tenant slug (SSRF/index-injection guard for private-scans-*)."""
    global _TENANT_RE
    if tenant is None:
        return None
    import re
    if _TENANT_RE is None:
        _TENANT_RE = re.compile(r"^[a-z0-9-]{1,40}$")
    t = str(tenant).strip().lower()
    return t if _TENANT_RE.match(t) else None


class ScanPipeline:
    def __init__(self, settings, engine, writer, os_client) -> None:
        self.settings = settings
        self.engine = engine
        self.writer = writer
        self.os = os_client
        self.counters = Counters()
        self._sem = asyncio.Semaphore(settings.threads)

    async def process(self, job: ScanJob) -> dict:
        async with self._sem:
            return await self._process_inner(job)

    async def _process_inner(self, job: ScanJob) -> dict:
        if self.settings.skip_if_exists and self.settings.save_elastic:
            domain = self.engine.enrich.domain_extract(job.url)[0]
            if domain:
                existing = await self.os.existing_domain_names([domain])
                if domain in existing:
                    await self.counters.record("skipped")
                    return {"scan_status": "skipped", "submission_url": job.url}

        tag_for_engine = (job.private_tag or []) if job.private else job.tag
        report = await self.engine.scan(job.url, job.report_id, tag_override=tag_for_engine)
        clean_data(report)
        await self.counters.record(report.get("scan_status", "failed"))

        if self.settings.save_elastic:
            await self._persist(report, job)
        return report

    @staticmethod
    def _private_index(job: ScanJob) -> str | None:
        """Tenant index for a private scan, or None for the public path.

        Matches v2 exactly: ``private-scans-<tenant>``, NOT date-suffixed.

        A private job whose tenant failed validation returns None, which routes
        it to the public index. That is the safe direction of the two available
        - the alternative is composing an index name from unvalidated input -
        but it means the document is not where the tenant expects, so it is
        logged loudly rather than silently downgraded.
        """
        if not job.private:
            return None
        if not job.tenant:
            logger.error(
                "private scan for report_id=%s has no usable tenant slug - writing "
                "to the PUBLIC scans index. The submitted tenant failed validation "
                "(expected ^[a-z0-9-]{1,40}$).", job.report_id or "?",
            )
            return None
        return f"private-scans-{job.tenant}"

    async def _persist(self, report: dict, job: ScanJob) -> None:
        report.setdefault("report_id", job.report_id or str(uuid.uuid4()))
        report.setdefault("date", datetime.datetime.now(timezone.utc).strftime("%Y-%m-%d"))
        report.setdefault("submission_utc", format_utc_datetime(datetime.datetime.now(timezone.utc)))

        if job.private:
            report["private"] = True
            report["tenant"] = job.tenant
            report["tag"] = job.private_tag or []

        # Optional monitor diff (before we hand the report to the writer).
        if report.get("monitor") and report.get("scan_status") == "success":
            report["changes"] = await fingerprints.detect_changes(report, self.os)
            report["changed"] = bool(report["changes"])

        screenshot_b64 = report.pop("_screenshot_b64", None)
        resource_master = report.pop("resource_master", None)
        if not self.settings.save_dom:
            report.pop("dom", None)

        # Report doc. A private scan goes to the TENANT'S OWN index, not the
        # shared daily one - this is the whole point of the private tier, and
        # the v3 rebuild lost it: the line here used to be
        #     index_report(report if not job.private else report)
        # where both branches were the same object, so every private scan landed
        # in scans-YYYY.MM.DD carrying `private: true` and the tenant index
        # stopped growing.
        #
        # job.tenant is whitelist-validated by _safe_tenant() before it can
        # reach an index name; if validation rejected it, tenant is None and we
        # deliberately fall back to the public index rather than write to a
        # half-formed one.
        await self.writer.index_report(report, index_override=self._private_index(job))

        # Screenshot doc.
        if screenshot_b64:
            await self.writer.raw_create("screenshots", {
                "screenshot": screenshot_b64, "page_title": report.get("page_title"),
                "domain_name": report.get("domain_name"), "tag": report.get("tag"),
                "date": report.get("date"), "submission_url": report.get("submission_url"),
                "submission_utc": report.get("submission_utc"), "report_id": report["report_id"],
            }, report["report_id"])

        # Resources — create op, no existence reads.
        if self.settings.save_resources and resource_master:
            for sha256, doc in resource_master.items():
                mime = (doc.get("mime_type") or "").lower()
                if not self.settings.save_images and "image" in mime:
                    continue
                if not self.settings.save_css and "css" in mime:
                    continue
                if not self.settings.save_video and capture.is_video_mime(mime):
                    continue
                doc = {**doc, "feed": report.get("feed"),
                       "tag": report.get("tag") if isinstance(report.get("tag"), list) else [report.get("tag")],
                       "ip": [], "asn": [], "country": [], "domains": [],
                       "notes": [], "whitelisted": None, "blacklisted": None}
                await self.writer.create_resource(sha256, doc)

        # Domains / servers — scripted atomic upserts (only for successful scans).
        if report.get("scan_status") == "success":
            for domain in report.get("domain", []):
                await self.writer.upsert_domain(dict(domain))
            for server in report.get("server", []):
                await self.writer.upsert_server(dict(server))


