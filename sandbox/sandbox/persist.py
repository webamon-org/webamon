"""Batched OpenSearch persistence — the core efficiency layer.

v2 issued ~155-195 unpooled HTTP requests per scan (per-doc existence GETs,
read-modify-write on domains/servers, no keep-alive, no timeouts). v3:

* ONE pooled async client for the whole process (keep-alive, gzip, timeouts,
  retry/backoff on 429/503).
* A background BulkWriter coalesces actions from all workers and flushes via
  a single ``_bulk`` every ``bulk_max_actions`` docs or ``bulk_flush_interval``
  seconds — so a scan's report + resources + domain/server upserts (and those
  of neighbouring scans) ride in one request.
* Resources use op_type ``create`` (id = sha256): duplicates 409 in the bulk
  response and are ignored — ZERO existence reads (v2 did one GET per resource).
* domains/servers use ``update`` with a painless scripted_upsert that merges
  server-side and ``retry_on_conflict`` — atomic, race-free, no read step
  (v2 did GET+GET+merge+POST per entity and silently lost concurrent updates).
* domains/servers live in SINGLE, NON-DATED entity indices so first_seen /
  last_seen and dedupe accumulate for real (v2 date-suffixed them, resetting
  every day).

skip_if_exists is a batch pre-filter (one terms query per batch), not one
search per URL.
"""
from __future__ import annotations

import asyncio
import base64
import datetime
import json
import logging
import time
from datetime import timezone

from opensearchpy import AsyncOpenSearch, AsyncHttpConnection

logger = logging.getLogger(__name__)


# Painless merge script for the domains entity index. Unions list fields and
# refreshes last_seen on every scan; scripted_upsert seeds first_seen on insert.
_DOMAIN_MERGE_SCRIPT = """
if (ctx.op == 'create') {
  ctx._source.first_seen_utc = params.now_utc;
}
ctx._source.last_seen = params.today;
ctx._source.last_seen_utc = params.now_utc;
def incoming = params.doc;
for (entry in incoming.entrySet()) {
  def key = entry.getKey();
  def val = entry.getValue();
  if (key == 'first_seen_utc' || key == 'last_seen' || key == 'last_seen_utc') { continue; }
  // NB: on a DOMAIN record `server` is a scalar string (the Server header) -
  // it is only a list on SERVER records. Unioning it here threw
  // "Cannot iterate over [java.lang.String]" and failed the whole update.
  // The instanceof guard also means an unexpected type degrades to an
  // overwrite instead of rejecting the document.
  if (key == 'sub_domain' || key == 'hostname' || key == 'ips') {
    if (!(val instanceof List)) { ctx._source[key] = val; continue; }
    if (!(ctx._source[key] instanceof List)) { ctx._source[key] = []; }
    for (item in val) { if (!ctx._source[key].contains(item)) { ctx._source[key].add(item); } }
    if (ctx._source[key].size() > params.max_list) {
      def n = ctx._source[key].size();
      ctx._source[key] = new ArrayList(ctx._source[key].subList(n - params.max_list, n));
    }
  } else if (key == 'resource') {
    if (!(val instanceof List)) { ctx._source.resource = val; continue; }
    if (!(ctx._source.resource instanceof List)) { ctx._source.resource = []; }
    def seen = new HashSet();
    for (r in ctx._source.resource) { if (r instanceof Map && r.sha256 != null) { seen.add(r.sha256); } }
    for (r in val) { if (r instanceof Map && r.sha256 != null && !seen.contains(r.sha256)) { ctx._source.resource.add(r); seen.add(r.sha256); } }
    // `resource` is mapped NESTED on domains-*/servers-*, so every element is a
    // separate Lucene document counting against index.mapping.nested_objects.limit
    // (10000 by default). Deduping is not a bound: a CDN host like gstatic.com
    // serves a different sha256 on every scan, so the array grows without limit
    // and eventually every update to that domain is rejected FOREVER with
    // "number of nested documents has exceeded the allowed limit". The busiest,
    // most valuable domains break first. Keep the most recent N.
    if (ctx._source.resource.size() > params.max_resource) {
      def n = ctx._source.resource.size();
      ctx._source.resource = new ArrayList(ctx._source.resource.subList(n - params.max_resource, n));
    }
  } else if (key == 'dns') {
    if (ctx._source.dns == null) { ctx._source.dns = val; }
    else if (val instanceof Map) {
      for (dentry in val.entrySet()) {
        def dk = dentry.getKey(); def dv = dentry.getValue();
        if (ctx._source.dns[dk] == null) { ctx._source.dns[dk] = dv; }
        else if (dv instanceof List) {
          for (item in dv) { if (!ctx._source.dns[dk].contains(item)) { ctx._source.dns[dk].add(item); } }
        }
      }
    }
  } else {
    ctx._source[key] = val;
  }
}
"""

_SERVER_MERGE_SCRIPT = """
if (ctx.op == 'create') {
  ctx._source.first_seen_utc = params.now_utc;
}
ctx._source.last_seen = params.today;
ctx._source.last_seen_utc = params.now_utc;
def incoming = params.doc;
for (entry in incoming.entrySet()) {
  def key = entry.getKey();
  def val = entry.getValue();
  if (key == 'first_seen_utc' || key == 'last_seen' || key == 'last_seen_utc') { continue; }
  // On SERVER records `domain` and `server` are genuinely lists. Same
  // instanceof guards so a type surprise degrades instead of failing.
  if (key == 'domain' || key == 'server' || key == 'ips' || key == 'hostname') {
    if (!(val instanceof List)) { ctx._source[key] = val; continue; }
    if (!(ctx._source[key] instanceof List)) { ctx._source[key] = []; }
    for (item in val) { if (!ctx._source[key].contains(item)) { ctx._source[key].add(item); } }
    if (ctx._source[key].size() > params.max_list) {
      def n = ctx._source[key].size();
      ctx._source[key] = new ArrayList(ctx._source[key].subList(n - params.max_list, n));
    }
  } else if (key == 'resource') {
    if (!(val instanceof List)) { ctx._source.resource = val; continue; }
    if (!(ctx._source.resource instanceof List)) { ctx._source.resource = []; }
    def seen = new HashSet();
    for (r in ctx._source.resource) { if (r instanceof Map && r.sha256 != null) { seen.add(r.sha256); } }
    for (r in val) { if (r instanceof Map && r.sha256 != null && !seen.contains(r.sha256)) { ctx._source.resource.add(r); seen.add(r.sha256); } }
    // Nested on servers-* as well - same unbounded growth, same permanent
    // rejection once the 10000 nested-document limit is reached.
    if (ctx._source.resource.size() > params.max_resource) {
      def n = ctx._source.resource.size();
      ctx._source.resource = new ArrayList(ctx._source.resource.subList(n - params.max_resource, n));
    }
  } else {
    ctx._source[key] = val;
  }
}
"""

# Fields stripped from a domain record before it becomes an entity doc (v2 parity).
_DOMAIN_STRIP = ("method", "mime_type", "request_count", "response_code", "request",
                 "total_response_size", "root")
_SERVER_STRIP = ("total_response_size", "mime_type", "response_code")


def _b64_id(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("utf-8")


def _strip_empty_ips(obj):
    """Drop ``ip`` keys whose value is an empty string, at any depth.

    OpenSearch maps these fields as type ``ip``, which rejects "" with
    ``'' is not an IP string literal`` and fails the ENTIRE document - so a
    single unresolved host costs the whole scan report. An absent ip and an
    empty ip carry the same meaning, so removing the key loses nothing.

    Applies to every ip-typed field in the schema (``ip``, ``domain[].ip``,
    ``domain[].request.ip``, ``server.ip``) because it matches on the key name
    rather than a fixed path.
    """
    if isinstance(obj, dict):
        return {k: _strip_empty_ips(v) for k, v in obj.items()
                if not (k == "ip" and isinstance(v, str) and not v.strip())}
    if isinstance(obj, list):
        return [_strip_empty_ips(v) for v in obj]
    return obj


class OpenSearchClient:
    """Thin wrapper owning the single pooled async client for the process."""

    def __init__(self, settings) -> None:
        self.settings = settings
        base = settings.elastic_base.split("://")
        protocol = base[0]
        host, port = base[1].split(":")
        self.client = AsyncOpenSearch(
            hosts=[{"host": host, "port": int(port)}],
            http_auth=(settings.elastic_username, settings.elastic_password),
            use_ssl=(protocol == "https"),
            verify_certs=settings.elastic_verify_certs,
            ssl_show_warn=False,
            connection_class=AsyncHttpConnection,
            http_compress=True,
            pool_maxsize=max(10, settings.threads + 4),
            timeout=30,
            max_retries=settings.bulk_max_retries,
            retry_on_timeout=True,
        )

    def dated(self, base_index: str) -> str:
        if not self.settings.dated_indices:
            return base_index
        return f"{base_index}-{datetime.datetime.now(timezone.utc).strftime('%Y.%m.%d')}"

    async def search(self, index: str, body: dict) -> dict:
        return await self.client.search(index=index, body=body)

    async def bulk(self, actions_ndjson: str) -> dict:
        return await self.client.bulk(body=actions_ndjson)

    async def existing_domain_names(self, urls: list[str], field: str = "domain_name") -> set[str]:
        """Batch skip-filter: which of these values already exist in scans*? One query."""
        if not urls:
            return set()
        body = {
            "size": 0,
            "query": {"terms": {field: urls}},
            "aggs": {"present": {"terms": {"field": field, "size": len(urls)}}},
        }
        try:
            resp = await self.client.search(index="scans*", body=body)
            buckets = resp.get("aggregations", {}).get("present", {}).get("buckets", [])
            return {b["key"] for b in buckets}
        except Exception as e:
            logger.error("skip pre-filter query failed: %s", e)
            return set()

    async def close(self) -> None:
        await self.client.close()


class BulkWriter:
    """Coalesces bulk actions from all scan workers into periodic _bulk flushes."""

    def __init__(self, os_client: OpenSearchClient, settings) -> None:
        self.os = os_client
        self.settings = settings
        maxsize = max(0, int(getattr(settings, "bulk_queue_maxsize", 0) or 0))
        self._queue: asyncio.Queue[str] = asyncio.Queue(maxsize=maxsize)
        self._task: asyncio.Task | None = None
        self._stopping = asyncio.Event()
        # Observability: without these, backpressure is invisible until OOM.
        self.stats = {
            "queued": 0, "flushed": 0, "flush_errors": 0,
            "item_errors": 0, "backpressure_waits": 0, "dropped": 0,
        }
        self._last_bp_log = 0.0

    @property
    def queue_depth(self) -> int:
        return self._queue.qsize()

    @property
    def queue_maxsize(self) -> int:
        return self._queue.maxsize

    def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="bulk-writer")

    async def stop(self) -> None:
        self._stopping.set()
        if self._task:
            await self._task

    # --- enqueue helpers (build NDJSON action pairs) -------------------
    async def index_report(self, report: dict, index_override: str | None = None) -> None:
        """Write the scan report.

        ``index_override`` is used VERBATIM and is NOT date-suffixed - v2 does
        ``index_override or get_current_index('scans')``, so a private tenant
        index is a single ``private-scans-<tenant>``, not one per day. Getting
        that wrong would scatter a tenant's history across daily indices their
        saved queries do not match.
        """
        index = index_override or self.os.dated("scans")
        await self._put({"index": {"_index": index, "_id": report["report_id"]}}, report)

    async def create_resource(self, doc_id: str, doc: dict) -> None:
        index = self.os.dated("resources")
        # op_type create → duplicate sha256 409s and is ignored (no pre-check read).
        await self._put({"create": {"_index": index, "_id": doc_id}}, doc)

    async def raw_create(self, base_index: str, doc: dict, doc_id: str) -> None:
        index = self.os.dated(base_index)
        await self._put({"create": {"_index": index, "_id": doc_id}}, doc)

    def _reject_blank_key(self, kind: str, value: str) -> bool:
        """True if this entity has no usable key.

        Checked on the RAW value, before base64. An empty name encodes to an
        empty _id (which fails the whole bulk batch), and a whitespace-only one
        encodes to a valid-looking id for a document that means nothing - a
        junk entity that then accumulates last_seen updates forever.
        """
        if isinstance(value, str) and value.strip():
            return False
        self.stats["dropped_blank_key"] = self.stats.get("dropped_blank_key", 0) + 1
        logger.warning(
            "skipping %s upsert with a blank key (%r); total dropped=%d",
            kind, value, self.stats["dropped_blank_key"],
        )
        return True

    async def upsert_domain(self, domain_record: dict) -> None:
        name = domain_record.get("name", "")
        if self._reject_blank_key("domain", name):
            return
        doc = {k: v for k, v in domain_record.items() if k not in _DOMAIN_STRIP}
        await self._scripted_upsert(self.settings.domains_index, _b64_id(name), doc, _DOMAIN_MERGE_SCRIPT)

    async def upsert_server(self, server_record: dict) -> None:
        ip = server_record.get("ip", "")
        if self._reject_blank_key("server", ip):
            return
        doc = {k: v for k, v in server_record.items() if k not in _SERVER_STRIP}
        await self._scripted_upsert(self.settings.servers_index, _b64_id(ip), doc, _SERVER_MERGE_SCRIPT)

    def _entity_index(self, base_index: str) -> str:
        """Dated (v2-compatible) or single entity index, per configuration."""
        if getattr(self.settings, "entity_dated_indices", False):
            return self.os.dated(base_index)
        return base_index

    async def _scripted_upsert(self, base_index: str, doc_id: str, doc: dict, script: str) -> None:
        base_index = self._entity_index(base_index)
        now_utc = datetime.datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        today = datetime.datetime.now(timezone.utc).strftime("%Y-%m-%d")
        action = {"update": {"_index": base_index, "_id": doc_id, "retry_on_conflict": 3}}
        payload = {
            "scripted_upsert": True,
            "script": {"source": script, "lang": "painless",
                       "params": {"doc": doc, "now_utc": now_utc, "today": today,
                                  "max_resource": int(getattr(self.settings, "entity_max_resource", 500)),
                                  "max_list": int(getattr(self.settings, "entity_max_list", 1000))}},
            "upsert": {},
        }
        await self._put(action, payload)

    async def _put(self, action: dict, doc: dict) -> None:
        # An action with an empty _id fails the WHOLE bulk request with
        #   Validation Failed: 1: id is missing
        # not just that item - so one unusable record destroys every good
        # document batched with it. _b64_id("") is "", and empty domain names
        # and IPs do occur in real scans, so this is reachable. Refuse the one
        # bad action rather than lose the batch.
        for _op, meta in action.items():
            if not meta.get("_id"):
                self.stats["dropped_no_id"] = self.stats.get("dropped_no_id", 0) + 1
                logger.warning(
                    "refusing to enqueue a %s to %s with an empty _id (would fail the "
                    "entire bulk batch); total dropped=%d",
                    _op, meta.get("_index"), self.stats["dropped_no_id"],
                )
                return

        doc = _strip_empty_ips(doc)
        item = f"{json.dumps(action)}\n{json.dumps(doc)}\n"

        if not self._queue.full():
            self._queue.put_nowait(item)
            self.stats["queued"] += 1
            return

        # Queue is full: OpenSearch cannot keep up. Blocking here is deliberate
        # — it propagates backpressure through the scan semaphore all the way
        # to intake, instead of buffering without limit.
        self.stats["backpressure_waits"] += 1
        now = time.monotonic()
        if now - self._last_bp_log > 5:
            self._last_bp_log = now
            logger.warning(
                "bulk writer backpressure: queue full (%d) — scans are throttled "
                "waiting on OpenSearch (waits=%d)",
                self._queue.maxsize, self.stats["backpressure_waits"],
            )

        timeout = float(getattr(self.settings, "bulk_put_timeout", 0) or 0)
        if timeout <= 0:
            await self._queue.put(item)          # wait indefinitely: never drop
        else:
            try:
                await asyncio.wait_for(self._queue.put(item), timeout=timeout)
            except asyncio.TimeoutError:
                self.stats["dropped"] += 1
                logger.error(
                    "bulk writer DROPPED a document after %.1fs waiting for queue "
                    "capacity (total dropped=%d)", timeout, self.stats["dropped"],
                )
                return
        self.stats["queued"] += 1

    # --- flush loop -----------------------------------------------------
    async def _run(self) -> None:
        buffer: list[str] = []
        while True:
            timed_out = False
            try:
                item = await asyncio.wait_for(self._queue.get(), timeout=self.settings.bulk_flush_interval)
                buffer.append(item)
            except asyncio.TimeoutError:
                timed_out = True

            # Drain whatever else is immediately available.
            while not self._queue.empty() and len(buffer) < self.settings.bulk_max_actions:
                buffer.append(self._queue.get_nowait())

            should_flush = (
                len(buffer) >= self.settings.bulk_max_actions
                or (timed_out and buffer)
                or (self._stopping.is_set() and buffer)
            )
            if should_flush:
                await self._flush(buffer)
                buffer = []

            if self._stopping.is_set() and self._queue.empty() and not buffer:
                return

    async def _flush(self, buffer: list[str]) -> None:
        ndjson = "".join(buffer)
        try:
            resp = await self.os.bulk(ndjson)
        except Exception as e:
            self.stats["flush_errors"] += 1
            logger.error("bulk flush failed (%d actions): %s", len(buffer), e)
            return
        self.stats["flushed"] += len(buffer)
        if resp.get("errors"):
            self._log_bulk_errors(resp)

    def _log_bulk_errors(self, resp: dict) -> None:
        """Summarise rejected items.

        Every rejected item is a document that is GONE - there is no retry - so
        this must make the volume obvious. Logging one line per item buried the
        scale: 4 identical nested-limit warnings look like noise, while
        "37 documents rejected" reads as the data loss it is.
        """
        by_reason: dict[str, int] = {}
        examples: dict[str, str] = {}
        for item in resp.get("items", []):
            for _op, result in item.items():
                status = result.get("status")
                # 409 on a resource "create" is an expected dedupe hit — not an error.
                if status == 409:
                    continue
                if status and status >= 400:
                    self.stats["item_errors"] += 1
                    err = result.get("error") or {}
                    reason = err.get("type", "unknown") if isinstance(err, dict) else "unknown"
                    by_reason[reason] = by_reason.get(reason, 0) + 1
                    if reason not in examples:
                        text = err.get("reason", "") if isinstance(err, dict) else str(err)
                        examples[reason] = f"{result.get('_index')}: {text[:200]}"

        for reason, count in sorted(by_reason.items(), key=lambda kv: -kv[1]):
            logger.warning(
                "DATA LOSS: %d document(s) rejected (%s) and not retried - %s",
                count, reason, examples[reason],
            )
        if by_reason:
            logger.warning(
                "bulk batch: %d rejected, %d accepted (session totals: %d rejected, "
                "%d flushed)",
                sum(by_reason.values()),
                len(resp.get("items", [])) - sum(by_reason.values()),
                self.stats["item_errors"], self.stats["flushed"],
            )
