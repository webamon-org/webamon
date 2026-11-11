"""Typed configuration.

Every setting is read from an environment variable of the same name
(``threads``, ``save_elastic``, ``elastic_base`` ...). Matching is
case-insensitive, so ``THREADS`` works too. Booleans accept "True"/"False".
"""
from __future__ import annotations

import json
import logging
import uuid

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.3"
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=False, extra="ignore")

    # --- scan behaviour -------------------------------------------------
    threads: int = 4                  # max concurrent scans
    scan_timeout: int = 30            # seconds for page navigation
    # Milliseconds to keep capturing AFTER the load event. Lazily loaded and
    # deferred requests arrive after load, so a longer dwell captures more of
    # the page at a direct cost to throughput (every scan gets this much
    # longer). 0 by default - tune it against your own targets.
    post_load_dwell_ms: int = 0
    user_agent: str = DEFAULT_UA
    set_cookies: str = "{}"           # JSON dict of cookies applied after first load
    resources: str = "scripts"        # images|scripts|all|none|txt_html — which bodies to persist
    save_screenshot: bool = False
    save_dom: bool = True
    save_resources: bool = False
    save_images: bool = False
    save_css: bool = False
    save_video: bool = False          # video/* and HLS/DASH playlists: off = bodies are not even fetched
    favicon_hashing: bool = False
    monitor: bool = False
    tag: str = ""
    feed: str = ""
    source: str = "url"               # url|mass_scan|query|openphish (batch mode)
    url: str = ""
    mass_scan_file: str = "/app/data/all_domains.txt"
    skip_if_exists: bool = False
    log_level: str = "INFO"
    # ALL  = resolve every domain on the page
    # MAIN = resolve only the page's own domain. v2 accepted MAIN but always
    #        behaved as ALL; here it is real, and on a page with 25 third
    #        parties it is ~25x less DNS for the record that matters most.
    # NONE = skip entirely (the `dns` block is then absent from the report)
    dns: str = "ALL"
    dns_timeout: float = 2.0          # per attempt
    dns_lifetime: float = 4.0         # per query, all attempts
    dns_concurrency: int = 8          # record types resolved in parallel
    # Record types queried per domain, comma separated. Queries per scan is
    # (domains) x (types), so this is a direct multiplier on resolver load.
    # PTR is NOT in the default set: it is the REVERSE lookup for an IP, so
    # asking for the PTR of a domain name always NXDOMAINs. It was 1/8 of all
    # DNS traffic returning nothing. Add it back only if you know why you want it.
    dns_record_types: str = "A,AAAA,MX,NS,TXT,CNAME,SOA"
    dns_cache_size: int = 8192        # domains; CDN/analytics hosts recur constantly
    whois: str = "NONE"               # reserved (not implemented in v2 either)

    # --- browser --------------------------------------------------------
    browser_executable_path: str = ""  # explicit chromium binary; empty = bundled
    # Headed mode needs a real (or virtual) display. On a Linux scanning host
    # that means running under Xvfb, which costs memory and a process per
    # container. Only worth it if it measurably improves evasion - see
    # scripts/headless_vs_headed.py.
    headless: bool = True
    browser_pool_size: int = 2         # browser processes
    browser_max_scans: int = 200       # recycle a browser process after N scans
    body_fetch_concurrency: int = 8    # parallel Network.getResponseBody per scan

    # --- memory bounds --------------------------------------------------
    # Without these, a hostile or broken page can grow a worker without limit: page.content(), evaluate, body
    # capture and context close can wait forever on a page that never yields, CDP buffers every response body, and a
    # renderer's JS heap can grow to Chromium's default of several GB.
    scan_deadline: int = 150           # seconds for a whole scan (load to body capture); then it fails and closes
    context_close_timeout: int = 15    # seconds to close a scan's context; past it the browser is recycled
    renderer_heap_mb: int = 1024       # V8 heap per renderer (--max-old-space-size): a runaway page crashes its own tab
    network_buffer_mb: int = 100       # CDP response-body buffer per page (Network.enable maxTotalBufferSize)
    network_resource_buffer_mb: int = 25   # and per response (maxResourceBufferSize): larger bodies are not kept
    # Above this share of the container's memory limit the guard logs which Chromium processes hold the memory and
    # kills stuck renderers (older than a scan can live), then the largest process: one scan fails instead of the
    # kernel killing the whole worker. 0 turns it off. No container limit (cgroup memory.max = max) = no guard.
    memory_guard_pct: int = 80
    memory_guard_interval: int = 20    # seconds between checks
    block_private_networks: bool = True  # SSRF guard for targets + favicons

    # --- OpenSearch -----------------------------------------------------
    save_elastic: bool = True
    elastic_base: str = "https://localhost:9200"
    elastic_username: str = "admin"
    elastic_password: str = "admin"
    elastic_verify_certs: bool = False
    elastic_query: str = ""
    elastic_query_index: str = "feeds"
    elastic_size: int = 100
    bulk_max_actions: int = 500        # flush bulk when this many actions queued
    bulk_flush_interval: float = 2.0   # ...or after this many seconds
    bulk_max_retries: int = 5
    # Entity index names. Override them to write alongside an existing
    # cluster whose `domains`/`servers` are aliases over dated indices
    # (writing to a multi-index alias with no write index fails per document).
    # Caps on the arrays the painless merge scripts append to. `resource` is
    # mapped NESTED on domains-*/servers-*, so each element is a separate Lucene
    # document counted against index.mapping.nested_objects.limit (10000). An
    # uncapped array means the busiest domains eventually reject every update.
    entity_max_resource: int = 500
    entity_max_list: int = 1000
    domains_index: str = "domains"
    servers_index: str = "servers"
    # False (default) = one non-dated `domains` / `servers` index, where
    # first_seen / last_seen accumulate across days. True = dated
    # domains-YYYY.MM.DD / servers-YYYY.MM.DD indices, where the scripted
    # upsert can only merge within a single day, so first_seen resets daily.
    entity_dated_indices: bool = False
    # Bounded writer queue = real backpressure. When OpenSearch is slow the
    # queue fills, scan coroutines block on put, and the stall propagates back
    # to intake instead of growing memory without limit. 0 disables the bound
    # (the old unbounded behaviour) — not recommended in production.
    bulk_queue_maxsize: int = 10000
    # Seconds a scan may wait for queue capacity before we give up on that
    # document. 0 = wait forever (safest: never drops data, but a dead
    # OpenSearch will stall scanning entirely, which is usually what you want).
    bulk_put_timeout: float = 0.0
    dated_indices: bool = True         # scans-YYYY.MM.DD naming (v2 compat)

    # --- API mode -------------------------------------------------------
    queue_worker: bool = True          # True = HTTP API on api_port; False = run one batch and exit
    api_key: str = ""                  # empty = auth disabled (parity with v2)
    api_host: str = "0.0.0.0"
    api_port: int = 5000

    # --- paths ----------------------------------------------------------
    geoip_asn_path: str = "/app/geoIP/GeoLite2-ASN.mmdb"
    geoip_country_path: str = "/app/geoIP/GeoLite2-Country.mmdb"
    technology_patterns_path: str = "technology_patterns.txt"

    @field_validator("resources")
    @classmethod
    def _valid_resources(cls, v: str) -> str:
        allowed = {"images", "scripts", "all", "none", "txt_html"}
        if v not in allowed:
            raise ValueError(f"resources must be one of {sorted(allowed)}")
        return v

    @field_validator("log_level")
    @classmethod
    def _valid_log_level(cls, v: str) -> str:
        v = v.upper()
        if not hasattr(logging, v):
            raise ValueError(f"invalid log level {v!r}")
        return v

    def cookies_dict(self) -> dict:
        try:
            parsed = json.loads(self.set_cookies or "{}")
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            logging.getLogger(__name__).warning("set_cookies is not valid JSON; ignoring")
            return {}

    def dns_enabled(self) -> bool:
        """Whether DNS enrichment runs.

        Case- and whitespace-insensitive, and accepts the obvious off-words.
        The previous exact-match test meant "none", "off" and " NONE " all left
        DNS fully ON - so an operator turning it off to relieve a saturated
        resolver would see no change and no error.
        """
        return (self.dns or "").strip().upper() not in (
            "NONE", "FALSE", "NO", "OFF", "0", "")


def make_engine_id() -> str:
    return str(uuid.uuid4())


def configure_logging(settings: Settings) -> None:
    logging.basicConfig(
        level=getattr(logging, settings.log_level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
