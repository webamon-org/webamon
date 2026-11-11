"""Scan engine.

Produces the Webamon report schema: submission_url, resolved_url, domain_name/sub_domain/tld,
resolved_* , dom, page_title, cookie, request[], certificate[], resource /
resource_master, technology, page_links, page_scripts, domain[], server[],
meta{}, fingerprint{}, scan_status, scan_time, errors[], plus optional
favicons, monitor/changes.
"""
from __future__ import annotations

import asyncio
import base64
import datetime
import io
import logging
from datetime import timezone

from bs4 import BeautifulSoup
from playwright.async_api import Error as PlaywrightError, TimeoutError as PlaywrightTimeout

from . import capture, fingerprints, scoring
from .netguard import BLOCKED_PRIVATE, check_url
from .transforms import transform_headers, format_utc_datetime, normalize_cookies

logger = logging.getLogger(__name__)


class ScanEngine:
    def __init__(self, settings, pool, enrichment, technology, http_client,
                 engine_id: str = "") -> None:
        self.settings = settings
        self.pool = pool
        self.enrich = enrichment
        self.tech = technology
        self.http = http_client
        # v2 stamps every report with the engine instance id; production
        # documents contain it, so parity requires we do the same.
        self.engine_id = engine_id or _uuid()

    async def scan(self, url: str, report_id: str = "", tag_override=None) -> dict:
        start_time = format_utc_datetime(datetime.datetime.now(timezone.utc))
        start = datetime.datetime.now()
        if not (url.startswith("http://") or url.startswith("https://")):
            url = f"http://{url}"

        tag_value = tag_override if tag_override is not None else self.settings.tag
        domain_name, sub_domain, tld = self.enrich.domain_extract(url)
        report = {
            "request": {}, "submission_utc": start_time, "tag": tag_value,
            "report_id": report_id or _uuid(), "submission_url": url,
            "source": self.settings.source, "feed": self.settings.feed,
            "date": datetime.datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "save_resources": self.settings.resources, "errors": [],
            "domain_name": domain_name, "sub_domain": sub_domain, "tld": tld,
            "engine_id": self.engine_id,
        }

        # A name that will not resolve is reported as such. It is not an SSRF
        # block, and on an NRD feed it is the common outcome - most of those
        # domains are dead or already taken down by the time we see them.
        verdict = await check_url(url, self.settings.block_private_networks)
        if verdict is not None:
            report["scan_status"] = "blocked" if verdict == BLOCKED_PRIVATE else "not_resolved"
            report["errors"].append({"error": verdict, "url": url})
            report["completion_utc"] = format_utc_datetime(datetime.datetime.now(timezone.utc))
            report["scan_time"] = str(datetime.datetime.now() - start)
            return report

        try:
            # One deadline for the whole scan: goto has its own timeout, but content(), evaluate, the screenshot,
            # body capture and the context close would otherwise wait forever on a page that never yields - and
            # keep its renderer growing.
            await asyncio.wait_for(self._run_scan(url, report), timeout=self.settings.scan_deadline)
            report["scan_status"] = "success"
        except asyncio.TimeoutError:
            report["errors"].append({"error": f"Deadline - {self.settings.scan_deadline}", "url": url})
            report["scan_status"] = "failed"
            logger.warning("scan deadline (%ss) exceeded: %s", self.settings.scan_deadline, url)
        except (PlaywrightTimeout,) as e:
            report["errors"].append({"error": f"Timeout - {self.settings.scan_timeout}", "url": url})
            report["scan_status"] = "failed"
            logger.warning("timeout: %s", url)
        except PlaywrightError as e:
            report["errors"].append({"error": _classify(str(e)), "url": url})
            report["scan_status"] = "failed"
            logger.warning("scan error %s: %s", url, e)
        except Exception as e:  # noqa: BLE001 — capture-all mirrors v2, but recorded not swallowed
            report["errors"].append({"error": str(e), "url": url})
            report["scan_status"] = "failed"
            logger.exception("uncaught scan error: %s", url)

        report["completion_utc"] = format_utc_datetime(datetime.datetime.now(timezone.utc))
        report["scan_time"] = str(datetime.datetime.now() - start)
        return report

    async def _run_scan(self, url: str, report: dict) -> None:
        net = capture.NetworkCapture()
        async with self.pool.context(self.settings.user_agent) as ctx:
            page = await ctx.new_page()
            cdp = await ctx.new_cdp_session(page)
            # Bounded: without limits Chromium keeps every response body for Network.getResponseBody, so a page that
            # streams without end grows the browser process. Bodies over the per-response limit are simply not kept.
            await cdp.send("Network.enable", {
                "maxTotalBufferSize": self.settings.network_buffer_mb * 1024 * 1024,
                "maxResourceBufferSize": self.settings.network_resource_buffer_mb * 1024 * 1024,
            })
            net.attach(cdp)

            try:
                await page.goto(url, timeout=self.settings.scan_timeout * 1000, wait_until="load")
            except PlaywrightTimeout:
                # Keep whatever loaded (parity with v2 which still captured partial state).
                pass

            # Keep capturing after load: lazily-loaded and deferred requests
            # arrive well after the load event and are otherwise missed.
            if self.settings.post_load_dwell_ms > 0:
                await page.wait_for_timeout(self.settings.post_load_dwell_ms)

            report["monitor"] = bool(self.settings.monitor)
            report["dom"] = await self._safe_dom(page, report)
            report["page_title"] = await self._safe_title(page)
            report["resolved_url"] = page.url
            report["cookie"] = normalize_cookies(await ctx.cookies())
            (report["resolved_domain"], report["resolved_sub_domain"],
             report["resolved_tld"]) = self.enrich.domain_extract(page.url)

            report["redirect_chain"] = list(net.redirect_chain)

            if self.settings.save_screenshot:
                await self._screenshot(page, report)

            soup = BeautifulSoup(report["dom"], "html.parser")
            if self.settings.favicon_hashing:
                await self._favicons(soup, report, url)

            script_tags = soup.find_all("script")
            link_tags = soup.find_all("link")
            report["page_links"] = [str(x) for x in link_tags]
            report["page_scripts"] = [str(x) for x in script_tags]
            report["technology"] = self.tech.detect(
                [t["src"] for t in script_tags if t.get("src")],
                [t["href"] for t in link_tags if t.get("href")],
                list(net.requests.values()),
            )

            # Body capture is done LAST and against a FROZEN snapshot.
            #
            # Previously report["request"] was assigned the live net.requests
            # dict by reference while body ids were snapshotted earlier, so any
            # request arriving during the intervening awaits (screenshot, DOM
            # parse, favicons) landed in request[] with no body ever fetched -
            # which is why resource counts came out lower than request counts.
            snapshot, bodies = await capture.capture_bodies(
                cdp, net, self.settings.body_fetch_concurrency,
                skip_video=not self.settings.save_video,
            )
            report["request"] = snapshot
            mapping, resource_master = capture.build_resources(
                snapshot, bodies, report["report_id"], url, report["submission_utc"]
            )
            report["resource"], report["resource_master"] = mapping, resource_master

        # --- enrichment (browser released) --------------------------------
        capture.finalize_network(report, self.enrich.domain_extract)
        transform_headers(report)
        report["domain"] = await self.enrich.third_parties(report, report["resolved_url"])
        report["server"] = self.enrich.server_data(report)
        self.enrich.scan_meta(report, scoring.generate)
        report["meta"]["risk_score_version"] = scoring.RISK_SCORE_VERSION
        report["fingerprint"] = fingerprints.generate_fingerprints(report)
        report["lexical"] = fingerprints.generate_lexical(report)

    async def _safe_dom(self, page, report: dict) -> str:
        """Get the DOM without letting a mid-navigation page fail the scan.

        Playwright's ``page.content()`` raises "Unable to retrieve content
        because the page is navigating" if the document is being replaced at
        that instant - common on sites with a late consent/region redirect.

        Selenium's ``driver.page_source`` (v2) had no such check: it returned
        whatever was in the DOM, mid-navigation or not. So v2 never raised -
        but it also silently captured a half-built or already-replaced
        document and reported success. The strict error is the more correct
        behaviour; failing the whole scan over it was not.

        Everything else - requests, certificates, domains, resources - is
        already captured by this point and is the bulk of the report's value.
        A missing DOM must not discard it.
        """
        for attempt in range(3):
            try:
                return await page.content()
            except PlaywrightError as e:
                if "navigating" not in str(e).lower():
                    raise
                # Let the in-flight navigation commit, then try again.
                try:
                    await page.wait_for_load_state("domcontentloaded", timeout=5000)
                except Exception:
                    await page.wait_for_timeout(500 * (attempt + 1))

        # Last resort: read the serialised document directly. This is not
        # subject to the navigation guard.
        try:
            dom = await page.evaluate("() => document.documentElement.outerHTML")
            if dom:
                report["errors"].append(
                    {"error": "dom_via_fallback_evaluate", "url": page.url})
                return dom
        except Exception:
            pass

        report["errors"].append({"error": "dom_unavailable_page_navigating",
                                 "url": page.url})
        logger.warning("DOM unavailable (page kept navigating): %s", page.url)
        return ""

    async def _safe_title(self, page) -> str:
        try:
            return await page.title()
        except Exception:
            return ""

    async def _screenshot(self, page, report: dict) -> None:
        from PIL import Image
        raw = await page.screenshot(type="png")
        image = Image.open(io.BytesIO(raw))
        if image.mode == "RGBA":
            image = image.convert("RGB")
        resized = image.resize((image.width // 2, image.height // 2), Image.Resampling.LANCZOS)
        buf = io.BytesIO()
        resized.save(buf, format="JPEG", quality=50)
        report["_screenshot_b64"] = base64.b64encode(buf.getvalue()).decode("utf-8")

    async def _favicons(self, soup, report: dict, url: str) -> None:
        from .favicon import extract_favicon_urls, fetch_and_hash
        base_url = report.get("resolved_url") or url
        favicons = []
        for fav_url in extract_favicon_urls(soup, base_url):
            hashed = await fetch_and_hash(
                self.http, fav_url, self.settings.user_agent, self.settings.scan_timeout,
                self.settings.block_private_networks,
            )
            if hashed:
                favicons.append(hashed)
        if favicons:
            report["favicons"] = favicons


def _uuid() -> str:
    import uuid
    return str(uuid.uuid4())


def _classify(msg: str) -> str:
    if "ERR_NAME_NOT_RESOLVED" in msg:
        return "ERR_NAME_NOT_RESOLVED"
    if "ERR_CONNECTION_REFUSED" in msg:
        return "ERR_CONNECTION_REFUSED"
    return msg
