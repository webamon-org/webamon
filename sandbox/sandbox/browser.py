"""Persistent Playwright browser pool.

v2 launched and destroyed a cold Chrome per URL (~1-2.5s each). v3 keeps a
small pool of long-lived browser processes and hands each scan a FRESH,
isolated ``BrowserContext`` (~50ms) so cookies/cache never leak between scans.
Processes are recycled after ``browser_max_scans`` to contain memory leaks from
hostile pages.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging

from playwright.async_api import async_playwright, Browser, BrowserContext

logger = logging.getLogger(__name__)

_CHROME_ARGS = [
    "--disable-gpu",
    "--ignore-certificate-errors",
    "--disable-dev-shm-usage",
    "--no-zygote",
    "--window-size=1280,1696",

    # --- disk I/O -------------------------------------------------------
    # A scanner visits a different site every time, so the HTTP cache has a
    # hit rate of approximately zero - it is pure write amplification. Left
    # on, Chromium's profile (cache index, cookie SQLite, LocalStorage
    # LevelDB) issues THOUSANDS of sub-kilobyte synchronous writes per
    # second, averaging around a kilobyte each, which is enough to saturate a
    # host's root disk when several scanners run side by side.
    #
    # Size 1 rather than 0: 0 means "unlimited" to Chromium, which is the
    # exact opposite of what is wanted here.
    "--disk-cache-size=1",
    "--media-cache-size=1",
    # Crash dumps, component downloads and background telemetry all write to
    # the profile and none of them are wanted in a disposable container.
    "--disable-breakpad",
    "--disable-component-update",
    "--disable-background-networking",
    "--no-first-run",
    "--no-default-browser-check",
]


def _chrome_args(settings) -> list[str]:
    """The fixed flags plus the per-renderer JS heap cap: a page that allocates without end crashes its own tab
    ("Target crashed", the scan fails) instead of growing the worker for hours."""
    heap = getattr(settings, "renderer_heap_mb", 0)
    return _CHROME_ARGS + ([f"--js-flags=--max-old-space-size={heap}"] if heap else [])


class _PooledBrowser:
    def __init__(self, browser: Browser) -> None:
        self.browser = browser
        self.scans = 0
        self.lock = asyncio.Lock()
        # Set when a scan's context would not close: the process is wedged on some page, so it is replaced before
        # the next scan instead of being handed out again.
        self.broken = False


class BrowserPool:
    def __init__(self, settings) -> None:
        self.settings = settings
        self._pw = None
        self._browsers: list[_PooledBrowser] = []
        self._rr = 0
        self._launch_lock = asyncio.Lock()

    async def start(self) -> None:
        self._pw = await async_playwright().start()
        for _ in range(self.settings.browser_pool_size):
            self._browsers.append(_PooledBrowser(await self._launch()))
        logger.info(
            "browser pool started: %d process(es) engine=%s",
            len(self._browsers), self.engine_name,
        )

    @property
    def engine_name(self) -> str:
        return "chromium"

    async def _launch(self) -> Browser:
        kwargs = {"headless": self.settings.headless, "args": _chrome_args(self.settings)}
        if self.settings.browser_executable_path:
            kwargs["executable_path"] = self.settings.browser_executable_path
        return await self._pw.chromium.launch(**kwargs)

    async def _recycle(self, pooled: _PooledBrowser) -> None:
        # A wedged browser can also hang on close; never let that stall the pool (the memory guard kills whatever
        # process tree is left behind).
        with contextlib.suppress(Exception):
            await asyncio.wait_for(pooled.browser.close(), getattr(self.settings, "context_close_timeout", 15) + 5)
        pooled.browser = await self._launch()
        pooled.scans = 0
        pooled.broken = False
        logger.debug("recycled a browser process")

    @contextlib.asynccontextmanager
    async def context(self, user_agent: str):
        """Yield a fresh isolated context for one scan; recycle process if over budget."""
        pooled = self._browsers[self._rr % len(self._browsers)]
        self._rr += 1

        async with pooled.lock:
            # A crashed process stays in the pool until replaced: without the
            # is_connected() check every scan routed to it fails instantly with
            # "Target page, context or browser has been closed" until the scan
            # budget below happens to recycle it (~100-200 lost scans per crash).
            if not pooled.browser.is_connected():
                logger.warning("browser process died; relaunching")
                await self._recycle(pooled)
            elif pooled.broken:
                logger.warning("browser had a context that would not close; relaunching")
                await self._recycle(pooled)
            elif pooled.scans >= self.settings.browser_max_scans:
                await self._recycle(pooled)
            pooled.scans += 1

        ctx_kwargs: dict = {
            "ignore_https_errors": True,
            "viewport": {"width": 1280, "height": 1696},
        }
        if user_agent:
            ctx_kwargs["user_agent"] = user_agent

        ctx: BrowserContext = await pooled.browser.new_context(**ctx_kwargs)
        try:
            yield ctx
        finally:
            # Also runs when the scan hit its deadline and was cancelled. A close that hangs means the page has the
            # process wedged: mark the browser so the next scan on it gets a fresh one.
            try:
                await asyncio.wait_for(ctx.close(), getattr(self.settings, "context_close_timeout", 15))
            except asyncio.TimeoutError:
                pooled.broken = True
                logger.warning("a scan context did not close in %ss; its browser will be recycled",
                               getattr(self.settings, "context_close_timeout", 15))
            except Exception:  # noqa: BLE001 - a dead browser cannot close its contexts; is_connected() catches it
                pass

    async def stop(self) -> None:
        for pooled in self._browsers:
            with contextlib.suppress(Exception):
                await pooled.browser.close()
        if self._pw:
            await self._pw.stop()
        logger.info("browser pool stopped")
