"""A crashed pooled browser must be relaunched before it is handed out again."""
import asyncio
import types

from sandbox.browser import BrowserPool, _PooledBrowser


class FakeBrowser:
    def __init__(self, alive=True):
        self.alive = alive

    def is_connected(self):
        return self.alive

    async def close(self):
        self.alive = False

    async def new_context(self, **kw):
        if not self.alive:
            raise RuntimeError("Browser.new_context: Target page, context or browser has been closed")

        class Ctx:
            async def close(self):
                pass

        return Ctx()


def _pool(max_scans=200):
    pool = BrowserPool(types.SimpleNamespace(browser_pool_size=1, browser_max_scans=max_scans))
    pool.launched = []

    async def launch():
        b = FakeBrowser()
        pool.launched.append(b)
        return b

    pool._launch = launch
    return pool


def test_dead_browser_is_relaunched():
    pool = _pool()
    pool._browsers = [_PooledBrowser(FakeBrowser(alive=False))]

    async def run():
        async with pool.context("ua") as ctx:
            assert ctx is not None

    asyncio.run(run())
    assert len(pool.launched) == 1
    assert pool._browsers[0].scans == 1


def test_live_browser_is_reused():
    pool = _pool()
    live = FakeBrowser()
    pool._browsers = [_PooledBrowser(live)]

    async def run():
        for _ in range(3):
            async with pool.context("ua"):
                pass

    asyncio.run(run())
    assert pool.launched == []
    assert pool._browsers[0].browser is live
