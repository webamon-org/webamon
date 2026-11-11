"""Bounds on a scan's memory (a runaway page must not grow a worker's Chromium without limit).

A scan has one overall deadline, its context close is time-limited (a wedged browser is replaced), CDP's response
buffer is capped, each renderer's JS heap is capped, and the memory guard kills the Chromium processes holding the
memory before the kernel kills the whole worker.
"""
import asyncio
import os
import time
import types

import pytest

from sandbox import engine as engine_mod
from sandbox.browser import BrowserPool, _PooledBrowser, _chrome_args
from sandbox.config import Settings
from sandbox.engine import ScanEngine
from sandbox.memguard import KILL_SIGNAL, MemoryGuard, choose_victims, chrome_processes


# ---------------------------------------------------------------- browser pool
def test_renderer_heap_is_capped():
    assert "--js-flags=--max-old-space-size=512" in _chrome_args(types.SimpleNamespace(renderer_heap_mb=512))
    assert not any(a.startswith("--js-flags") for a in _chrome_args(types.SimpleNamespace(renderer_heap_mb=0)))


class _Browser:
    def __init__(self, close_hangs=False):
        self.close_hangs = close_hangs

    def is_connected(self):
        return True

    async def close(self):
        pass

    async def new_context(self, **kw):
        hangs = self.close_hangs

        class Ctx:
            async def close(self):
                if hangs:
                    await asyncio.sleep(10)

        return Ctx()


def _pool(**settings):
    s = dict(browser_pool_size=1, browser_max_scans=200, context_close_timeout=0.1)
    s.update(settings)
    pool = BrowserPool(types.SimpleNamespace(**s))
    pool.launched = []

    async def launch():
        b = _Browser()
        pool.launched.append(b)
        return b

    pool._launch = launch
    return pool


def test_a_context_that_will_not_close_gets_its_browser_replaced():
    pool = _pool()
    pool._browsers = [_PooledBrowser(_Browser(close_hangs=True))]

    async def run():
        t0 = time.monotonic()
        async with pool.context("ua"):
            pass
        assert time.monotonic() - t0 < 2          # the hung close did not stall the scan
        assert pool._browsers[0].broken
        async with pool.context("ua"):           # next scan: a fresh browser
            pass

    asyncio.run(run())
    assert len(pool.launched) == 1
    assert not pool._browsers[0].broken


# ---------------------------------------------------------------- scan engine
class _Enrich:
    def domain_extract(self, url):
        return "example.com", "", "com"


def _engine(**settings):
    return ScanEngine(Settings(save_elastic=False, **settings), pool=None, enrichment=_Enrich(),
                      technology=None, http_client=None)


def test_a_scan_that_never_finishes_fails_at_its_deadline(monkeypatch):
    async def resolves(url, block_private):
        return None
    monkeypatch.setattr(engine_mod, "check_url", resolves)
    eng = _engine(scan_deadline=1)

    async def forever(url, report):
        await asyncio.sleep(30)
    eng._run_scan = forever

    t0 = time.monotonic()
    report = asyncio.run(eng.scan("https://example.com"))
    assert time.monotonic() - t0 < 5
    assert report["scan_status"] == "failed"
    assert {"error": "Deadline - 1", "url": "https://example.com"} in report["errors"]


def test_network_capture_buffer_is_bounded():
    sent = []

    class Stop(Exception):
        pass

    class CDP:
        async def send(self, method, params=None):
            sent.append((method, params))
            raise Stop

    class Ctx:
        async def new_page(self):
            return object()

        async def new_cdp_session(self, page):
            return CDP()

    class Pool:
        def context(self, ua):
            class CM:
                async def __aenter__(self):
                    return Ctx()

                async def __aexit__(self, *a):
                    return False
            return CM()

    eng = _engine(network_buffer_mb=100, network_resource_buffer_mb=25)
    eng.pool = Pool()
    with pytest.raises(Stop):
        asyncio.run(eng._run_scan("https://example.com", {}))
    assert sent == [("Network.enable", {"maxTotalBufferSize": 100 * 2**20, "maxResourceBufferSize": 25 * 2**20})]


# ---------------------------------------------------------------- memory guard
MB = 2**20


def test_stuck_renderers_go_first_then_the_largest():
    procs = [
        {"pid": 1, "rss": 300 * MB, "type": "browser", "age_s": 600},
        {"pid": 2, "rss": 200 * MB, "type": "renderer", "age_s": 900},    # stuck: older than a scan can live
        {"pid": 3, "rss": 1500 * MB, "type": "renderer", "age_s": 20},
        {"pid": 4, "rss": 100 * MB, "type": "renderer", "age_s": 10},
        {"pid": 5, "rss": 2000 * MB, "type": "zygote", "age_s": 600},   # not a type the guard kills
    ]
    assert [p["pid"] for p in choose_victims(procs, 100 * MB, stuck_age_s=210)] == [2]
    assert [p["pid"] for p in choose_victims(procs, 1000 * MB, stuck_age_s=210)] == [2, 3]
    assert [p["pid"] for p in choose_victims(procs, 0, stuck_age_s=210)] == [2]   # stuck ones always go


def _fake_container(tmp_path, limit, current, procs, uptime=10_000.0):
    cg = tmp_path / "cg"
    cg.mkdir()
    (cg / "memory.max").write_text(str(limit))
    (cg / "memory.current").write_text(str(current))
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "uptime").write_text(f"{uptime} 1.0")
    hz = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    for pid, comm, ptype, rss_mb, age in procs:
        d = proc / str(pid)
        d.mkdir()
        (d / "comm").write_text(comm + "\n")
        args = [b"/opt/chrome/chrome"] + ([f"--type={ptype}".encode()] if ptype != "browser" else [])
        (d / "cmdline").write_bytes(b"\0".join(args) + b"\0")
        (d / "status").write_text(f"Name:\t{comm}\nVmRSS:\t{rss_mb * 1024} kB\n")
        start = int((uptime - age) * hz)
        (d / "stat").write_text(f"{pid} ({comm}) S " + " ".join(["0"] * 18) + f" {start} 0 0\n")
    return str(cg), str(proc)


def test_guard_reads_the_container_and_kills_over_the_line(tmp_path):
    cg, proc = _fake_container(tmp_path, limit=5000 * MB, current=4800 * MB, procs=[
        (101, "chrome", "browser", 300, 600),
        (102, "chrome", "renderer", 2500, 30),
        (103, "chrome", "renderer", 150, 15),
        (104, "python", "browser", 450, 600),          # not chromium: never touched
    ])
    procs = {p["pid"]: p for p in chrome_processes(proc)}
    assert set(procs) == {101, 102, 103}
    assert procs[102]["type"] == "renderer" and procs[102]["rss"] == 2500 * MB and abs(procs[102]["age_s"] - 30) <= 1

    killed = []
    guard = MemoryGuard(types.SimpleNamespace(memory_guard_pct=80, scan_deadline=150, memory_guard_interval=20),
                        cgroup=cg, proc=proc, kill=lambda pid, sig: killed.append((pid, sig)))
    victims = guard.check()
    assert [v["pid"] for v in victims] == [102]
    assert killed == [(102, KILL_SIGNAL)]


def test_guard_does_nothing_under_the_line_or_without_a_limit(tmp_path):
    cg, proc = _fake_container(tmp_path, limit=5000 * MB, current=1000 * MB, procs=[(101, "chrome", "renderer", 900, 10)])
    settings = types.SimpleNamespace(memory_guard_pct=80, scan_deadline=150, memory_guard_interval=20)
    assert MemoryGuard(settings, cgroup=cg, proc=proc, kill=lambda *a: pytest.fail("killed")).check() == []
    open(os.path.join(cg, "memory.max"), "w").write("max")
    open(os.path.join(cg, "memory.current"), "w").write(str(9000 * MB))
    assert MemoryGuard(settings, cgroup=cg, proc=proc, kill=lambda *a: pytest.fail("killed")).check() == []
