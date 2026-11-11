"""Memory guard: keep a worker under its container's memory limit by killing the Chromium processes that hold the
memory, and log what they were.

Without it the kernel's OOM killer takes the whole worker (every in-flight scan) and leaves no record of which page
did it. The guard reads the container's own cgroup (``memory.current`` against ``memory.max``); above
``memory_guard_pct`` of the limit it logs the largest Chromium processes, then kills stuck renderers first (older
than any scan can live, so their scan is already past its deadline), then the largest processes until usage is back
under the line. A killed renderer fails its scan ("Target crashed"); a killed browser process is relaunched by the
pool on its next scan. No limit on the container (``memory.max`` = ``max``) means nothing to guard.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal

logger = logging.getLogger(__name__)

CGROUP = "/sys/fs/cgroup"
CHROME_NAMES = {"chrome", "chromium", "chromium-browse", "headless_shell"}
KILLABLE = {"renderer", "browser", "gpu-process", "utility"}
KILL_SIGNAL = getattr(signal, "SIGKILL", signal.SIGTERM)   # SIGKILL on Linux (the workers); tests also run on Windows


def read_memory(cgroup: str = CGROUP) -> tuple[int | None, int | None]:
    """(limit, current) in bytes for this container; limit None when the container has none."""
    try:
        raw = open(os.path.join(cgroup, "memory.max")).read().strip()
        current = int(open(os.path.join(cgroup, "memory.current")).read().strip())
    except (OSError, ValueError):
        return None, None
    return (None if raw == "max" else int(raw)), current


def chrome_processes(proc: str = "/proc") -> list[dict]:
    """Every Chromium process this container can see: pid, rss (bytes), type (browser, renderer, ...), age (s)."""
    try:
        uptime = float(open(os.path.join(proc, "uptime")).read().split()[0])
    except (OSError, ValueError):
        return []
    hz = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    out = []
    for pid in os.listdir(proc):
        if not pid.isdigit():
            continue
        base = os.path.join(proc, pid)
        try:
            if open(os.path.join(base, "comm")).read().strip() not in CHROME_NAMES:
                continue
            cmd = open(os.path.join(base, "cmdline"), "rb").read().split(b"\0")
            ptype = next((a[7:].decode() for a in cmd if a.startswith(b"--type=")), "browser")
            rss = next((int(line.split()[1]) * 1024 for line in open(os.path.join(base, "status"))
                        if line.startswith("VmRSS:")), 0)
            # field 22 of stat is the start time in clock ticks; the comm field may hold spaces, so split after ")"
            start = int(open(os.path.join(base, "stat")).read().rsplit(")", 1)[1].split()[19])
        except (OSError, ValueError, IndexError):
            continue   # the process exited while we read it
        out.append({"pid": int(pid), "rss": rss, "type": ptype, "age_s": int(uptime - start / hz)})
    return out


def choose_victims(procs: list[dict], over_bytes: int, stuck_age_s: int) -> list[dict]:
    """Stuck renderers first (older than a scan can live), then the largest killable processes, until the processes
    chosen hold at least ``over_bytes`` (RSS counts shared pages more than once, so this errs on killing less)."""
    stuck = sorted((p for p in procs if p["type"] == "renderer" and p["age_s"] > stuck_age_s), key=lambda p: -p["rss"])
    victims, freed = list(stuck), sum(p["rss"] for p in stuck)
    for p in sorted((p for p in procs if p["type"] in KILLABLE and p not in victims), key=lambda p: -p["rss"]):
        if freed >= over_bytes:
            break
        victims.append(p)
        freed += p["rss"]
    return victims


class MemoryGuard:
    def __init__(self, settings, cgroup: str = CGROUP, proc: str = "/proc", kill=os.kill) -> None:
        self.settings = settings
        self.cgroup, self.proc, self._kill = cgroup, proc, kill
        self._task: asyncio.Task | None = None

    def check(self) -> list[dict]:
        """One pass: returns the processes it killed (empty when under the line or nothing to guard)."""
        pct = self.settings.memory_guard_pct
        limit, current = read_memory(self.cgroup)
        if not pct or not limit or current is None or current < limit * pct / 100:
            return []
        procs = chrome_processes(self.proc)
        top = sorted(procs, key=lambda p: -p["rss"])[:10]
        logger.warning("memory guard: worker at %d of %d MB (%d%%); largest chromium processes: %s",
                       current // 2**20, limit // 2**20, current * 100 // limit,
                       ", ".join(f"{p['type']} pid {p['pid']} {p['rss'] // 2**20} MB {p['age_s']}s" for p in top))
        victims = choose_victims(procs, current - int(limit * pct / 100), self.settings.scan_deadline + 60)
        for v in victims:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                self._kill(v["pid"], KILL_SIGNAL)
                logger.warning("memory guard: killed %s pid %d (%d MB, %ds old)",
                               v["type"], v["pid"], v["rss"] // 2**20, v["age_s"])
        return victims

    async def _run(self) -> None:
        while True:
            await asyncio.sleep(self.settings.memory_guard_interval)
            try:
                self.check()
            except Exception:  # noqa: BLE001 - the guard must never take the worker down
                logger.exception("memory guard check failed")

    def start(self) -> None:
        if self.settings.memory_guard_pct and read_memory(self.cgroup)[0]:
            self._task = asyncio.create_task(self._run())
            logger.info("memory guard on: above %d%% of the container limit", self.settings.memory_guard_pct)
        else:
            logger.info("memory guard off (no container memory limit, or memory_guard_pct=0)")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
