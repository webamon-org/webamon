"""Engine-selection tests for the browser pool (no browser launched)."""
from sandbox.browser import BrowserPool
from sandbox.config import Settings


class TestEngineSelection:
    def test_runs_stock_chromium(self):
        pool = BrowserPool(Settings(save_elastic=False))
        assert pool.engine_name == "chromium"
