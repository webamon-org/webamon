"""A page that is mid-navigation must not fail the whole scan.

v2 (Selenium) never raised here - `driver.page_source` returned whatever was in
the DOM, so a half-built or already-replaced document was silently reported as
success. Playwright's guard is more correct, but the scan carries requests,
certificates, domains and resources by this point; discarding all of that
because the DOM was momentarily unavailable is a regression against v2.
"""
import pytest
from playwright.async_api import Error as PlaywrightError

from sandbox.config import Settings
from sandbox.engine import ScanEngine

NAV_ERROR = ("Page.content: Unable to retrieve content because the page is "
             "navigating and changing the content.")


def _engine():
    return ScanEngine(Settings(save_elastic=False), pool=None, enrichment=None,
                      technology=None, http_client=None)


class _Page:
    """Fake page: fails `content()` a set number of times, then succeeds."""

    def __init__(self, fail_times=0, evaluate_result="<html>fallback</html>",
                 always_fail=False):
        self.fail_times = fail_times
        self.always_fail = always_fail
        self.calls = 0
        self.evaluate_result = evaluate_result
        self.url = "https://example.test/"

    async def content(self):
        self.calls += 1
        if self.always_fail or self.calls <= self.fail_times:
            raise PlaywrightError(NAV_ERROR)
        return "<html>real</html>"

    async def wait_for_load_state(self, state, timeout=None):
        return None

    async def wait_for_timeout(self, ms):
        return None

    async def evaluate(self, script):
        if self.evaluate_result is None:
            raise PlaywrightError("evaluate failed too")
        return self.evaluate_result

    async def title(self):
        return "T"


class TestSafeDom:
    @pytest.mark.asyncio
    async def test_returns_dom_when_page_is_settled(self):
        report = {"errors": []}
        page = _Page(fail_times=0)
        assert await _engine()._safe_dom(page, report) == "<html>real</html>"
        assert report["errors"] == []

    @pytest.mark.asyncio
    async def test_retries_through_a_transient_navigation(self):
        report = {"errors": []}
        page = _Page(fail_times=2)
        assert await _engine()._safe_dom(page, report) == "<html>real</html>"
        assert page.calls == 3
        assert report["errors"] == [], "a recovered retry should not be logged as an error"

    @pytest.mark.asyncio
    async def test_falls_back_to_evaluate_when_navigation_never_settles(self):
        report = {"errors": []}
        page = _Page(always_fail=True)
        dom = await _engine()._safe_dom(page, report)
        assert dom == "<html>fallback</html>"
        assert report["errors"][0]["error"] == "dom_via_fallback_evaluate"

    @pytest.mark.asyncio
    async def test_returns_empty_and_records_rather_than_raising(self):
        """The scan must survive: network data is already captured."""
        report = {"errors": []}
        page = _Page(always_fail=True, evaluate_result=None)
        dom = await _engine()._safe_dom(page, report)
        assert dom == ""
        assert report["errors"][0]["error"] == "dom_unavailable_page_navigating"

    @pytest.mark.asyncio
    async def test_unrelated_playwright_errors_still_propagate(self):
        """Only the navigation race is tolerated - a crashed target is a real
        failure and must not be silently swallowed."""
        class _Broken(_Page):
            async def content(self):
                raise PlaywrightError("Target page, context or browser has been closed")

        with pytest.raises(PlaywrightError):
            await _engine()._safe_dom(_Broken(), {"errors": []})

    @pytest.mark.asyncio
    async def test_title_failure_is_not_fatal(self):
        class _NoTitle(_Page):
            async def title(self):
                raise PlaywrightError(NAV_ERROR)

        assert await _engine()._safe_title(_NoTitle()) == ""
