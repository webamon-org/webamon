"""Unit tests for the SSRF egress guard."""
import asyncio
import socket
import threading
from unittest import mock

import pytest

from sandbox.netguard import (
    BLOCKED_PRIVATE, DNS_FAILED, INVALID_URL,
    check_url, check_url_sync, is_allowed_url,
)


class TestBlockedTargets:
    def test_localhost_ip_blocked(self):
        assert is_allowed_url("http://127.0.0.1/") is False

    def test_private_10_blocked(self):
        assert is_allowed_url("http://10.0.0.5/") is False

    def test_private_192_blocked(self):
        assert is_allowed_url("http://192.168.1.1/") is False

    def test_link_local_metadata_blocked(self):
        assert is_allowed_url("http://169.254.169.254/latest/meta-data/") is False

    def test_ipv6_loopback_blocked(self):
        assert is_allowed_url("http://[::1]/") is False


class TestAllowedTargets:
    def test_public_ip_allowed(self):
        assert is_allowed_url("http://8.8.8.8/") is True

    def test_bypass_when_disabled(self):
        assert is_allowed_url("http://127.0.0.1/", block_private=False) is True

    def test_malformed_url_blocked(self):
        assert is_allowed_url("not a url", block_private=True) is False


class TestVerdictCodes:
    """A name that does not resolve must not be reported as an SSRF block.

    Both used to return False, so every dead NRD was filed as
    blocked_private_network - on an NRD feed, most of the corpus.
    """

    def test_unresolvable_host_is_dns_failure_not_a_block(self):
        # Mocked rather than resolving a real name: a unit test must not depend
        # on the network, and a genuine NXDOMAIN costs seconds in retries.
        with mock.patch("socket.getaddrinfo", side_effect=socket.gaierror(-2, "no name")):
            assert check_url_sync("http://nope.example/") == DNS_FAILED

    def test_private_target_is_a_block(self):
        assert check_url_sync("http://10.0.0.5/") == BLOCKED_PRIVATE

    def test_metadata_endpoint_is_a_block(self):
        assert check_url_sync("http://169.254.169.254/latest/meta-data/") == BLOCKED_PRIVATE

    def test_public_ip_allowed(self):
        assert check_url_sync("http://8.8.8.8/") is None

    def test_malformed_url_is_its_own_code(self):
        assert check_url_sync("not a url") == INVALID_URL

    def test_disabled_allows_everything(self):
        assert check_url_sync("http://127.0.0.1/", block_private=False) is None


class TestAsyncGuard:
    @pytest.mark.asyncio
    async def test_async_agrees_with_sync(self):
        for url in ("http://10.0.0.5/", "http://8.8.8.8/", "http://[::1]/"):
            assert await check_url(url) == check_url_sync(url)

    @pytest.mark.asyncio
    async def test_async_reports_dns_failure(self):
        with mock.patch("socket.getaddrinfo", side_effect=socket.gaierror(-2, "no name")):
            assert await check_url("http://nope.example/") == DNS_FAILED

    @pytest.mark.asyncio
    async def test_public_name_resolving_to_private_ip_is_blocked(self):
        """DNS rebinding: a public name whose records point inside."""
        rec = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 0))]
        with mock.patch("socket.getaddrinfo", return_value=rec):
            assert await check_url("http://evil.example/") == BLOCKED_PRIVATE

    @pytest.mark.asyncio
    async def test_blocked_if_any_record_is_private(self):
        """One internal record among public ones is still a block."""
        rec = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
               (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 0))]
        with mock.patch("socket.getaddrinfo", return_value=rec):
            assert await check_url("http://mixed.example/") == BLOCKED_PRIVATE

    @pytest.mark.asyncio
    async def test_resolution_does_not_block_the_event_loop(self):
        """A slow resolve must not stop other coroutines from running.

        This is the regression that cost throughput elsewhere: a blocking
        getaddrinfo in async code stalls every concurrent scan.
        """
        slow = threading.Event()

        def _slow_getaddrinfo(*a, **k):
            slow.wait(2.0)
            raise socket.gaierror(-2, "Name or service not known")

        ticks = 0

        async def ticker():
            nonlocal ticks
            for _ in range(50):
                ticks += 1
                await asyncio.sleep(0.001)

        with mock.patch("socket.getaddrinfo", _slow_getaddrinfo):
            task = asyncio.create_task(check_url("http://slow.example/"))
            await ticker()
            slow.set()
            assert await task == DNS_FAILED

        assert ticks == 50, "event loop was blocked during DNS resolution"
