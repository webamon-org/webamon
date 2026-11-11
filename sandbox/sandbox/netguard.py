"""SSRF egress guard.

The sandbox visits hostile URLs; it must refuse to be pointed at internal /
link-local / cloud-metadata addresses. Used to gate both the scan target and
auxiliary fetches (favicons).

Two things this module is careful about, both learned the hard way:

* A name that does not resolve is NOT a blocked target. Collapsing both into
  one boolean filed every dead NRD as ``blocked_private_network``, which on a
  newly-registered-domain feed is most of them - burying any real SSRF attempt
  in noise. Callers get a reason code instead.
* Resolution must not block the event loop. ``socket.getaddrinfo`` is a
  blocking call, and the scan path is async; on a feed full of unresolvable
  domains it stalls every concurrent scan for the resolver timeout.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlparse

#: Returned by the check functions. ``None`` means the URL is allowed.
BLOCKED_PRIVATE = "blocked_private_network"
DNS_FAILED = "dns_resolution_failed"
INVALID_URL = "invalid_url"


def _is_blocked_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_reserved or addr.is_multicast or addr.is_unspecified
    )


def _host_of(url: str) -> str | None:
    try:
        return urlparse(url).hostname
    except ValueError:
        return None


def _literal_verdict(host: str) -> str | None | bool:
    """Verdict for an IP literal, or False if `host` is a name needing DNS."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return BLOCKED_PRIVATE if _is_blocked_ip(host) else None


def _verdict_for_addrs(addrs) -> str | None:
    return BLOCKED_PRIVATE if any(_is_blocked_ip(ip) for ip in addrs) else None


async def check_url(url: str, block_private: bool = True) -> str | None:
    """Async: return None if the URL may be fetched, else a reason code.

    Resolution runs on the loop's executor so a slow or dead name cannot stall
    other scans.
    """
    if not block_private:
        return None
    host = _host_of(url)
    if not host:
        return INVALID_URL

    literal = _literal_verdict(host)
    if literal is not False:
        return literal

    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None)
    except socket.gaierror:
        return DNS_FAILED
    except (UnicodeError, OSError):
        # IDNA failures and similar surface here; not a private-network block.
        return DNS_FAILED
    return _verdict_for_addrs(info[4][0] for info in infos)


def check_url_sync(url: str, block_private: bool = True) -> str | None:
    """Blocking variant, for callers that are not async."""
    if not block_private:
        return None
    host = _host_of(url)
    if not host:
        return INVALID_URL

    literal = _literal_verdict(host)
    if literal is not False:
        return literal

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return DNS_FAILED
    except (UnicodeError, OSError):
        return DNS_FAILED
    return _verdict_for_addrs(info[4][0] for info in infos)


def is_allowed_url(url: str, block_private: bool = True) -> bool:
    """Boolean form, kept for callers that only need allow/deny.

    Prefer ``check_url`` where the distinction between "unresolvable" and
    "points somewhere internal" matters - which is anywhere the answer is
    recorded in a report.
    """
    return check_url_sync(url, block_private) is None
