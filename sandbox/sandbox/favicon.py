"""Favicon discovery + hashing (port of v2 main.py favicon helpers).

Uses a shared async httpx client instead of per-call requests, and honours the
SSRF guard on every candidate URL.
"""
from __future__ import annotations

import base64
import hashlib

from . import fpx
from urllib.parse import urljoin

import mmh3

from .netguard import check_url

_REL_WHITELIST = {"icon", "shortcut icon", "apple-touch-icon", "apple-touch-icon-precomposed", "mask-icon"}


def favicon_mmh3(content: bytes) -> int:
    """Shodan-compatible favicon hash: mmh3 of base64(content-with-newlines)."""
    b64 = base64.encodebytes(content).decode("utf-8")
    return mmh3.hash(b64)


def extract_favicon_urls(soup, base_url: str) -> list[str]:
    urls: set[str] = set()
    for link in soup.find_all("link"):
        href = link.get("href")
        if not href:
            continue
        rel = link.get("rel")
        rel_str = " ".join(rel).lower() if isinstance(rel, list) else str(rel or "").lower()
        rel_str = " ".join(rel_str.split())
        if rel_str in _REL_WHITELIST or "icon" in rel_str:
            urls.add(urljoin(base_url, str(href).strip()))
    urls.add(urljoin(base_url, "/favicon.ico"))
    urls.add(urljoin(base_url, "/apple-touch-icon.png"))
    return sorted(urls)


async def fetch_and_hash(client, url: str, user_agent: str, timeout_s: int,
                         block_private: bool = True, max_bytes: int = 1024 * 1024) -> dict | None:
    # Async form: this runs per candidate favicon URL, so a blocking resolve
    # here stalls the loop several times per scan.
    if await check_url(url, block_private) is not None:
        return None
    try:
        resp = await client.get(url, headers={"User-Agent": user_agent},
                                timeout=timeout_s, follow_redirects=True)
        if resp.status_code != 200:
            return None
        data = resp.content
        if len(data) > max_bytes:
            return None
        return {
            "url": url,
            "content_type": (resp.headers.get("Content-Type") or "").lower(),
            "content_length": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "mmh3": favicon_mmh3(data),
            # Perceptual: survives recompression/resize, unlike mmh3/md5/sha256
            # which all move on a single changed byte.
            "dhash": fpx.favicon_dhash(data),
        }
    except Exception:
        return None
