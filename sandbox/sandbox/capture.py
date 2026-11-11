"""Network capture over a raw CDP session.

Data-parity note: Selenium v2 obtained network data by parsing Chrome's
"performance log", which is nothing more than serialized CDP ``Network.*``
events. Playwright exposes the same CDP session directly
(``context.new_cdp_session(page)``), so the event payloads consumed here —
``Network.requestWillBeSent`` / ``Network.responseReceived`` including
``securityDetails``, ``remoteIPAddress``, ``encodedDataLength`` — are
byte-identical to what v2 parsed. Report output is therefore the same schema.

Additive over v2: redirect chains and response bodies fetched concurrently.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Any

from .transforms import format_utc_datetime
import datetime
from datetime import timezone

logger = logging.getLogger(__name__)

_BAD_URL_PREFIXES = ("blob", "data")


class NetworkCapture:
    """Accumulates CDP Network events for one page load (v2 Enrichment.response_data)."""

    def __init__(self) -> None:
        self.requests: dict[str, dict[str, Any]] = {}
        self.redirect_chain: list[dict[str, Any]] = []

    def attach(self, cdp_session) -> None:
        cdp_session.on("Network.requestWillBeSent", self._on_request)
        cdp_session.on("Network.responseReceived", self._on_response)

    def _on_request(self, params: dict) -> None:
        request_id = params.get("requestId")
        if not request_id:
            return
        # A redirectResponse means the previous request for this id was redirected.
        redirect = params.get("redirectResponse")
        if redirect:
            self.redirect_chain.append({
                "url": redirect.get("url"),
                "status": redirect.get("status"),
                "ip": redirect.get("remoteIPAddress", ""),
                "location": params.get("request", {}).get("url"),
            })
        self.requests[request_id] = {"request": params.get("request", {})}

    def _on_response(self, params: dict) -> None:
        request_id = params.get("requestId")
        if request_id in self.requests:
            self.requests[request_id]["response"] = params.get("response", {})


async def fetch_response_bodies(cdp_session, request_ids: list[str], concurrency: int = 8) -> dict[str, dict]:
    """Fetch response bodies via CDP concurrently (v2 fetched serially via chromedriver)."""
    semaphore = asyncio.Semaphore(max(1, concurrency))
    bodies: dict[str, dict] = {}

    async def one(request_id: str) -> None:
        async with semaphore:
            try:
                bodies[request_id] = await cdp_session.send(
                    "Network.getResponseBody", {"requestId": request_id}
                )
            except Exception:
                # Body evicted / no body for this request — same silent-skip semantics as v2.
                pass

    await asyncio.gather(*(one(rid) for rid in request_ids))
    return bodies


# Streaming video is never kept as evidence: it was ~19% of resource bytes (MP4,
# MPEG-TS segments, HLS/DASH playlists), does not compress, and repeats per scan.
VIDEO_PLAYLIST_MIMES = {"application/vnd.apple.mpegurl", "application/x-mpegurl", "application/dash+xml"}


def is_video_mime(mime: str | None) -> bool:
    m = (mime or "").split(";")[0].strip().lower()
    return m.startswith("video/") or m in VIDEO_PLAYLIST_MIMES


async def capture_bodies(cdp_session, net: "NetworkCapture", concurrency: int = 8,
                         max_passes: int = 3, skip_video: bool = False) -> tuple[dict, dict]:
    """Freeze the request map and fetch every body, including late arrivals.

    Requests keep streaming in while bodies are being fetched. Fetching once
    against a single snapshot therefore leaves the newest requests body-less,
    which shows up as ``resource`` counts lower than ``request`` counts.

    Here we fetch, then re-check for requests that appeared *during* the fetch
    and top those up, repeating until nothing new arrives (bounded by
    ``max_passes`` so a page streaming requests forever cannot hang the scan).

    ``skip_video`` leaves video bodies unfetched (the request itself is still
    recorded in the network log), so they are never transferred over CDP or held
    in memory, and never reach the resources index.

    Returns ``(frozen_requests, bodies)`` - both consistent with each other.
    """
    snapshot: dict = dict(net.requests)
    bodies: dict = {}

    for _ in range(max(1, max_passes)):
        pending = [rid for rid, entry in snapshot.items()
                   if "response" in entry and rid not in bodies
                   and not (skip_video and is_video_mime(entry["response"].get("mimeType")))]
        if not pending:
            break
        bodies.update(await fetch_response_bodies(cdp_session, pending, concurrency))
        # Absorb anything that arrived while we were fetching.
        fresh = {rid: entry for rid, entry in net.requests.items() if rid not in snapshot}
        if not fresh:
            break
        snapshot.update(fresh)

    return snapshot, bodies


def build_resources(
    requests: dict[str, dict], bodies: dict[str, dict], report_id: str, scan_url: str, first_seen: str
) -> tuple[list[dict], dict[str, dict]]:
    """Port of v2 Resources.getResources.

    Hash-compat note: sha256 is computed over the body string exactly as CDP
    returns it (base64 text for binary bodies) to stay dedupe-compatible with
    the sha256 values already stored in the resources indices by v2.
    """
    mapping: list[dict] = []
    resource_master: dict[str, dict] = {}
    for request_id, entry in requests.items():
        if "response" not in entry:
            continue
        body = bodies.get(request_id)
        if not body or "body" not in body:
            continue
        sha256 = hashlib.sha256(body["body"].encode("utf-8")).hexdigest()
        mapping.append({
            "sha256": sha256,
            "url": entry["request"].get("url"),
            "mime_type": entry["response"].get("mimeType"),
        })
        resource_master[sha256] = {
            "report_id": report_id,
            "resource": body["body"],
            "sha256": sha256,
            "mime_type": entry["response"].get("mimeType"),
            "request_id": request_id,
            "submission_url": scan_url,
            "resource_url": entry["response"].get("url"),
            "first_seen_utc": first_seen,
            "last_seen_utc": first_seen,
        }
    return mapping, resource_master


def finalize_network(network_data: dict, domain_extract) -> dict:
    """Filter blob:/data: requests, extract unique certificates, convert the
    request map to a list, and stamp certificate UTC fields.

    DIVERGENCE FROM v2 (deliberate): v2 only kept requests that carried TLS
    ``securityDetails``, so every plain-HTTP request was silently discarded and
    never reached ``request[]``, ``domain[]`` or the risk score. v3 keeps ALL
    completed requests regardless of scheme; certificates are still harvested
    only from those that actually have ``securityDetails``.

    Requests with no response at all are still skipped - they have no URL to
    attribute, and including them produces empty-string domain buckets.

    ``domain_extract`` is a callable url -> (domain, sub, tld).
    """
    seen_subjects: list[str] = []
    certificates: list[dict] = []
    request_list: list[dict] = []

    for request_id, entry in list(network_data["request"].items()):
        if "response" not in entry:
            continue
        request_url = entry["request"].get("url", "")
        response_url = entry["response"].get("url", "")
        if request_url[:4] in _BAD_URL_PREFIXES or response_url[:4] in _BAD_URL_PREFIXES:
            del network_data["request"][request_id]
            continue
        security = entry["response"].get("securityDetails")
        if security:
            security["domain_name"], security["sub_domain"], security["tld"] = domain_extract(request_url)
            subject = security.get("subjectName")
            if subject not in seen_subjects:
                certificates.append(security)
                seen_subjects.append(subject)
        # Keep every completed request, TLS or not.
        request_list.append(entry)

    network_data["certificate"] = certificates
    network_data["request"] = request_list

    for certificate in network_data["certificate"]:
        if "validFrom" in certificate:
            certificate["valid_from_utc"] = format_utc_datetime(
                datetime.datetime.fromtimestamp(certificate["validFrom"], tz=timezone.utc)
            )
        if "validTo" in certificate:
            certificate["valid_to_utc"] = format_utc_datetime(
                datetime.datetime.fromtimestamp(certificate["validTo"], tz=timezone.utc)
            )
    return network_data
