"""Threat-intel fingerprint extensions.

Everything here is ADDITIVE - the nine existing ``fingerprint.*`` hashes keep
their exact values so dashboards and saved queries do not move.

The design constraint throughout is cost. The existing stage already spends
~134 ms on a 1.5 MB page hashing the whole report, so anything added here has
to be cheap enough not to matter next to that. Each function is written to make
one pass over its input and to bound the work it will do on a pathological page.

WHY MINHASH AND NOT SIMHASH for near-duplicate DOM search: a 64-bit SimHash
needs 64 add/subtract operations per shingle. On a page with ~30k unique
shingles that is ~2M Python-level operations - measured at over half a second,
which is far more than the entire rest of the scan pipeline. A bottom-k MinHash
sketch needs ONE hash per shingle plus a bounded heap, and supports the same
LSH-banded "find similar" query. Same capability, ~40x cheaper.
"""
from __future__ import annotations

import hashlib
import heapq
import math
import re
from collections import Counter

import mmh3

# Bound the work on a pathological page. 2 MB of markup is already far past the
# point where more input changes the fingerprint meaningfully.
MAX_DOM_CHARS = 2_000_000

SHINGLE_SIZE = 5      # tag n-gram width
SKETCH_K = 16         # bottom-k MinHash sketch size
BAND_COUNT = 4        # LSH bands => SKETCH_K / BAND_COUNT values per band

_TAG_RE = re.compile(r"<\s*(/?)\s*([a-zA-Z][a-zA-Z0-9]{0,19})")
_WS_RE = re.compile(r"\s+")

# Brands worth alerting on. Deliberately short - every entry costs an edit
# distance computation per scan, and a long tail of rare brands adds cost
# without adding detections.
DEFAULT_BRANDS = (
    "paypal", "microsoft", "apple", "amazon", "google", "facebook", "netflix",
    "instagram", "whatsapp", "linkedin", "dhl", "fedex", "ups", "hsbc",
    "barclays", "santander", "natwest", "lloyds", "revolut", "monzo",
    "coinbase", "binance", "metamask", "outlook", "office365", "docusign",
)


def _first(mapping: dict, *names):
    """First present key among aliases.

    Fingerprints are computed on the IN-FLIGHT report, where certificate fields
    still carry CDP camelCase (sanList, keyExchange). The snake_case spellings
    (san_list, key_exchange) only appear after the persistence transform. Code
    written against the stored schema therefore reads nothing at scan time -
    which silently produced an empty cert_san on every single page.
    """
    for name in names:
        if (value := mapping.get(name)) not in (None, ""):
            return value
    return None


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


# --- certificate ---------------------------------------------------------

def cert_fingerprints(certificates: list) -> dict:
    """Split the monolithic ``ssl`` hash into three independent pivots.

    ``ssl`` hashes the whole certificate array including validity dates and the
    SCT list, so it changes on every renewal and can only ever match the exact
    same certificate. These three each answer a question you actually ask:
    who issued it, what names it covers, and how the TLS endpoint is configured.
    """
    issuers, sans, configs = [], [], []
    for cert in certificates or []:
        if not isinstance(cert, dict):
            continue
        if issuer := (cert.get("issuer") or "").strip().lower():
            issuers.append(issuer)
        for san in _first(cert, "sanList", "san_list") or []:
            if isinstance(san, str) and san.strip():
                sans.append(san.strip().lower().rstrip("."))
        configs.append("|".join(str(_first(cert, *names) or "") for names in (
            ("protocol",), ("cipher",),
            ("keyExchange", "key_exchange"),
            ("keyExchangeGroup", "key_exchange_group"),
            ("serverSignatureAlgorithm", "signature_algorithm"))))
    return {
        "cert_issuer": _sha("\n".join(sorted(set(issuers)))) if issuers else "",
        "cert_san": _sha("\n".join(sorted(set(sans)))) if sans else "",
        "cert_config": _sha("\n".join(sorted(set(configs)))) if configs else "",
    }


# --- response shape ------------------------------------------------------

def header_order_fingerprint(requests: list, resolved_url: str) -> str:
    """Hash the ORDER and casing of the main document's response headers.

    Header order is a property of the server stack, not the content, so it
    survives the page changing completely - which is exactly what you want when
    tracking infrastructure rather than a landing page. Order matters, so this
    deliberately does not sort.
    """
    entry = _main_request(requests, resolved_url)
    if not entry:
        return ""
    headers = (entry.get("response") or {}).get("headers") or []
    names = [h.get("name", "") for h in headers if isinstance(h, dict)]
    if not names:
        # Some captures store headers as a plain mapping; dict order is
        # insertion order in the JSON, so it still carries the signal.
        raw = (entry.get("response") or {}).get("headers")
        if isinstance(raw, dict):
            names = list(raw.keys())
    return _sha("\n".join(names)) if names else ""


def _main_request(requests: list, resolved_url: str) -> dict | None:
    """The request for the page itself, not a subresource."""
    if not isinstance(requests, list):
        return None
    for entry in requests:
        if not isinstance(entry, dict):
            continue
        resp = entry.get("response") or {}
        if resp.get("url") == resolved_url:
            return entry
    return requests[0] if requests and isinstance(requests[0], dict) else None


def cookie_name_fingerprint(cookies: list) -> str:
    """Hash cookie NAMES only.

    The existing ``cookies`` hash includes values, which are per-session, so it
    almost never matches across two visits. Names are set by the framework or
    kit and are stable.
    """
    names = sorted({c.get("name", "") for c in cookies or []
                    if isinstance(c, dict) and c.get("name")})
    return _sha("\n".join(names)) if names else ""


# --- DOM -----------------------------------------------------------------

def dom_skeleton(dom: str) -> str:
    """The tag sequence with all text and attribute values removed.

    What survives a re-brand: a kit that swaps logos, colours and copy keeps
    its markup structure. What does not survive: any text change at all, which
    is why the existing ``dom`` hash sits at ~0.50 cardinality.
    """
    if not dom:
        return ""
    tags = _TAG_RE.findall(dom[:MAX_DOM_CHARS])
    return " ".join(f"{slash}{name.lower()}" for slash, name in tags)


def _shingle_hashes(skeleton: str) -> set[int]:
    """Hashes of overlapping tag n-grams. Deduped - repetition in a page (table
    rows, list items) should not dominate the sketch."""
    tokens = skeleton.split()
    if len(tokens) < SHINGLE_SIZE:
        return {mmh3.hash(skeleton, signed=False)} if skeleton else set()
    return {
        mmh3.hash(" ".join(tokens[i:i + SHINGLE_SIZE]), signed=False)
        for i in range(len(tokens) - SHINGLE_SIZE + 1)
    }


def dom_similarity(dom: str) -> dict:
    """Structural hash plus an LSH-banded near-duplicate key.

    ``dom_structure`` finds pages with byte-identical structure.
    ``dom_band``     finds pages with SIMILAR structure: index it as a keyword
                     array and a ``terms`` query on all four bands returns
                     anything sharing at least one, which is the candidate set
                     for near-duplicate clustering.
    """
    skeleton = dom_skeleton(dom)
    if not skeleton:
        return {"dom_structure": "", "dom_band": []}

    hashes = _shingle_hashes(skeleton)
    sketch = heapq.nsmallest(SKETCH_K, hashes)
    per_band = max(1, len(sketch) // BAND_COUNT)
    bands = []
    for i in range(BAND_COUNT):
        chunk = sketch[i * per_band:(i + 1) * per_band]
        if not chunk:
            break
        # The band index is part of the key: without it, a value appearing in
        # band 0 would spuriously match the same value in band 2.
        digest = hashlib.blake2b(
            ",".join(str(v) for v in chunk).encode(), digest_size=6
        ).hexdigest()
        bands.append(f"{i}:{digest}")
    return {"dom_structure": _sha(skeleton), "dom_band": bands}


# --- infrastructure ------------------------------------------------------

def _norm_host(value: str) -> str:
    return value.strip().lower().rstrip(".")


def dns_set_fingerprints(domains: list, resolved_domain: str) -> dict:
    """Hash the nameserver and MX host sets of the page's own domain.

    Clusters shared and bulletproof hosting: the landing page changes every
    campaign, the nameservers rarely do.
    """
    dns = {}
    for entry in domains or []:
        if isinstance(entry, dict) and entry.get("name") == resolved_domain:
            dns = entry.get("dns") or {}
            break
    else:
        for entry in domains or []:
            if isinstance(entry, dict) and entry.get("dns"):
                dns = entry["dns"]
                break

    # Normalise first, THEN drop empties: a null MX or root NS of "." (RFC 7505)
    # normalises to "" and would otherwise be hashed as a real value, giving
    # every such domain the identical sha256-of-empty-string fingerprint.
    ns = sorted({h for h in (_norm_host(v) for v in dns.get("ns") or []
                             if isinstance(v, str)) if h})
    # MX records arrive as "10 mx.example.com." - the priority is operational
    # noise that changes when a provider reweights, so strip it.
    mx = sorted({h for h in (_norm_host(v.split(None, 1)[-1]) for v in dns.get("mx") or []
                             if isinstance(v, str)) if h})
    return {
        "ns_set": _sha("\n".join(ns)) if ns else "",
        "mx_set": _sha("\n".join(mx)) if mx else "",
    }


# --- lexical -------------------------------------------------------------

def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 4)


def _edit_distance(a: str, b: str, cap: int = 4) -> int:
    """Levenshtein with early exit.

    Capped because only near misses matter: "paypa1" is interesting, a domain
    12 edits from "paypal" is not, and computing the exact distance for every
    brand on every scan is wasted work.
    """
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def lexical_features(domain: str, sub_domain: str = "", brands=DEFAULT_BRANDS) -> dict:
    """Cheap lexical signals about the domain itself.

    Makes "newly registered AND high entropy AND carries a brand token" a
    single query instead of an offline analysis job.
    """
    domain = (domain or "").strip().lower()
    if not domain:
        return {}
    full = f"{sub_domain}.{domain}" if sub_domain else domain
    labels = [x for x in full.split(".") if x]
    core = domain.split(".")[0]
    digits = sum(c.isdigit() for c in domain)
    tokens = [t for t in re.split(r"[-.]", full) if t]

    # A FIXED distance threshold is wrong for short names: "bbc" is 3 edits
    # from "hsbc" and "example" is 3 from "apple", both of which were reported
    # as brand impersonation on the first real run. Scale with brand length and
    # cap at 2 - typosquats are one or two characters off, not three.
    best_brand, best_distance = None, 99
    for brand in brands:
        if brand in full:
            best_brand, best_distance = brand, 0
            break
        allowed = min(2, max(1, len(brand) // 4))
        d = _edit_distance(core, brand, cap=allowed)
        if d <= allowed and d < best_distance:
            best_brand, best_distance = brand, d

    return {
        "length": len(full),
        "label_count": len(labels),
        "max_label_length": max((len(x) for x in labels), default=0),
        "entropy": _entropy(core),
        "digit_ratio": round(digits / len(domain), 4) if domain else 0.0,
        "hyphen_count": full.count("-"),
        "token_count": len(tokens),
        "has_punycode": "xn--" in full,
        "is_idn": any(ord(c) > 127 for c in full),
        # Only report a brand when it is close enough to be worth looking at.
        "brand_match": best_brand if best_distance <= 2 else None,
        "brand_distance": best_distance if best_distance <= 2 else None,
    }


# --- favicon -------------------------------------------------------------

def favicon_dhash(data: bytes) -> str | None:
    """64-bit difference hash of a favicon.

    The existing mmh3 hash is exact: one re-encoded pixel and it lands in a
    different bucket. dhash compares adjacent pixel brightness, so it survives
    recompression, palette changes and resizing - which is what actually
    happens when a kit is copied.
    """
    try:
        import io
        import warnings

        from PIL import Image
        with warnings.catch_warnings():
            # Palette-with-transparency favicons emit an advisory UserWarning.
            # Harmless, and at production scan volume it would flood the logs.
            warnings.simplefilter("ignore")
            im_ctx = Image.open(io.BytesIO(data))
        with im_ctx as im:
            im = im.convert("L").resize((9, 8), Image.Resampling.LANCZOS)
            px = list(im.getdata())
        bits = 0
        for row in range(8):
            base = row * 9
            for col in range(8):
                bits = (bits << 1) | int(px[base + col] > px[base + col + 1])
        return f"{bits:016x}"
    except Exception:
        # Favicons are frequently truncated, mislabelled or not images at all.
        return None
