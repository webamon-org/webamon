"""Heuristic risk score (port of v2 threat_score.py).

Behaviour-preserving port so historical scores stay comparable. The known v2
quirks (TLS 1.2 counted weak; issuer.startswith('R') flags LE intermediates;
http:// saturates the request cap) are retained deliberately — retuning is a
separate, versioned change per the analysis report. ``RISK_SCORE_VERSION`` is
stamped so a future re-weighting is distinguishable in stored data.
"""
from __future__ import annotations

import time

# v2 = same algorithm as v1, but the INPUTS changed materially: from v3 the
# capture layer keeps plain-HTTP requests that v2 discarded, so
# request_check()'s "+7 for http://" now actually fires. Cleartext-HTTP sites
# will score higher than they did historically. Bumped so stored scores stay
# comparable only within a version.
RISK_SCORE_VERSION = 2

SSL_MAX = 10
REQUEST_MAX = 10
META_MAX = 10
DOMAIN_MAX = 20
COOKIE_MAX = 10
TECHNOLOGY_MAX = 10
MAX_POSSIBLE = SSL_MAX + REQUEST_MAX + META_MAX + DOMAIN_MAX + COOKIE_MAX + TECHNOLOGY_MAX

_WEAK_PROTOCOLS = {"TLS 1.0", "TLS 1.1", "TLS 1.2"}
_WEAK_CIPHERS = {"AES_128_GCM", "AES_128_CBC", "3DES", "RC4", "NULL", "DES"}
_GENERIC_ISSUERS = {"R10", "R11", "WE1"}
_RISKY_TLDS = {"xyz", "top", "club", "tk"}
_RISKY_COUNTRIES = {"RU", "CN", "KP", "IR"}
_RISKY_ASNS = {12389, 4134, 24940}
_RISKY_TECHS = ["jquery 1.", "angularjs", "php 5", "wordpress 4", "drupal 7", "bootstrap 3"]


def ssl_checks(certificates: list[dict]) -> int:
    score = 0
    now = int(time.time())
    for cert in certificates:
        valid_to = cert.get("valid_to")
        valid_from = cert.get("valid_from")
        if valid_to and valid_to < now:
            score += 5
        if cert.get("protocol", "") in _WEAK_PROTOCOLS:
            score += 3
        if cert.get("cipher", "") in _WEAK_CIPHERS:
            score += 2
        if valid_from and valid_to and (valid_to - valid_from) < 60 * 60 * 24 * 90:
            score += 2
        subject = cert.get("subject_name", "")
        san_list = cert.get("san_list", [])
        flat: list = []
        for item in san_list:
            flat.extend(item) if isinstance(item, list) else flat.append(item)
        if "*" in subject or any("*" in str(e) for e in flat):
            score += 2
        issuer = cert.get("issuer", "")
        if issuer in _GENERIC_ISSUERS or issuer.startswith("R"):
            score += 1
    return min(score, SSL_MAX)


def request_check(requests: list[dict]) -> int:
    score = 0
    for wrapper in requests:
        req = wrapper.get("request", {})
        if req.get("method", "").upper() == "POST":
            score += 3
        if req.get("url", "").startswith("http://"):
            score += 7
    return min(score, REQUEST_MAX)


def meta_check(meta: dict) -> int:
    score = 0
    script_count = meta.get("script_count", 0)
    if script_count > 20:
        score += 4
    if script_count > 40:
        score += 6
    return min(score, META_MAX)


def domain_check(domains: list[dict]) -> int:
    score = 0
    for d in domains:
        if d.get("tld", "").lower().strip(".") in _RISKY_TLDS:
            score += 5
        if ((d.get("country") or {}).get("iso") or "").upper() in _RISKY_COUNTRIES:
            score += 5
        if (d.get("asn") or {}).get("number") in _RISKY_ASNS:
            score += 5
        if "tracking" in d.get("tags", []):
            score += 5
    return min(score, DOMAIN_MAX)


def cookie_check(cookies: list[dict]) -> int:
    score = 0
    for cookie in cookies:
        if not cookie.get("secure", False):
            score += 3
        if not cookie.get("httpOnly", cookie.get("http_only", False)):
            score += 3
        if cookie.get("domain", "").startswith("thirdparty."):
            score += 4
    return min(score, COOKIE_MAX)


def technology_check(technologies: list[dict]) -> int:
    score = 0
    for tech in technologies:
        full = f"{tech.get('name', '').lower()} {tech.get('version', '').lower()}"
        for risk in _RISKY_TECHS:
            if risk in full:
                score += 5
    return min(score, TECHNOLOGY_MAX)


def generate(report: dict) -> int:
    total = (
        ssl_checks(report.get("certificate", []))
        + request_check(report.get("request", []))
        + meta_check(report.get("meta", {}))
        + domain_check(report.get("domain", []))
        + cookie_check(report.get("cookie", []))
        + technology_check(report.get("technology", []))
    )
    return round((total / MAX_POSSIBLE) * 100)
