"""Report-shaping transforms ported from v2 (report.py Formatting + main._normalize_private_tags).

These preserve the exact output key names of the v2 report schema so existing
OpenSearch consumers keep working. Pure functions — fully unit-testable.
"""
from __future__ import annotations

import ast
import datetime
import json
from datetime import timezone


def format_utc_datetime(dt: datetime.datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_now_str() -> str:
    return format_utc_datetime(datetime.datetime.now(timezone.utc))


def utc_today_str() -> str:
    return datetime.datetime.now(timezone.utc).strftime("%Y-%m-%d")


def normalize_private_tags(value) -> list[str]:
    """Normalize private tag inputs to a list of strings.

    Accepts ["a","b"], "a,b", "['a','b']", '["a","b"]'.
    """
    if value is None:
        return []

    if isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        s = str(value).strip()
        if not s:
            return []
        if (s.startswith("[") and s.endswith("]")) or (s.startswith("(") and s.endswith(")")):
            parsed = None
            try:
                parsed = ast.literal_eval(s)
            except (ValueError, SyntaxError):
                try:
                    parsed = json.loads(s)
                except json.JSONDecodeError:
                    parsed = None
            items = list(parsed) if isinstance(parsed, (list, tuple, set)) else [s]
        else:
            items = s.split(",")

    out: list[str] = []
    for item in items:
        t = str(item).strip()
        if not t:
            continue
        if (t.startswith("[") and t.endswith("]")) or (t.startswith("(") and t.endswith(")")):
            try:
                parsed = ast.literal_eval(t)
                if isinstance(parsed, (list, tuple, set)):
                    for p in parsed:
                        pt = str(p).strip().strip('"').strip("'").strip()
                        if pt:
                            out.append(pt)
                    continue
            except (ValueError, SyntaxError):
                pass
        t = t.strip('"').strip("'").strip()
        if t:
            out.append(t)
    return out


_REQUEST_DROP = ("initialPriority", "isLinkPreload", "isSameSite", "mixedContentType")
_REQUEST_RENAME = {
    "hasPostData": "has_post_data",
    "postData": "post_data",
    "postDataEntries": "post_data_entry",
    "referrerPolicy": "referrer_policy",
}
_RESPONSE_DROP = (
    "timing", "alternateProtocolUsage", "charset", "connectionId", "connectionReused",
    "fromDiskCache", "fromPrefetchCache", "fromServiceWorker",
)
_RESPONSE_RENAME = {
    "encodedDataLength": "encoded_data_length",
    "mimeType": "mime_type",
    "remoteIPAddress": "ip",
    "remotePort": "port",
    "responseTime": "response_time",
    "securityDetails": "security_details",
    "securityState": "security_state",
    "statusText": "status_text",
}
_CERT_DROP = ("certificateId", "certificateTransparencyCompliance", "encryptedClientHello")
_CERT_RENAME = {
    "keyExchange": "key_exchange",
    "keyExchangeGroup": "key_exchange_group",
    "sanList": "san_list",
    "serverSignatureAlgorithm": "signature_algorithm",
    "subjectName": "subject_name",
    "validFrom": "valid_from",
    "validTo": "valid_to",
}
_COOKIE_RENAME = {"httpOnly": "http_only", "sameSite": "same_site"}


def _rename_keys(d: dict, mapping: dict[str, str]) -> None:
    for old, new in mapping.items():
        if old in d:
            d[new] = d.pop(old)


def clean_data(report: dict) -> dict:
    """Snake-case CDP camelCase keys and drop noise fields (v2 Formatting.clean_data)."""
    for _request in report.get("request", []):
        if "request" in _request:
            for key in _REQUEST_DROP:
                _request["request"].pop(key, None)
            _rename_keys(_request["request"], _REQUEST_RENAME)
        if "response" in _request:
            for key in _RESPONSE_DROP:
                _request["response"].pop(key, None)
            _rename_keys(_request["response"], _RESPONSE_RENAME)

    for certificate in report.get("certificate", []):
        for key in _CERT_DROP:
            certificate.pop(key, None)
        _rename_keys(certificate, _CERT_RENAME)

    for cookie in report.get("cookie", []):
        _rename_keys(cookie, _COOKIE_RENAME)

    return report


def transform_headers(report: dict) -> dict:
    """Convert header dicts to [{name, value}] lists (v2 Formatting.transform_headers)."""
    for request in report.get("request", []):
        if "request" in request and isinstance(request["request"].get("headers"), dict):
            request["request"]["headers"] = [
                {"name": str(k), "value": str(v)} for k, v in request["request"]["headers"].items()
            ]
        if "response" in request:
            if isinstance(request["response"].get("headers"), dict):
                request["response"]["headers"] = [
                    {"name": str(k), "value": str(v)} for k, v in request["response"]["headers"].items()
                ]
            if isinstance(request["response"].get("securityDetails"), dict):
                request["response"]["securityDetails"] = [
                    {"name": str(k), "value": str(v)}
                    for k, v in request["response"]["securityDetails"].items()
                ]
    return report


def normalize_cookies(cookies: list[dict]) -> list[dict]:
    """Map Playwright cookie fields onto the v2/Selenium shape.

    Selenium's ``get_cookies()`` emits ``expiry`` as an int and OMITS it for
    session cookies. Playwright emits ``expires`` as a float, using -1 for
    session cookies. Production v2 documents contain ``expiry``, so without
    this mapping every stored cookie would change shape.
    """
    out: list[dict] = []
    for cookie in cookies:
        c = dict(cookie)
        if "expires" in c:
            expires = c.pop("expires")
            try:
                expires = float(expires)
            except (TypeError, ValueError):
                expires = -1
            # -1 (and any non-positive) marks a session cookie -> no expiry key.
            if expires > 0:
                c["expiry"] = int(expires)
        out.append(c)
    return out


def format_errors(error_log: list[dict]) -> dict:
    results: dict[str, list] = {}
    for error in error_log:
        results.setdefault(error["error"], []).append(error["url"])
    return results
