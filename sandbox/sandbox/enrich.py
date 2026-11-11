"""Enrichment: GeoIP, DNS, third-party domain analysis, server aggregation, tech.

Port of v2 report.py Enrichment + Technology. Import-safe: GeoIP databases are
opened lazily on first use (not at import) so the module can be imported by the
test runner on any machine.
"""
from __future__ import annotations

import asyncio
import functools
import logging
import re
from urllib.parse import urlparse

import tldextract

logger = logging.getLogger(__name__)


class Technology:
    """URL-pattern based technology detection (v2 Technology). Patterns compiled once."""

    def __init__(self, patterns_path: str) -> None:
        self.patterns: list[tuple[re.Pattern, str]] = []
        try:
            with open(patterns_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        pattern, technology = line.split(",", 1)
                        self.patterns.append((re.compile(pattern, re.IGNORECASE), technology))
        except FileNotFoundError:
            logger.warning("technology patterns file not found: %s", patterns_path)

    def from_url(self, url: str) -> str | bool:
        for compiled, technology in self.patterns:
            if compiled.search(url):
                return technology
        return False

    def detect(self, script_srcs: list[str], link_hrefs: list[str], requests_in: list[dict]) -> list[dict]:
        found: list[dict] = []
        for url in script_srcs:
            name = self.from_url(url)
            if name:
                found.append({"url": url, "name": name})
        for url in link_hrefs:
            name = self.from_url(url)
            if name:
                found.append({"url": url, "name": name})
        for entry in requests_in:
            url = entry.get("request", {}).get("url", "")
            name = self.from_url(url)
            if name:
                found.append({"url": url, "name": name})
        unique = {c["name"]: c for c in found}
        return list(unique.values())


class Enrichment:
    """GeoIP / DNS / domain / server enrichment (v2 Enrichment)."""

    def __init__(self, settings) -> None:
        self.settings = settings
        self._ip_asn = None
        self._ip_country = None
        self._dns_resolver = None
        self._dns_cache: dict[str, dict] = {}
        self._dns_inflight: dict = {}
        self.extractor = tldextract.TLDExtract(cache_dir=False)

    # --- lazy GeoIP readers --------------------------------------------
    @property
    def ip_asn(self):
        if self._ip_asn is None:
            import geoip2.database
            self._ip_asn = geoip2.database.Reader(self.settings.geoip_asn_path)
        return self._ip_asn

    @property
    def ip_country(self):
        if self._ip_country is None:
            import geoip2.database
            self._ip_country = geoip2.database.Reader(self.settings.geoip_country_path)
        return self._ip_country

    def domain_extract(self, url: str) -> tuple[str, str, str]:
        clean = self.extractor(urlparse(url).netloc)
        return clean.registered_domain, clean.subdomain, clean.suffix

    @functools.lru_cache(maxsize=4096)
    def ip2country(self, ip: str) -> dict:
        result = self.ip_country.country(ip)
        return {"name": result.country.name, "iso": result.country.iso_code}

    @functools.lru_cache(maxsize=4096)
    def ip2asn(self, ip: str) -> dict:
        result = self.ip_asn.asn(ip)
        return {
            "number": result.autonomous_system_number,
            "name": result.autonomous_system_organization,
            "network": str(result.network),
        }

    # The v2 record set, kept as the fallback only. The ACTIVE list comes from
    # settings.dns_record_types so resolver load can be tuned without a rebuild.
    DNS_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR")

    @property
    def dns_record_types(self) -> tuple[str, ...]:
        raw = getattr(self.settings, "dns_record_types", "") or ""
        types = tuple(t.strip().upper() for t in raw.split(",") if t.strip())
        return types or self.DNS_RECORD_TYPES

    def _resolver(self):
        """Async resolver with EXPLICIT timeouts.

        dnspython defaults to 2s per attempt / 5s lifetime. With 8 record types
        that is a 40s worst case for one domain, on top of the scan - and
        `scan_timeout` does not cover enrichment. A dead authoritative server
        would stall the whole pipeline, so both are pinned.
        """
        if self._dns_resolver is None:
            import dns.asyncresolver
            r = dns.asyncresolver.Resolver()
            r.timeout = self.settings.dns_timeout
            r.lifetime = self.settings.dns_lifetime
            self._dns_resolver = r
        return self._dns_resolver

    async def _resolve_one(self, domain: str, record_type: str, sem) -> tuple:
        import dns.resolver as _r
        async with sem:
            try:
                answers = await self._resolver().resolve(domain, record_type)
                return record_type.lower(), [str(a) for a in answers]
            except _r.NXDOMAIN:
                return "__nxdomain__", []
            except Exception:
                # NoAnswer, timeout, SERVFAIL: the record legitimately has no
                # value. Keep the key with an empty list so the field shape
                # stays stable for strict OpenSearch mappings.
                return record_type.lower(), []

    async def get_dns_info(self, domain: str, is_root: bool = True) -> dict:
        """Resolve the v2 record set for one domain.

        Two changes from v2, both required to run this in production:
          * record types resolve CONCURRENTLY, not one after another;
          * `MAIN` resolves only the page's own domain, not all third parties.
            v2 accepted MAIN as a value but always behaved as ALL, so a page
            with 25 domains issued 200 lookups to describe 1 domain of interest.
        """
        if not self.settings.dns_enabled():
            return {}
        if self.settings.dns.upper() == "MAIN" and not is_root:
            return {}

        cached = self._dns_cache.get(domain)
        if cached is not None:
            return dict(cached)

        # Collapse duplicate in-flight lookups for the same domain.
        inflight = self._dns_inflight.get(domain)
        if inflight is None:
            inflight = asyncio.get_running_loop().create_future()
            self._dns_inflight[domain] = inflight
        else:
            return dict(await inflight)

        try:
            sem = asyncio.Semaphore(self.settings.dns_concurrency)
            pairs = await asyncio.gather(
                *(self._resolve_one(domain, rt, sem) for rt in self.dns_record_types))
            if any(k == "__nxdomain__" for k, _ in pairs):
                out = {"error": "Domain does not exist"}
            else:
                out = {k: v for k, v in pairs if k != "__nxdomain__"}
            if len(self._dns_cache) < self.settings.dns_cache_size:
                self._dns_cache[domain] = out
            inflight.set_result(out)
            return dict(out)
        except Exception as e:                       # never fail a scan on DNS
            out = {"error": f"Error retrieving DNS info: {e}"}
            inflight.set_result(out)
            return out
        finally:
            self._dns_inflight.pop(domain, None)

    # --- domain analysis (v2 domain_info) ------------------------------
    def domain_info(self, domain: str, raw: dict) -> dict:
        master = {
            "hosting_scripts": False, "mime_type": [], "whois": {}, "resource": [],
            "ip": "", "ips": [], "response_code": [], "request": [], "sub_domain": [],
            "total_response_size": 0.0, "server": "", "root": False,
            "hostname": [],
        }
        for request in raw["request"]:
            response = request.get("response", {})
            _domain, sub, tld = self.domain_extract(response.get("url", ""))
            if _domain != domain:
                continue
            master["request"].append({
                "url": response.get("url", ""),
                "mime_type": response.get("mime_type", response.get("mimeType", "")),
                "ip": response.get("ip", response.get("remoteIPAddress", "")),
                "response_code": response.get("status", ""),
                "encoded_data_length": response.get("encoded_data_length", response.get("encodedDataLength", "")),
            })
            ip = response.get("ip", response.get("remoteIPAddress", ""))
            if ip:
                # `ip` keeps the FIRST address (v2 schema parity: it is a
                # string). `ips` is additive and records every address this
                # domain actually served from - CDNs and load-balanced hosts
                # routinely use several, and keeping only the first was
                # discarding ~21% of observed addresses on a typical page.
                if not master["ip"]:
                    master["ip"] = ip
                if ip not in master["ips"]:
                    master["ips"].append(ip)
            master["total_response_size"] += float(
                response.get("encoded_data_length", response.get("encodedDataLength", 0)) or 0
            )
            master["name"] = _domain
            master["sub_domain"].append(sub)
            master["tld"] = tld
            # Fully-qualified host actually contacted. Registered-domain
            # rollup hides subdomain infrastructure (and is why our domain
            # counts read lower than scanners that count hostnames).
            fqdn = f"{sub}.{_domain}" if sub else _domain
            if fqdn not in master["hostname"]:
                master["hostname"].append(fqdn)
            master["response_code"].append(response.get("status", ""))
            master["mime_type"].append(response.get("mime_type", response.get("mimeType", "")))
            for header in response.get("headers", []):
                name = header["name"] if isinstance(header, dict) else header
                value = header["value"] if isinstance(header, dict) else response["headers"][header]
                if str(name).lower() == "server":
                    master["server"] = value
            for resource in raw.get("resource", []):
                rd, _, _ = self.domain_extract(resource["url"])
                if rd == _domain:
                    master["resource"].append(resource)
            for certificate in raw.get("certificate", []):
                if certificate.get("domain_name") == master.get("name"):
                    master["certificate"] = certificate

        master["response_code"] = list(set(master["response_code"]))
        master["mime_type"] = list(set(master["mime_type"]))
        master["sub_domain"] = list(set(master["sub_domain"]))
        master["request_count"] = len(master["request"])
        if master["ip"]:
            try:
                master["country"] = self.ip2country(master["ip"])
                master["asn"] = self.ip2asn(master["ip"])
            except Exception:
                pass
        for mime in master["mime_type"]:
            if "script" in mime:
                master["hosting_scripts"] = True
                break
        dedup = {r["sha256"]: r for r in master["resource"]}
        master["resource"] = list(dedup.values())
        return master

    async def third_parties(self, raw: dict, resolved_url: str) -> list[dict]:
        root_domain = tldextract.extract(resolved_url).registered_domain
        domains = list({self.domain_extract(r["request"]["url"])[0] for r in raw["request"]})
        result = []
        for domain in domains:
            analysis = self.domain_info(domain, raw)
            analysis["root"] = (domain == root_domain)
            result.append(analysis)

        # DNS for every domain at once. Serial resolution was the single
        # biggest enrichment cost in v2; concurrency plus the MAIN filter is
        # what makes leaving this enabled affordable.
        dns_results = await asyncio.gather(
            *(self.get_dns_info(a["name"], is_root=a["root"])
              for a in result if a.get("name")))
        for analysis, dns in zip([a for a in result if a.get("name")], dns_results):
            analysis["dns"] = dns
        for analysis in result:
            analysis.setdefault("dns", {})
        return result

    @staticmethod
    def server_data(report: dict) -> list[dict]:
        """Aggregate domains by server IP (v2 server_data)."""
        results: dict[str, dict] = {}
        # Emit a server entry for EVERY address a domain served from, not just
        # the first. A CDN answering from three IPs is three pieces of
        # infrastructure worth pivoting on.
        pairs = []
        for domain in report["domain"]:
            for ip in (domain.get("ips") or ([domain["ip"]] if domain.get("ip") else [])):
                pairs.append((ip, domain))
        for ip, domain in pairs:
            if ip not in results:
                results[ip] = {
                    "hosting_scripts": domain["hosting_scripts"], "mime_type": list(domain["mime_type"]),
                    "ip": ip, "country": domain.get("country"), "asn": domain.get("asn"),
                    "resource": list(domain["resource"]), "response_code": list(domain["response_code"]),
                    "domain": [domain["name"]], "total_response_size": domain["total_response_size"],
                    "server": [domain["server"]] if domain["server"] else [],
                }
            else:
                cur = results[ip]
                if domain["name"] not in cur["domain"]:
                    cur["domain"].append(domain["name"])
                if domain["hosting_scripts"]:
                    cur["hosting_scripts"] = True
                if domain["server"] and domain["server"] not in cur["server"]:
                    cur["server"].append(domain["server"])
                for mime in domain["mime_type"]:
                    if mime not in cur["mime_type"]:
                        cur["mime_type"].append(mime)
                for resource in domain["resource"]:
                    if resource not in cur["resource"]:
                        cur["resource"].append(resource)
                for code in domain["response_code"]:
                    if code not in cur["response_code"]:
                        cur["response_code"].append(code)
                cur["total_response_size"] += float(domain["total_response_size"])

        for server in results.values():
            dedup = {r["sha256"]: r for r in server["resource"]}
            server["resource"] = list(dedup.values())
            server["response_code"] = list(set(server["response_code"]))
            server["server"] = list(set(server["server"]))
            server["mime_type"] = list(set(server["mime_type"]))
            server["domain"] = list(set(server["domain"]))
        return list(results.values())

    @staticmethod
    def scan_meta(report: dict, risk_score_fn) -> dict:
        meta = {
            "request_count": len(report.get("request", [])),
            "script_count": len(report.get("page_scripts", [])),
            "domain_count": len(report.get("domain", [])),
            "submission_url": report["submission_url"],
            "submission": report["submission_url"],
            "submission_utc": report["submission_utc"],
            "report_id": report["report_id"],
            "risk_score": 0,
        }
        report["meta"] = meta
        meta["risk_score"] = risk_score_fn(report)
        return report
