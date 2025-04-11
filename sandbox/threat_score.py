import json
import time
import requests
from requests.auth import HTTPBasicAuth


def get_document_by_id(document_id, host="https://webamon-node1:9200", index="scans", username="admin", password="admin"):
    url = f"{host}/{index}/_doc/{document_id}"
    try:
        response = requests.get(url, auth=HTTPBasicAuth(username, password), verify=False)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print("Error:", e)
        return None


def ssl_checks(certificates):
    score = 0
    max_score = 10
    now = int(time.time())

    weak_protocols = {"TLS 1.0", "TLS 1.1", "TLS 1.2"}
    weak_ciphers = {"AES_128_GCM", "AES_128_CBC", "3DES", "RC4", "NULL", "DES"}
    generic_issuers = {"R10", "R11", "WE1"}

    for cert in certificates:
        valid_to = cert.get("valid_to")
        valid_from = cert.get("valid_from")

        # 1. Expired
        if valid_to and valid_to < now:
            score += 5

        # 2. Weak protocol
        protocol = cert.get("protocol", "")
        if protocol in weak_protocols:
            score += 3

        # 3. Weak cipher
        cipher = cert.get("cipher", "")
        if cipher in weak_ciphers:
            score += 2

        # 4. Short validity period
        if valid_from and valid_to:
            lifetime = valid_to - valid_from
            if lifetime < 60 * 60 * 24 * 90:  # < 90 days
                score += 2

        # 5. Wildcard cert
        subject = cert.get("subject_name", "")
        san_list = cert.get("san_list", [])
        flat_san_list = []
        for item in san_list:
            if isinstance(item, list):
                flat_san_list.extend(item)
            else:
                flat_san_list.append(item)

        if "*" in subject or any("*" in entry for entry in flat_san_list):
            score += 2

        # 6. Suspicious issuer
        issuer = cert.get("issuer", "")
        if issuer in generic_issuers or issuer.startswith("R"):
            score += 1

    return min(score, max_score)


def request_check(requests):
    score = 0
    max_score = 10
    for wrapper in requests:
        req = wrapper.get("request", {})

        method = req.get("method", "").upper()
        url = req.get("url", "")

        if method == "POST":
            score += 3

        if url.startswith("http://"):
            score += 7

    return min(score, max_score)



def meta_check(meta):
    score = 0
    max_score = 10
    script_count = meta.get("script_count", 0)
    if script_count > 20:
        score += 4
    if script_count > 40:
        score += 6
    return min(score, max_score)


def domain_check(domains):
    score = 0
    max_score = 20

    risky_tlds = {"xyz", "top", "club", "tk"}
    risky_countries = {"RU", "CN", "KP", "IR"}
    risky_asns = {12389, 4134, 24940}

    for d in domains:
        # TLD check
        tld = d.get("tld", "").lower().strip(".")
        if tld in risky_tlds:
            score += 5

        # Country check
        country = d.get("country") or {}
        country_code = (country.get("iso") or "").upper()
        if country_code in risky_countries:
            score += 5

        # ASN check
        asn = d.get("asn") or {}
        asn_number = asn.get("number")
        if asn_number in risky_asns:
            score += 5

        # Optional tag check
        if "tracking" in d.get("tags", []):
            score += 5

    return min(score, max_score)


def resource_check(resources):
    score = 0
    max_score = 10
    nsfw_keywords = ["porn", "gambling", "casino", "xxx"]
    for res in resources:
        if any(k in res.lower() for k in nsfw_keywords):
            score += 5
        if "base64," in res:
            score += 3
    return min(score, max_score)


def cookie_check(cookies):
    score = 0
    max_score = 10
    for cookie in cookies:
        if not cookie.get("secure", False):
            score += 3
        if not cookie.get("httpOnly", False):
            score += 3
        if cookie.get("domain", "").startswith("thirdparty."):
            score += 4
    return min(score, max_score)


def technology_check(technologies):
    # Example: list of tech dicts, with name and version
    score = 0
    max_score = 10
    risky_techs = ["jquery 1.", "angularjs", "php 5", "wordpress 4", "drupal 7", "bootstrap 3"]

    for tech in technologies:
        name = tech.get("name", "").lower()
        version = tech.get("version", "").lower()
        full = f"{name} {version}"
        for risk in risky_techs:
            if risk in full:
                score += 5

    return min(score, max_score)


def generate(report):
    total_score = 0
    max_possible = 80  # Updated to include technology check

    ssl_score = ssl_checks(report.get('certificate', []))
    request_score = request_check(report.get('request', []))
    meta_score = meta_check(report.get('meta', {}))
    domain_score = domain_check(report.get('domain', []))
    # resource_score = resource_check(report.get('resource_master', []))
    cookie_score = cookie_check(report.get('cookie', []))
    technology_score = technology_check(report.get('technology', []))

    total_score = (
        ssl_score +
        request_score +
        meta_score +
        domain_score +
        # resource_score +
        cookie_score +
        technology_score
    )

    normalized_score = (total_score / max_possible) * 100
    return round(normalized_score)
