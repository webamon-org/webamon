import hashlib
import json
import requests
from requests.auth import HTTPBasicAuth


opensearch_host = 'https://localhost:9200'


def deep_sort(obj):
    if isinstance(obj, dict):
        return {k: deep_sort(v) for k, v in sorted(obj.items())}
    elif isinstance(obj, list):
        return sorted([deep_sort(v) for v in obj], key=lambda x: json.dumps(x, sort_keys=True))
    else:
        return obj


def normalize_for_hashing(data):
    """
    Recursively sorts dicts and lists, then returns normalized JSON string.
    """
    normalized = deep_sort(data)
    return json.dumps(normalized, sort_keys=True, separators=(',', ':'))


def hash_data(data):
    normalized = normalize_for_hashing(data)
    return hashlib.sha256(normalized.encode()).hexdigest()


def generate_fingerprints(scan):
    return {
        "ssl": hash_data(scan.get("certificate", [])),
        "tech": hash_data(scan.get("technology", [])),
        "cookies": hash_data(scan.get("cookie", [])),
        "asn": hash_data([
            d["asn"]["number"] for d in scan.get("server", [])
            if isinstance(d.get("asn"), dict) and "number" in d["asn"]
        ]),
        "scan_fingerprint": hash_data(scan),
        "scripts": hash_data(scan['page_scripts']),
        "links": hash_data(scan['page_links']),
        "domains": hash_data([d['name'] for d in scan.get("domain", [])]),
        "dom": hash_data(scan['dom'])

    }


def fetch_previous(url):
    query = {
        "size": 1,
        "query": {
            "term": {
                "submission_url": url
            }
        },
        "sort": [
            {"submission_utc": "desc"}
        ]
    }

    response = requests.post(
        f"{opensearch_host}/scans/_search",
        json=query,
        auth=HTTPBasicAuth("admin", "admin"),
        headers={"Content-Type": "application/json"}, verify=False
    )

    if response.status_code == 200:
        hits = response.json().get("hits", {}).get("hits", [])
        return hits[0]["_source"] if hits else None
    else:
        print("Error:", response.status_code, response.text)
        return None


def compare_fingerprints(old, new):
    changed = []
    if old['asn'] != new['asn']:
        changed.append('asn')
    if old['cookies'] != new['cookies']:
        changed.append('cookies')
    if old['domains'] != new['domains']:
        changed.append('domains')
    if old['links'] != new['links']:
        changed.append('links')
    if old['scripts'] != new['scripts']:
        changed.append('scripts')
    if old['ssl'] != new['ssl']:
        changed.append('ssl')
    if old['tech'] != new['tech']:
        changed.append('tech')
    if old['dom'] != new['dom']:
        changed.append('dom')
    return changed


def monitor(scan):
    changes = set()
    previous = fetch_previous(scan['submission_url'])
    if previous:
        changes.update(compare_fingerprints(previous['fingerprint'], scan['fingerprint']))
        if scan['page_title'] != previous['page_title']:
            changes.update('page_title')
        if scan['resolved_url'] != previous['resolved_url']:
            changes.update('resolved_url')
        return list(changes)
    return []


