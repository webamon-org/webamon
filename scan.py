#!/usr/bin/env python3

import argparse
import requests


def submit_scan(url):
    endpoint = "http://localhost:5000/scan"
    payload = {"submission_url": url}

    try:
        response = requests.post(endpoint, json=payload)
        response.raise_for_status()
        print("✅ Scan submitted successfully.")
        print("📦 Response:", response.json())
    except requests.exceptions.RequestException as e:
        print("❌ Failed to submit scan:", e)


def main():
    parser = argparse.ArgumentParser(description="Submit a URL for scanning.")
    parser.add_argument("-u", "--url", required=True, help="The URL to scan")
    args = parser.parse_args()

    submit_scan(args.url)


if __name__ == "__main__":
    main()
