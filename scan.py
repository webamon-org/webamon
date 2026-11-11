#!/usr/bin/env python3

import argparse
import os
import sys

import requests


def submit_scan(url, endpoint, api_key):
    payload = {"submission_url": url.strip()}
    headers = {"x-api-key": api_key} if api_key else {}

    try:
        response = requests.post(endpoint, json=payload, headers=headers, timeout=300)
        response.raise_for_status()
        print(f"✅ Scan submitted for {url}")
        print("📦 Response:", response.json())
    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to submit scan for {url}:", e)


def main():
    parser = argparse.ArgumentParser(description="Submit a URL or a file of URLs for scanning.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="The URL to scan")
    group.add_argument("-f", "--file", help="Path to a file containing URLs (one per line)")
    parser.add_argument("-e", "--endpoint", default=os.getenv("SANDBOX_URL", "http://localhost:5000/scan"),
                        help="Scanner endpoint (default: http://localhost:5000/scan)")
    parser.add_argument("-k", "--api-key", default=os.getenv("SANDBOX_API_KEY", ""),
                        help="API key, if SANDBOX_API_KEY is set on the scanner")

    args = parser.parse_args()

    if args.url:
        submit_scan(args.url, args.endpoint, args.api_key)
    elif args.file:
        try:
            with open(args.file, "r") as file:
                for line in file:
                    line = line.strip()
                    if line:
                        submit_scan(line, args.endpoint, args.api_key)
        except FileNotFoundError:
            print(f"❌ File not found: {args.file}")
            sys.exit(1)


if __name__ == "__main__":
    main()
