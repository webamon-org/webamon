#!/usr/bin/env python3

import argparse
import requests
import sys


def submit_scan(url):
    endpoint = "http://localhost:5000/scan"
    payload = {"submission_url": url.strip()}

    try:
        response = requests.post(endpoint, json=payload)
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

    args = parser.parse_args()

    if args.url:
        submit_scan(args.url)
    elif args.file:
        try:
            with open(args.file, "r") as file:
                for line in file:
                    line = line.strip()
                    if line:
                        submit_scan(line)
        except FileNotFoundError:
            print(f"❌ File not found: {args.file}")
            sys.exit(1)


if __name__ == "__main__":
    main()
