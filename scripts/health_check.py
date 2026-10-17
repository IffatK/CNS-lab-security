#!/usr/bin/env python3
"""GET /api/health from a running server. Exit 0 only if status == ok."""
import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request

parser = argparse.ArgumentParser(description="Check the CNS app's public health endpoint.")
parser.add_argument("base_url", nargs="?", default="http://127.0.0.1:5000")
parser.add_argument("--ca-cert", help="PEM certificate to trust for an HTTPS lab server")
args = parser.parse_args()
url = args.base_url.rstrip("/") + "/api/health"
context = ssl.create_default_context(cafile=args.ca_cert) if url.startswith("https://") and args.ca_cert else None
try:
    with urllib.request.urlopen(url, timeout=5, context=context) as r:
        data = json.load(r)
except urllib.error.HTTPError as e:
    data = json.load(e)
except Exception as e:
    print(f"UNREACHABLE {url}: {e}")
    sys.exit(2)
print(json.dumps(data, indent=2))
sys.exit(0 if data.get("status") == "ok" else 1)
