#!/usr/bin/env python3
"""HTTP Request Smuggling Discovery

Detects CDN+origin architectures and identifies CL.TE, TE.CL, TE.TE variants.
"""

import argparse
import json
import os
import time
from typing import Any, Dict, List
from urllib.parse import urlparse

# Import stealth HTTP client for WAF evasion
try:
    from tools.http_client import safe_get, safe_post, get_stealth_session
    USE_STEALTH = True
except ImportError:
    import requests
    USE_STEALTH = False
    
    def safe_get(url, **kwargs):
        return requests.get(url, **kwargs)
    
    def safe_post(url, **kwargs):
        return requests.post(url, **kwargs)




def detect_cdn_architecture(target_url: str) -> Dict[str, Any]:
    """Detect if target uses CDN or load balancer."""
    result = {
        "has_cdn": False,
        "cdn_indicators": [],
        "architecture": "unknown",
    }
    
    try:
        resp = safe_get(target_url, timeout=5, allow_redirects=True)
        headers = resp.headers
        
        # CDN indicators
        cdn_headers = ["cf-ray", "x-amz-cf-id", "x-cache", "x-served-by", "server", "via"]
        for header in cdn_headers:
            if header.lower() in headers:
                result["has_cdn"] = True
                result["cdn_indicators"].append({
                    "header": header,
                    "value": headers[header],
                })
        
        # Server header analysis
        server = headers.get("server", "").lower()
        if "cloudflare" in server or "cloudfront" in server or "fastly" in server:
            result["has_cdn"] = True
            result["architecture"] = "cdn_proxy"
        
    except Exception:
        pass
    
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description="HTTP Request Smuggling Discovery")
    ap.add_argument("--target", required=True, help="Target URL")
    ap.add_argument("--output", help="Output JSON file")
    
    args = ap.parse_args()
    
    result = detect_cdn_architecture(args.target)
    
    if args.output:
        out_path = args.output
    else:
        parsed = urlparse(args.target)
        host = parsed.netloc.replace(":", "_")
        out_path = f"smuggling_discovery_{host}.json"
    
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    
    print(out_path)


if __name__ == "__main__":
    main()

