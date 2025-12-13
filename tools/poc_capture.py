#!/usr/bin/env python3
"""POC Capture Module

Captures HTTP requests and responses during validation for proof of concept evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests  # Always import for Session/exceptions support

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




class POCCapture:
    """Capture HTTP requests and responses for POC evidence."""
    
    def __init__(self, output_dir: str = "artifacts/poc_captures"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
    
    def capture_request_response(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        params: Optional[Dict[str, Any]] = None,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        """Capture a single HTTP request and response.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            headers: Request headers
            data: Request body/data
            params: Query parameters
            timeout: Request timeout
        
        Returns:
            Dict with captured request/response data
        """
        capture = {
            "timestamp": time.time(),
            "method": method.upper(),
            "url": url,
            "request": {
                "headers": headers or {},
                "params": params or {},
                "data": str(data) if data else None,
            },
            "response": {},
        }
        
        try:
            # Make the request
            resp = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                params=params,
                timeout=timeout,
                allow_redirects=False,
            )
            
            # Capture response
            capture["response"] = {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:10000],  # Limit body size
                "body_size": len(resp.text),
                "content_type": resp.headers.get("Content-Type", ""),
            }
            
            # Try to parse JSON response
            try:
                capture["response"]["json"] = resp.json()
            except (ValueError, json.JSONDecodeError):
                pass
            
        except requests.exceptions.Timeout:
            capture["response"] = {"error": "timeout"}
        except requests.exceptions.RequestException as e:
            capture["response"] = {"error": str(e)}
        
        return capture
    
    def save_capture(self, capture: Dict[str, Any], finding_id: Optional[str] = None) -> str:
        """Save capture to file.
        
        Args:
            capture: Capture data
            finding_id: Optional finding ID for filename
        
        Returns:
            Path to saved capture file
        """
        timestamp = int(capture["timestamp"])
        if finding_id:
            filename = f"poc_{finding_id}_{timestamp}.json"
        else:
            filename = f"poc_{timestamp}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(capture, fh, indent=2)
        
        return filepath
    
    def format_for_report(self, capture: Dict[str, Any]) -> str:
        """Format capture for markdown report inclusion.
        
        Args:
            capture: Capture data
        
        Returns:
            Formatted markdown string
        """
        method = capture["method"]
        url = capture["url"]
        req_headers = capture["request"]["headers"]
        req_data = capture["request"]["data"]
        req_params = capture["request"]["params"]
        
        resp = capture.get("response", {})
        status_code = resp.get("status_code", "N/A")
        resp_headers = resp.get("headers", {})
        resp_body = resp.get("body", "")
        
        # Build request section
        request_lines = [f"{method} {url} HTTP/1.1"]
        
        if req_params:
            from urllib.parse import urlencode
            query_string = urlencode(req_params, doseq=True)
            if query_string:
                request_lines[0] += f"?{query_string}"
        
        request_lines.append("")
        
        for key, value in req_headers.items():
            request_lines.append(f"{key}: {value}")
        
        if req_data:
            request_lines.append("")
            request_lines.append(str(req_data))
        
        # Build response section
        response_lines = [f"HTTP/1.1 {status_code}"]
        response_lines.append("")
        
        for key, value in resp_headers.items():
            response_lines.append(f"{key}: {value}")
        
        if resp_body:
            response_lines.append("")
            # Truncate long bodies
            if len(resp_body) > 2000:
                response_lines.append(resp_body[:2000])
                response_lines.append("\n... (truncated)")
            else:
                response_lines.append(resp_body)
        
        return f"""**Request:**
```
{chr(10).join(request_lines)}
```

**Response:**
```
{chr(10).join(response_lines)}
```"""


def main() -> None:
    ap = argparse.ArgumentParser(description="POC Capture Tool")
    ap.add_argument("--method", default="GET", help="HTTP method")
    ap.add_argument("--url", required=True, help="Target URL")
    ap.add_argument("--headers", help="Request headers as JSON")
    ap.add_argument("--data", help="Request body/data")
    ap.add_argument("--params", help="Query parameters as JSON")
    ap.add_argument("--output-dir", default="artifacts/poc_captures", help="Output directory")
    ap.add_argument("--finding-id", help="Finding ID for filename")
    
    args = ap.parse_args()
    
    capture = POCCapture(output_dir=args.output_dir)
    
    headers = None
    if args.headers:
        headers = json.loads(args.headers)
    
    params = None
    if args.params:
        params = json.loads(args.params)
    
    # Capture request/response
    result = capture.capture_request_response(
        method=args.method,
        url=args.url,
        headers=headers,
        data=args.data,
        params=params,
    )
    
    # Save capture
    filepath = capture.save_capture(result, finding_id=args.finding_id)
    
    print(f"[POC-CAPTURE] Saved capture to {filepath}")
    print(filepath)


if __name__ == "__main__":
    main()

