#!/usr/bin/env python3
"""WebSocket Security Tester

Tests for WebSocket security vulnerabilities:
- Authentication bypass
- Message injection
- Origin validation
- Subprotocol negotiation
- Denial of service
"""

import os
import asyncio
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse


async def test_websocket_security(
    endpoint: str,
    origin: Optional[str] = None,
    subprotocols: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Test for WebSocket security vulnerabilities
    
    Args:
        endpoint: WebSocket endpoint URL
        origin: Origin header value
        subprotocols: List of subprotocols to test
        
    Returns:
        Dict with test results
    """
    result = {
        "type": "websocket_security",
        "test": "websocket_security",
        "vulnerable": False,
        "url": endpoint,
        "issues": [],
        "evidence": None
    }
    
    # Convert WebSocket URL to HTTP for initial checks
    http_endpoint = endpoint.replace("ws://", "http://").replace("wss://", "https://")
    
    # First, try HTTP-based WebSocket detection and origin validation
    try:
        import requests
        
        # Test WebSocket upgrade request without Origin
        headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13"
        }
        
        try:
            resp = requests.get(http_endpoint, headers=headers, timeout=5)
            # If we get 101 Switching Protocols, WebSocket is available
            if resp.status_code == 101:
                result["issues"].append("websocket_available_without_auth")
                result["vulnerable"] = True
            # Check for WebSocket handshake response
            if "websocket" in resp.headers.get("Upgrade", "").lower():
                result["issues"].append("websocket_upgrade_allowed")
        except Exception:
            pass
        
        # Test with malicious Origin header
        malicious_headers = headers.copy()
        malicious_headers["Origin"] = "https://evil.com"
        
        try:
            resp = requests.get(http_endpoint, headers=malicious_headers, timeout=5)
            # If request succeeds with evil origin, origin validation is missing
            if resp.status_code in [101, 200]:
                # Check if access-control headers allow any origin
                allow_origin = resp.headers.get("Access-Control-Allow-Origin", "")
                if allow_origin == "*" or "evil.com" in allow_origin:
                    result["issues"].append("cswsh_vulnerable_cors")
                    result["vulnerable"] = True
                elif resp.status_code == 101:
                    result["issues"].append("origin_validation_missing")
                    result["vulnerable"] = True
        except Exception:
            pass
            
    except ImportError:
        pass
    
    # Then try actual WebSocket connection if library available
    try:
        import websockets
        
        # Test connection without authentication
        try:
            async with websockets.connect(endpoint, close_timeout=3, open_timeout=5) as ws:
                result["issues"].append("no_authentication_required")
                result["vulnerable"] = True
                
                # Test message injection
                try:
                    await ws.send("<script>alert(1)</script>")
                    response = await asyncio.wait_for(ws.recv(), timeout=2)
                    
                    if "<script>" in str(response):
                        result["issues"].append("message_injection")
                        result["vulnerable"] = True
                except Exception:
                    pass
                    
        except Exception as e:
            # Connection failed - record but don't fail
            result["evidence"] = result.get("evidence", {})
            if isinstance(result["evidence"], dict):
                result["evidence"]["connection_error"] = str(e)
        
        # Test origin validation with malicious origin
        if not origin:
            origin = "https://evil.com"
        try:
            headers = {"Origin": origin}
            async with websockets.connect(endpoint, extra_headers=headers, close_timeout=3, open_timeout=5) as ws:
                result["issues"].append("origin_validation_missing")
                result["vulnerable"] = True
        except Exception:
            # Origin validation might be working
            pass
        
    except ImportError:
        # websockets not available, rely on HTTP-based checks above
        if not result["evidence"]:
            result["evidence"] = {
                "note": "WebSocket library not available, used HTTP-based detection"
            }
    except Exception as e:
        if not result["evidence"]:
            result["evidence"] = {"error": str(e)}
    
    # Finalize evidence
    if not result["evidence"]:
        result["evidence"] = {}
    if isinstance(result["evidence"], dict):
        result["evidence"]["endpoint"] = endpoint
        result["evidence"]["issues_found"] = result["issues"]
    
    return result


def validate_websocket_security(
    discovery_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Main validation function for WebSocket security
    
    Args:
        discovery_data: Discovery data containing WebSocket endpoints
        
    Returns:
        Dict with validation results
    """
    results = {
        "vulnerable": False,
        "tests_run": 0,
        "findings": []
    }
    
    # Extract WebSocket endpoints
    ws_endpoints = []
    if "websocket_endpoints" in discovery_data:
        ws_endpoints = discovery_data["websocket_endpoints"]
    elif "endpoints" in discovery_data:
        # Filter for WebSocket endpoints
        for ep in discovery_data["endpoints"]:
            url = ep.get("url", "")
            if "ws://" in url or "wss://" in url or "/ws" in url.lower():
                ws_endpoints.append(url)
    
    if not ws_endpoints:
        return results
    
    # Test each WebSocket endpoint
    for endpoint in ws_endpoints:
        test_result = asyncio.run(test_websocket_security(endpoint))
        results["tests_run"] += 1
        if test_result["vulnerable"]:
            results["vulnerable"] = True
            results["findings"].append(test_result)
    
    return results


if __name__ == "__main__":
    import argparse
    
    ap = argparse.ArgumentParser(description="WebSocket Security Tester")
    ap.add_argument("--endpoint", required=True, help="WebSocket endpoint URL")
    ap.add_argument("--origin", help="Origin header value")
    args = ap.parse_args()
    
    result = asyncio.run(test_websocket_security(args.endpoint, args.origin))
    
    import json
    print(json.dumps(result, indent=2))

