#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import subprocess
import tempfile
import time
import requests
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

try:
    import websocket
    WEBSOCKET_AVAILABLE = True
except ImportError:
    WEBSOCKET_AVAILABLE = False
    print("[WARNING] websocket-client not installed. Install with: pip install websocket-client", file=sys.stderr)

# This helper connects to Chrome DevTools via WebSocket to extract authenticated session data
# and then runs Katana with those cookies for authenticated crawling.


def _default_output() -> Dict[str, Any]:
    return {
        "source": "katana_auth_helper",
        "auth_session": False,
        "target": None,
        "urls": [],
        "api_endpoints": [],
        "cookies": [],
        "graphql_endpoints": [],
        "post_bodies": [],
        "notes": [],
    }


def _auto_detect_chrome_devtools(port: int = 9222) -> Optional[str]:
    """Auto-detect Chrome DevTools WebSocket URL on localhost."""
    try:
        # Try to get list of tabs from Chrome DevTools
        resp = requests.get(f"http://localhost:{port}/json", timeout=2)
        if resp.status_code == 200:
            tabs = resp.json()
            if tabs:
                # Use the first tab's WebSocket URL
                ws_url = tabs[0].get("webSocketDebuggerUrl")
                if ws_url:
                    return ws_url
    except Exception:
        pass
    return None


def _extract_cookies_from_devtools(ws_url: str, target_domain: str) -> List[Dict[str, Any]]:
    """Extract cookies from Chrome DevTools Protocol."""
    cookies = []
    
    if not WEBSOCKET_AVAILABLE:
        return cookies
    
    try:
        # Parse WebSocket URL to get HTTP endpoint
        ws_parsed = urlparse(ws_url.replace("ws://", "http://").replace("wss://", "https://"))
        http_endpoint = f"http://{ws_parsed.netloc}"
        
        # Get cookies via HTTP API (simpler than WebSocket for cookies)
        resp = requests.get(f"{http_endpoint}/json/cookies", timeout=5)
        if resp.status_code == 200:
            all_cookies = resp.json()
            # Filter cookies for target domain
            for cookie in all_cookies:
                cookie_domain = cookie.get("domain", "")
                if target_domain in cookie_domain or cookie_domain.lstrip(".") in target_domain:
                    cookies.append({
                        "name": cookie.get("name", ""),
                        "value": cookie.get("value", ""),
                        "domain": cookie_domain,
                        "path": cookie.get("path", "/"),
                        "secure": cookie.get("secure", False),
                        "httpOnly": cookie.get("httpOnly", False),
                    })
    except Exception as e:
        print(f"[WARNING] Failed to extract cookies via DevTools: {e}", file=sys.stderr)
    
    return cookies


def _monitor_network_traffic(ws_url: str, target_domain: str, duration: int = 30) -> Dict[str, Any]:
    """Monitor network traffic via Chrome DevTools Protocol to capture authenticated requests."""
    captured_data = {
        "urls": set(),
        "api_endpoints": [],
        "graphql_endpoints": [],
        "post_bodies": [],
    }
    
    if not WEBSOCKET_AVAILABLE:
        return captured_data
    
    try:
        # Use HTTP API to enable Network domain and capture requests
        ws_parsed = urlparse(ws_url.replace("ws://", "http://").replace("wss://", "https://"))
        http_endpoint = f"http://{ws_parsed.netloc}"
        
        # Get active tab
        resp = requests.get(f"{http_endpoint}/json", timeout=5)
        if resp.status_code != 200:
            return captured_data
        
        tabs = resp.json()
        if not tabs:
            return captured_data
        
        tab_id = tabs[0].get("id")
        if not tab_id:
            return captured_data
        
        # Enable Network domain
        requests.post(f"{http_endpoint}/json/runtime/evaluate", 
                     json={"expression": "1"}, timeout=5)
        
        # Get network logs (simplified - in production, use WebSocket for real-time monitoring)
        # For now, we'll extract from page source and known patterns
        # Full WebSocket implementation would require more complex async handling
        
    except Exception as e:
        print(f"[WARNING] Network monitoring failed: {e}", file=sys.stderr)
    
    return captured_data


def _run_katana_with_cookies(target: str, cookies: List[Dict[str, Any]], output_file: str) -> List[str]:
    """Run Katana with extracted cookies for authenticated crawling."""
    urls = []
    
    if not cookies:
        print("[INFO] No cookies extracted, skipping authenticated Katana run", file=sys.stderr)
        return urls
    
    # Create a cookie file for Katana
    # Katana supports --cookie flag or cookie file
    cookie_file = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            cookie_file = f.name
            # Format: domain, flag, path, secure, expiration, name, value
            for cookie in cookies:
                domain = cookie.get("domain", "").lstrip(".")
                secure = "TRUE" if cookie.get("secure") else "FALSE"
                path = cookie.get("path", "/")
                name = cookie.get("name", "")
                value = cookie.get("value", "")
                # Netscape cookie format
                f.write(f"{domain}\tTRUE\t{path}\t{secure}\t0\t{name}\t{value}\n")
        
        # Run Katana via Docker with cookie file
        docker_network = os.environ.get("DOCKER_NETWORK", "agentic-bugbounty_lab_network")
        rate_limit = int(os.environ.get("KATANA_RATE_LIMIT", "10"))
        
        # Mount cookie file into container
        cmd = [
            "docker", "run", "--rm",
            "--network", docker_network,
            "-v", f"{cookie_file}:/tmp/cookies.txt:ro",
            "projectdiscovery/katana:latest",
            "-u", target,
            "-cookie-file", "/tmp/cookies.txt",
            "-d", "2",
            "-c", "3",
            "-rl", str(rate_limit),
            "-ct", "2m",
            "-jsonl",
            "-silent",
        ]
        
        print(f"[KATANA-AUTH] Running authenticated Katana: {' '.join(cmd)}", file=sys.stderr)
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    url = item.get("url") or item.get("endpoint") or (item.get("request", {}) or {}).get("url")
                    if url:
                        urls.append(url)
                except json.JSONDecodeError:
                    continue
        else:
            print(f"[KATANA-AUTH] Katana failed: {proc.stderr}", file=sys.stderr)
    
    except Exception as e:
        print(f"[ERROR] Failed to run authenticated Katana: {e}", file=sys.stderr)
    finally:
        if cookie_file and os.path.exists(cookie_file):
            try:
                os.unlink(cookie_file)
            except Exception:
                pass
    
    return urls


def main(argv: List[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Authenticated Katana helper via Chrome DevTools")
    ap.add_argument("--target", required=True, help="Target base URL, e.g. https://example.com")
    ap.add_argument("--output", required=True, help="Output JSON path under artifacts/katana_auth/<host>/")
    ap.add_argument(
        "--ws-url",
        dest="ws_url",
        default=os.environ.get("CHROME_DEVTOOLS_WS", ""),
        help="Chrome DevTools WebSocket URL. If omitted, attempts auto-detection on port 9222.",
    )
    ap.add_argument(
        "--devtools-port",
        type=int,
        default=9222,
        help="Chrome DevTools port for auto-detection (default: 9222)",
    )

    args = ap.parse_args(argv)

    out: Dict[str, Any] = _default_output()
    out["target"] = args.target

    # Parse target domain
    parsed_target = urlparse(args.target)
    target_domain = parsed_target.netloc.split(":")[0]

    # Get WebSocket URL
    ws_url = (args.ws_url or "").strip()
    if not ws_url:
        # Try auto-detection
        ws_url = _auto_detect_chrome_devtools(args.devtools_port)
        if ws_url:
            out["notes"].append(f"Auto-detected Chrome DevTools at port {args.devtools_port}")
        else:
            out["notes"].append(f"Could not auto-detect Chrome DevTools on port {args.devtools_port}")
            out["notes"].append("Start Chrome with: chrome --remote-debugging-port=9222")

    if ws_url:
        out["auth_session"] = True
        out["notes"].append(f"Using DevTools WebSocket: {ws_url[:80]}...")
        
        # Extract cookies
        cookies = _extract_cookies_from_devtools(ws_url, target_domain)
        out["cookies"] = cookies
        out["notes"].append(f"Extracted {len(cookies)} cookies for domain {target_domain}")
        
        # Monitor network traffic (simplified - full implementation would use WebSocket)
        network_data = _monitor_network_traffic(ws_url, target_domain, duration=10)
        out["urls"].extend(list(network_data["urls"]))
        out["api_endpoints"].extend(network_data["api_endpoints"])
        out["graphql_endpoints"].extend(network_data["graphql_endpoints"])
        out["post_bodies"].extend(network_data["post_bodies"])
        
        # Run authenticated Katana
        if cookies:
            katana_urls = _run_katana_with_cookies(args.target, cookies, args.output)
            # Merge URLs, avoiding duplicates
            existing_urls = set(out["urls"])
            for url in katana_urls:
                if url not in existing_urls:
                    out["urls"].append(url)
                    existing_urls.add(url)
            
            out["notes"].append(f"Katana discovered {len(katana_urls)} authenticated URLs")
        else:
            out["notes"].append("No cookies found, skipping authenticated Katana run")
    else:
        out["notes"].append("No DevTools WebSocket URL available; running in stub mode")

    # Convert sets to lists for JSON serialization
    out["urls"] = list(set(out["urls"]))  # Deduplicate

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)

    # Print the output path so callers/debuggers can see it easily.
    print(args.output)


if __name__ == "__main__":  # pragma: no cover - simple CLI wrapper
    main()
