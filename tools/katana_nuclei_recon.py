#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse


OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "./output_zap")
NUCLEI_TEMPLATES_DIR = os.environ.get(
    "NUCLEI_TEMPLATES_DIR", os.path.expanduser("~/nuclei-templates")
)
NUCLEI_BIN = os.environ.get("NUCLEI_BIN", "nuclei")

# Docker network for running katana/whatweb containers
# When running MCP in Docker, this should be the compose network name
DOCKER_NETWORK = os.environ.get("DOCKER_NETWORK", "agentic-bugbounty_lab_network")

# Conservative rate limits for bug bounty compliance
# For lab testing (controlled environment), use higher limits
IS_LAB_ENV = os.environ.get("LAB_TESTING", "false").lower() == "true"
LAB_KATANA_RATE_LIMIT = int(os.environ.get("LAB_KATANA_RATE_LIMIT", "50"))  # Higher for lab
LAB_NUCLEI_RATE_LIMIT = int(os.environ.get("LAB_NUCLEI_RATE_LIMIT", "50"))  # Higher for lab

DEFAULT_KATANA_RATE_LIMIT = LAB_KATANA_RATE_LIMIT if IS_LAB_ENV else int(os.environ.get("DEFAULT_KATANA_RATE_LIMIT", "10"))  # req/sec
DEFAULT_NUCLEI_RATE_LIMIT = LAB_NUCLEI_RATE_LIMIT if IS_LAB_ENV else int(os.environ.get("DEFAULT_NUCLEI_RATE_LIMIT", "10"))  # req/sec

# Template packs for different scan modes (relative to NUCLEI_TEMPLATES_DIR)
TEMPLATE_MODES = {
    "recon": [
        # Fast fingerprinting and technology detection
        "http/technologies/",
        "http/exposed-panels/",
        "http/fingerprints/",
        "ssl/",
    ],
    "auth": [
        # Authentication and authorization focused - EXCLUDE massive CVE directory
        "http/exposed-panels/",
        "http/default-logins/",
        "http/vulnerabilities/other/",  # Contains auth bypasses
        "http/misconfiguration/",
        # "http/cves/",  # REMOVED - too large, causes timeouts
        "exposures/configs/",
        "exposures/tokens/",
        "http/exposures/",
    ],
    "targeted": [
        # Ultra-targeted mode using specific directories + tags
        # This mode uses tags instead of directories for better performance
    ],
    "full": [
        # All templates - use with caution, very slow
        "",  # Empty string means use root templates dir
    ],
}

# Tag-based template selection for targeted scanning
# More specific tags to reduce scan time and focus on high-value findings
TEMPLATE_TAGS = {
    "auth": ["auth", "jwt", "session", "login"],  # Removed: oauth, token, credential (too broad)
    "idor": ["idor", "access-control"],  # Removed: authorization (too broad)
    "exposure": ["exposure", "config", "secret"],  # Removed: token, api-key (covered by auth)
}

# Backwards compatibility
RECON_TEMPLATE_DIRS = TEMPLATE_MODES["recon"]


def run_katana(target: str, out_path: str, max_urls: int = 200, rate_limit: Optional[int] = None) -> None:
    """Run Katana via docker image and write JSONL results to out_path.
    
    Uses DOCKER_NETWORK env var to connect to the same network as target services.
    When running in Docker compose, targets should use service names (e.g., http://xss_js_secrets:5000)
    rather than localhost URLs.
    
    Args:
        target: Target URL to crawl
        out_path: Output file path
        max_urls: Maximum number of URLs to collect (prevents excessive crawling)
        rate_limit: Rate limit in requests per second (defaults to env var or 10)
    """
    # Get rate limit from env or use conservative default
    if rate_limit is None:
        rate_limit = int(os.environ.get("KATANA_RATE_LIMIT", DEFAULT_KATANA_RATE_LIMIT))
    
    cmd = [
        "docker",
        "run",
        "--rm",
        "--network",
        DOCKER_NETWORK,  # Connect to the same network as target services
        "projectdiscovery/katana:latest",
        "-u",
        target,
        "-d",
        "2",  # Depth 2 is usually sufficient
        "-c",
        "3",  # Lower concurrency to respect rate limits
        "-rl",  # Rate limit
        str(rate_limit),  # Respect bug bounty program limits
        "-ct",  # Crawl duration limit
        "2m",  # Max 2 minutes of crawling
        "-jsonl",
        "-silent",
    ]
    print(f"[KATANA] Running: {' '.join(cmd)}", file=sys.stderr)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print("[KATANA] failed:", proc.stderr or proc.stdout, file=sys.stderr)
        with open(out_path, "w", encoding="utf-8") as fh:
            return

    with open(out_path, "w", encoding="utf-8") as dst:
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("[launcher.Browser]"):
                # Skip rod/chromium progress logs
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            req = obj.get("request") or {}

            url = (
                obj.get("url")
                or obj.get("endpoint")
                or req.get("url")
                or req.get("endpoint")  # <- this is what your output uses
            )
            if not url:
                continue

            dst.write(json.dumps({"url": url}) + "\n")
def run_nuclei(urls_file: str, out_file: str, mode: str = "recon", rate_limit: Optional[int] = None, cookies: Optional[List[Dict[str, Any]]] = None) -> None:
    """Run nuclei over URLs from urls_file, write JSONL to out_file.
    
    Modes:
    - recon: Fast fingerprinting and technology detection
    - auth: Authentication and authorization focused templates (directories)
    - targeted: Tag-based scanning for auth-related vulnerabilities (faster)
    - full: All templates (slow, comprehensive)
    
    Args:
        urls_file: File containing URLs to scan (one per line)
        out_file: Output file for JSONL results
        mode: Scan mode (recon, auth, targeted, full)
        rate_limit: Rate limit in requests per second (defaults to env var or 10)
        cookies: Optional list of cookie dicts (from katana_auth) to pass to Nuclei
    """
    # Get rate limit from env or use conservative default
    if rate_limit is None:
        rate_limit = int(os.environ.get("NUCLEI_RATE_LIMIT", DEFAULT_NUCLEI_RATE_LIMIT))
    
    cmd = [NUCLEI_BIN, "-l", urls_file]
    
    # Use tag-based approach for "targeted" mode (much faster)
    if mode == "targeted":
        # Use more specific tags - focus on high-value auth vulnerabilities
        # Combine tags with OR logic (templates matching any tag)
        auth_tags = TEMPLATE_TAGS.get("auth", [])
        idor_tags = TEMPLATE_TAGS.get("idor", [])
        exposure_tags = TEMPLATE_TAGS.get("exposure", [])
        
        # Use most specific tags first to reduce template count
        all_tags = auth_tags + idor_tags + exposure_tags
        cmd += ["-tags", ",".join(all_tags)]
        cmd += ["-severity", "critical,high,medium"]
        
        # Exclude noisy tags
        exclude_tags = ["dos", "fuzz", "brute-force"]  # Exclude DoS and brute-force templates
        cmd += ["-etags", ",".join(exclude_tags)]
    else:
        # Get template dirs for the selected mode
        template_dirs = TEMPLATE_MODES.get(mode, TEMPLATE_MODES["recon"])
        
        if mode == "full" or not template_dirs or template_dirs == [""]:
            # Full scan uses all templates
            cmd += ["-t", NUCLEI_TEMPLATES_DIR]
        else:
            # Add specific template directories
            for rel_dir in template_dirs:
                if rel_dir:  # Skip empty strings
                    abs_dir = os.path.join(NUCLEI_TEMPLATES_DIR, rel_dir)
                    if os.path.exists(abs_dir):
                        cmd += ["-t", abs_dir]
        
        # Add severity filter for auth mode to focus on important findings
        if mode == "auth":
            cmd += ["-severity", "critical,high,medium"]
    
    # Always add rate limiting - respect bug bounty program limits
    cmd += ["-rl", str(rate_limit)]
    
    # Add cookies if provided (for authenticated scanning)
    if cookies:
        # Convert cookies list to cookie string format: "name1=value1; name2=value2"
        cookie_parts = []
        for cookie in cookies:
            name = cookie.get("name", "")
            value = cookie.get("value", "")
            if name and value:
                cookie_parts.append(f"{name}={value}")
        if cookie_parts:
            cookie_string = "; ".join(cookie_parts)
            cmd += ["-H", f"Cookie: {cookie_string}"]
            print(f"[NUCLEI] Using authenticated cookies for {len(cookies)} cookies", file=sys.stderr)
    
    cmd += ["-jsonl", "-silent", "-o", out_file]
    print(f"[NUCLEI] Running: {' '.join(cmd)}", file=sys.stderr)
    
    # Increase timeout for targeted/auth modes since they're more focused
    timeout = 600 if mode in ("auth", "targeted") else 300
    
    try:
        subprocess.run(cmd, check=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"[NUCLEI] Timed out after {timeout}s", file=sys.stderr)
    except subprocess.CalledProcessError as e:
        print(f"[NUCLEI] Error: {e}", file=sys.stderr)


def load_jsonl(path: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    if not os.path.exists(path):
        return items
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except Exception:
                continue
    return items


def classify_katana_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """Mark entries that look like API endpoints."""
    url = item.get("url", "")
    method = (item.get("method") or "GET").upper()
    ctype = (item.get("content_type") or "").lower()

    is_api = False
    reasons: List[str] = []

    try:
        parsed = urlparse(url)
        path = (parsed.path or "").lower()
    except Exception:
        path = url.lower()

    # Path indicators
    if any(seg in path for seg in ["/api", "/v1", "/v2", "/graphql", "/rest", "/services"]):
        is_api = True
        reasons.append("path_indicator")

    # Content type indicators
    if "json" in ctype or "xml" in ctype:
        is_api = True
        reasons.append("content_type")

    # Method indicators
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        is_api = True
        reasons.append("http_method")

    item["is_api_candidate"] = is_api
    item["api_reasons"] = reasons
    return item


def _extract_url(item: Dict[str, Any]) -> str | None:
    # Our run_katana now writes simple {"url": ...} items
    if "url" in item:
        return item["url"]
    req = item.get("request") or {}
    if isinstance(req, dict):
        if "url" in req:
            return req["url"]
        if "endpoint" in req:
            return req["endpoint"]
    return None


def run_whatweb(hosts: list[str]) -> dict[str, dict[str, Any]]:
    """
    Run whatweb via Docker for each host, return a dict:
      { host: { "plugins": [...], "raw": "<whatweb-json>" } }
    
    Uses DOCKER_NETWORK env var to connect to the same network as target services.
    """
    fingerprints: dict[str, dict[str, Any]] = {}
    for host in hosts:
        cmd = [
            "docker", "run", "--rm",
            "--network", DOCKER_NETWORK,
            "bberastegui/whatweb",
            "-a", "3",
            "--log-json=-",
            host,
        ]
        print(f"[WHATWEB] Running: {' '.join(cmd)}", file=sys.stderr)
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            print("[WHATWEB] failed for", host, ":", proc.stderr or proc.stdout, file=sys.stderr)
            continue
        # whatweb JSON is usually one object per line; take first line
        line = proc.stdout.splitlines()[0] if proc.stdout else "{}"
        try:
            data = json.loads(line)
        except Exception:
            data = {"raw": line}
        fingerprints[host] = data
    return fingerprints



def main() -> None:
    ap = argparse.ArgumentParser(description="Katana + Nuclei web recon helper")
    ap.add_argument("--target", required=True, help="Target URL, e.g. https://example.com")
    ap.add_argument(
        "--output",
        default=None,
        help="Output JSON file (under OUTPUT_DIR). Default: katana_nuclei_<host>.json",
    )
    ap.add_argument(
        "--recon-only",
        action="store_true",
        help="[DEPRECATED] Use --mode=recon instead",
    )
    ap.add_argument(
        "--mode",
        choices=["recon", "auth", "targeted", "full"],
        default="recon",
        help="Scan mode: recon (fast fingerprinting), auth (auth-focused dirs), targeted (tag-based, fastest), full (all templates)",
    )
    args = ap.parse_args()
    
    # Handle deprecated --recon-only flag
    if args.recon_only:
        args.mode = "recon"

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    host_key = args.target.replace("://", "_").replace("/", "_")
    out_name = args.output or f"katana_nuclei_{host_key}.json"
    out_path = os.path.join(OUTPUT_DIR, out_name)

    with tempfile.TemporaryDirectory() as tmpdir:
        katana_out = os.path.join(tmpdir, "katana_urls.jsonl")
        nuclei_out = os.path.join(tmpdir, "nuclei_results.jsonl")

        # Get rate limits from environment (set by MCP server based on scope)
        katana_rate_limit = int(os.environ.get("KATANA_RATE_LIMIT", DEFAULT_KATANA_RATE_LIMIT))
        nuclei_rate_limit = int(os.environ.get("NUCLEI_RATE_LIMIT", DEFAULT_NUCLEI_RATE_LIMIT))
        
        # 1) Crawl with katana (limit URLs for faster scanning)
        max_urls = 150 if args.mode in ("auth", "targeted") else 200
        run_katana(args.target, katana_out, max_urls=max_urls, rate_limit=katana_rate_limit)
        katana_items = load_jsonl(katana_out)
        
        # Limit URLs if we got too many
        if len(katana_items) > max_urls:
            print(f"[KATANA] Limiting to {max_urls} URLs (found {len(katana_items)})", file=sys.stderr)
            katana_items = katana_items[:max_urls]
        katana_items = [classify_katana_item(x) for x in katana_items]

        # Extract URLs to a simple file for nuclei
        urls_txt = os.path.join(tmpdir, "urls.txt")
        print("[DEBUG] Writing URLs to", urls_txt, file=sys.stderr)
        with open(urls_txt, "w", encoding="utf-8") as fh:
            for item in katana_items:
                u = _extract_url(item)
                if u:
                    print("[DEBUG] URL:", u, file=sys.stderr)
                    fh.write(u + "\n")

        # 2) Run nuclei over discovered URLs
        # Check for cookies from authenticated session (passed via environment)
        cookies = None
        cookies_file = os.environ.get("AUTH_COOKIES_FILE")
        if cookies_file and os.path.exists(cookies_file):
            try:
                with open(cookies_file, "r") as f:
                    cookies = json.load(f)
                    print(f"[NUCLEI] Loading {len(cookies)} cookies from {cookies_file}", file=sys.stderr)
            except Exception:
                pass
        
        run_nuclei(urls_txt, nuclei_out, mode=args.mode, rate_limit=nuclei_rate_limit, cookies=cookies)
        nuclei_items = load_jsonl(nuclei_out)

        # 3) Build structured HTTP surface
        api_candidates = []
        all_urls = []

        for x in katana_items:
            u = _extract_url(x)
            if not u:
                continue
            all_urls.append(u)
            if x.get("is_api_candidate"):
                api_candidates.append(
                    {
                        "url": u,
                        "method": (x.get("method") or "GET").upper(),
                        "content_type": x.get("content_type"),
                        "status_code": x.get("status_code"),
                        "reasons": x.get("api_reasons", []),
                    }
                )

        result = {
            "target": args.target,
            "katana": {
                "count": len(katana_items),
                "all_urls": all_urls,
                "api_candidates": api_candidates,
            },
            "nuclei_findings": nuclei_items,
        }

        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)

    print(out_path)


if __name__ == "__main__":
    main()

