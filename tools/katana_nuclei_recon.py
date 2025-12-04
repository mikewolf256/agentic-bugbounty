#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from typing import List, Dict, Any
from urllib.parse import urlparse


OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "./output_zap")
NUCLEI_TEMPLATES_DIR = os.environ.get(
    "NUCLEI_TEMPLATES_DIR", os.path.expanduser("~/nuclei-templates")
)
NUCLEI_BIN = os.environ.get("NUCLEI_BIN", "nuclei")

# Docker network for running katana/whatweb containers
# When running MCP in Docker, this should be the compose network name
DOCKER_NETWORK = os.environ.get("DOCKER_NETWORK", "agentic-bugbounty_lab_network")

# Recon-only template pack (relative to NUCLEI_TEMPLATES_DIR)
RECON_TEMPLATE_DIRS = [
    "http/technologies/",
    "http/exposed-panels/",
    "http/fingerprints/",
    "http/misconfiguration/",
    "exposures/files/",
    "exposures/configs/",
    "ssl/",
]


def run_katana(target: str, out_path: str) -> None:
    """Run Katana via docker image and write JSONL results to out_path.
    
    Uses DOCKER_NETWORK env var to connect to the same network as target services.
    When running in Docker compose, targets should use service names (e.g., http://xss_js_secrets:5000)
    rather than localhost URLs.
    """
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
        "2",  # working depth from manual test
        "-c",
        "5",  # working concurrency from manual test
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
def run_nuclei(urls_file: str, out_file: str, recon_only: bool = False) -> None:
    """Run nuclei over URLs from urls_file, write JSONL to out_file. If recon_only, use only recon template pack."""
    cmd = [NUCLEI_BIN, "-l", urls_file]
    if recon_only:
        for rel_dir in RECON_TEMPLATE_DIRS:
            abs_dir = os.path.join(NUCLEI_TEMPLATES_DIR, rel_dir)
            cmd += ["-t", abs_dir]
    else:
        cmd += ["-t", NUCLEI_TEMPLATES_DIR]
    cmd += ["-jsonl", "-silent", "-o", out_file]
    print(f"[NUCLEI] Running: {' '.join(cmd)}", file=sys.stderr)
    subprocess.run(cmd, check=True)


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
            "cyberwatch/whatweb",
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
        help="Use only recon/fingerprinting Nuclei templates (fast, low-noise)",
    )
    args = ap.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    host_key = args.target.replace("://", "_").replace("/", "_")
    out_name = args.output or f"katana_nuclei_{host_key}.json"
    out_path = os.path.join(OUTPUT_DIR, out_name)

    with tempfile.TemporaryDirectory() as tmpdir:
        katana_out = os.path.join(tmpdir, "katana_urls.jsonl")
        nuclei_out = os.path.join(tmpdir, "nuclei_results.jsonl")

        # 1) Crawl with katana
        run_katana(args.target, katana_out)
        katana_items = load_jsonl(katana_out)
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
        run_nuclei(urls_txt, nuclei_out, recon_only=args.recon_only)
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

