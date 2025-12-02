#!/usr/bin/env python3
import argparse
import json
import os
from typing import List, Dict, Any

import requests


COMMON_BACKUP_PATHS: List[str] = [
    "index.php.bak",
    "index.php~",
    "index.html.bak",
    "index.html~",
    "config.php.bak",
    "config.php~",
    ".env",
    "backup.zip",
    "backup.tar.gz",
    "db.sql",
    "database.sql",
    "dump.sql",
    ".git/config",
    ".svn/entries",
]


def probe_url(url: str, timeout: int = 10) -> Dict[str, Any]:
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        return {
            "url": url,
            "status": r.status_code,
            "length": int(r.headers.get("content-length") or len(r.content)),
        }
    except Exception as e:
        return {"url": url, "error": str(e)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple backup/VCS hunter")
    parser.add_argument("--base-url", required=True, help="Base URL to probe (e.g. https://target/app)")
    parser.add_argument("--output-dir", required=True, help="Directory to write hunt results into")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    base = args.base_url.rstrip("/")

    hits: List[Dict[str, Any]] = []
    for rel in COMMON_BACKUP_PATHS:
        target = f"{base}/{rel}"
        info = probe_url(target)
        # Treat non-404/400 responses without errors as interesting
        if info.get("error") is None and info.get("status") not in (400, 404):
            hits.append(info)

    out = {
        "base_url": args.base_url,
        "wordlist_size": len(COMMON_BACKUP_PATHS),
        "hits": hits,
    }

    out_path = os.path.join(args.output_dir, "backup_hunt_results.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)


if __name__ == "__main__":
    main()
