#!/usr/bin/env python3
import argparse
import json
import os
from typing import List, Dict, Any

import requests


COMMON_BACKUP_PATHS: List[str] = [
    # Backup files
    "index.php.bak",
    "index.php~",
    "index.php.old",
    "index.php.backup",
    "index.html.bak",
    "index.html~",
    "config.php.bak",
    "config.php~",
    "config.php.old",
    "config.bak",
    "config.old",
    "settings.php.bak",
    "database.php.bak",
    "db.php.bak",
    "wp-config.php.bak",
    "app.config.bak",
    # Archive files
    ".env",
    ".env.bak",
    ".env.old",
    ".env.local",
    ".env.production",
    "backup.zip",
    "backup.tar.gz",
    "backup.tar",
    "backup.sql",
    "site.zip",
    "www.zip",
    "web.zip",
    # Database dumps
    "db.sql",
    "database.sql",
    "dump.sql",
    "mysql.sql",
    "backup.sql",
    # VCS/IDE files
    ".git/config",
    ".git/HEAD",
    ".git/index",
    ".gitignore",
    ".svn/entries",
    ".svn/wc.db",
    ".hg/hgrc",
    ".DS_Store",
    "Thumbs.db",
    # Config files
    "web.config",
    "web.config.bak",
    ".htaccess",
    ".htaccess.bak",
    ".htpasswd",
    "nginx.conf",
    "robots.txt.bak",
    # Editor backup files
    "*.swp",
    "*.swo",
    "#index.php#",
    # Common test/debug files
    "phpinfo.php",
    "info.php",
    "test.php",
    "debug.php",
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
