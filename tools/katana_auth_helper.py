#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List

# This helper is intentionally minimal and dev-focused.
# It is designed to be called by /mcp/run_katana_auth and produce
# a well-structured JSON artifact under ARTIFACTS_DIR/katana_auth/<host>/.


def _default_output() -> Dict[str, Any]:
    return {
        "source": "katana_auth_stub",
        "auth_session": False,
        "target": None,
        "urls": [],
        "api_endpoints": [],
        "notes": [
            "This is a stub implementation. It confirms wiring and JSON shape,",
            "but does not yet talk to Chrome DevTools or run katana.",
        ],
    }


def main(argv: List[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Dev-mode authenticated Katana helper (stub)")
    ap.add_argument("--target", required=True, help="Target base URL, e.g. https://example.com")
    ap.add_argument("--output", required=True, help="Output JSON path under artifacts/katana_auth/<host>/")
    ap.add_argument(
        "--ws-url",
        dest="ws_url",
        default=os.environ.get("CHROME_DEVTOOLS_WS", ""),
        help="Chrome DevTools WebSocket URL (dev mode). If omitted, runs in stub mode.",
    )

    args = ap.parse_args(argv)

    out: Dict[str, Any] = _default_output()
    out["target"] = args.target

    # For now, we only flip auth_session=True when a DevTools WS URL is present.
    # Future work: connect to DevTools, scrape network activity, and populate
    # urls/api_endpoints from authenticated traffic plus katana runs.
    ws_url = (args.ws_url or "").strip()
    if ws_url:
        out["auth_session"] = True
        out.setdefault("notes", []).append(f"DevTools WS URL provided: {ws_url[:80]}...")
    else:
        out.setdefault("notes", []).append("No DevTools WS URL provided; running in pure stub mode.")

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)

    # Print the output path so callers/debuggers can see it easily.
    print(args.output)


if __name__ == "__main__":  # pragma: no cover - simple CLI wrapper
    main()
