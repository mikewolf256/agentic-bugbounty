#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LABS_DIR = REPO_ROOT / "labs"
MCP_URL = "http://127.0.0.1:8000"


def load_lab_metadata(lab_name: str) -> dict:
    lab_dir = LABS_DIR / lab_name
    meta_path = lab_dir / "lab_metadata.json"
    if not meta_path.exists():
        raise SystemExit(f"lab_metadata.json not found for lab {lab_name} at {meta_path}")
    return json.loads(meta_path.read_text(encoding="utf-8"))


def run(cmd: list[str]) -> None:
    print(f"[lab_runner] $ {' '.join(cmd)}")
    proc = subprocess.run(cmd, cwd=REPO_ROOT)
    if proc.returncode != 0:
        raise SystemExit(f"command failed with {proc.returncode}: {' '.join(cmd)}")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Agentic lab harness")
    ap.add_argument("lab", help="Lab name (directory under labs/)")
    args = ap.parse_args(argv)

    meta = load_lab_metadata(args.lab)
    base_url = meta.get("base_url")
    if not base_url:
        raise SystemExit("lab_metadata.json missing 'base_url'")

    print(f"[lab_runner] Lab: {meta.get('name')}")
    print(f"[lab_runner] Base URL: {base_url}")

    # 1) Build a temp scope.json just for this lab
    scope = {
        "program_name": f"lab-{meta.get('name')}",
        "primary_targets": [base_url],
        "secondary_targets": [],
        "rules": {}
    }
    scope_path = REPO_ROOT / "scope.lab.json"
    scope_path.write_text(json.dumps(scope, indent=2), encoding="utf-8")
    print(f"[lab_runner] Wrote {scope_path}")

    # 2) POST /mcp/set_scope
    run([
        "curl", "-s",
        "-X", "POST", f"{MCP_URL}/mcp/set_scope",
        "-H", "Content-Type: application/json",
        "--data-binary", "@scope.lab.json"
    ])

    # 3) Run full-scan for this scope
    run([
        sys.executable, "agentic_runner.py",
        "--mode", "full-scan",
        "--scope_file", "scope.lab.json",
        "--mcp-url", MCP_URL,
    ])


if __name__ == "__main__":  # pragma: no cover
    main()
