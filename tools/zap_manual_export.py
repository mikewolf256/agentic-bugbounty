# filepath: /home/mike/Documents/Cyber/agentic-bugbounty/tools/zap_manual_export.py
import os
import json
import argparse
import requests

ZAP_API_BASE = os.environ.get("ZAP_API_BASE", "http://localhost:8080")
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "./output_zap")


def zap_api(endpoint_path: str, params: dict | None = None):
    if params is None:
        params = {}
    if ZAP_API_KEY:
        params["apikey"] = ZAP_API_KEY
    url = ZAP_API_BASE.rstrip("/") + endpoint_path
    r = requests.get(url, params=params, timeout=60)
    r.raise_for_status()
    return r.json()


def main():
    ap = argparse.ArgumentParser(description="Manual ZAP alerts export for a base URL")
    ap.add_argument("--base-url", required=True, help="Base URL, e.g. http://juice-shop:3000")
    ap.add_argument("--output", default="zap_findings_manual.json", help="Output filename (under OUTPUT_DIR)")
    args = ap.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    alerts = zap_api("/JSON/core/view/alerts/", params={"baseurl": args.base_url})
    findings = []
    for a in alerts.get("alerts", []):
        fid = a.get("alertId") or a.get("pluginId") or a.get("id")
        findings.append(
            {
                "id": fid,
                "name": a.get("alert"),
                "risk": a.get("risk"),
                "confidence": a.get("confidence"),
                "url": a.get("url"),
                "param": a.get("param"),
                "evidence": a.get("evidence"),
                "otherinfo": a.get("otherInfo"),
                "solution": a.get("solution"),
                "reference": a.get("reference"),
                "cweid": a.get("cweid"),
                "wascid": a.get("wascid"),
                "raw": a,
            }
        )

    out_path = os.path.join(OUTPUT_DIR, args.output)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)

    print(out_path)


if __name__ == "__main__":
    main()
