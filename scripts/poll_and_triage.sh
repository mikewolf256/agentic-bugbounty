#!/usr/bin/env bash
set -euo pipefail
SCAN_ID="$1"
while true; do
  OUT=$(curl -s "http://127.0.0.1:8100/mcp/poll_zap/${SCAN_ID}")
  COUNT=$(echo "$OUT" | jq -r '.count // 0')
  if [ "$COUNT" -gt  -0 ]; then
    echo "Found $COUNT findings"
    echo "$OUT" | jq .
    break
  fi
  echo "No findings yet; re-polling in 10s..."
  sleep 10
done
python agentic_from_file.py --findings_file "output_zap/zap_findings_${SCAN_ID}.json" --scope_file scope.json
jq '.[] | {title,confidence,recommended_bounty_usd,validation:.validation.dalfox_confirmed}' output_zap/triage_"${SCAN_ID}".json
