#!/bin/bash
# Test script to validate all labs detection and Discord alerting

set -e

echo "=== All Labs Validation Test ==="
echo ""

# Set environment variables (these should be set in your environment or .env file)
# export DISCORD_WEBHOOK_URL="your_discord_webhook_url"
# export OPENAI_API_KEY="your_openai_api_key"
export MCP_SERVER_URL="${MCP_SERVER_URL:-http://localhost:8000}"
export OUTPUT_DIR="${OUTPUT_DIR:-output_scans}"

# Validate required environment variables
if [ -z "$DISCORD_WEBHOOK_URL" ]; then
    echo "⚠️  DISCORD_WEBHOOK_URL not set, Discord alerts will be skipped"
fi

echo "1. Checking MCP server health..."
MCP_HEALTH=$(curl -s http://localhost:8000/mcp/health | jq -r '.status')
if [ "$MCP_HEALTH" != "healthy" ] && [ "$MCP_HEALTH" != "degraded" ]; then
    echo "❌ MCP server not healthy: $MCP_HEALTH"
    exit 1
fi
echo "✅ MCP server is $MCP_HEALTH"

echo ""
echo "2. Setting scope for all labs..."
SCOPE_RESULT=$(curl -s -X POST http://localhost:8000/mcp/set_scope \
    -H "Content-Type: application/json" \
    --data-binary @scope.lab.all.json | jq -r '.status')
if [ "$SCOPE_RESULT" != "ok" ]; then
    echo "❌ Failed to set scope: $SCOPE_RESULT"
    exit 1
fi
echo "✅ Scope set successfully"

echo ""
echo "3. Testing Discord webhook..."
if [ -n "$DISCORD_WEBHOOK_URL" ]; then
    DISCORD_TEST=$(curl -s -X POST "$DISCORD_WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d '{"content": "🧪 Test alert from validation script"}' | head -1)
    if [ -z "$DISCORD_TEST" ] || echo "$DISCORD_TEST" | grep -q "204\|200"; then
        echo "✅ Discord webhook is working"
    else
        echo "⚠️  Discord webhook test returned: $DISCORD_TEST"
    fi
else
    echo "⏭️  Skipping Discord test (DISCORD_WEBHOOK_URL not set)"
fi

echo ""
echo "4. Running full scan against all labs..."
echo "   This may take several minutes..."
echo ""

# Run the scan and capture output
python3 agentic_runner.py \
    --mode full-scan \
    --scope_file scope.lab.all.json \
    --profile full \
    2>&1 | tee scan_all_labs_$(date +%Y%m%d_%H%M%S).log

echo ""
echo "5. Checking scan results..."
LATEST_SUMMARY=$(ls -t output_scans/program_run_*.json 2>/dev/null | head -1)
if [ -n "$LATEST_SUMMARY" ]; then
    echo "✅ Scan summary found: $LATEST_SUMMARY"
    echo ""
    echo "Summary statistics:"
    jq -r '
        "Hosts scanned: " + (.hosts | length | tostring),
        "Modules run: " + (.modules | keys | length | tostring)
    ' "$LATEST_SUMMARY" 2>/dev/null || echo "Could not parse summary"
else
    echo "⚠️  No scan summary found"
fi

echo ""
echo "6. Checking for findings..."
FINDINGS_COUNT=$(find output_scans -name "triage_*.json" -newer scope.lab.all.json 2>/dev/null | wc -l)
if [ "$FINDINGS_COUNT" -gt 0 ]; then
    echo "✅ Found $FINDINGS_COUNT triage files"
    
    # Count total findings
    TOTAL_FINDINGS=0
    for f in $(find output_scans -name "triage_*.json" -newer scope.lab.all.json 2>/dev/null); do
        COUNT=$(jq '. | length' "$f" 2>/dev/null || echo "0")
        TOTAL_FINDINGS=$((TOTAL_FINDINGS + COUNT))
    done
    echo "   Total findings: $TOTAL_FINDINGS"
else
    echo "⚠️  No triage files found"
fi

echo ""
echo "7. Checking validation queue..."
if [ -d "validation_queue" ]; then
    QUEUE_COUNT=$(find validation_queue -name "*.json" 2>/dev/null | wc -l)
    echo "✅ Validation queue has $QUEUE_COUNT items"
    if [ "$QUEUE_COUNT" -gt 0 ]; then
        echo "   Discord alerts should have been sent for high-value findings"
    fi
else
    echo "⚠️  Validation queue directory not found"
fi

echo ""
echo "=== Test Complete ==="
echo ""
echo "Next steps:"
echo "1. Check Discord channel for validation alerts"
echo "2. Review findings in output_scans/triage_*.json"
echo "3. Check validation queue: python3 tools/validation_cli.py list"
