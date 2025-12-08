#!/bin/bash
# Script to check scan results and Discord alerting

cd /home/mike/Documents/Cyber/agentic-bugbounty

echo "=== Scan Results Check ==="
echo ""

# Check if scan is still running
SCAN_RUNNING=$(ps aux | grep "agentic_runner.py" | grep -v grep | wc -l)
if [ "$SCAN_RUNNING" -gt 0 ]; then
    echo "⏳ Scan is still running..."
    echo ""
else
    echo "✅ Scan appears to have completed"
    echo ""
fi

# Check for program run summary
echo "1. Program Run Summary:"
LATEST_SUMMARY=$(ls -t output_scans/program_run_*.json 2>/dev/null | head -1)
if [ -n "$LATEST_SUMMARY" ]; then
    echo "   ✅ Found: $LATEST_SUMMARY"
    echo ""
    echo "   Summary Statistics:"
    jq -r '
        "   - Hosts scanned: " + (.hosts | length | tostring),
        "   - Modules: " + (.modules | keys | length | tostring),
        "   - Scan cost: $" + (.scan_cost | tostring)
    ' "$LATEST_SUMMARY" 2>/dev/null || echo "   (Could not parse)"
else
    echo "   ⏳ No summary file yet"
fi
echo ""

# Check for triage files
echo "2. Triage Results:"
TRIAGE_FILES=$(find output_scans -name "triage_*.json" -type f 2>/dev/null | wc -l)
if [ "$TRIAGE_FILES" -gt 0 ]; then
    echo "   ✅ Found $TRIAGE_FILES triage file(s)"
    
    # Count total findings
    TOTAL_FINDINGS=0
    HIGH_SEVERITY=0
    for f in $(find output_scans -name "triage_*.json" -type f 2>/dev/null); do
        COUNT=$(jq '. | length' "$f" 2>/dev/null || echo "0")
        TOTAL_FINDINGS=$((TOTAL_FINDINGS + COUNT))
        
        # Count high severity (CVSS >= 7.0)
        HIGH=$(jq '[.[] | select(.cvss_score >= 7.0)] | length' "$f" 2>/dev/null || echo "0")
        HIGH_SEVERITY=$((HIGH_SEVERITY + HIGH))
    done
    echo "   - Total findings: $TOTAL_FINDINGS"
    echo "   - High severity (CVSS >= 7.0): $HIGH_SEVERITY"
    
    # Show sample findings
    echo ""
    echo "   Sample findings (first 5):"
    FIRST_TRIAGE=$(find output_scans -name "triage_*.json" -type f 2>/dev/null | head -1)
    if [ -n "$FIRST_TRIAGE" ]; then
        jq -r '.[0:5] | .[] | "   - \(.title // "Unknown") (CVSS: \(.cvss_score // 0))"' "$FIRST_TRIAGE" 2>/dev/null || echo "   (Could not parse)"
    fi
else
    echo "   ⏳ No triage files yet"
fi
echo ""

# Check validation queue
echo "3. Validation Queue (Discord Alerts):"
if [ -d "validation_queue" ]; then
    QUEUE_FILES=$(find validation_queue -name "*.json" -type f 2>/dev/null | wc -l)
    if [ "$QUEUE_FILES" -gt 0 ]; then
        echo "   ✅ Found $QUEUE_FILES validation(s) queued"
        echo "   (Discord alerts should have been sent)"
        echo ""
        echo "   Queued validations:"
        for f in $(find validation_queue -name "*.json" -type f 2>/dev/null | head -5); do
            VAL_ID=$(jq -r '.validation_id' "$f" 2>/dev/null)
            TITLE=$(jq -r '.finding.title // "Unknown"' "$f" 2>/dev/null)
            CVSS=$(jq -r '.finding.cvss_score // 0' "$f" 2>/dev/null)
            STATUS=$(jq -r '.status' "$f" 2>/dev/null)
            echo "   - [$VAL_ID] $TITLE (CVSS: $CVSS, Status: $STATUS)"
        done
    else
        echo "   ⏳ No validations queued yet"
    fi
else
    echo "   ⚠️  Validation queue directory not found"
fi
echo ""

# Check for markdown reports
echo "4. Markdown Reports:"
REPORT_COUNT=$(find output_scans -name "*__*.md" -type f 2>/dev/null | wc -l)
if [ "$REPORT_COUNT" -gt 0 ]; then
    echo "   ✅ Found $REPORT_COUNT report(s)"
else
    echo "   ⏳ No reports yet"
fi
echo ""

# Check targeted vulnerability test results
echo "5. Targeted Vulnerability Tests:"
if [ -n "$LATEST_SUMMARY" ]; then
    TARGETED_COUNT=$(jq '[.modules | to_entries[] | .value.targeted_vuln_tests.findings // []] | add | length' "$LATEST_SUMMARY" 2>/dev/null || echo "0")
    if [ "$TARGETED_COUNT" != "0" ] && [ -n "$TARGETED_COUNT" ]; then
        echo "   ✅ Found $TARGETED_COUNT targeted vulnerability findings"
    else
        echo "   ⏳ No targeted vulnerability findings yet"
    fi
else
    echo "   ⏳ Waiting for scan summary"
fi
echo ""

echo "=== Check Complete ==="
echo ""
echo "To view validation queue: python3 tools/validation_cli.py list"
echo "To view scan summary: jq . $LATEST_SUMMARY"

