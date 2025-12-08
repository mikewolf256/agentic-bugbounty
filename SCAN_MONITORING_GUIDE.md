# All Labs Scan - Monitoring Guide

## Scan Status

**Started**: 2024-12-06 22:17:20  
**Scope**: All 25 labs (ports 5001-5027)  
**Profile**: Full scan profile  
**Status**: Running in background

## What's Happening

The scan is running against all 25 labs and will:

1. **Recon Phase** (Katana + Nuclei)
   - Discover endpoints for each lab
   - Run Nuclei templates for fingerprinting
   - This phase takes ~5-10 minutes per lab

2. **Targeted Vulnerability Testing**
   - Run 15 vulnerability testers against discovered endpoints
   - Testers include: command injection, path traversal, file upload, CSRF, NoSQL injection, etc.
   - This phase takes ~2-5 minutes per lab

3. **AI Triage**
   - Analyze findings with LLM
   - Assign CVSS scores and bounty estimates
   - This phase takes ~1-2 minutes per finding

4. **Validation Queue & Discord Alerts**
   - Queue findings with CVSS ≥ 7.0 or bounty ≥ $500
   - Send Discord alerts for each queued finding
   - This happens automatically during triage

## Expected Timeline

- **Total estimated time**: 30-60 minutes for all 25 labs
- **Per lab**: ~2-5 minutes (depending on endpoints discovered)

## Monitoring Commands

### Check if scan is still running:
```bash
ps aux | grep agentic_runner.py | grep -v grep
```

### Check scan progress:
```bash
./check_scan_results.sh
```

### View log file:
```bash
tail -f scan_all_labs_*.log
```

### Check for findings:
```bash
# Count triage files
find output_scans -name "triage_*.json" | wc -l

# View latest findings
jq '.[0:5] | .[] | {title, cvss_score, url}' output_scans/triage_*.json | head -30
```

### Check validation queue:
```bash
# List queued validations (requires PYTHONPATH)
cd /home/mike/Documents/Cyber/agentic-bugbounty
PYTHONPATH=. python3 tools/validation_cli.py list
```

### Check Discord alerts:
- Check your Discord channel for validation alerts
- Alerts are sent when findings meet thresholds (CVSS ≥ 7.0 or bounty ≥ $500)

## Expected Results

Based on `LAB_TEST_VALIDATION_REPORT.md`:

- **Command Injection Lab**: Should detect 4 vulnerabilities (100% detection rate)
- **Other Labs**: Detection rates vary, but testers should run against all labs
- **Total Expected Findings**: ~35+ across all labs

## Output Files

When scan completes, you'll find:

1. **Scan Summary**: `output_scans/program_run_*.json`
   - Overall scan statistics
   - Per-host module results
   - Token usage and costs

2. **Triage Results**: `output_scans/triage_*.json`
   - AI-analyzed findings with CVSS scores
   - Validation evidence
   - Bounty estimates

3. **Markdown Reports**: `output_scans/*__*.md`
   - Human-readable vulnerability reports
   - Ready for submission

4. **Validation Queue**: `validation_queue/pending_validations.json`
   - High-value findings queued for review
   - Discord alerts sent for each

## Discord Alert Verification

To verify Discord alerts were sent:

1. Check Discord channel for messages with:
   - Title: "🔍 Validation Required: [Finding Title]"
   - Fields: Validation ID, CVSS Score, Estimated Bounty, Target URL

2. Check validation queue:
   ```bash
   find validation_queue -name "*.json" -exec jq . {} \;
   ```

3. If alerts weren't sent, check:
   - `DISCORD_WEBHOOK_URL` environment variable is set
   - Webhook URL is valid
   - Findings meet thresholds (CVSS ≥ 7.0 or bounty ≥ $500)

## Troubleshooting

### Scan seems stuck:
- Check MCP server: `curl http://localhost:8000/mcp/health`
- Check for errors in log: `tail -100 scan_all_labs_*.log`
- Verify labs are running: `docker ps | grep lab`

### No findings detected:
- Check if labs are accessible: `curl http://localhost:5013` (command injection lab)
- Verify scope is set: `curl http://localhost:8000/mcp/health | jq .scope`
- Check Katana/Nuclei output: `ls -lt output_scans/katana_nuclei_*.json`

### Discord alerts not sent:
- Verify webhook URL is correct
- Check if findings meet thresholds
- Look for errors in scan log: `grep -i discord scan_all_labs_*.log`

## Next Steps After Scan Completes

1. **Review Findings**:
   ```bash
   jq '.[] | {title, cvss_score, url, recommended_bounty_usd}' output_scans/triage_*.json
   ```

2. **Check Validation Queue**:
   ```bash
   PYTHONPATH=. python3 tools/validation_cli.py list
   ```

3. **Review Discord Alerts**:
   - Check Discord channel for validation notifications

4. **Validate Detection Rates**:
   - Compare detected findings against expected findings in `LAB_TEST_VALIDATION_REPORT.md`
   - Focus on command injection lab (should be 100% detection)

5. **Approve/Reject Findings**:
   ```bash
   PYTHONPATH=. python3 tools/validation_cli.py approve <validation_id>
   PYTHONPATH=. python3 tools/validation_cli.py reject <validation_id> --reason "reason"
   ```

