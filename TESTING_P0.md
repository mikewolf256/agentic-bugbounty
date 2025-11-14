    # TESTING_P0 - How to validate P0 deliverables locally

    ## Prereqs
    - Python 3.11
    - ffuf installed (optional, fallback logic exists)
    - Internet access (or test against local mock endpoints)
    - Your repo cloned at ~/agentic-bugbounty (or run tools pointing at real URLs)

    ## Smoke tests

    1. JS miner
       ```bash
       python tools/js_miner.py --base-url https://example.com --output output_zap/artifacts/js_miner/example.com
       ls output_zap/artifacts/js_miner/example.com
       ```
       Expected: endpoints.json and page.html present.

    2. Reflector tester
       ```bash
       python tools/reflector_tester.py --url 'https://example.com/?q=test' --output output_zap/artifacts/reflector/example.com
       ```
       Expected: reflection_summary.json with any found reflections.

    3. Backup hunt (ffuf)
       ```bash
       python tools/backup_hunt.py --target https://example.com --output output_zap/artifacts/backup_hunt/example.com
       ```
       If ffuf present, a ffuf_*.json will be created. Otherwise fallback JSON.

    4. Dedupe filter
       ```python
       python - <<'PY'
from mcp_helpers.dedupe import filter_and_dedupe
print(filter_and_dedupe([{'name':'XSS','confidence':'High','url':'https://a','cweid':'79','evidence':'x'},{'name':'Noise','confidence':'low','url':'https://b','evidence':''}]))
PY
       ```
       Expected: only XSS remains.

    ## Notes
    - Artifacts will include accompanying `.meta.json` files with command and redaction metadata.
    - Review `output_zap/artifacts/*` to confirm meta files exist.
