# HackerOne Integration

This module enables automatic import of bug bounty program scopes from HackerOne, allowing your agentic bug bounty pipeline to target real programs with proper scope enforcement.

## Features

- **Automatic Scope Import**: Fetch program details including in-scope/out-of-scope assets
- **GraphQL API Support**: Uses HackerOne's public GraphQL for complete data
- **Fallback Scraping**: Falls back to page scraping if GraphQL fails
- **Policy Extraction**: Parses program rules, rate limits, and excluded vuln types
- **Bounty Information**: Extracts bounty ranges and statistics
- **Direct Integration**: Automatically sets scope for your scanning pipeline

## Quick Start

### CLI Usage

```bash
# Fetch a single program
python tools/h1_scope_fetcher.py fetch 23andme_bbp

# Fetch from URL
python tools/h1_scope_fetcher.py fetch "https://hackerone.com/23andme_bbp?type=team"

# Fetch and immediately start scanning
python tools/h1_scope_fetcher.py fetch hackerone --run

# Search for programs
python tools/h1_scope_fetcher.py search "fintech"

# List popular bounty programs
python tools/h1_scope_fetcher.py list --top 20

# Batch fetch multiple programs
python tools/h1_scope_fetcher.py batch hackerone shopify github
```

### MCP API Usage

The integration adds three new endpoints to the MCP server:

#### Import a Program Scope

```bash
curl -X POST http://localhost:8000/mcp/import_h1_scope \
  -H "Content-Type: application/json" \
  -d '{"handle": "23andme_bbp", "auto_set_scope": true}'
```

Response:
```json
{
  "program_name": "23andMe",
  "program_handle": "23andme_bbp",
  "program_url": "https://hackerone.com/23andme_bbp",
  "in_scope_count": 15,
  "out_of_scope_count": 8,
  "primary_targets": ["https://www.23andme.com", "https://api.23andme.com"],
  "secondary_targets": [],
  "bounty_ranges": {
    "low": {"min": 150, "max": 300},
    "medium": {"min": 500, "max": 1000},
    "high": {"min": 2500, "max": 5000},
    "critical": {"min": 7500, "max": 15000}
  },
  "scope_file": "/path/to/output_zap/scopes/23andme_bbp.json",
  "scope_set": true
}
```

#### Search Programs

```bash
curl -X POST http://localhost:8000/mcp/search_h1_programs \
  -H "Content-Type: application/json" \
  -d '{"query": "crypto", "bounties_only": true, "limit": 10}'
```

#### Get Program Details

```bash
curl http://localhost:8000/mcp/h1_program/hackerone
```

### Python API Usage

```python
from tools.h1_client import H1Client, fetch_and_save_scope

# Simple: fetch and save scope
program = fetch_and_save_scope("23andme_bbp", output_path="scope.json")

# Advanced: use client directly
client = H1Client()
program = client.fetch_program("23andme_bbp")

# Access scope details
for asset in program.in_scope_assets:
    print(f"{asset.asset_type.value}: {asset.identifier}")
    if asset.instruction:
        print(f"  Note: {asset.instruction}")

# Generate scope.json for runner
scope = program.to_scope_json(include_out_of_scope=True)

# Search for programs
results = client.search_programs(query="fintech", limit=20)
```

## Scope Format

The generated `scope.json` is compatible with the existing agentic runner:

```json
{
  "program_name": "23andMe",
  "program_handle": "23andme_bbp",
  "program_url": "https://hackerone.com/23andme_bbp",
  "primary_targets": [
    "https://www.23andme.com",
    "https://api.23andme.com"
  ],
  "secondary_targets": [],
  "rules": {
    "rate_limit": "10 requests per second",
    "safe_harbor": true,
    "allow_automated": true,
    "excluded_vuln_types": ["social engineering", "phishing"],
    "requires_poc": true
  },
  "in_scope": [
    {
      "url": "https://www.23andme.com",
      "target": "*.23andme.com",
      "type": "WILDCARD",
      "bounty_eligible": true,
      "instruction": "Main web properties"
    }
  ],
  "out_of_scope": [
    {
      "target": "store.23andme.com",
      "type": "URL",
      "instruction": "Third-party store platform"
    }
  ],
  "bounties": {
    "low": {"min": 150, "max": 300},
    "medium": {"min": 500, "max": 1000},
    "high": {"min": 2500, "max": 5000},
    "critical": {"min": 7500, "max": 15000}
  }
}
```

## Workflow for Container Cluster

To distribute work across a container cluster:

1. **Fetch Program Scope**:
   ```python
   from tools.h1_client import H1Client
   
   client = H1Client()
   program = client.fetch_program("target_program")
   ```

2. **Generate Per-Target Scope Files**:
   ```python
   for asset in program.in_scope_assets:
       if asset.asset_type.value in ("URL", "WILDCARD", "API"):
           target_scope = {
               "program_name": program.name,
               "primary_targets": [asset.to_target_url()],
               "secondary_targets": [],
               "rules": program.policy.to_dict(),
           }
           # Save to shared storage for workers
           save_scope(target_scope, f"scopes/{asset.identifier}.json")
   ```

3. **Worker Container Job**:
   ```python
   # Each worker picks up a scope file
   import os
   import json
   
   scope_file = os.environ.get("SCOPE_FILE")
   with open(scope_file) as f:
       scope = json.load(f)
   
   # Run full scan on this target
   from agentic_runner import run_full_scan_via_mcp
   run_full_scan_via_mcp(scope)
   ```

## Asset Types

The following HackerOne asset types are supported:

| Type | Description | Target URL Generated |
|------|-------------|---------------------|
| URL | Specific URLs | Yes, as-is |
| WILDCARD | Wildcard domains (*.example.com) | Yes, base domain |
| API | API endpoints | Yes |
| CIDR | IP ranges | No (requires special handling) |
| MOBILE_APPLICATION | iOS/Android apps | No |
| SOURCE_CODE | Git repos, etc. | No |
| HARDWARE | IoT devices | No |
| SMART_CONTRACT | Blockchain contracts | No |

## Policy Extraction

The tool extracts the following policy information:

- **Rate limits**: Parsed from program rules
- **Excluded vulnerabilities**: DoS, social engineering, etc.
- **Safe harbor status**: Whether safe harbor applies
- **Automated testing**: Whether automated tools are allowed
- **Disclosure timeline**: Coordinated disclosure period

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `H1_API_TOKEN` | HackerOne API token (for private programs) | None |
| `H1_API_USER` | HackerOne username for API auth | None |
| `H1_RATE_LIMIT` | Requests per second to H1 | 1.0 |

## Limitations

- **Private Programs**: Requires API authentication (set `H1_API_TOKEN`)
- **Rate Limiting**: HackerOne enforces rate limits; the client respects them
- **Policy Parsing**: Some program rules may not be fully parsed
- **Asset Validation**: URLs are extracted but not validated for accessibility

## Files

- `tools/h1_models.py` - Data models for H1 programs
- `tools/h1_client.py` - HackerOne API client
- `tools/h1_scope_fetcher.py` - CLI tool for scope fetching
- `mcp_zap_server.py` - MCP endpoints (import_h1_scope, search_h1_programs)

