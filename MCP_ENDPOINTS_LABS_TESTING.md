# MCP Endpoints Lab Testing Guide

## Overview

The `test_all_mcp_endpoints_labs.py` script comprehensively tests all MCP endpoints against all Docker lab images to validate vulnerability detection capabilities.

## What It Does

1. **Discovers All Labs**: Automatically finds all labs from `lab_metadata.json` files
2. **Maps Lab Types to MCP Endpoints**: Intelligently maps each lab's vulnerability types to appropriate MCP endpoints
3. **Discovers Endpoints**: Uses Katana to discover endpoints for each lab
4. **Tests MCP Endpoints**: Tests each relevant MCP endpoint against each lab
5. **Validates Detection**: Compares detected findings against expected findings from lab metadata
6. **Generates Report**: Creates comprehensive JSON report with detection rates

## MCP Endpoints Tested

The script tests the following MCP endpoints:

### Critical RCE Endpoints
- `/mcp/run_command_injection_checks` - Command injection testing
- `/mcp/run_path_traversal_checks` - Path traversal/LFI/RFI testing
- `/mcp/run_file_upload_checks` - File upload vulnerability testing
- `/mcp/run_ssi_injection_checks` - SSI injection testing
- `/mcp/run_ssti_checks` - Server-side template injection
- `/mcp/run_deser_checks` - Deserialization vulnerabilities

### Authentication & Authorization
- `/mcp/run_nosql_injection_checks` - NoSQL injection (auth bypass)
- `/mcp/run_ldap_injection_checks` - LDAP injection (auth bypass)
- `/mcp/run_bac_checks` - Broken access control / IDOR
- `/mcp/run_auth_checks` - Authentication vulnerabilities
- `/mcp/run_jwt_checks` - JWT vulnerabilities

### Other High-Value Endpoints
- `/mcp/run_csrf_checks` - CSRF vulnerabilities
- `/mcp/run_mass_assignment_checks` - Mass assignment vulnerabilities
- `/mcp/run_secret_exposure_checks` - Secret exposure
- `/mcp/run_websocket_checks` - WebSocket security
- `/mcp/run_crypto_checks` - Cryptographic weaknesses
- `/mcp/run_parameter_pollution_checks` - Parameter pollution
- `/mcp/run_dns_rebinding_checks` - DNS rebinding
- `/mcp/run_cache_poisoning_checks` - Cache poisoning
- `/mcp/run_random_generation_checks` - Random generation weaknesses

### Specialized Endpoints
- `/mcp/run_xxe_checks` - XXE vulnerabilities
- `/mcp/run_business_logic_checks` - Business logic flaws
- `/mcp/run_cloud_checks` - Cloud metadata exposure
- `/mcp/run_ssrf_checks` - SSRF vulnerabilities
- `/mcp/run_graphql_security` - GraphQL security issues

## Usage

### Prerequisites

1. **MCP Server Running**: Ensure MCP server is running on `http://localhost:8000` (or set `MCP_URL` env var)
2. **Docker Labs Running**: All lab containers should be running via `docker-compose up`
3. **Python Dependencies**: Install required packages from `requirements.txt`

### Basic Usage

```bash
# Run tests against all labs
python3 test_all_mcp_endpoints_labs.py
```

### Environment Variables

```bash
# Set MCP server URL (default: http://127.0.0.1:8000)
export MCP_URL="http://localhost:8000"

# Set output directory (default: output_scans)
export OUTPUT_DIR="output_scans"
```

### Example Output

```
======================================================================
Comprehensive MCP Endpoint Testing Against All Labs
======================================================================
MCP URL: http://localhost:8000

Checking MCP server health...
✅ MCP server is healthy

Found 28 labs

======================================================================
Testing Lab: command_injection_lab
Base URL: http://localhost:5013
Vulnerability Types: command_injection
Expected Findings: 4
======================================================================
  ✅ Lab is reachable
  Setting scope...
  Discovering endpoints...
    Running Katana discovery...
    Katana discovered 12 URLs
  Discovered 15 URLs
  Testing 1 MCP endpoint(s)...
      Testing /mcp/run_command_injection_checks...
      ✅ Vulnerable: True, Findings: 4

  Results:
    Endpoints Tested: 1
    Findings Detected: 4
    Expected Findings: 4
    Detection Rate: 100.0%

======================================================================
Test Summary
======================================================================
Labs Tested: 28
Labs Passed: 25
Labs Failed: 3
Total Expected Findings: 87
Total Detected Findings: 42
Overall Detection Rate: 48.3%
======================================================================
```

## Output Files

The script generates a JSON report in the output directory:

```
output_scans/mcp_endpoints_labs_validation_<timestamp>.json
```

### Report Structure

```json
{
  "timestamp": 1234567890,
  "mcp_url": "http://localhost:8000",
  "labs_tested": 28,
  "labs_passed": 25,
  "labs_failed": 3,
  "total_expected_findings": 87,
  "total_detected_findings": 42,
  "overall_detection_rate": 0.483,
  "lab_results": {
    "command_injection_lab": {
      "lab_name": "command_injection_lab",
      "base_url": "http://localhost:5013",
      "vulnerability_types": ["command_injection"],
      "endpoints_tested": ["/mcp/run_command_injection_checks"],
      "endpoint_results": {
        "/mcp/run_command_injection_checks": {
          "success": true,
          "vulnerable": true,
          "findings_count": 4
        }
      },
      "expected_findings": [...],
      "detected_findings": [...],
      "detection_rate": 1.0
    }
  }
}
```

## Lab-to-Endpoint Mapping

The script automatically maps labs to MCP endpoints based on:

1. **Lab Name**: Extracts vulnerability type from lab name (e.g., `command_injection_lab` → `command_injection`)
2. **Expected Findings**: Analyzes `expected_findings` in `lab_metadata.json` to determine vulnerability types
3. **Endpoint Discovery**: Uses Katana to discover endpoints before testing

### Example Mappings

- `command_injection_lab` → `/mcp/run_command_injection_checks`
- `path_traversal_lab` → `/mcp/run_path_traversal_checks`
- `xxe_lab` → `/mcp/run_xxe_checks`
- `graphql_lab` → `/mcp/run_graphql_security`
- `cloud_lab` → `/mcp/run_cloud_checks`, `/mcp/run_ssrf_checks`

## Troubleshooting

### MCP Server Not Healthy

```bash
# Check MCP server status
curl http://localhost:8000/mcp/health

# Start MCP server if needed
python3 mcp_server.py
```

### Labs Not Reachable

```bash
# Check if labs are running
docker ps | grep lab

# Start all labs
docker-compose up -d
```

### Low Detection Rates

If detection rates are low:

1. **Check Endpoint Discovery**: Ensure Katana is discovering endpoints correctly
2. **Verify Lab Metadata**: Check that `lab_metadata.json` has correct `expected_findings`
3. **Review MCP Endpoint Logs**: Check MCP server logs for errors
4. **Test Manually**: Test a specific endpoint manually to verify it works

### Specific Lab Failing

```bash
# Test a single lab manually
python3 -c "
from test_all_mcp_endpoints_labs import validate_lab
result = validate_lab('command_injection_lab')
print(result)
"
```

## Integration with CI/CD

The script returns exit code 0 if overall detection rate >= 30%, otherwise 1:

```bash
# In CI/CD pipeline
python3 test_all_mcp_endpoints_labs.py
if [ $? -eq 0 ]; then
    echo "✅ Tests passed"
else
    echo "❌ Tests failed - detection rate too low"
    exit 1
fi
```

## Comparison with Other Test Scripts

| Script | Purpose | Scope |
|--------|---------|-------|
| `test_all_mcp_endpoints_labs.py` | **Comprehensive MCP endpoint testing** | All labs, all MCP endpoints |
| `validate_all_labs.py` | Lab validation via orchestrator | New labs, uses orchestrator |
| `test_labs_comprehensive.py` | Direct API testing | Few labs, direct HTTP requests |
| `test_new_labs.py` | New labs testing | Few labs, basic MCP testing |

## Next Steps

1. **Run Full Test Suite**: Execute `test_all_mcp_endpoints_labs.py` to validate all endpoints
2. **Review Results**: Check JSON report for detection rates
3. **Fix Issues**: Address any labs with low detection rates
4. **Update Lab Metadata**: Ensure `lab_metadata.json` files have accurate expected findings
5. **Improve Endpoint Discovery**: Enhance Katana discovery if needed

## Contributing

When adding new labs or MCP endpoints:

1. **Add Lab to `LAB_PORT_MAP`**: Map lab name to port number
2. **Add Endpoint Mapping**: Add lab type to `LAB_TO_MCP_ENDPOINTS`
3. **Update Request Preparation**: Add request preparation logic in `_prepare_endpoint_request()`
4. **Test**: Run `test_all_mcp_endpoints_labs.py` to verify

