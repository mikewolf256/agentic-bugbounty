# MCP Server Test Suite

Comprehensive test suite for validating MCP server functionality with POC validation.

## Test Structure

### Core Test Files

- **`conftest.py`** - Pytest fixtures and configuration
- **`test_utils_poc_validation.py`** - Test utilities and helpers
- **`test_mcp_endpoints_comprehensive.py`** - Core MCP endpoint tests
- **`test_validation_endpoints.py`** - Validation endpoint tests with POC validation
- **`test_poc_validation_pipeline.py`** - Complete POC validation pipeline tests
- **`test_mcp_poc_validation_labs.py`** - Integration tests against Docker labs
- **`test_missing_endpoints.py`** - Documentation of missing endpoints

### Test Fixtures

- **`fixtures/`** - Sample test data (findings, host profiles, etc.)

## Running Tests

### All Tests

```bash
pytest tests/
```

### Specific Test Suites

```bash
# Core endpoint tests
pytest tests/test_mcp_endpoints_comprehensive.py

# Validation endpoint tests
pytest tests/test_validation_endpoints.py

# POC validation pipeline tests
pytest tests/test_poc_validation_pipeline.py

# Lab integration tests (requires Docker labs running)
pytest tests/test_mcp_poc_validation_labs.py

# Missing endpoint documentation
pytest tests/test_missing_endpoints.py
```

### With Coverage

```bash
pytest tests/ --cov=mcp_zap_server --cov=tools --cov-report=html
```

## Prerequisites

1. **MCP Server Running**: Start the MCP server before running tests
   ```bash
   python mcp_zap_server.py
   ```

2. **Docker Labs** (for lab integration tests):
   ```bash
   cd labs/xss_js_secrets && docker-compose up -d
   cd labs/idor_auth && docker-compose up -d
   cd labs/auth_scan_lab && docker-compose up -d
   ```

3. **Environment Variables**:
   - `OUTPUT_DIR` - Output directory for test artifacts
   - `OPENAI_API_KEY` - For AI-driven tests (optional)
   - `MCP_BASE_URL` - MCP server URL (default: http://127.0.0.1:8000)

## Test Categories

### Unit Tests
Fast, isolated tests for individual functions and modules.

### Integration Tests
Tests that verify endpoint interactions and data flow.

### Lab Tests
Tests against known vulnerable Docker labs (slower, requires labs running).

### Smoke Tests
Quick validation of critical paths.

## Test Markers

Tests can be marked for selective execution:

```bash
# Run only fast tests
pytest -m "not slow"

# Run only lab tests
pytest -m "lab"

# Skip lab tests
pytest -m "not lab"
```

## Expected Test Coverage

- All documented MCP endpoints
- All validation endpoints with POC validation
- Complete validation pipeline (capture → validate → report)
- Report quality checking
- Missing endpoint documentation

## Troubleshooting

### Tests Fail with Connection Errors

Ensure MCP server is running:
```bash
python mcp_zap_server.py
```

### Lab Tests Skip

Ensure Docker labs are running:
```bash
docker ps | grep -E "xss|idor|auth"
```

### Import Errors

Ensure you're in the project root and dependencies are installed:
```bash
pip install -r requirements.txt
```

## Contributing

When adding new tests:

1. Use existing fixtures from `conftest.py`
2. Follow naming conventions: `test_<feature>_<scenario>`
3. Add appropriate markers for test categorization
4. Include docstrings explaining what is being tested
5. Use test utilities from `test_utils_poc_validation.py`

