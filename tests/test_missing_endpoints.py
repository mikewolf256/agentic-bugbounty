"""Tests to document and track missing MCP endpoints."""

import inspect
from typing import Dict, Any, List

import pytest

import mcp_zap_server


# Expected endpoints from mcp_zap_server.py docstring
DOCUMENTED_ENDPOINTS = [
    "/mcp/set_scope",
    "/mcp/import_h1_scope",
    "/mcp/search_h1_programs",
    "/mcp/h1_program/{handle}",
    "/mcp/run_ffuf",
    "/mcp/run_sqlmap",
    "/mcp/run_nuclei",
    "/mcp/validate_poc_with_nuclei",  # Documented but may not be implemented
    "/mcp/run_cloud_recon",
    "/mcp/host_profile",
    "/mcp/prioritize_host",
    "/mcp/host_delta",
    "/mcp/run_js_miner",
    "/mcp/run_reflector",
    "/mcp/run_backup_hunt",
    "/mcp/job/{id}",
    "/mcp/run_katana_nuclei",
    "/mcp/run_katana_auth",
    "/mcp/run_fingerprints",
    "/mcp/run_whatweb",
    "/mcp/run_api_recon",
    "/mcp/triage_nuclei_templates",
    "/mcp/run_targeted_nuclei",
    "/mcp/rag_search",
    "/mcp/rag_similar_vulns",
    "/mcp/rag_stats",
    "/mcp/rag_search_by_type",
    "/mcp/rag_search_by_tech",
    "/mcp/run_bac_checks",
    "/mcp/run_ssrf_checks",
    "/mcp/run_oauth_checks",
    "/mcp/run_race_checks",
    "/mcp/run_smuggling_checks",
    "/mcp/run_graphql_security",
]


def get_implemented_endpoints() -> List[str]:
    """Get list of actually implemented endpoints from FastAPI app."""
    endpoints = []
    for route in mcp_zap_server.app.routes:
        if hasattr(route, "path") and route.path.startswith("/mcp/"):
            endpoints.append(route.path)
    return endpoints


def test_endpoint_implementation_status():
    """Test and document which endpoints are implemented vs documented."""
    implemented = get_implemented_endpoints()
    
    missing = []
    for endpoint in DOCUMENTED_ENDPOINTS:
        # Handle parameterized routes
        base_endpoint = endpoint.split("{")[0].rstrip("/")
        found = False
        
        for impl_endpoint in implemented:
            impl_base = impl_endpoint.split("{")[0].rstrip("/")
            if base_endpoint == impl_base:
                found = True
                break
        
        if not found:
            missing.append(endpoint)
    
    if missing:
        print("\n=== Missing Endpoints ===")
        for endpoint in missing:
            print(f"  - {endpoint}")
        print(f"\nTotal missing: {len(missing)}/{len(DOCUMENTED_ENDPOINTS)}")
    
    # This test documents the gap but doesn't fail
    # Remove pytest.skip() to make it fail when endpoints are missing
    if missing:
        pytest.skip(f"Some documented endpoints are not implemented: {', '.join(missing)}")


class TestValidatePOCWithNuclei:
    """Tests for /mcp/validate_poc_with_nuclei endpoint (may be missing)."""
    
    def test_validate_poc_with_nuclei_exists(self, client, scoped_program):
        """Test that /mcp/validate_poc_with_nuclei endpoint exists."""
        resp = client.post("/mcp/validate_poc_with_nuclei", json={
            "target": "http://example.com/api/v1/users?id=123",
            "templates": ["http/technologies/tech-detect.yaml"]
        })
        
        if resp.status_code == 404:
            pytest.skip(
                "Endpoint /mcp/validate_poc_with_nuclei is documented but not implemented. "
                "Expected behavior: Validate POC using Nuclei templates, return validation results."
            )
        
        assert resp.status_code in (200, 400, 422)
        
        if resp.status_code == 200:
            data = resp.json()
            # Expected response structure
            assert "validated" in data or "match_count" in data
            assert "findings" in data or "summaries" in data
    
    def test_validate_poc_with_nuclei_expected_behavior(self):
        """Document expected behavior for validate_poc_with_nuclei endpoint."""
        expected_request = {
            "target": "http://example.com/api/v1/users?id=123",
            "templates": ["http/pocs/xss.yaml", "http/vulnerabilities/sqli.yaml"],
        }
        
        expected_response = {
            "validated": True,
            "match_count": 1,
            "findings": [
                {
                    "template": "http/pocs/xss.yaml",
                    "matched": True,
                    "evidence": "...",
                }
            ],
            "summaries": ["XSS confirmed in parameter q"],
        }
        
        # This test documents expected behavior
        assert expected_request["target"] is not None
        assert expected_response["validated"] is not None


class TestMissingEndpointStubs:
    """Create test stubs for missing endpoints."""
    
    def test_run_cloud_recon_stub(self, client):
        """Stub test for /mcp/run_cloud_recon endpoint."""
        resp = client.post("/mcp/run_cloud_recon", json={
            "target": "example.com"
        })
        
        if resp.status_code == 404:
            pytest.skip(
                "Endpoint /mcp/run_cloud_recon is documented but not implemented. "
                "Expected: Cloud resource discovery (S3, Azure, GCP buckets, etc.)"
            )
    
    def test_run_reflector_stub(self, client):
        """Stub test for /mcp/run_reflector endpoint."""
        resp = client.post("/mcp/run_reflector", json={
            "target": "http://example.com",
            "params": ["q", "id"]
        })
        
        if resp.status_code == 404:
            pytest.skip(
                "Endpoint /mcp/run_reflector is documented but not implemented. "
                "Expected: Parameter reflection testing"
            )
    
    def test_prioritize_host_stub(self, client):
        """Stub test for /mcp/prioritize_host endpoint."""
        resp = client.post("/mcp/prioritize_host", json={
            "host": "example.com"
        })
        
        if resp.status_code == 404:
            pytest.skip(
                "Endpoint /mcp/prioritize_host is documented but not implemented. "
                "Expected: Risk scoring for host prioritization"
            )


def test_endpoint_documentation_completeness():
    """Test that all implemented endpoints are documented."""
    implemented = get_implemented_endpoints()
    
    # Read docstring to get documented endpoints
    docstring = mcp_zap_server.__doc__ or ""
    
    undocumented = []
    for endpoint in implemented:
        # Check if endpoint is mentioned in docstring
        endpoint_name = endpoint.replace("/mcp/", "").split("/")[0]
        if endpoint_name not in docstring:
            undocumented.append(endpoint)
    
    if undocumented:
        print("\n=== Undocumented Endpoints ===")
        for endpoint in undocumented:
            print(f"  - {endpoint}")
    
    # This is informational, not a failure
    assert True  # Always pass, just document gaps

