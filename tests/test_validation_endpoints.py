"""Tests for validation endpoints with POC validation."""

import json
import os
from pathlib import Path
from unittest import mock

import pytest

from tests.test_utils_poc_validation import (
    MCPTestClient,
    create_mock_finding,
    create_mock_validation_evidence,
    assert_poc_validated,
    assert_poc_quality,
    assert_validation_evidence_complete,
)


class TestXSSValidation:
    """Tests for XSS validation with Dalfox."""
    
    def test_dalfox_validation_confirmed(self, client, scoped_program, tmp_output_dir):
        """Test Dalfox validation when XSS is confirmed."""
        # This would require actual Dalfox binary or mocking
        # For now, test the endpoint exists and accepts requests
        mcp = MCPTestClient(client)
        
        # Note: This endpoint may not exist as a direct MCP endpoint
        # It's likely called internally during triage
        # Test that validation evidence can be collected
        
        finding = create_mock_finding(vuln_type="xss")
        evidence = create_mock_validation_evidence("dalfox", confirmed=True)
        
        finding["validation"] = {"dalfox": evidence, "dalfox_confirmed": True}
        
        assert_poc_validated(finding, expected=True)
        assert_poc_quality(finding, min_quality="high")
    
    def test_dalfox_poc_capture(self, client, tmp_output_dir):
        """Test that Dalfox validation captures POC evidence."""
        from tools.poc_capture import POCCapture
        
        capture = POCCapture(output_dir=str(tmp_output_dir / "poc_captures"))
        
        # Simulate capturing a request/response
        capture_data = capture.capture_request_response(
            method="GET",
            url="https://example.com/search?q=<script>alert(1)</script>",
        )
        
        assert "request" in capture_data
        assert "response" in capture_data
        assert "timestamp" in capture_data
        
        # Save capture
        filepath = capture.save_capture(capture_data, finding_id="test-xss-1")
        assert Path(filepath).exists()
    
    def test_dalfox_evidence_quality(self, client):
        """Test POC quality scoring for Dalfox evidence."""
        from tools.poc_validator import validate_poc
        
        finding = create_mock_finding(vuln_type="xss")
        finding["validation"] = {
            "dalfox": create_mock_validation_evidence("dalfox", confirmed=True),
            "dalfox_confirmed": True,
        }
        finding["validation_status"] = "validated"
        finding["validation_engines"] = ["dalfox"]
        
        result = validate_poc(finding)
        
        assert result["poc_validated"] is True
        assert result["poc_quality_score"] in ("high", "medium", "low")
        assert "dalfox" in result["reasons"]


class TestSQLiValidation:
    """Tests for SQL injection validation with SQLmap."""
    
    def test_sqlmap_validation(self, client, scoped_program):
        """Test SQLmap validation endpoint."""
        mcp = MCPTestClient(client)
        
        result = mcp.post("/run_sqlmap", {
            "target": "http://example.com/search?id=1"
        })
        
        assert "output_dir" in result or "returncode" in result
        assert "endpoint" in result or "target" in result
    
    def test_sqlmap_output_parsing(self, client):
        """Test parsing SQLmap output for POC evidence."""
        finding = create_mock_finding(vuln_type="sqli")
        finding["validation"] = {
            "sqlmap": create_mock_validation_evidence("sqlmap", confirmed=True),
        }
        finding["validation_status"] = "validated"
        finding["validation_engines"] = ["sqlmap"]
        
        from tools.poc_validator import validate_poc
        result = validate_poc(finding)
        
        assert result["poc_validated"] is True
        if finding["validation"]["sqlmap"].get("dbms"):
            assert "sqlmap" in result["reasons"]
    
    def test_sqlmap_poc_evidence(self, client):
        """Test SQLmap POC evidence collection."""
        finding = create_mock_finding(vuln_type="sqli")
        finding["validation"] = {
            "sqlmap": {
                "engine_result": "confirmed",
                "dbms": "MySQL",
                "vulnerable_params": ["id"],
                "validation_confidence": "high",
            },
        }
        finding["validation_status"] = "validated"
        finding["validation_engines"] = ["sqlmap"]
        
        from tools.poc_validator import validate_poc
        result = validate_poc(finding)
        
        assert result["poc_validated"] is True
        assert result["poc_quality_score"] in ("high", "medium")


class TestBACValidation:
    """Tests for Broken Access Control validation."""
    
    def test_bac_checks(self, client, scoped_program):
        """Test BAC checks endpoint."""
        mcp = MCPTestClient(client)
        
        result = mcp.run_bac_checks("example.com")
        
        assert "meta" in result or "confirmed_issues_count" in result
    
    def test_bac_poc_validation(self, client):
        """Test BAC POC validation."""
        finding = create_mock_finding(vuln_type="bac")
        finding["validation"] = {
            "bac": create_mock_validation_evidence("bac", confirmed=True),
        }
        finding["validation_status"] = "validated"
        finding["validation_engines"] = ["bac"]
        
        from tools.poc_validator import validate_poc
        result = validate_poc(finding)
        
        assert result["poc_validated"] is True
    
    def test_bac_evidence_completeness(self, client):
        """Test BAC evidence completeness."""
        finding = create_mock_finding(vuln_type="bac")
        finding["validation"] = {
            "bac": {
                "engine_result": "confirmed",
                "confirmed_issues_count": 2,
                "checks_count": 10,
                "validation_confidence": "high",
            },
        }
        finding["validation_status"] = "validated"
        finding["validation_engines"] = ["bac"]
        
        from tools.poc_validator import validate_poc
        result = validate_poc(finding)
        
        if result["poc_validated"] and result["poc_quality_score"] in ("high", "medium"):
            assert result["validation_evidence_complete"] is True


class TestSSRFValidation:
    """Tests for SSRF validation."""
    
    def test_ssrf_checks(self, client, scoped_program):
        """Test SSRF checks endpoint."""
        mcp = MCPTestClient(client)
        
        result = mcp.run_ssrf_checks(
            "http://example.com/api/fetch",
            param="url"
        )
        
        assert "meta" in result or "confirmed_issues_count" in result
    
    def test_ssrf_target_reachability(self, client):
        """Test SSRF target reachability validation."""
        finding = create_mock_finding(vuln_type="ssrf")
        finding["validation"] = {
            "ssrf": {
                "engine_result": "confirmed",
                "confirmed_issues_count": 1,
                "targets_reached": ["http://internal:8080"],
                "validation_confidence": "high",
            },
        }
        finding["validation_status"] = "validated"
        finding["validation_engines"] = ["ssrf"]
        
        from tools.poc_validator import validate_poc
        result = validate_poc(finding)
        
        assert result["poc_validated"] is True
        if finding["validation"]["ssrf"].get("targets_reached"):
            assert "ssrf" in result["reasons"]
    
    def test_ssrf_poc_quality(self, client):
        """Test SSRF POC quality scoring."""
        finding = create_mock_finding(vuln_type="ssrf")
        finding["validation"] = {
            "ssrf": create_mock_validation_evidence("ssrf", confirmed=True),
        }
        finding["validation_status"] = "validated"
        finding["validation_engines"] = ["ssrf"]
        
        from tools.poc_validator import validate_poc
        result = validate_poc(finding)
        
        assert_poc_quality(finding, min_quality="medium")


class TestOAuthValidation:
    """Tests for OAuth/OIDC validation."""
    
    def test_oauth_checks(self, client, scoped_program):
        """Test OAuth checks endpoint."""
        mcp = MCPTestClient(client)
        
        result = mcp.post("/run_oauth_checks", {"host": "example.com"})
        
        assert "vulnerable_count" in result or "meta" in result
    
    def test_oauth_poc_validation(self, client):
        """Test OAuth POC validation."""
        finding = create_mock_finding(vuln_type="oauth")
        finding["validation"] = {
            "oauth": {
                "engine_result": "confirmed",
                "vulnerable_count": 2,
                "validation_confidence": "high",
            },
        }
        finding["validation_status"] = "validated"
        finding["validation_engines"] = ["oauth"]
        
        from tools.poc_validator import validate_poc
        result = validate_poc(finding)
        
        assert result["poc_validated"] is True
    
    def test_oauth_evidence_collection(self, client):
        """Test OAuth evidence collection."""
        finding = create_mock_finding(vuln_type="oauth")
        finding["validation"] = {
            "oauth": {
                "engine_result": "confirmed",
                "vulnerable_count": 1,
                "vulnerable_tests": ["open_redirect", "state_fixation"],
            },
        }
        finding["validation_status"] = "validated"
        finding["validation_engines"] = ["oauth"]
        
        from tools.poc_validator import validate_poc
        result = validate_poc(finding)
        
        assert result["poc_validated"] is True
        assert "oauth" in result["reasons"]


class TestRaceConditionValidation:
    """Tests for race condition validation."""
    
    def test_race_checks(self, client, scoped_program):
        """Test race condition checks endpoint."""
        mcp = MCPTestClient(client)
        
        result = mcp.post("/run_race_checks", {"host": "example.com"})
        
        assert "vulnerable_count" in result or "meta" in result
    
    def test_race_poc_validation(self, client):
        """Test race condition POC validation."""
        finding = create_mock_finding(vuln_type="race")
        finding["validation"] = {
            "race": {
                "engine_result": "confirmed",
                "vulnerable_count": 1,
                "validation_confidence": "high",
            },
        }
        finding["validation_status"] = "validated"
        finding["validation_engines"] = ["race"]
        
        from tools.poc_validator import validate_poc
        result = validate_poc(finding)
        
        assert result["poc_validated"] is True
    
    def test_race_parallel_requests(self, client):
        """Test race condition parallel request handling."""
        # This would test the actual race validator implementation
        # For now, verify evidence structure
        finding = create_mock_finding(vuln_type="race")
        finding["validation"] = {
            "race": {
                "engine_result": "confirmed",
                "vulnerable_count": 1,
                "vulnerable_tests": ["parallel_account_creation"],
            },
        }
        finding["validation_status"] = "validated"
        finding["validation_engines"] = ["race"]
        
        from tools.poc_validator import validate_poc
        result = validate_poc(finding)
        
        assert result["poc_validated"] is True


class TestRequestSmugglingValidation:
    """Tests for HTTP request smuggling validation."""
    
    def test_smuggling_checks(self, client, scoped_program):
        """Test request smuggling checks endpoint."""
        mcp = MCPTestClient(client)
        
        result = mcp.post("/run_smuggling_checks", {"host": "example.com"})
        
        assert "vulnerable" in result or "meta" in result
    
    def test_smuggling_poc_validation(self, client):
        """Test request smuggling POC validation."""
        finding = create_mock_finding(vuln_type="smuggling")
        finding["validation"] = {
            "smuggling": {
                "engine_result": "confirmed",
                "vulnerable": True,
                "validation_confidence": "high",
            },
        }
        finding["validation_status"] = "validated"
        finding["validation_engines"] = ["smuggling"]
        
        from tools.poc_validator import validate_poc
        result = validate_poc(finding)
        
        assert result["poc_validated"] is True
    
    def test_smuggling_timing_analysis(self, client):
        """Test smuggling timing-based detection."""
        finding = create_mock_finding(vuln_type="smuggling")
        finding["validation"] = {
            "smuggling": {
                "engine_result": "confirmed",
                "vulnerable": True,
                "tests": [
                    {"type": "CL.TE", "vulnerable": True, "elapsed": 0.5},
                ],
            },
        }
        finding["validation_status"] = "validated"
        finding["validation_engines"] = ["smuggling"]
        
        from tools.poc_validator import validate_poc
        result = validate_poc(finding)
        
        assert result["poc_validated"] is True


class TestGraphQLValidation:
    """Tests for GraphQL security validation."""
    
    def test_graphql_security(self, client, scoped_program):
        """Test GraphQL security endpoint."""
        mcp = MCPTestClient(client)
        
        result = mcp.post("/run_graphql_security", {
            "endpoint": "http://example.com/graphql"
        })
        
        assert "vulnerable" in result or "meta" in result
    
    def test_graphql_poc_validation(self, client):
        """Test GraphQL POC validation."""
        finding = create_mock_finding(vuln_type="graphql")
        finding["validation"] = {
            "graphql": {
                "engine_result": "confirmed",
                "vulnerable": True,
                "validation_confidence": "high",
            },
        }
        finding["validation_status"] = "validated"
        finding["validation_engines"] = ["graphql"]
        
        from tools.poc_validator import validate_poc
        result = validate_poc(finding)
        
        assert result["poc_validated"] is True
    
    def test_graphql_depth_attacks(self, client):
        """Test GraphQL query depth attack validation."""
        finding = create_mock_finding(vuln_type="graphql")
        finding["validation"] = {
            "graphql": {
                "engine_result": "confirmed",
                "vulnerable": True,
                "depth_attack": {"vulnerable": True, "depth": 20},
            },
        }
        finding["validation_status"] = "validated"
        finding["validation_engines"] = ["graphql"]
        
        from tools.poc_validator import validate_poc
        result = validate_poc(finding)
        
        assert result["poc_validated"] is True


class TestNucleiPOCValidation:
    """Tests for Nuclei POC validation (when implemented)."""
    
    def test_validate_poc_with_nuclei_endpoint_exists(self, client):
        """Test that /mcp/validate_poc_with_nuclei endpoint exists or is documented."""
        resp = client.post("/mcp/validate_poc_with_nuclei", json={
            "target": "http://example.com",
            "templates": ["http/technologies/tech-detect.yaml"]
        })
        
        # Endpoint may not be implemented yet
        # Document the expected behavior
        if resp.status_code == 404:
            pytest.skip("Endpoint /mcp/validate_poc_with_nuclei not yet implemented")
        
        assert resp.status_code in (200, 400, 422)
        if resp.status_code == 200:
            data = resp.json()
            assert "validated" in data or "match_count" in data
    
    def test_custom_nuclei_template_generation(self, client):
        """Test AI-generated custom Nuclei template validation."""
        # This will test the AI template generator when implemented
        # For now, verify the concept
        pytest.skip("AI template generation not yet implemented")
    
    def test_nuclei_poc_execution(self, client, scoped_program, tmp_output_dir):
        """Test executing custom Nuclei templates for POC."""
        # This will test template execution when implemented
        pytest.skip("Custom Nuclei template execution not yet implemented")
    
    def test_nuclei_poc_evidence(self, client):
        """Test collecting Nuclei POC evidence."""
        # This will test evidence collection from Nuclei execution
        pytest.skip("Nuclei POC evidence collection not yet implemented")

