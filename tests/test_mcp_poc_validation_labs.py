"""Integration tests for POC validation against known vulnerable labs."""

import json
import os
import time
from pathlib import Path
from typing import Dict, Any, Optional

import pytest
import requests

from tests.test_utils_poc_validation import (
    MCPTestClient,
    setup_test_scope,
    wait_for_job_completion,
    assert_poc_validated,
    assert_poc_quality,
)


# Lab configurations - these should match test_mcp_lab_simulation.py
LABS = {
    "xss_js_secrets": {
        "base_url": "http://localhost:5001",
        "description": "Reflected XSS in /search?q= and JS-exposed secrets",
        "expected_findings": {
            "xss": [{"url": "/search?q=<script>alert(1)</script>", "param": "q"}],
        },
    },
    "idor_auth": {
        "base_url": "http://localhost:5002",
        "description": "IDOR on /api/users/<id> with bearer token auth",
        "expected_findings": {
            "bac": [{"url": "/api/users/2", "requires_auth": True}],
        },
    },
    "auth_scan_lab": {
        "base_url": "http://localhost:5004",
        "description": "Comprehensive auth vulnerability lab",
        "expected_findings": {
            "bac": [
                {"url": "/api/users/3", "requires_auth": True},
                {"url": "/admin", "requires_auth": False},
            ],
        },
    },
}


def check_lab_reachable(lab_name: str) -> bool:
    """Check if a lab is reachable."""
    if lab_name not in LABS:
        return False
    
    lab = LABS[lab_name]
    try:
        resp = requests.get(lab["base_url"], timeout=5)
        return resp.status_code < 500
    except Exception:
        return False


@pytest.fixture
def lab_available(request):
    """Skip test if lab is not available."""
    lab_name = request.param
    if not check_lab_reachable(lab_name):
        pytest.skip(f"Lab {lab_name} is not reachable. Start with: cd labs/{lab_name} && docker-compose up -d")
    return lab_name


class TestXSSLabValidation:
    """Tests for XSS lab POC validation."""
    
    @pytest.mark.parametrize("lab_available", ["xss_js_secrets"], indirect=True)
    def test_xss_lab_dalfox_validation(self, client, lab_available):
        """Test XSS validation with Dalfox against XSS lab."""
        mcp = MCPTestClient(client)
        
        # Setup scope
        setup_test_scope(mcp, ["localhost:5001"])
        
        # Note: Dalfox validation is typically done during triage
        # This test verifies the validation evidence structure
        finding = {
            "id": "xss-lab-1",
            "name": "Reflected XSS",
            "url": f"{LABS[lab_available]['base_url']}/search?q=<script>alert(1)</script>",
            "parameter": "q",
            "category": "xss",
            "validation": {
                "dalfox": {
                    "engine_result": "confirmed",
                    "validation_confidence": "high",
                    "payload": "<script>alert(1)</script>",
                },
                "dalfox_confirmed": True,
            },
            "validation_status": "validated",
            "validation_engines": ["dalfox"],
        }
        
        from tools.poc_validator import validate_poc
        result = validate_poc(finding)
        
        assert result["poc_validated"] is True
        assert result["poc_quality_score"] in ("high", "medium")
    
    @pytest.mark.parametrize("lab_available", ["xss_js_secrets"], indirect=True)
    def test_xss_lab_poc_capture(self, client, lab_available, tmp_path):
        """Test capturing XSS POC from lab."""
        from tools.poc_capture import POCCapture
        
        capture = POCCapture(output_dir=str(tmp_path / "poc_captures"))
        
        # Capture request to XSS lab
        capture_data = capture.capture_request_response(
            method="GET",
            url=f"{LABS[lab_available]['base_url']}/search?q=<script>alert(1)</script>",
        )
        
        assert capture_data["response"]["status_code"] == 200
        assert "request" in capture_data
        assert "response" in capture_data
        
        # Save capture
        filepath = capture.save_capture(capture_data, finding_id="xss-lab-1")
        assert Path(filepath).exists()
    
    @pytest.mark.parametrize("lab_available", ["xss_js_secrets"], indirect=True)
    def test_xss_lab_report_generation(self, client, lab_available, tmp_path):
        """Test generating XSS report with POC."""
        finding = {
            "id": "xss-lab-1",
            "title": "Reflected XSS in Search Parameter",
            "summary": "XSS vulnerability in search parameter",
            "repro": "Navigate to /search?q=<script>alert(1)</script>",
            "impact": "User data compromise",
            "remediation": "Input validation and output encoding",
            "cvss_score": "7.5",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "cwe": "CWE-79",
            "confidence": "high",
            "validation": {
                "dalfox": {
                    "engine_result": "confirmed",
                    "validation_confidence": "high",
                    "payload": "<script>alert(1)</script>",
                },
                "dalfox_confirmed": True,
            },
            "validation_status": "validated",
            "validation_engines": ["dalfox"],
            "poc_validated": True,
            "poc_quality_score": "high",
            "validation_evidence_complete": True,
        }
        
        from tools.report_quality_checker import score_report_quality
        quality = score_report_quality(finding)
        
        assert quality["total_score"] >= 60  # Should be good quality
        assert quality["quality_rating"] in ("excellent", "good")


class TestSQLiLabValidation:
    """Tests for SQL injection lab validation."""
    
    @pytest.mark.skip(reason="SQLi lab not yet configured")
    def test_sqli_lab_sqlmap_validation(self, client):
        """Test SQLi validation with SQLmap against SQLi lab."""
        # This would test against a SQLi lab when available
        pass
    
    @pytest.mark.skip(reason="SQLi lab not yet configured")
    def test_sqli_lab_poc_evidence(self, client):
        """Test collecting SQLi POC evidence."""
        pass
    
    @pytest.mark.skip(reason="SQLi lab not yet configured")
    def test_sqli_lab_quality_scoring(self, client):
        """Test SQLi POC quality scoring."""
        pass


class TestBACLabValidation:
    """Tests for BAC lab validation."""
    
    @pytest.mark.parametrize("lab_available", ["idor_auth"], indirect=True)
    def test_bac_lab_validation(self, client, lab_available):
        """Test BAC validation against IDOR lab."""
        mcp = MCPTestClient(client)
        
        # Setup scope
        setup_test_scope(mcp, ["localhost:5002"])
        
        # Run BAC checks
        result = mcp.run_bac_checks("localhost:5002")
        
        assert "meta" in result or "confirmed_issues_count" in result
    
    @pytest.mark.parametrize("lab_available", ["idor_auth"], indirect=True)
    def test_bac_lab_poc_validation(self, client, lab_available):
        """Test BAC POC validation against lab."""
        finding = {
            "id": "bac-lab-1",
            "name": "IDOR Vulnerability",
            "url": f"{LABS[lab_available]['base_url']}/api/users/2",
            "category": "bac",
            "validation": {
                "bac": {
                    "engine_result": "confirmed",
                    "confirmed_issues_count": 1,
                    "validation_confidence": "high",
                },
            },
            "validation_status": "validated",
            "validation_engines": ["bac"],
        }
        
        from tools.poc_validator import validate_poc
        result = validate_poc(finding)
        
        assert result["poc_validated"] is True
    
    @pytest.mark.parametrize("lab_available", ["idor_auth"], indirect=True)
    def test_bac_lab_evidence_completeness(self, client, lab_available):
        """Test BAC evidence completeness against lab."""
        finding = {
            "id": "bac-lab-1",
            "name": "IDOR Vulnerability",
            "url": f"{LABS[lab_available]['base_url']}/api/users/2",
            "category": "bac",
            "validation": {
                "bac": {
                    "engine_result": "confirmed",
                    "confirmed_issues_count": 1,
                    "checks_count": 10,
                    "validation_confidence": "high",
                },
            },
            "validation_status": "validated",
            "validation_engines": ["bac"],
            "request_capture": {"request": "...", "response": "..."},
        }
        
        from tools.poc_validator import validate_poc
        result = validate_poc(finding)
        
        if result["poc_quality_score"] in ("high", "medium"):
            assert result["validation_evidence_complete"] is True


class TestMultiVulnerabilityLab:
    """Tests for multi-vulnerability lab validation."""
    
    @pytest.mark.parametrize("lab_available", ["auth_scan_lab"], indirect=True)
    def test_auth_scan_lab_full_validation(self, client, lab_available, tmp_output_dir):
        """Test full validation pipeline against auth scan lab."""
        mcp = MCPTestClient(client)
        
        # Setup scope
        setup_test_scope(mcp, ["localhost:5004"])
        
        # Run recon
        mcp.run_nuclei("localhost:5004", mode="recon")
        
        # Get host profile
        profile = mcp.host_profile("localhost:5004")
        
        assert "host" in profile
        assert "web" in profile or "cloud" in profile
    
    @pytest.mark.parametrize("lab_available", ["auth_scan_lab"], indirect=True)
    def test_auth_scan_lab_poc_aggregation(self, client, lab_available):
        """Test aggregating POCs from multiple validators."""
        findings = [
            {
                "id": "auth-lab-1",
                "name": "IDOR",
                "category": "bac",
                "validation": {
                    "bac": {
                        "engine_result": "confirmed",
                        "confirmed_issues_count": 1,
                    },
                },
                "validation_status": "validated",
                "validation_engines": ["bac"],
            },
            {
                "id": "auth-lab-2",
                "name": "Weak JWT",
                "category": "jwt",
                "validation": {
                    "jwt": {
                        "engine_result": "confirmed",
                        "weak_secret": True,
                    },
                },
                "validation_status": "validated",
                "validation_engines": ["jwt"],
            },
        ]
        
        from tools.poc_validator import validate_findings
        result = validate_findings(findings, require_validation=False)
        
        assert len(result["validated"]) >= 1
        assert result["stats"]["total"] == 2
    
    @pytest.mark.parametrize("lab_available", ["auth_scan_lab"], indirect=True)
    def test_auth_scan_lab_report_quality(self, client, lab_available):
        """Test report quality for auth scan lab findings."""
        finding = {
            "id": "auth-lab-1",
            "title": "IDOR Vulnerability",
            "summary": "IDOR in user endpoint",
            "repro": "Access /api/users/3",
            "impact": "Data exposure",
            "remediation": "Authorization checks",
            "cvss_score": "6.5",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            "cwe": "CWE-284",
            "confidence": "high",
            "validation": {
                "bac": {
                    "engine_result": "confirmed",
                    "confirmed_issues_count": 1,
                },
            },
            "validation_status": "validated",
            "validation_engines": ["bac"],
            "poc_validated": True,
            "poc_quality_score": "medium",
        }
        
        from tools.report_quality_checker import score_report_quality
        quality = score_report_quality(finding)
        
        assert quality["total_score"] >= 40
        assert "breakdown" in quality
        assert "recommendations" in quality

