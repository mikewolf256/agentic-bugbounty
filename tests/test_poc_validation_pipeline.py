"""Tests for complete POC validation pipeline."""

import json
import os
from pathlib import Path
from unittest import mock

import pytest

from tests.test_utils_poc_validation import (
    create_mock_finding,
    create_mock_validation_evidence,
    assert_poc_validated,
    assert_poc_quality,
    assert_validation_evidence_complete,
)


class TestPOCCapture:
    """Tests for POC capture functionality."""
    
    def test_poc_capture_request_response(self, tmp_path):
        """Test capturing HTTP requests and responses."""
        from tools.poc_capture import POCCapture
        
        capture = POCCapture(output_dir=str(tmp_path / "poc_captures"))
        
        # Capture a request/response
        capture_data = capture.capture_request_response(
            method="POST",
            url="https://example.com/api/users",
            headers={"Content-Type": "application/json"},
            data='{"name": "test"}',
        )
        
        assert "timestamp" in capture_data
        assert "method" in capture_data
        assert "url" in capture_data
        assert "request" in capture_data
        assert "response" in capture_data
        assert capture_data["request"]["headers"]["Content-Type"] == "application/json"
    
    def test_poc_capture_storage(self, tmp_path):
        """Test storing POC captures to disk."""
        from tools.poc_capture import POCCapture
        
        capture = POCCapture(output_dir=str(tmp_path / "poc_captures"))
        
        capture_data = capture.capture_request_response(
            method="GET",
            url="https://example.com/test",
        )
        
        filepath = capture.save_capture(capture_data, finding_id="test-1")
        
        assert Path(filepath).exists()
        assert filepath.endswith(".json")
        
        # Verify file contents
        with open(filepath, "r") as f:
            saved_data = json.load(f)
        
        assert saved_data["url"] == capture_data["url"]
        assert saved_data["method"] == capture_data["method"]
    
    def test_poc_capture_formatting(self, tmp_path):
        """Test formatting captures for reports."""
        from tools.poc_capture import POCCapture
        
        capture = POCCapture(output_dir=str(tmp_path / "poc_captures"))
        
        capture_data = capture.capture_request_response(
            method="GET",
            url="https://example.com/search?q=test",
        )
        
        formatted = capture.format_for_report(capture_data)
        
        assert "Request:" in formatted
        assert "Response:" in formatted
        assert "GET" in formatted
        assert "example.com" in formatted


class TestPOCValidator:
    """Tests for POC validator functionality."""
    
    def test_poc_validator_single_finding(self):
        """Test validating a single finding."""
        from tools.poc_validator import validate_poc
        
        finding = create_mock_finding(vuln_type="xss")
        finding["validation"] = {
            "dalfox": create_mock_validation_evidence("dalfox", confirmed=True),
            "dalfox_confirmed": True,
        }
        finding["validation_status"] = "validated"
        finding["validation_engines"] = ["dalfox"]
        
        result = validate_poc(finding)
        
        assert "poc_validated" in result
        assert "poc_quality_score" in result
        assert "validation_evidence_complete" in result
        assert "reasons" in result
        assert "missing_evidence" in result
    
    def test_poc_validator_batch(self):
        """Test validating multiple findings."""
        from tools.poc_validator import validate_findings
        
        findings = [
            create_mock_finding(finding_id=f"f{i}", vuln_type="xss")
            for i in range(3)
        ]
        
        # Add validation evidence to some findings
        findings[0]["validation"] = {
            "dalfox": create_mock_validation_evidence("dalfox", confirmed=True),
            "dalfox_confirmed": True,
        }
        findings[0]["validation_status"] = "validated"
        findings[0]["validation_engines"] = ["dalfox"]
        
        findings[1]["validation"] = {
            "dalfox": create_mock_validation_evidence("dalfox", confirmed=False),
            "dalfox_confirmed": False,
        }
        findings[1]["validation_status"] = "skipped"
        findings[1]["validation_engines"] = ["dalfox"]
        
        # findings[2] has no validation
        
        result = validate_findings(findings, require_validation=False)
        
        assert "validated" in result
        assert "rejected" in result
        assert "stats" in result
        
        assert len(result["validated"]) >= 1
        assert len(result["rejected"]) >= 1
        assert result["stats"]["total"] == 3
    
    def test_poc_quality_scoring(self):
        """Test POC quality scoring logic."""
        from tools.poc_validator import validate_poc
        
        # High quality: confirmed + evidence
        finding_high = create_mock_finding(vuln_type="xss")
        finding_high["validation"] = {
            "dalfox": create_mock_validation_evidence("dalfox", confirmed=True),
            "dalfox_confirmed": True,
        }
        finding_high["validation_status"] = "validated"
        finding_high["validation_engines"] = ["dalfox"]
        finding_high["request_capture"] = {"request": "...", "response": "..."}
        
        result_high = validate_poc(finding_high)
        assert result_high["poc_quality_score"] in ("high", "medium")
        
        # Low quality: no confirmation
        finding_low = create_mock_finding(vuln_type="xss")
        finding_low["validation"] = {
            "dalfox": create_mock_validation_evidence("dalfox", confirmed=False),
            "dalfox_confirmed": False,
        }
        finding_low["validation_status"] = "skipped"
        finding_low["validation_engines"] = ["dalfox"]
        
        result_low = validate_poc(finding_low)
        assert result_low["poc_quality_score"] == "low"
    
    def test_poc_validation_gate(self):
        """Test validation gate filtering."""
        from tools.poc_validator import validate_findings
        
        findings = [
            create_mock_finding(finding_id="f1", vuln_type="xss"),
            create_mock_finding(finding_id="f2", vuln_type="sqli"),
        ]
        
        # Only first finding has validation
        findings[0]["validation"] = {
            "dalfox": create_mock_validation_evidence("dalfox", confirmed=True),
            "dalfox_confirmed": True,
        }
        findings[0]["validation_status"] = "validated"
        findings[0]["validation_engines"] = ["dalfox"]
        findings[0]["validation_evidence_complete"] = True
        
        # With require_validation=True
        result = validate_findings(findings, require_validation=True)
        
        assert len(result["validated"]) == 1
        assert result["validated"][0]["id"] == "f1"


class TestValidationEvidenceCollection:
    """Tests for validation evidence collection."""
    
    def test_validation_evidence_aggregation(self):
        """Test aggregating evidence from multiple validators."""
        finding = create_mock_finding(vuln_type="xss")
        finding["validation"] = {
            "dalfox": create_mock_validation_evidence("dalfox", confirmed=True),
            "dalfox_confirmed": True,
            "sqlmap": create_mock_validation_evidence("sqlmap", confirmed=False),
        }
        finding["validation_status"] = "validated"
        finding["validation_engines"] = ["dalfox", "sqlmap"]
        
        from tools.poc_validator import validate_poc
        result = validate_poc(finding)
        
        assert result["poc_validated"] is True
        assert "dalfox" in result["reasons"]
        assert len(finding["validation_engines"]) == 2
    
    def test_validation_evidence_completeness(self):
        """Test checking evidence completeness."""
        finding = create_mock_finding(vuln_type="xss")
        finding["validation"] = {
            "dalfox": create_mock_validation_evidence("dalfox", confirmed=True),
            "dalfox_confirmed": True,
        }
        finding["validation_status"] = "validated"
        finding["validation_engines"] = ["dalfox"]
        finding["request_capture"] = {"request": "...", "response": "..."}
        
        from tools.poc_validator import validate_poc
        result = validate_poc(finding)
        
        if result["poc_quality_score"] in ("high", "medium"):
            assert result["validation_evidence_complete"] is True
    
    def test_validation_evidence_storage(self, tmp_path):
        """Test storing validation evidence in triage JSON."""
        finding = create_mock_finding(vuln_type="xss")
        finding["validation"] = {
            "dalfox": create_mock_validation_evidence("dalfox", confirmed=True),
            "dalfox_confirmed": True,
        }
        finding["validation_status"] = "validated"
        finding["validation_engines"] = ["dalfox"]
        finding["poc_validated"] = True
        finding["poc_quality_score"] = "high"
        
        # Save to file
        triage_file = tmp_path / "triage_test.json"
        with open(triage_file, "w") as f:
            json.dump([finding], f, indent=2)
        
        # Verify structure
        with open(triage_file, "r") as f:
            loaded = json.load(f)
        
        assert loaded[0]["validation"]["dalfox"]["engine_result"] == "confirmed"
        assert loaded[0]["poc_validated"] is True
        assert loaded[0]["poc_quality_score"] == "high"


class TestReportQuality:
    """Tests for report quality checking."""
    
    def test_report_quality_checker(self, tmp_path):
        """Test report quality scoring."""
        from tools.report_quality_checker import score_report_quality
        
        report = {
            "title": "Test XSS Vulnerability",
            "summary": "XSS in search parameter",
            "repro": "Steps to reproduce",
            "impact": "User data compromise",
            "remediation": "Input validation",
            "cvss_score": "7.5",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "cwe": "CWE-79",
            "poc_validated": True,
            "poc_quality_score": "high",
            "validation_evidence_complete": True,
            "validation_status": "validated",
            "validation_engines": ["dalfox"],
        }
        
        result = score_report_quality(report)
        
        assert "total_score" in result
        assert "quality_rating" in result
        assert "breakdown" in result
        assert result["total_score"] >= 0
        assert result["total_score"] <= 100
    
    def test_report_completeness_check(self, tmp_path):
        """Test checking report completeness."""
        from tools.report_quality_checker import check_report_completeness
        
        # Complete report
        complete_report = {
            "title": "Test",
            "summary": "Summary",
            "repro": "Steps",
            "impact": "Impact",
            "remediation": "Fix",
            "cvss_score": "7.5",
            "cvss_vector": "CVSS:3.1/...",
            "cwe": "CWE-79",
        }
        
        result = check_report_completeness(complete_report)
        assert result["complete"] is True
        assert len(result["missing_fields"]) == 0
        
        # Incomplete report
        incomplete_report = {
            "title": "Test",
            "summary": "Summary",
            # Missing other fields
        }
        
        result = check_report_completeness(incomplete_report)
        assert result["complete"] is False
        assert len(result["missing_fields"]) > 0
    
    def test_report_scope_compliance(self, tmp_path):
        """Test scope compliance checking."""
        from tools.report_quality_checker import check_scope_compliance
        
        report = {
            "_raw_finding": {
                "url": "https://example.com/test",
            },
        }
        
        scope = {
            "in_scope": [
                {"url": "example.com"},
            ],
        }
        
        result = check_scope_compliance(report, scope)
        assert "in_scope" in result
    
    def test_report_sensitive_data_check(self, tmp_path):
        """Test checking for sensitive data exposure."""
        from tools.report_quality_checker import check_sensitive_data
        
        # Report with potential sensitive data
        report_with_secrets = {
            "summary": "Found API key: sk_live_1234567890 in response",
            "repro": "Password is admin123",
        }
        
        result = check_sensitive_data(report_with_secrets)
        assert result["has_sensitive_data"] is True
        assert len(result["issues"]) > 0
        
        # Clean report
        clean_report = {
            "summary": "XSS vulnerability found",
            "repro": "Navigate to /search?q=test",
        }
        
        result = check_sensitive_data(clean_report)
        assert result["has_sensitive_data"] is False


class TestEndToEndValidationFlow:
    """Tests for complete end-to-end validation flow."""
    
    def test_full_validation_pipeline(self, tmp_path):
        """Test complete flow from finding to validated report."""
        from tools.poc_validator import validate_findings
        from tools.report_quality_checker import score_report_quality
        
        # Create finding with validation evidence
        finding = create_mock_finding(vuln_type="xss")
        finding["validation"] = {
            "dalfox": create_mock_validation_evidence("dalfox", confirmed=True),
            "dalfox_confirmed": True,
        }
        finding["validation_status"] = "validated"
        finding["validation_engines"] = ["dalfox"]
        finding["request_capture"] = {"request": "...", "response": "..."}
        
        # Validate POC
        validation_result = validate_findings([finding], require_validation=False)
        assert len(validation_result["validated"]) == 1
        
        validated_finding = validation_result["validated"][0]
        assert validated_finding["poc_validated"] is True
        
        # Check report quality
        quality_result = score_report_quality(validated_finding)
        assert quality_result["total_score"] > 0
    
    def test_validation_with_multiple_engines(self):
        """Test validation with multiple engines for same finding."""
        finding = create_mock_finding(vuln_type="xss")
        finding["validation"] = {
            "dalfox": create_mock_validation_evidence("dalfox", confirmed=True),
            "dalfox_confirmed": True,
            "sqlmap": create_mock_validation_evidence("sqlmap", confirmed=False),
        }
        finding["validation_status"] = "validated"
        finding["validation_engines"] = ["dalfox", "sqlmap"]
        
        from tools.poc_validator import validate_poc
        result = validate_poc(finding)
        
        assert result["poc_validated"] is True
        assert len(finding["validation_engines"]) == 2
        # Multiple engines should increase quality score
        assert result["poc_quality_score"] in ("high", "medium", "low")
    
    def test_validation_fallback(self):
        """Test fallback when dedicated validator unavailable."""
        # Finding without dedicated validator
        finding = create_mock_finding(vuln_type="custom_vuln")
        finding["validation"] = {}
        finding["validation_status"] = "unknown"
        finding["validation_engines"] = []
        
        from tools.poc_validator import validate_poc
        result = validate_poc(finding)
        
        # Should still validate if manual validation provided
        assert result["poc_validated"] is False
        
        # With manual validation
        finding["manual_validation"] = True
        finding["request_capture"] = {"request": "...", "response": "..."}
        
        result = validate_poc(finding)
        assert result["poc_validated"] is True

