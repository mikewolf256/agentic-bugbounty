"""Pytest configuration and fixtures for MCP server tests."""

import json
import os
import tempfile
from pathlib import Path
from typing import Dict, Any, Generator

import pytest
from fastapi.testclient import TestClient

import mcp_zap_server


@pytest.fixture
def tmp_output_dir(tmp_path, monkeypatch):
    """Create temporary output directory and set as OUTPUT_DIR."""
    output_dir = tmp_path / "output_zap"
    output_dir.mkdir()
    monkeypatch.setenv("OUTPUT_DIR", str(output_dir))
    mcp_zap_server.OUTPUT_DIR = str(output_dir)
    return output_dir


@pytest.fixture
def client(tmp_output_dir):
    """FastAPI TestClient for MCP server."""
    return TestClient(mcp_zap_server.app)


@pytest.fixture
def test_scope() -> Dict[str, Any]:
    """Default test scope configuration."""
    return {
        "program_name": "test-program",
        "primary_targets": ["example.com", "api.example.com"],
        "secondary_targets": ["staging.example.com"],
        "rules": {
            "rate_limit": 10,
            "max_concurrent": 5,
        },
    }


@pytest.fixture
def scoped_program(client, test_scope):
    """Set scope and return scope configuration."""
    resp = client.post("/mcp/set_scope", json=test_scope)
    assert resp.status_code == 200
    return test_scope


@pytest.fixture
def mock_finding() -> Dict[str, Any]:
    """Create a mock finding for testing."""
    return {
        "id": "test-finding-1",
        "name": "Test XSS Vulnerability",
        "url": "https://example.com/search?q=test",
        "parameter": "q",
        "risk": "High",
        "evidence": "<script>alert(1)</script>",
        "category": "xss",
        "cwe": "CWE-79",
    }


@pytest.fixture
def mock_host_profile() -> Dict[str, Any]:
    """Create a mock host profile for testing."""
    return {
        "host": "example.com",
        "created": 1234567890.0,
        "web": {
            "urls": [
                "https://example.com/",
                "https://example.com/search",
                "https://example.com/api/users",
            ],
            "api_endpoints": [
                {"path": "/api/users", "method": "GET"},
                {"path": "/api/users/{id}", "method": "GET"},
            ],
            "fingerprints": {
                "technologies": ["Python", "Flask", "nginx"],
                "plugins": {},
            },
        },
        "cloud": {},
    }


@pytest.fixture
def mock_validation_evidence() -> Dict[str, Any]:
    """Create mock validation evidence for testing."""
    return {
        "dalfox": {
            "engine_result": "confirmed",
            "validation_confidence": "high",
            "payload": "<script>alert(1)</script>",
            "raw_output": "XSS confirmed",
        },
        "dalfox_confirmed": True,
    }


@pytest.fixture
def artifacts_dir(tmp_path):
    """Create artifacts directory structure."""
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "poc_captures").mkdir()
    (artifacts / "custom_nuclei_templates").mkdir()
    (artifacts / "katana_auth").mkdir()
    return artifacts


@pytest.fixture
def sample_findings_file(tmp_path, mock_finding):
    """Create a sample findings JSON file."""
    findings_file = tmp_path / "test_findings.json"
    findings_file.write_text(json.dumps([mock_finding], indent=2))
    return str(findings_file)


@pytest.fixture
def sample_triage_file(tmp_path, mock_finding):
    """Create a sample triage JSON file with validation evidence."""
    triage_data = {
        **mock_finding,
        "title": "Test XSS Vulnerability",
        "summary": "XSS in search parameter",
        "cvss_score": "7.5",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
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
    triage_file = tmp_path / "test_triage.json"
    triage_file.write_text(json.dumps([triage_data], indent=2))
    return str(triage_file)


# RAG-related fixtures
@pytest.fixture
def mock_rag_results():
    """Create mock RAG search results for testing."""
    from tools.rag_client import VulnMatch
    
    return [
        VulnMatch(
            report_id="1000567",
            title="XSS in search parameter",
            vuln_type="xss",
            severity="high",
            cwe="CWE-79",
            target_technology=["python", "flask"],
            attack_vector="Reflected XSS in search query parameter",
            payload="<script>alert(1)</script>",
            impact="Attacker can execute arbitrary JavaScript in user's browser",
            source_url="https://hackerone.com/reports/1000567",
            similarity=0.85,
        ),
        VulnMatch(
            report_id="1000568",
            title="SQL injection in login form",
            vuln_type="sqli",
            severity="critical",
            cwe="CWE-89",
            target_technology=["php", "mysql"],
            attack_vector="SQL injection via username parameter",
            payload="' OR 1=1 --",
            impact="Attacker can bypass authentication and access user data",
            source_url="https://hackerone.com/reports/1000568",
            similarity=0.78,
        ),
        VulnMatch(
            report_id="1000569",
            title="SSRF in image upload",
            vuln_type="ssrf",
            severity="high",
            cwe="CWE-918",
            target_technology=["nodejs", "express"],
            attack_vector="Server-side request forgery via image URL parameter",
            payload="http://internal-server:8080/admin",
            impact="Attacker can access internal services and sensitive endpoints",
            source_url="https://hackerone.com/reports/1000569",
            similarity=0.72,
        ),
    ]


@pytest.fixture
def sample_findings():
    """Create sample findings of various types."""
    return {
        "xss": {
            "id": "xss-1",
            "name": "Cross-site scripting in search",
            "title": "XSS in search parameter",
            "url": "https://example.com/search?q=test",
            "parameter": "q",
            "category": "xss",
            "cwe": "CWE-79",
            "severity": "high",
            "evidence": "<script>alert(1)</script>",
        },
        "sqli": {
            "id": "sqli-1",
            "name": "SQL injection in login",
            "title": "SQL injection vulnerability",
            "url": "https://example.com/login",
            "parameter": "username",
            "category": "sqli",
            "cwe": "CWE-89",
            "severity": "critical",
            "evidence": "' OR 1=1 --",
        },
        "ssrf": {
            "id": "ssrf-1",
            "name": "SSRF in image upload",
            "title": "Server-side request forgery",
            "url": "https://example.com/upload",
            "parameter": "image_url",
            "category": "ssrf",
            "cwe": "CWE-918",
            "severity": "high",
            "evidence": "http://internal-server:8080",
        },
        "idor": {
            "id": "idor-1",
            "name": "IDOR in API endpoint",
            "title": "Insecure direct object reference",
            "url": "https://example.com/api/users/123",
            "parameter": "user_id",
            "category": "idor",
            "cwe": "CWE-639",
            "severity": "medium",
        },
    }


@pytest.fixture
def mock_supabase_client(monkeypatch):
    """Mock Supabase client for testing."""
    from unittest.mock import MagicMock
    
    mock_client = MagicMock()
    mock_table = MagicMock()
    mock_client.table.return_value = mock_table
    
    # Mock RPC call for search_similar_vulns
    mock_rpc = MagicMock()
    mock_client.rpc.return_value = mock_rpc
    
    return mock_client


@pytest.fixture
def rag_client_mock(mock_supabase_client, monkeypatch):
    """Create a RAG client with mocked Supabase."""
    from unittest.mock import patch, MagicMock
    from tools.rag_client import RAGClient
    
    # Mock OpenAI embedding API
    mock_embedding = [0.1] * 1536  # Dummy embedding vector
    
    with patch('tools.rag_client.requests.post') as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{"embedding": mock_embedding}]
        }
        mock_post.return_value = mock_response
        
        # Create client with test config
        client = RAGClient(
            supabase_url="https://test.supabase.co",
            supabase_key="test-key",
            openai_api_key="test-openai-key",
        )
        client._supabase = mock_supabase_client
        yield client

