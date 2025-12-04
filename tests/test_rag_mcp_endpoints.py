"""Integration tests for RAG MCP endpoints."""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from tests.test_utils_poc_validation import MCPTestClient


class TestRAGMCPEndpoints:
    """Tests for RAG-related MCP endpoints."""
    
    def test_rag_search(self, client):
        """Test RAG semantic search endpoint."""
        mcp = MCPTestClient(client)
        
        # Mock the RAG client to avoid requiring real Supabase
        with patch('mcp_zap_server._get_rag_client') as mock_get_client:
            mock_client = MagicMock()
            mock_result = MagicMock()
            mock_result.report_id = "1000567"
            mock_result.title = "XSS in search"
            mock_result.vuln_type = "xss"
            mock_result.severity = "high"
            mock_result.cwe = "CWE-79"
            mock_result.target_technology = ["python"]
            mock_result.attack_vector = "Reflected XSS"
            mock_result.payload = "<script>alert(1)</script>"
            mock_result.impact = "JS execution"
            mock_result.source_url = "https://hackerone.com/reports/1000567"
            mock_result.similarity = 0.85
            mock_result.to_dict.return_value = {
                "report_id": "1000567",
                "title": "XSS in search",
                "vuln_type": "xss",
                "severity": "high",
                "cwe": "CWE-79",
                "target_technology": ["python"],
                "attack_vector": "Reflected XSS",
                "payload": "<script>alert(1)</script>",
                "impact": "JS execution",
                "source_url": "https://hackerone.com/reports/1000567",
                "similarity": 0.85,
            }
            
            mock_client.search.return_value = [mock_result]
            mock_get_client.return_value = mock_client
            
            result = mcp.post("/rag_search", {
                "query": "XSS vulnerability",
                "top_k": 5,
                "min_similarity": 0.3,
            })
            
            assert "results" in result
            assert "total_results" in result
            assert result["total_results"] == 1
            if result["results"]:
                assert result["results"][0]["vuln_type"] == "xss"
                assert result["results"][0]["similarity"] == 0.85
    
    def test_rag_search_with_filters(self, client):
        """Test RAG search with filters."""
        mcp = MCPTestClient(client)
        
        with patch('mcp_zap_server._get_rag_client') as mock_get_client:
            mock_client = MagicMock()
            mock_client.search.return_value = []
            mock_get_client.return_value = mock_client
            
            result = mcp.post("/rag_search", {
                "query": "SSRF vulnerability",
                "top_k": 10,
                "min_similarity": 0.5,
                "vuln_type": "ssrf",
                "severity": "high",
                "technologies": ["nodejs"],
            })
            
            assert "results" in result
            # Verify filters were passed
            mock_client.search.assert_called_once()
            call_args = mock_client.search.call_args
            assert call_args[1]["vuln_type"] == "ssrf"
            assert call_args[1]["severity"] == "high"
            assert call_args[1]["technologies"] == ["nodejs"]
    
    def test_rag_similar_vulns(self, client, mock_finding):
        """Test finding-based similarity search endpoint."""
        mcp = MCPTestClient(client)
        
        with patch('mcp_zap_server._get_rag_client') as mock_get_client:
            mock_client = MagicMock()
            mock_result = MagicMock()
            mock_result.report_id = "1000567"
            mock_result.title = "XSS in search"
            mock_result.vuln_type = "xss"
            mock_result.severity = "high"
            mock_result.cwe = "CWE-79"
            mock_result.target_technology = []
            mock_result.attack_vector = "Reflected XSS"
            mock_result.payload = "<script>alert(1)</script>"
            mock_result.impact = "JS execution"
            mock_result.source_url = "https://hackerone.com/reports/1000567"
            mock_result.similarity = 0.85
            
            mock_client.search_similar_to_finding.return_value = [mock_result]
            mock_client.get_context_for_triage.return_value = (
                "## Similar Historical Vulnerabilities\n\n"
                "### Example 1 (similarity: 0.85)\n"
                "**XSS in search** (high)\n"
            )
            mock_get_client.return_value = mock_client
            
            result = mcp.post("/rag_similar_vulns", {
                "finding": mock_finding,
                "top_k": 3,
                "min_similarity": 0.4,
            })
            
            assert "results" in result
            assert "context_string" in result
            assert "total_results" in result
            assert result["total_results"] == 1
            assert "Similar Historical Vulnerabilities" in result["context_string"]
            assert "XSS in search" in result["context_string"]
            
            # Verify methods were called
            mock_client.search_similar_to_finding.assert_called_once()
            mock_client.get_context_for_triage.assert_called_once()
    
    def test_rag_similar_vulns_with_host_profile(self, client, mock_finding, mock_host_profile):
        """Test finding-based search with host profile."""
        mcp = MCPTestClient(client)
        
        with patch('mcp_zap_server._get_rag_client') as mock_get_client:
            mock_client = MagicMock()
            mock_client.search_similar_to_finding.return_value = []
            mock_client.get_context_for_triage.return_value = ""
            mock_get_client.return_value = mock_client
            
            result = mcp.post("/rag_similar_vulns", {
                "finding": mock_finding,
                "host_profile": mock_host_profile,
                "top_k": 5,
            })
            
            # Verify host profile was passed to context generation
            mock_client.get_context_for_triage.assert_called_once()
            call_args = mock_client.get_context_for_triage.call_args
            assert call_args[1]["host_profile"] == mock_host_profile
    
    def test_rag_stats(self, client):
        """Test RAG statistics endpoint."""
        mcp = MCPTestClient(client)
        
        with patch('mcp_zap_server._get_rag_client') as mock_get_client:
            mock_client = MagicMock()
            mock_client.get_stats.return_value = {
                "total_reports": 8500,
                "vuln_types": {
                    "xss": 1200,
                    "sqli": 800,
                    "ssrf": 600,
                },
                "severities": {
                    "critical": 500,
                    "high": 2000,
                    "medium": 4000,
                    "low": 2000,
                },
            }
            mock_get_client.return_value = mock_client
            
            result = mcp.get("/rag_stats")
            
            # RAGStatsResponse has total_reports, vuln_types, severities directly
            assert "total_reports" in result
            assert "vuln_types" in result
            assert "severities" in result
            assert result["total_reports"] == 8500
            assert result["vuln_types"]["xss"] == 1200
    
    def test_rag_search_by_type(self, client):
        """Test search by vulnerability type endpoint."""
        mcp = MCPTestClient(client)
        
        with patch('mcp_zap_server._get_rag_client') as mock_get_client:
            mock_client = MagicMock()
            mock_result = MagicMock()
            mock_result.report_id = "1000567"
            mock_result.title = "XSS in search"
            mock_result.to_dict.return_value = {
                "report_id": "1000567",
                "title": "XSS in search",
                "vuln_type": "xss",
            }
            
            mock_client.search_by_vuln_type.return_value = [mock_result]
            mock_get_client.return_value = mock_client
            
            result = mcp.post("/rag_search_by_type", {
                "vuln_type": "xss",
                "top_k": 10,
            })
            
            assert "results" in result
            assert "total_results" in result
            assert result["vuln_type"] == "xss"
            mock_client.search_by_vuln_type.assert_called_once_with(
                vuln_type="xss",
                top_k=10
            )
    
    def test_rag_search_by_tech(self, client):
        """Test search by technology endpoint."""
        mcp = MCPTestClient(client)
        
        with patch('mcp_zap_server._get_rag_client') as mock_get_client:
            mock_client = MagicMock()
            mock_result = MagicMock()
            mock_result.report_id = "1000567"
            mock_result.title = "GraphQL vulnerability"
            mock_result.to_dict.return_value = {
                "report_id": "1000567",
                "title": "GraphQL vulnerability",
                "target_technology": ["graphql", "nodejs"],
            }
            
            mock_client.search_by_tech.return_value = [mock_result]
            mock_get_client.return_value = mock_client
            
            result = mcp.post("/rag_search_by_tech", {
                "technologies": ["graphql", "nodejs"],
                "top_k": 10,
            })
            
            assert "results" in result
            assert "total_results" in result
            assert result["technologies"] == ["graphql", "nodejs"]
            mock_client.search_by_tech.assert_called_once_with(
                technologies=["graphql", "nodejs"],
                top_k=10
            )
    
    def test_rag_endpoints_handle_errors(self, client):
        """Test that RAG endpoints handle errors gracefully."""
        mcp = MCPTestClient(client)
        
        with patch('mcp_zap_server._get_rag_client') as mock_get_client:
            mock_client = MagicMock()
            mock_client.search.side_effect = Exception("Database connection failed")
            mock_get_client.return_value = mock_client
            
            # Should return error response, not crash
            resp = client.post("/mcp/rag_search", json={
                "query": "test",
                "top_k": 5,
            })
            
            # Should return error status
            assert resp.status_code in (500, 400)
            assert "detail" in resp.json()
    
    def test_rag_similar_vulns_empty_context(self, client, mock_finding):
        """Test that empty context string is handled."""
        mcp = MCPTestClient(client)
        
        with patch('mcp_zap_server._get_rag_client') as mock_get_client:
            mock_client = MagicMock()
            mock_client.search_similar_to_finding.return_value = []
            mock_client.get_context_for_triage.return_value = ""
            mock_get_client.return_value = mock_client
            
            result = mcp.post("/rag_similar_vulns", {
                "finding": mock_finding,
                "top_k": 3,
            })
            
            assert "context_string" in result
            assert result["context_string"] == ""
            assert result["total_results"] == 0

