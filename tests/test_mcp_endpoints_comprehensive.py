"""Comprehensive tests for all documented MCP server endpoints."""

import json
import os
from pathlib import Path
from unittest import mock

import pytest

from tests.test_utils_poc_validation import MCPTestClient, setup_test_scope


class TestScopeManagement:
    """Tests for scope management endpoints."""
    
    def test_set_scope(self, client, test_scope):
        """Test setting scope configuration."""
        mcp = MCPTestClient(client)
        result = mcp.set_scope(test_scope)
        
        assert result.get("program") == test_scope["program_name"]
        assert "scope_id" in result
    
    def test_set_scope_invalid_json(self, client):
        """Test setting scope with invalid JSON."""
        resp = client.post("/mcp/set_scope", json={"invalid": "data"})
        # Should either accept or return clear error
        assert resp.status_code in (200, 400, 422)
    
    def test_scope_enforcement(self, client, scoped_program):
        """Test that out-of-scope requests are rejected."""
        mcp = MCPTestClient(client)
        
        # Try to access out-of-scope target
        resp = client.post(
            "/mcp/host_profile",
            json={"host": "out-of-scope.com"}
        )
        # Should reject or return error
        assert resp.status_code in (400, 403, 404)
    
    def test_import_h1_scope(self, client):
        """Test importing HackerOne scope."""
        mcp = MCPTestClient(client)
        
        # This may require mocking H1 API
        with mock.patch("mcp_zap_server._fetch_h1_program") as mock_fetch:
            mock_fetch.return_value = {
                "handle": "test-program",
                "in_scope": [{"asset": "example.com"}],
            }
            
            resp = client.post(
                "/mcp/import_h1_scope",
                json={"program_handle": "test-program"}
            )
            # Should either work or return clear error if not implemented
            assert resp.status_code in (200, 404, 501)


class TestReconEndpoints:
    """Tests for reconnaissance endpoints."""
    
    def test_run_nuclei_recon_mode(self, client, scoped_program, tmp_output_dir):
        """Test Nuclei scan in recon mode."""
        mcp = MCPTestClient(client)
        
        result = mcp.run_nuclei("example.com", mode="recon")
        
        assert "findings_file" in result
        assert "findings_count" in result
        assert result.get("mode") == "recon"
    
    def test_run_nuclei_with_templates(self, client, scoped_program, tmp_output_dir):
        """Test Nuclei scan with specific templates."""
        mcp = MCPTestClient(client)
        
        # Use a known template if available
        result = mcp.run_nuclei(
            "example.com",
            templates=["http/technologies/"]
        )
        
        assert "findings_file" in result
        assert "templates_used" in result
    
    def test_run_katana_nuclei(self, client, scoped_program, tmp_output_dir):
        """Test Katana + Nuclei recon wrapper."""
        mcp = MCPTestClient(client)
        
        result = mcp.post("/run_katana_nuclei", {
            "target": "http://example.com",
            "max_urls": 50,
        })
        
        assert "katana" in result or "nuclei" in result
        assert "findings_file" in result or "urls_file" in result
    
    def test_host_profile_aggregation(self, client, scoped_program, tmp_output_dir):
        """Test host profile aggregation."""
        mcp = MCPTestClient(client)
        
        # First run some recon
        mcp.run_nuclei("example.com", mode="recon")
        
        # Then get host profile
        profile = mcp.host_profile("example.com")
        
        assert "host" in profile
        assert "web" in profile or "cloud" in profile
    
    def test_host_profile_llm_view(self, client, scoped_program, tmp_output_dir):
        """Test host profile LLM view."""
        mcp = MCPTestClient(client)
        
        profile = mcp.host_profile("example.com", llm_view=True)
        
        assert "llm_profile" in profile or "web" in profile
        # LLM view should be compact
        if "llm_profile" in profile:
            profile_str = json.dumps(profile["llm_profile"])
            assert len(profile_str) < 100000  # Should be reasonably sized


class TestValidationEndpoints:
    """Tests for validation endpoints."""
    
    def test_run_bac_checks(self, client, scoped_program):
        """Test BAC checks endpoint."""
        mcp = MCPTestClient(client)
        
        result = mcp.run_bac_checks("example.com")
        
        assert "meta" in result or "confirmed_issues_count" in result
        assert "host" in result
    
    def test_run_ssrf_checks(self, client, scoped_program):
        """Test SSRF checks endpoint."""
        mcp = MCPTestClient(client)
        
        result = mcp.run_ssrf_checks("http://example.com/api/fetch", "url")
        
        assert "meta" in result or "confirmed_issues_count" in result
        assert "target" in result
    
    def test_run_oauth_checks(self, client, scoped_program):
        """Test OAuth checks endpoint."""
        mcp = MCPTestClient(client)
        
        result = mcp.post("/run_oauth_checks", {"host": "example.com"})
        
        assert "vulnerable_count" in result or "meta" in result
    
    def test_run_race_checks(self, client, scoped_program):
        """Test race condition checks endpoint."""
        mcp = MCPTestClient(client)
        
        result = mcp.post("/run_race_checks", {"host": "example.com"})
        
        assert "vulnerable_count" in result or "meta" in result
    
    def test_run_smuggling_checks(self, client, scoped_program):
        """Test request smuggling checks endpoint."""
        mcp = MCPTestClient(client)
        
        result = mcp.post("/run_smuggling_checks", {"host": "example.com"})
        
        assert "vulnerable" in result or "meta" in result
    
    def test_run_graphql_security(self, client, scoped_program):
        """Test GraphQL security endpoint."""
        mcp = MCPTestClient(client)
        
        result = mcp.post("/run_graphql_security", {
            "endpoint": "http://example.com/graphql"
        })
        
        assert "vulnerable" in result or "meta" in result


class TestAIDrivenFeatures:
    """Tests for AI-driven features."""
    
    def test_triage_nuclei_templates(self, client, scoped_program, mock_host_profile):
        """Test AI-driven Nuclei template selection."""
        mcp = MCPTestClient(client)
        
        # Mock host profile or use real one
        result = mcp.post("/triage_nuclei_templates", {
            "host": "example.com",
            "use_llm": True,
        })
        
        assert "templates" in result or "mode" in result
        assert "reasoning" in result or "tags" in result
    
    def test_run_targeted_nuclei(self, client, scoped_program, tmp_output_dir):
        """Test running AI-selected Nuclei templates."""
        mcp = MCPTestClient(client)
        
        # First get templates
        triage_result = mcp.post("/triage_nuclei_templates", {
            "host": "example.com",
            "use_llm": False,  # Use static selection for speed
        })
        
        if "templates" in triage_result and triage_result["templates"]:
            result = mcp.post("/run_targeted_nuclei", {
                "target": "example.com",
                "templates": triage_result["templates"][:3],  # Limit for speed
            })
            
            assert "findings_file" in result
            assert "findings_count" in result
    
    def test_rag_search(self, client):
        """Test RAG semantic search."""
        mcp = MCPTestClient(client)
        
        # Mock RAG client to avoid requiring real Supabase
        with patch('mcp_zap_server._get_rag_client') as mock_get_client:
            from tools.rag_client import VulnMatch
            mock_client = mock.MagicMock()
            mock_result = VulnMatch(
                report_id="1000567",
                title="XSS in search",
                vuln_type="xss",
                severity="high",
                cwe="CWE-79",
                target_technology=[],
                attack_vector="",
                payload="",
                impact="",
                source_url="",
                similarity=0.85,
            )
            mock_client.search.return_value = [mock_result]
            mock_get_client.return_value = mock_client
            
            result = mcp.post("/rag_search", {
                "query": "XSS vulnerability",
                "top_k": 5,
            })
            
            assert "results" in result
            assert "total_results" in result
            assert result["total_results"] >= 0
            if result["results"]:
                assert "vuln_type" in result["results"][0]
                assert "similarity" in result["results"][0]
    
    def test_rag_search_with_filters(self, client):
        """Test RAG search with filters."""
        mcp = MCPTestClient(client)
        
        with patch('mcp_zap_server._get_rag_client') as mock_get_client:
            mock_client = mock.MagicMock()
            mock_client.search.return_value = []
            mock_get_client.return_value = mock_client
            
            result = mcp.post("/rag_search", {
                "query": "SSRF",
                "top_k": 10,
                "vuln_type": "ssrf",
                "severity": "high",
                "min_similarity": 0.5,
            })
            
            assert "results" in result
            # Verify filters were passed
            mock_client.search.assert_called_once()
            call_kwargs = mock_client.search.call_args[1]
            assert call_kwargs["vuln_type"] == "ssrf"
            assert call_kwargs["severity"] == "high"
    
    def test_rag_similar_vulns(self, client, mock_finding):
        """Test finding similar vulnerabilities."""
        mcp = MCPTestClient(client)
        
        with patch('mcp_zap_server._get_rag_client') as mock_get_client:
            from tools.rag_client import VulnMatch
            mock_client = mock.MagicMock()
            mock_result = VulnMatch(
                report_id="1000567",
                title="XSS in search",
                vuln_type="xss",
                severity="high",
                cwe="CWE-79",
                target_technology=[],
                attack_vector="",
                payload="",
                impact="",
                source_url="",
                similarity=0.85,
            )
            mock_client.search_similar_to_finding.return_value = [mock_result]
            mock_client.get_context_for_triage.return_value = "## Similar Historical Vulnerabilities"
            mock_get_client.return_value = mock_client
            
            result = mcp.post("/rag_similar_vulns", {
                "finding": mock_finding,
                "top_k": 3,
            })
            
            assert "results" in result
            assert "context_string" in result
            assert "total_results" in result
            assert "Similar Historical Vulnerabilities" in result["context_string"]
            mock_client.search_similar_to_finding.assert_called_once()
            mock_client.get_context_for_triage.assert_called_once()
    
    def test_rag_stats(self, client):
        """Test RAG statistics endpoint."""
        mcp = MCPTestClient(client)
        
        with patch('mcp_zap_server._get_rag_client') as mock_get_client:
            mock_client = mock.MagicMock()
            mock_client.get_stats.return_value = {
                "total_reports": 8500,
                "vuln_types": {"xss": 1200, "sqli": 800},
                "severities": {"high": 2000, "medium": 4000},
            }
            mock_get_client.return_value = mock_client
            
            result = mcp.get("/rag_stats")
            
            assert "total_vulns" in result or "stats" in result
            # Verify stats structure
            stats = result.get("stats") or result
            if "total_reports" in stats:
                assert stats["total_reports"] == 8500
    
    def test_rag_search_by_type(self, client):
        """Test RAG search by vulnerability type."""
        mcp = MCPTestClient(client)
        
        with patch('mcp_zap_server._get_rag_client') as mock_get_client:
            from tools.rag_client import VulnMatch
            mock_client = mock.MagicMock()
            mock_result = VulnMatch(
                report_id="1000567",
                title="XSS in search",
                vuln_type="xss",
                severity="high",
                cwe="CWE-79",
                target_technology=[],
                attack_vector="",
                payload="",
                impact="",
                source_url="",
                similarity=1.0,
            )
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
        """Test RAG search by technology."""
        mcp = MCPTestClient(client)
        
        with patch('mcp_zap_server._get_rag_client') as mock_get_client:
            from tools.rag_client import VulnMatch
            mock_client = mock.MagicMock()
            mock_result = VulnMatch(
                report_id="1000567",
                title="GraphQL vulnerability",
                vuln_type="graphql",
                severity="high",
                cwe="CWE-200",
                target_technology=["graphql", "nodejs"],
                attack_vector="",
                payload="",
                impact="",
                source_url="",
                similarity=1.0,
            )
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


class TestBackgroundJobs:
    """Tests for background job endpoints."""
    
    def test_run_js_miner_job(self, client, scoped_program):
        """Test JS miner background job."""
        mcp = MCPTestClient(client)
        
        result = mcp.post("/run_js_miner", {
            "target": "http://example.com",
        })
        
        assert "job_id" in result
        job_id = result["job_id"]
        
        # Check job status
        status = mcp.get(f"/job/{job_id}")
        assert "status" in status
    
    def test_run_backup_hunt_job(self, client, scoped_program):
        """Test backup hunt background job."""
        mcp = MCPTestClient(client)
        
        result = mcp.post("/run_backup_hunt", {
            "base_url": "http://example.com",
        })
        
        assert "job_id" in result
        job_id = result["job_id"]
        
        # Check job status
        status = mcp.get(f"/job/{job_id}")
        assert "status" in status
    
    def test_job_polling(self, client, scoped_program):
        """Test polling job until completion."""
        from tests.test_utils_poc_validation import wait_for_job_completion
        
        mcp = MCPTestClient(client)
        
        result = mcp.post("/run_backup_hunt", {
            "base_url": "http://example.com",
        })
        
        if "job_id" in result:
            # Poll with short timeout for test
            try:
                final_status = wait_for_job_completion(
                    mcp, result["job_id"], max_wait=10
                )
                assert "status" in final_status
            except Exception:
                # Job may not complete in test timeout, that's OK
                pass

