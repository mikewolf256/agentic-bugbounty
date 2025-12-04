"""Integration tests for RAG in triage flow."""

import os
import json
import pytest
from unittest.mock import patch, MagicMock, Mock
from pathlib import Path

import agentic_runner


class TestRAGTriageIntegration:
    """Tests for RAG integration in triage flow."""
    
    def test_get_rag_context_called(self, sample_findings):
        """Test that _get_rag_context is called during triage."""
        finding = sample_findings["xss"]
        
        with patch('agentic_runner._rag_client_instance') as mock_client:
            mock_context = "## Similar Historical Vulnerabilities\n\n### Example 1"
            mock_client.get_context_for_triage.return_value = mock_context
            
            # Enable RAG
            with patch.dict(os.environ, {"RAG_ENABLED": "true"}):
                # Reset the global instance
                agentic_runner._rag_client_instance = mock_client
                
                context = agentic_runner._get_rag_context(finding, max_examples=3)
                
                assert context == mock_context
                mock_client.get_context_for_triage.assert_called_once_with(
                    finding=finding,
                    max_examples=3
                )
    
    def test_get_rag_context_disabled(self, sample_findings):
        """Test that RAG context is empty when disabled."""
        finding = sample_findings["xss"]
        
        with patch.dict(os.environ, {"RAG_ENABLED": "false"}):
            # Reset RAG enabled state
            agentic_runner.RAG_ENABLED = False
            
            context = agentic_runner._get_rag_context(finding)
            
            assert context == ""
    
    def test_get_rag_context_handles_errors(self, sample_findings):
        """Test that RAG context errors don't break triage."""
        finding = sample_findings["xss"]
        
        with patch('agentic_runner._rag_client_instance') as mock_client:
            mock_client.get_context_for_triage.side_effect = Exception("RAG failed")
            
            with patch.dict(os.environ, {"RAG_ENABLED": "true"}):
                agentic_runner._rag_client_instance = mock_client
                agentic_runner.RAG_ENABLED = True
                
                # Should return empty string, not raise exception
                context = agentic_runner._get_rag_context(finding)
                
                assert context == ""
    
    def test_rag_context_injected_into_prompt(self, sample_findings):
        """Test that RAG context is injected into LLM prompt."""
        finding = sample_findings["xss"]
        scope = {
            "program_name": "test-program",
            "primary_targets": ["example.com"],
        }
        
        rag_context = "## Similar Historical Vulnerabilities\n\n### Example 1\n**XSS in search** (high)"
        
        with patch('agentic_runner._get_rag_context', return_value=rag_context):
            with patch.dict(os.environ, {"RAG_ENABLED": "true"}):
                agentic_runner.RAG_ENABLED = True
                
                # Build user message
                user_content = agentic_runner.USER_TMPL_WITH_RAG.format(
                    scope=json.dumps(scope, indent=2),
                    rag_context=rag_context,
                    finding=json.dumps(finding, indent=2),
                )
                
                assert "Similar Historical Vulnerabilities" in user_content
                assert "XSS in search" in user_content
                assert finding["name"] in user_content
    
    def test_triage_without_rag_uses_standard_template(self, sample_findings):
        """Test that triage without RAG uses standard template."""
        finding = sample_findings["xss"]
        scope = {
            "program_name": "test-program",
            "primary_targets": ["example.com"],
        }
        
        with patch('agentic_runner._get_rag_context', return_value=""):
            with patch.dict(os.environ, {"RAG_ENABLED": "false"}):
                agentic_runner.RAG_ENABLED = False
                
                # Build user message (should use standard template)
                user_content = agentic_runner.USER_TMPL.format(
                    scope=json.dumps(scope, indent=2),
                    finding=json.dumps(finding, indent=2),
                )
                
                assert "Similar Historical Vulnerabilities" not in user_content
                assert finding["name"] in user_content
    
    @patch('agentic_runner.openai_chat')
    def test_triage_flow_with_rag(self, mock_openai, sample_findings, tmp_path):
        """Test complete triage flow with RAG enabled."""
        finding = sample_findings["xss"]
        scope = {
            "program_name": "test-program",
            "primary_targets": ["example.com"],
        }
        
        # Create findings file
        findings_file = tmp_path / "test_findings.json"
        findings_file.write_text(json.dumps([finding], indent=2))
        
        # Mock OpenAI response
        mock_openai.return_value = json.dumps({
            "title": "XSS in search parameter",
            "summary": "Reflected XSS vulnerability",
            "cvss_score": "7.5",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "confidence": "high",
            "recommended_bounty_usd": 500,
        })
        
        # Mock RAG context
        rag_context = "## Similar Historical Vulnerabilities\n\n### Example 1\n**XSS in search** (high)"
        
        with patch('agentic_runner._get_rag_context', return_value=rag_context):
            with patch.dict(os.environ, {"RAG_ENABLED": "true", "OPENAI_API_KEY": "test-key"}):
                agentic_runner.RAG_ENABLED = True
                
                # Run triage
                output_file = agentic_runner.run_triage_for_findings(
                    str(findings_file),
                    scope,
                    out_dir=str(tmp_path)
                )
                
                # Verify OpenAI was called
                assert mock_openai.called
                
                # Verify RAG context was included in prompt
                call_args = mock_openai.call_args
                messages = call_args[0][0]
                user_message = messages[1]["content"]
                
                assert "Similar Historical Vulnerabilities" in user_message
                assert "XSS in search" in user_message
    
    @patch('agentic_runner.openai_chat')
    def test_triage_flow_without_rag(self, mock_openai, sample_findings, tmp_path):
        """Test complete triage flow without RAG."""
        finding = sample_findings["xss"]
        scope = {
            "program_name": "test-program",
            "primary_targets": ["example.com"],
        }
        
        # Create findings file
        findings_file = tmp_path / "test_findings.json"
        findings_file.write_text(json.dumps([finding], indent=2))
        
        # Mock OpenAI response
        mock_openai.return_value = json.dumps({
            "title": "XSS in search parameter",
            "summary": "Reflected XSS vulnerability",
            "cvss_score": "7.5",
            "confidence": "high",
        })
        
        with patch('agentic_runner._get_rag_context', return_value=""):
            with patch.dict(os.environ, {"RAG_ENABLED": "false", "OPENAI_API_KEY": "test-key"}):
                agentic_runner.RAG_ENABLED = False
                
                # Run triage
                output_file = agentic_runner.run_triage_for_findings(
                    str(findings_file),
                    scope,
                    out_dir=str(tmp_path)
                )
                
                # Verify OpenAI was called
                assert mock_openai.called
                
                # Verify RAG context was NOT included
                call_args = mock_openai.call_args
                messages = call_args[0][0]
                user_message = messages[1]["content"]
                
                assert "Similar Historical Vulnerabilities" not in user_message
    
    def test_rag_max_examples_config(self, sample_findings):
        """Test that RAG_MAX_EXAMPLES config is respected."""
        finding = sample_findings["xss"]
        
        with patch('agentic_runner._rag_client_instance') as mock_client:
            mock_client.get_context_for_triage.return_value = "test context"
            
            with patch.dict(os.environ, {"RAG_ENABLED": "true", "RAG_MAX_EXAMPLES": "5"}):
                agentic_runner._rag_client_instance = mock_client
                agentic_runner.RAG_ENABLED = True
                agentic_runner.RAG_MAX_EXAMPLES = 5
                
                # Call with explicit max_examples to test the parameter
                context = agentic_runner._get_rag_context(finding, max_examples=5)
                
                # Verify max_examples was passed
                mock_client.get_context_for_triage.assert_called_once()
                call_args = mock_client.get_context_for_triage.call_args
                assert call_args[1]["max_examples"] == 5
    
    def test_rag_context_for_different_vuln_types(self, sample_findings):
        """Test RAG context generation for different vulnerability types."""
        with patch('agentic_runner._rag_client_instance') as mock_client:
            mock_client.get_context_for_triage.return_value = "test context"
            
            with patch.dict(os.environ, {"RAG_ENABLED": "true"}):
                agentic_runner._rag_client_instance = mock_client
                agentic_runner.RAG_ENABLED = True
                
                # Test XSS
                xss_context = agentic_runner._get_rag_context(sample_findings["xss"])
                assert xss_context == "test context"
                
                # Test SQLi
                sqli_context = agentic_runner._get_rag_context(sample_findings["sqli"])
                assert sqli_context == "test context"
                
                # Test SSRF
                ssrf_context = agentic_runner._get_rag_context(sample_findings["ssrf"])
                assert ssrf_context == "test context"
                
                # Verify each was called with correct finding
                assert mock_client.get_context_for_triage.call_count == 3

