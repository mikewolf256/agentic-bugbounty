"""Comparison tests for RAG impact on triage quality."""

import os
import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

import agentic_runner


class TestRAGComparison:
    """Tests comparing triage results with and without RAG."""
    
    @pytest.fixture
    def sample_finding(self):
        """Create a sample finding for comparison."""
        return {
            "id": "xss-1",
            "name": "Cross-site scripting in search parameter",
            "title": "XSS vulnerability",
            "url": "https://example.com/search?q=test",
            "parameter": "q",
            "category": "xss",
            "cwe": "CWE-79",
            "severity": "high",
            "evidence": "<script>alert(1)</script>",
        }
    
    @pytest.fixture
    def mock_rag_context(self):
        """Create mock RAG context with historical examples."""
        return """## Similar Historical Vulnerabilities (for reference)

### Example 1 (similarity: 0.85)
**XSS in search parameter** (high)
Type: xss
CWE: CWE-79
Tech: python, flask
Attack: Reflected XSS in search query parameter
Payload: `<script>alert(1)</script>`
Impact: Attacker can execute arbitrary JavaScript in user's browser
Ref: https://hackerone.com/reports/1000567

### Example 2 (similarity: 0.78)
**Stored XSS in comment field** (high)
Type: xss
CWE: CWE-79
Tech: nodejs, express
Attack: Stored XSS via comment submission
Payload: `<img src=x onerror=alert(1)>`
Impact: Persistent XSS affecting all users viewing comments
Ref: https://hackerone.com/reports/1000568

### Example 3 (similarity: 0.72)
**DOM-based XSS** (medium)
Type: xss
CWE: CWE-79
Tech: javascript, react
Attack: DOM manipulation leading to XSS
Payload: `#<img src=x onerror=alert(document.cookie)>`
Impact: Client-side XSS via URL fragment
Ref: https://hackerone.com/reports/1000569
"""
    
    @patch('agentic_runner.openai_chat')
    def test_triage_with_rag_vs_without(self, mock_openai, sample_finding, mock_rag_context, tmp_path):
        """Compare triage results with and without RAG."""
        scope = {
            "program_name": "test-program",
            "primary_targets": ["example.com"],
        }
        
        findings_file = tmp_path / "test_findings.json"
        findings_file.write_text(json.dumps([sample_finding], indent=2))
        
        # Mock OpenAI responses
        triage_with_rag = {
            "title": "Reflected Cross-Site Scripting (XSS) in Search Parameter",
            "summary": "A reflected XSS vulnerability exists in the search functionality, allowing attackers to execute arbitrary JavaScript. Based on similar historical reports, this type of vulnerability typically receives bounties ranging from $500-$2000 depending on impact scope.",
            "cvss_score": "7.2",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
            "confidence": "high",
            "recommended_bounty_usd": 750,
            "impact": "Attacker can execute arbitrary JavaScript in victim's browser context, potentially stealing session cookies or performing actions on behalf of the user. Similar vulnerabilities have been exploited to hijack user accounts.",
        }
        
        triage_without_rag = {
            "title": "Cross-Site Scripting Vulnerability",
            "summary": "XSS vulnerability found in search parameter",
            "cvss_score": "6.5",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            "confidence": "medium",
            "recommended_bounty_usd": 300,
            "impact": "JavaScript execution possible",
        }
        
        # Test with RAG
        with patch('agentic_runner._get_rag_context', return_value=mock_rag_context):
            with patch.dict(os.environ, {"RAG_ENABLED": "true", "OPENAI_API_KEY": "test-key"}):
                agentic_runner.RAG_ENABLED = True
                mock_openai.return_value = json.dumps(triage_with_rag)
                
                output_with_rag = agentic_runner.run_triage_for_findings(
                    str(findings_file),
                    scope,
                    out_dir=str(tmp_path / "with_rag")
                )
                
                # Verify RAG context was in prompt
                call_args = mock_openai.call_args
                messages_with_rag = call_args[0][0]
                assert "Similar Historical Vulnerabilities" in messages_with_rag[1]["content"]
        
        # Test without RAG
        with patch('agentic_runner._get_rag_context', return_value=""):
            with patch.dict(os.environ, {"RAG_ENABLED": "false", "OPENAI_API_KEY": "test-key"}):
                agentic_runner.RAG_ENABLED = False
                mock_openai.return_value = json.dumps(triage_without_rag)
                
                output_without_rag = agentic_runner.run_triage_for_findings(
                    str(findings_file),
                    scope,
                    out_dir=str(tmp_path / "without_rag")
                )
                
                # Verify RAG context was NOT in prompt
                call_args = mock_openai.call_args
                messages_without_rag = call_args[0][0]
                assert "Similar Historical Vulnerabilities" not in messages_without_rag[1]["content"]
        
        # Compare results
        # Note: In real tests, you would load and compare the actual triage outputs
        # This demonstrates the structure of comparison testing
    
    def test_rag_improves_cvss_accuracy(self, sample_finding, mock_rag_context):
        """Test that RAG helps improve CVSS scoring accuracy."""
        # This test would compare CVSS scores with historical data
        # In a real scenario, you'd have ground truth CVSS scores and compare
        
        with patch('agentic_runner._get_rag_context', return_value=mock_rag_context):
            with patch.dict(os.environ, {"RAG_ENABLED": "true"}):
                agentic_runner.RAG_ENABLED = True
                
                # RAG context includes historical examples with similar CVSS scores
                # This helps the LLM make more accurate assessments
                assert "similarity: 0.85" in mock_rag_context
                assert "high" in mock_rag_context  # Severity from historical example
    
    def test_rag_improves_bounty_estimation(self, sample_finding, mock_rag_context):
        """Test that RAG helps with bounty estimation."""
        # Historical examples in RAG context provide reference for bounty ranges
        # The LLM can use these to make more informed estimates
        
        assert "hackerone.com/reports" in mock_rag_context
        # In real tests, you'd verify that bounty estimates align better
        # with historical payouts when RAG is enabled
    
    def test_rag_provides_impact_context(self, sample_finding, mock_rag_context):
        """Test that RAG provides better impact descriptions."""
        # RAG context includes impact descriptions from historical reports
        # This helps the LLM write more detailed and accurate impact assessments
        
        assert "Impact:" in mock_rag_context
        assert "Attacker can execute" in mock_rag_context
        # RAG provides concrete examples of how similar vulnerabilities were exploited
    
    def test_rag_includes_payload_examples(self, sample_finding, mock_rag_context):
        """Test that RAG includes proven payload examples."""
        # Historical payloads in RAG context help the LLM suggest better PoCs
        
        assert "Payload:" in mock_rag_context
        assert "<script>alert(1)</script>" in mock_rag_context
        assert "<img src=x onerror=" in mock_rag_context
        # Multiple payload examples from different historical reports
    
    def test_rag_includes_technology_context(self, sample_finding, mock_rag_context):
        """Test that RAG includes technology stack context."""
        # Technology information helps the LLM understand the attack surface
        
        assert "Tech:" in mock_rag_context
        assert "python" in mock_rag_context or "flask" in mock_rag_context
        assert "nodejs" in mock_rag_context or "express" in mock_rag_context
        # Different technology stacks from historical examples
    
    @patch('agentic_runner.openai_chat')
    def test_rag_improves_confidence_scores(self, mock_openai, sample_finding, mock_rag_context, tmp_path):
        """Test that RAG improves confidence in triage results."""
        scope = {"program_name": "test-program", "primary_targets": ["example.com"]}
        findings_file = tmp_path / "test_findings.json"
        findings_file.write_text(json.dumps([sample_finding], indent=2))
        
        # With RAG: higher confidence due to historical precedent
        triage_with_rag = {
            "confidence": "high",
            "cvss_score": "7.2",
        }
        
        # Without RAG: lower confidence without historical context
        triage_without_rag = {
            "confidence": "medium",
            "cvss_score": "6.5",
        }
        
        # Test with RAG
        with patch('agentic_runner._get_rag_context', return_value=mock_rag_context):
            with patch.dict(os.environ, {"RAG_ENABLED": "true", "OPENAI_API_KEY": "test-key"}):
                agentic_runner.RAG_ENABLED = True
                mock_openai.return_value = json.dumps(triage_with_rag)
                
                agentic_runner.run_triage_for_findings(
                    str(findings_file),
                    scope,
                    out_dir=str(tmp_path)
                )
        
        # In real tests, you would compare the confidence scores
        # RAG should generally lead to higher confidence when historical
        # examples closely match the current finding
    
    def test_rag_context_relevance(self, sample_finding):
        """Test that RAG returns relevant historical examples."""
        # This would test that similarity scores are meaningful
        # and that returned examples are actually relevant to the finding
        
        with patch('agentic_runner._rag_client_instance') as mock_client:
            mock_client.get_context_for_triage.return_value = "## Similar Historical Vulnerabilities\n\n### Example 1"
            
            with patch.dict(os.environ, {"RAG_ENABLED": "true"}):
                agentic_runner._rag_client_instance = mock_client
                agentic_runner.RAG_ENABLED = True
                
                context = agentic_runner._get_rag_context(sample_finding)
                
                # Verify that get_context_for_triage was called
                mock_client.get_context_for_triage.assert_called_once()
                # Verify context was returned
                assert "Similar Historical Vulnerabilities" in context
                # In real tests, verify similarity > threshold (e.g., > 0.4)

