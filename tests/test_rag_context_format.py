"""Tests for RAG context format validation."""

import pytest
from tools.rag_client import VulnMatch, RAGClient
from unittest.mock import patch, MagicMock


class TestRAGContextFormat:
    """Tests for RAG context string format and structure."""
    
    def test_context_string_structure(self):
        """Test that context string has expected markdown structure."""
        match = VulnMatch(
            report_id="1000567",
            title="XSS in search parameter",
            vuln_type="xss",
            severity="high",
            cwe="CWE-79",
            target_technology=["python", "flask"],
            attack_vector="Reflected XSS in search query parameter",
            payload="<script>alert(1)</script>",
            impact="Attacker can execute arbitrary JavaScript",
            source_url="https://hackerone.com/reports/1000567",
            similarity=0.85,
        )
        
        context = match.to_context_string()
        
        # Should include title
        assert "XSS in search parameter" in context
        # Should include severity
        assert "high" in context
        # Should include CWE
        assert "CWE-79" in context
        # Should include technology
        assert "python" in context or "flask" in context
        # Should include attack vector
        assert "Reflected XSS" in context
        # Should include payload
        assert "alert(1)" in context
        # Should include impact
        assert "JavaScript" in context
        # Should include source URL
        assert "1000567" in context or "hackerone.com" in context
    
    def test_context_string_includes_similarity(self, rag_client_mock):
        """Test that context includes similarity scores."""
        finding = {"name": "XSS vulnerability"}
        
        mock_results = [
            VulnMatch(
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
            ),
            VulnMatch(
                report_id="1000568",
                title="Another XSS",
                vuln_type="xss",
                severity="medium",
                cwe="CWE-79",
                target_technology=[],
                attack_vector="",
                payload="",
                impact="",
                source_url="",
                similarity=0.72,
            ),
        ]
        
        with patch.object(rag_client_mock, 'search_similar_to_finding', return_value=mock_results):
            context = rag_client_mock.get_context_for_triage(finding, max_examples=2)
            
            # Should include similarity scores in headers
            assert "similarity: 0.85" in context
            assert "similarity: 0.72" in context
            assert "Example 1" in context
            assert "Example 2" in context
    
    def test_context_string_has_section_header(self, rag_client_mock):
        """Test that context has proper section header."""
        finding = {"name": "XSS vulnerability"}
        
        mock_results = [
            VulnMatch(
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
            ),
        ]
        
        with patch.object(rag_client_mock, 'search_similar_to_finding', return_value=mock_results):
            context = rag_client_mock.get_context_for_triage(finding)
            
            # Should have main section header
            assert "## Similar Historical Vulnerabilities" in context
            assert "(for reference)" in context
    
    def test_context_string_includes_all_required_fields(self):
        """Test that context includes all required fields from VulnMatch."""
        match = VulnMatch(
            report_id="1000567",
            title="XSS in search",
            vuln_type="xss",
            severity="high",
            cwe="CWE-79",
            target_technology=["python"],
            attack_vector="Reflected XSS",
            payload="<script>alert(1)</script>",
            impact="JS execution",
            source_url="https://hackerone.com/reports/1000567",
            similarity=0.85,
        )
        
        context = match.to_context_string()
        
        # Check all fields are present
        required_fields = [
            "XSS in search",  # title
            "high",  # severity
            "CWE-79",  # cwe
            "xss",  # vuln_type
            "Reflected XSS",  # attack_vector
            "alert(1)",  # payload (partial)
            "JS execution",  # impact
            "1000567",  # report_id or source_url
        ]
        
        for field in required_fields:
            assert field in context, f"Required field '{field}' not found in context"
    
    def test_context_string_truncates_long_fields(self):
        """Test that long fields are properly truncated."""
        long_attack_vector = "A" * 500
        long_payload = "B" * 1000
        long_impact = "C" * 500
        
        match = VulnMatch(
            report_id="1000567",
            title="Test",
            vuln_type="xss",
            severity="high",
            cwe="CWE-79",
            target_technology=[],
            attack_vector=long_attack_vector,
            payload=long_payload,
            impact=long_impact,
            source_url="",
            similarity=0.85,
        )
        
        context = match.to_context_string()
        
        # Attack vector should be truncated to ~300 chars
        assert len(context.split("Attack:")[1].split("\n")[0]) <= 310  # Some buffer
        
        # Payload should be truncated
        payload_section = context.split("Payload:")[1] if "Payload:" in context else ""
        if payload_section:
            # Payload is shown in first 3 lines, max 200 chars
            assert len(payload_section.split("\n")[0]) <= 210
        
        # Impact should be truncated to ~150 chars
        if "Impact:" in context:
            impact_section = context.split("Impact:")[1].split("\n")[0]
            assert len(impact_section) <= 160
    
    def test_context_string_handles_missing_fields(self):
        """Test that context handles missing optional fields gracefully."""
        match = VulnMatch(
            report_id="1000567",
            title="XSS in search",
            vuln_type="",
            severity="",
            cwe="",
            target_technology=[],
            attack_vector="",
            payload="",
            impact="",
            source_url="",
            similarity=0.85,
        )
        
        context = match.to_context_string()
        
        # Should still include title
        assert "XSS in search" in context
        # Should not crash on missing fields
        assert isinstance(context, str)
        assert len(context) > 0
    
    def test_get_context_for_triage_respects_max_examples(self, rag_client_mock):
        """Test that max_examples limit is respected."""
        finding = {"name": "XSS vulnerability"}
        
        # Create 5 mock results
        mock_results = [
            VulnMatch(
                report_id=f"100056{i}",
                title=f"XSS Example {i}",
                vuln_type="xss",
                severity="high",
                cwe="CWE-79",
                target_technology=[],
                attack_vector="",
                payload="",
                impact="",
                source_url="",
                similarity=0.9 - (i * 0.1),
            )
            for i in range(1, 6)
        ]
        
        with patch.object(rag_client_mock, 'search_similar_to_finding', return_value=mock_results):
            # Request max 3 examples
            context = rag_client_mock.get_context_for_triage(finding, max_examples=3)
            
            # Should only include 3 examples
            assert context.count("### Example") == 3
            assert "Example 1" in context
            assert "Example 2" in context
            assert "Example 3" in context
            assert "Example 4" not in context
            assert "Example 5" not in context
    
    def test_context_string_formats_multiple_examples(self, rag_client_mock):
        """Test that multiple examples are properly formatted."""
        finding = {"name": "XSS vulnerability"}
        
        mock_results = [
            VulnMatch(
                report_id="1000567",
                title="XSS in search",
                vuln_type="xss",
                severity="high",
                cwe="CWE-79",
                target_technology=["python"],
                attack_vector="Reflected XSS",
                payload="<script>alert(1)</script>",
                impact="JS execution",
                source_url="https://hackerone.com/reports/1000567",
                similarity=0.85,
            ),
            VulnMatch(
                report_id="1000568",
                title="Stored XSS",
                vuln_type="xss",
                severity="high",
                cwe="CWE-79",
                target_technology=["nodejs"],
                attack_vector="Stored XSS",
                payload="<img src=x onerror=alert(1)>",
                impact="Persistent XSS",
                source_url="https://hackerone.com/reports/1000568",
                similarity=0.78,
            ),
        ]
        
        with patch.object(rag_client_mock, 'search_similar_to_finding', return_value=mock_results):
            context = rag_client_mock.get_context_for_triage(finding, max_examples=2)
            
            # Should have both examples
            assert "Example 1" in context
            assert "Example 2" in context
            assert "XSS in search" in context
            assert "Stored XSS" in context
            assert "0.85" in context
            assert "0.78" in context
    
    def test_context_string_empty_when_no_results(self, rag_client_mock):
        """Test that context is empty when no similar vulnerabilities found."""
        finding = {"name": "Unknown vulnerability"}
        
        with patch.object(rag_client_mock, 'search_similar_to_finding', return_value=[]):
            context = rag_client_mock.get_context_for_triage(finding)
            
            assert context == ""
    
    def test_context_string_payload_formatting(self):
        """Test that payloads are properly formatted in context."""
        match = VulnMatch(
            report_id="1000567",
            title="XSS",
            vuln_type="xss",
            severity="high",
            cwe="CWE-79",
            target_technology=[],
            attack_vector="",
            payload="<script>alert(document.cookie)</script>\n<img src=x onerror=alert(1)>\n{{7*7}}",
            impact="",
            source_url="",
            similarity=0.85,
        )
        
        context = match.to_context_string()
        
        # Payload should be in code format (backticks)
        if "Payload:" in context:
            payload_section = context.split("Payload:")[1]
            # Should have backticks for code
            assert "`" in payload_section or "<script>" in payload_section
    
    def test_context_string_markdown_compatibility(self, rag_client_mock):
        """Test that context string is valid markdown."""
        finding = {"name": "XSS vulnerability"}
        
        mock_results = [
            VulnMatch(
                report_id="1000567",
                title="XSS in search",
                vuln_type="xss",
                severity="high",
                cwe="CWE-79",
                target_technology=["python"],
                attack_vector="Reflected XSS",
                payload="<script>alert(1)</script>",
                impact="JS execution",
                source_url="https://hackerone.com/reports/1000567",
                similarity=0.85,
            ),
        ]
        
        with patch.object(rag_client_mock, 'search_similar_to_finding', return_value=mock_results):
            context = rag_client_mock.get_context_for_triage(finding)
            
            # Should have proper markdown headers
            assert context.startswith("##")
            # Should have example headers
            assert "### Example" in context
            # Should not have unescaped special characters that break markdown
            # (basic check - full markdown parsing would be more thorough)
            assert "\n\n" in context or "\n" in context  # Proper line breaks

