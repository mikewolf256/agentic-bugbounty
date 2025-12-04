"""Unit tests for RAGClient."""

import pytest
from unittest.mock import MagicMock, patch, Mock
from typing import Dict, Any, List

from tools.rag_client import RAGClient, VulnMatch


class TestVulnMatch:
    """Tests for VulnMatch dataclass."""
    
    def test_to_context_string(self):
        """Test context string formatting."""
        match = VulnMatch(
            report_id="1000567",
            title="XSS in search",
            vuln_type="xss",
            severity="high",
            cwe="CWE-79",
            target_technology=["python", "flask"],
            attack_vector="Reflected XSS",
            payload="<script>alert(1)</script>",
            impact="Arbitrary JS execution",
            source_url="https://hackerone.com/reports/1000567",
            similarity=0.85,
        )
        
        context = match.to_context_string()
        
        assert "XSS in search" in context
        assert "high" in context
        assert "CWE-79" in context
        assert "python" in context or "flask" in context
        assert "Reflected XSS" in context
        assert "alert(1)" in context
        assert "1000567" in context
    
    def test_to_dict(self):
        """Test dictionary conversion."""
        match = VulnMatch(
            report_id="1000567",
            title="Test",
            vuln_type="xss",
            severity="high",
            cwe="CWE-79",
            target_technology=["python"],
            attack_vector="test",
            payload="test",
            impact="test",
            source_url="https://test.com",
            similarity=0.85,
        )
        
        result = match.to_dict()
        
        assert result["report_id"] == "1000567"
        assert result["similarity"] == 0.85
        assert isinstance(result["target_technology"], list)


class TestRAGClient:
    """Tests for RAGClient class."""
    
    def test_init_missing_config(self):
        """Test initialization with missing config raises error."""
        with pytest.raises(ValueError, match="Missing required configuration"):
            RAGClient(
                supabase_url=None,
                supabase_key=None,
                openai_api_key=None,
            )
    
    def test_init_valid_config(self):
        """Test initialization with valid config."""
        client = RAGClient(
            supabase_url="https://test.supabase.co",
            supabase_key="test-key",
            openai_api_key="test-openai-key",
        )
        
        assert client.supabase_url == "https://test.supabase.co"
        assert client.supabase_key == "test-key"
        assert client.openai_api_key == "test-openai-key"
    
    @patch('tools.rag_client.create_client')
    def test_supabase_lazy_init(self, mock_create_client):
        """Test Supabase client is lazily initialized."""
        mock_client = MagicMock()
        mock_create_client.return_value = mock_client
        
        client = RAGClient(
            supabase_url="https://test.supabase.co",
            supabase_key="test-key",
            openai_api_key="test-openai-key",
        )
        
        # Should not be initialized yet
        assert client._supabase is None
        
        # Access property to trigger initialization
        supabase = client.supabase
        
        assert supabase == mock_client
        mock_create_client.assert_called_once_with(
            "https://test.supabase.co",
            "test-key"
        )
    
    @patch('tools.rag_client.requests.post')
    def test_get_embedding(self, mock_post):
        """Test embedding generation."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{"embedding": [0.1] * 1536}]
        }
        mock_post.return_value = mock_response
        
        client = RAGClient(
            supabase_url="https://test.supabase.co",
            supabase_key="test-key",
            openai_api_key="test-openai-key",
        )
        
        embedding = client._get_embedding("test query")
        
        assert len(embedding) == 1536
        assert embedding[0] == 0.1
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args[0][0] == "https://api.openai.com/v1/embeddings"
        assert call_args[1]["json"]["model"] == "text-embedding-3-small"
    
    @patch('tools.rag_client.requests.post')
    def test_get_embedding_error(self, mock_post):
        """Test embedding generation handles errors."""
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Bad request"
        mock_post.return_value = mock_response
        
        client = RAGClient(
            supabase_url="https://test.supabase.co",
            supabase_key="test-key",
            openai_api_key="test-openai-key",
        )
        
        with pytest.raises(Exception, match="OpenAI API error"):
            client._get_embedding("test query")
    
    def test_parse_results(self):
        """Test parsing Supabase results."""
        client = RAGClient(
            supabase_url="https://test.supabase.co",
            supabase_key="test-key",
            openai_api_key="test-openai-key",
        )
        
        data = [
            {
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
        ]
        
        results = client._parse_results(data)
        
        assert len(results) == 1
        assert isinstance(results[0], VulnMatch)
        assert results[0].report_id == "1000567"
        assert results[0].similarity == 0.85
    
    def test_parse_results_empty(self):
        """Test parsing empty results."""
        client = RAGClient(
            supabase_url="https://test.supabase.co",
            supabase_key="test-key",
            openai_api_key="test-openai-key",
        )
        
        results = client._parse_results([])
        assert results == []
    
    @patch('tools.rag_client.requests.post')
    def test_search(self, mock_post, rag_client_mock):
        """Test semantic search."""
        # Mock embedding
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": [{"embedding": [0.1] * 1536}]
        }
        mock_post.return_value = mock_response
        
        # Mock Supabase RPC call
        mock_rpc_result = MagicMock()
        mock_rpc_result.data = [
            {
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
        ]
        rag_client_mock.supabase.rpc.return_value.execute.return_value = mock_rpc_result
        
        results = rag_client_mock.search("XSS vulnerability", top_k=5)
        
        assert len(results) == 1
        assert results[0].vuln_type == "xss"
        rag_client_mock.supabase.rpc.assert_called_once()
    
    def test_search_by_vuln_type(self, rag_client_mock):
        """Test search by vulnerability type."""
        mock_table = MagicMock()
        mock_result = MagicMock()
        mock_result.data = [
            {
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
            }
        ]
        mock_table.select.return_value.ilike.return_value.limit.return_value.execute.return_value = mock_result
        rag_client_mock.supabase.table.return_value = mock_table
        
        results = rag_client_mock.search_by_vuln_type("xss", top_k=10)
        
        assert len(results) == 1
        assert results[0].vuln_type == "xss"
        assert results[0].similarity == 1.0  # Default similarity for type search
    
    def test_search_by_tech(self, rag_client_mock):
        """Test search by technology."""
        mock_table = MagicMock()
        mock_result = MagicMock()
        mock_result.data = [
            {
                "report_id": "1000567",
                "title": "XSS in search",
                "vuln_type": "xss",
                "severity": "high",
                "cwe": "CWE-79",
                "target_technology": ["python", "flask"],
                "attack_vector": "Reflected XSS",
                "payload": "<script>alert(1)</script>",
                "impact": "JS execution",
                "source_url": "https://hackerone.com/reports/1000567",
            }
        ]
        mock_table.select.return_value.contains.return_value.limit.return_value.execute.return_value = mock_result
        rag_client_mock.supabase.table.return_value = mock_table
        
        results = rag_client_mock.search_by_tech(["python", "flask"], top_k=10)
        
        assert len(results) == 1
        assert "python" in results[0].target_technology
    
    def test_search_similar_to_finding(self, rag_client_mock):
        """Test finding-based similarity search."""
        finding = {
            "name": "XSS in search parameter",
            "title": "Cross-site scripting vulnerability",
            "description": "Reflected XSS in search query",
            "severity": "high",
            "cwe": "CWE-79",
            "url": "https://example.com/search?q=test",
            "tags": ["xss", "reflected"],
        }
        
        # Mock the search method
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
            )
        ]
        
        with patch.object(rag_client_mock, 'search', return_value=mock_results):
            results = rag_client_mock.search_similar_to_finding(finding, top_k=5)
            
            assert len(results) == 1
            assert results[0].vuln_type == "xss"
            # Verify search was called with extracted query
            rag_client_mock.search.assert_called_once()
            call_args = rag_client_mock.search.call_args
            assert "XSS" in call_args[1]["query"] or "xss" in call_args[1]["query"].lower()
            assert call_args[1]["vuln_type"] == "xss"
    
    def test_search_similar_to_finding_empty(self, rag_client_mock):
        """Test finding-based search with empty finding."""
        with patch.object(rag_client_mock, 'search', return_value=[]):
            results = rag_client_mock.search_similar_to_finding({}, top_k=5)
            assert results == []
    
    def test_get_context_for_triage(self, rag_client_mock):
        """Test context generation for triage."""
        finding = {
            "name": "XSS in search",
            "title": "Cross-site scripting",
        }
        
        mock_results = [
            VulnMatch(
                report_id="1000567",
                title="XSS in search",
                vuln_type="xss",
                severity="high",
                cwe="CWE-79",
                target_technology=[],
                attack_vector="Reflected XSS",
                payload="<script>alert(1)</script>",
                impact="JS execution",
                source_url="https://hackerone.com/reports/1000567",
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
                similarity=0.75,
            ),
        ]
        
        with patch.object(rag_client_mock, 'search_similar_to_finding', return_value=mock_results):
            context = rag_client_mock.get_context_for_triage(finding, max_examples=2)
            
            assert "Similar Historical Vulnerabilities" in context
            assert "Example 1" in context
            assert "Example 2" in context
            assert "0.85" in context
            assert "XSS in search" in context
    
    def test_get_context_for_triage_no_results(self, rag_client_mock):
        """Test context generation with no results."""
        finding = {"name": "Unknown vulnerability"}
        
        with patch.object(rag_client_mock, 'search_similar_to_finding', return_value=[]):
            context = rag_client_mock.get_context_for_triage(finding)
            assert context == ""
    
    def test_get_stats(self, rag_client_mock):
        """Test statistics retrieval."""
        # Mock count query
        mock_count_result = MagicMock()
        mock_count_result.count = 100
        
        # Mock vuln types query
        mock_types_result = MagicMock()
        mock_types_result.data = [
            {"vuln_type": "xss"},
            {"vuln_type": "xss"},
            {"vuln_type": "sqli"},
        ]
        
        # Mock severity query
        mock_severity_result = MagicMock()
        mock_severity_result.data = [
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "high"},
        ]
        
        mock_table = MagicMock()
        mock_table.select.return_value.execute.side_effect = [
            mock_count_result,  # First call for count
            mock_types_result,  # Second call for types
            mock_severity_result,  # Third call for severities
        ]
        rag_client_mock.supabase.table.return_value = mock_table
        
        stats = rag_client_mock.get_stats()
        
        assert stats["total_reports"] == 100
        assert stats["vuln_types"]["xss"] == 2
        assert stats["vuln_types"]["sqli"] == 1
        assert stats["severities"]["high"] == 2
        assert stats["severities"]["medium"] == 1

