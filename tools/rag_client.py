#!/usr/bin/env python3
"""
RAG Client - Search and retrieve vulnerability knowledge from Supabase pgvector.

This module provides a client for querying the RAG vulnerability knowledge base.
It supports:
- Semantic similarity search using embeddings
- Filtering by vulnerability type, severity, and technologies
- Hybrid search (semantic + keyword)

Usage:
    from tools.rag_client import RAGClient
    
    client = RAGClient()
    results = client.search("SSRF vulnerability in image upload")
    results = client.search_by_tech(["graphql", "nodejs"])
    results = client.search_similar_to_finding(finding_dict)
"""

import os
import sys
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

try:
    from supabase import create_client, Client
except ImportError:
    print("Missing supabase library. Install with: pip install supabase")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("Missing requests library. Install with: pip install requests")
    sys.exit(1)


@dataclass
class VulnMatch:
    """A matched vulnerability report from RAG search."""
    
    report_id: str
    title: str
    vuln_type: str
    severity: str
    cwe: str
    target_technology: List[str]
    attack_vector: str
    payload: str
    impact: str
    source_url: str
    similarity: float
    
    def to_context_string(self) -> str:
        """Format as context for LLM injection."""
        parts = [f"**{self.title}** ({self.severity})"]
        
        if self.vuln_type:
            parts.append(f"Type: {self.vuln_type}")
        
        if self.cwe:
            parts.append(f"CWE: {self.cwe}")
        
        if self.target_technology:
            parts.append(f"Tech: {', '.join(self.target_technology)}")
        
        if self.attack_vector:
            # Truncate long attack vectors
            av = self.attack_vector[:300]
            parts.append(f"Attack: {av}")
        
        if self.payload:
            # Show only first payload
            payload_lines = self.payload.split("\n")[:3]
            payload_preview = "\n".join(payload_lines)[:200]
            parts.append(f"Payload: `{payload_preview}`")
        
        if self.impact:
            impact_preview = self.impact[:150]
            parts.append(f"Impact: {impact_preview}")
        
        if self.source_url:
            parts.append(f"Ref: {self.source_url}")
        
        return "\n".join(parts)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "report_id": self.report_id,
            "title": self.title,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "cwe": self.cwe,
            "target_technology": self.target_technology,
            "attack_vector": self.attack_vector,
            "payload": self.payload,
            "impact": self.impact,
            "source_url": self.source_url,
            "similarity": self.similarity,
        }


class RAGClient:
    """Client for querying the RAG vulnerability knowledge base."""
    
    def __init__(
        self,
        supabase_url: Optional[str] = None,
        supabase_key: Optional[str] = None,
        openai_api_key: Optional[str] = None,
        embedding_model: str = "text-embedding-3-small",
    ):
        """
        Initialize RAG client.
        
        Args:
            supabase_url: Supabase project URL (or SUPABASE_URL env var)
            supabase_key: Supabase API key (or SUPABASE_KEY env var)
            openai_api_key: OpenAI API key (or OPENAI_API_KEY env var)
            embedding_model: OpenAI embedding model to use
        """
        self.supabase_url = supabase_url or os.environ.get("SUPABASE_URL")
        self.supabase_key = supabase_key or os.environ.get("SUPABASE_KEY")
        self.openai_api_key = openai_api_key or os.environ.get("OPENAI_API_KEY")
        self.embedding_model = embedding_model
        
        self._supabase: Optional[Client] = None
        self._validate_config()
    
    def _validate_config(self):
        """Validate configuration."""
        missing = []
        if not self.supabase_url:
            missing.append("SUPABASE_URL")
        if not self.supabase_key:
            missing.append("SUPABASE_KEY")
        if not self.openai_api_key:
            missing.append("OPENAI_API_KEY")
        
        if missing:
            raise ValueError(f"Missing required configuration: {', '.join(missing)}")
    
    @property
    def supabase(self) -> Client:
        """Lazy-initialize Supabase client."""
        if self._supabase is None:
            self._supabase = create_client(self.supabase_url, self.supabase_key)
        return self._supabase
    
    def _get_embedding(self, text: str) -> List[float]:
        """Get embedding for a text string."""
        headers = {
            "Authorization": f"Bearer {self.openai_api_key}",
            "Content-Type": "application/json",
        }
        
        payload = {
            "model": self.embedding_model,
            "input": text[:8000],  # Truncate to avoid token limits
        }
        
        response = requests.post(
            "https://api.openai.com/v1/embeddings",
            headers=headers,
            json=payload,
            timeout=30,
        )
        
        if response.status_code != 200:
            raise Exception(f"OpenAI API error: {response.status_code} - {response.text}")
        
        data = response.json()
        return data["data"][0]["embedding"]
    
    def _parse_results(self, data: List[Dict[str, Any]]) -> List[VulnMatch]:
        """Parse Supabase results into VulnMatch objects."""
        results = []
        for row in data:
            match = VulnMatch(
                report_id=row.get("report_id", ""),
                title=row.get("title", ""),
                vuln_type=row.get("vuln_type", ""),
                severity=row.get("severity", ""),
                cwe=row.get("cwe", ""),
                target_technology=row.get("target_technology", []) or [],
                attack_vector=row.get("attack_vector", ""),
                payload=row.get("payload", ""),
                impact=row.get("impact", ""),
                source_url=row.get("source_url", ""),
                similarity=row.get("similarity", 0.0),
            )
            results.append(match)
        return results
    
    def search(
        self,
        query: str,
        top_k: int = 5,
        min_similarity: float = 0.3,
        vuln_type: Optional[str] = None,
        severity: Optional[str] = None,
        technologies: Optional[List[str]] = None,
    ) -> List[VulnMatch]:
        """
        Semantic search for similar vulnerabilities.
        
        Args:
            query: Natural language query describing the vulnerability
            top_k: Maximum number of results to return
            min_similarity: Minimum cosine similarity threshold (0-1)
            vuln_type: Filter by vulnerability type (e.g., "xss", "ssrf")
            severity: Filter by severity (e.g., "critical", "high")
            technologies: Filter by technologies (e.g., ["nodejs", "graphql"])
        
        Returns:
            List of matched vulnerability reports
        """
        # Generate query embedding
        query_embedding = self._get_embedding(query)
        
        # Call the Supabase search function
        result = self.supabase.rpc(
            "search_similar_vulns",
            {
                "query_embedding": query_embedding,
                "match_threshold": min_similarity,
                "match_count": top_k,
                "filter_vuln_type": vuln_type,
                "filter_severity": severity,
                "filter_technologies": technologies,
            }
        ).execute()
        
        return self._parse_results(result.data or [])
    
    def search_by_vuln_type(
        self,
        vuln_type: str,
        top_k: int = 10,
    ) -> List[VulnMatch]:
        """
        Search for reports by vulnerability type.
        
        Args:
            vuln_type: Vulnerability type (e.g., "xss", "ssrf", "sqli")
            top_k: Maximum number of results
        
        Returns:
            List of matched vulnerability reports
        """
        result = self.supabase.table("vuln_reports")\
            .select("report_id, title, vuln_type, severity, cwe, target_technology, attack_vector, payload, impact, source_url")\
            .ilike("vuln_type", f"%{vuln_type}%")\
            .limit(top_k)\
            .execute()
        
        # Add default similarity score
        for row in result.data or []:
            row["similarity"] = 1.0
        
        return self._parse_results(result.data or [])
    
    def search_by_tech(
        self,
        technologies: List[str],
        top_k: int = 10,
    ) -> List[VulnMatch]:
        """
        Search for reports by technology stack.
        
        Args:
            technologies: List of technologies (e.g., ["nodejs", "graphql"])
            top_k: Maximum number of results
        
        Returns:
            List of matched vulnerability reports
        """
        result = self.supabase.table("vuln_reports")\
            .select("report_id, title, vuln_type, severity, cwe, target_technology, attack_vector, payload, impact, source_url")\
            .contains("target_technology", technologies)\
            .limit(top_k)\
            .execute()
        
        # Add default similarity score
        for row in result.data or []:
            row["similarity"] = 1.0
        
        return self._parse_results(result.data or [])
    
    def search_by_cwe(
        self,
        cwe: str,
        top_k: int = 10,
    ) -> List[VulnMatch]:
        """
        Search for reports by CWE identifier.
        
        Args:
            cwe: CWE identifier (e.g., "CWE-79", "79")
            top_k: Maximum number of results
        
        Returns:
            List of matched vulnerability reports
        """
        # Normalize CWE format
        if not cwe.upper().startswith("CWE-"):
            cwe = f"CWE-{cwe}"
        
        result = self.supabase.table("vuln_reports")\
            .select("report_id, title, vuln_type, severity, cwe, target_technology, attack_vector, payload, impact, source_url")\
            .ilike("cwe", f"%{cwe}%")\
            .limit(top_k)\
            .execute()
        
        # Add default similarity score
        for row in result.data or []:
            row["similarity"] = 1.0
        
        return self._parse_results(result.data or [])
    
    def search_similar_to_finding(
        self,
        finding: Dict[str, Any],
        top_k: int = 5,
        min_similarity: float = 0.4,
    ) -> List[VulnMatch]:
        """
        Find similar historical reports for a scanner finding.
        
        This method extracts key information from a scanner finding
        and searches for similar historical vulnerabilities.
        
        Args:
            finding: Scanner finding dictionary (from Nuclei, ZAP, etc.)
            top_k: Maximum number of results
            min_similarity: Minimum similarity threshold
        
        Returns:
            List of similar historical vulnerability reports
        """
        # Build search query from finding
        query_parts = []
        
        # Extract title/name
        title = finding.get("title") or finding.get("name") or finding.get("info", {}).get("name", "")
        if title:
            query_parts.append(title)
        
        # Extract description/summary
        desc = finding.get("description") or finding.get("summary") or finding.get("info", {}).get("description", "")
        if desc:
            query_parts.append(desc[:300])
        
        # Extract severity
        severity = finding.get("severity") or finding.get("info", {}).get("severity", "")
        if severity:
            query_parts.append(f"Severity: {severity}")
        
        # Extract CWE if available
        cwe = finding.get("cwe") or ""
        if not cwe:
            # Try to extract from classification
            classification = finding.get("info", {}).get("classification", {})
            cwe_ids = classification.get("cwe-id", [])
            if cwe_ids:
                cwe = f"CWE-{cwe_ids[0]}"
        if cwe:
            query_parts.append(f"CWE: {cwe}")
        
        # Extract URL/endpoint context
        url = finding.get("url") or finding.get("matched-at") or finding.get("host", "")
        if url:
            # Extract endpoint pattern
            from urllib.parse import urlparse
            try:
                parsed = urlparse(url)
                path = parsed.path or "/"
                query_parts.append(f"Endpoint: {path}")
            except Exception:
                pass
        
        # Extract any tags
        tags = finding.get("tags") or finding.get("info", {}).get("tags", [])
        if tags:
            query_parts.append(f"Tags: {', '.join(tags[:5])}")
        
        # Build final query
        query = " | ".join(query_parts)
        
        if not query:
            return []
        
        # Determine filters from finding
        vuln_type = None
        # Try to classify from title/tags
        title_lower = title.lower()
        if "xss" in title_lower or "cross-site scripting" in title_lower:
            vuln_type = "xss"
        elif "sql" in title_lower and "injection" in title_lower:
            vuln_type = "sqli"
        elif "ssrf" in title_lower:
            vuln_type = "ssrf"
        elif "idor" in title_lower or "insecure direct" in title_lower:
            vuln_type = "idor"
        
        return self.search(
            query=query,
            top_k=top_k,
            min_similarity=min_similarity,
            vuln_type=vuln_type,
        )
    
    def get_context_for_triage(
        self,
        finding: Dict[str, Any],
        host_profile: Optional[Dict[str, Any]] = None,
        max_examples: int = 3,
    ) -> str:
        """
        Generate RAG context string for LLM triage.
        
        This method finds similar historical vulnerabilities and formats
        them as context to inject into the triage prompt.
        
        Args:
            finding: Scanner finding to triage
            host_profile: Optional host profile with technology info
            max_examples: Maximum number of examples to include
        
        Returns:
            Formatted context string for LLM prompt
        """
        # Search for similar vulnerabilities
        similar = self.search_similar_to_finding(finding, top_k=max_examples + 2)
        
        if not similar:
            return ""
        
        # Take top matches
        top_matches = similar[:max_examples]
        
        # Format as context
        context_parts = [
            "## Similar Historical Vulnerabilities (for reference)",
            "",
        ]
        
        for i, match in enumerate(top_matches, 1):
            context_parts.append(f"### Example {i} (similarity: {match.similarity:.2f})")
            context_parts.append(match.to_context_string())
            context_parts.append("")
        
        return "\n".join(context_parts)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the RAG knowledge base."""
        # Total count
        total_result = self.supabase.table("vuln_reports")\
            .select("report_id", count="exact")\
            .execute()
        total_count = total_result.count or 0
        
        # Counts by vulnerability type
        vuln_types_result = self.supabase.table("vuln_reports")\
            .select("vuln_type")\
            .execute()
        
        vuln_type_counts = {}
        for row in vuln_types_result.data or []:
            vt = row.get("vuln_type") or "unknown"
            vuln_type_counts[vt] = vuln_type_counts.get(vt, 0) + 1
        
        # Counts by severity
        severity_result = self.supabase.table("vuln_reports")\
            .select("severity")\
            .execute()
        
        severity_counts = {}
        for row in severity_result.data or []:
            sev = row.get("severity") or "unknown"
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        return {
            "total_reports": total_count,
            "vuln_types": vuln_type_counts,
            "severities": severity_counts,
        }


# Singleton instance for easy import
_client: Optional[RAGClient] = None


def get_rag_client() -> RAGClient:
    """Get or create the singleton RAG client."""
    global _client
    if _client is None:
        _client = RAGClient()
    return _client


def search_similar_vulns(
    query: str,
    top_k: int = 5,
    vuln_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Convenience function for searching similar vulnerabilities.
    
    This is a simplified interface for use in MCP endpoints.
    """
    client = get_rag_client()
    results = client.search(query, top_k=top_k, vuln_type=vuln_type)
    return [r.to_dict() for r in results]


def get_triage_context(
    finding: Dict[str, Any],
    max_examples: int = 3,
) -> str:
    """
    Convenience function for getting triage context.
    
    This is the main integration point for agentic_runner.py.
    """
    try:
        client = get_rag_client()
        return client.get_context_for_triage(finding, max_examples=max_examples)
    except Exception as e:
        # RAG failures should not break triage
        print(f"[RAG] Warning: Failed to get context: {e}")
        return ""


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="RAG Client CLI")
    subparsers = parser.add_subparsers(dest="command")
    
    # Search command
    search_parser = subparsers.add_parser("search", help="Semantic search")
    search_parser.add_argument("query", help="Search query")
    search_parser.add_argument("--top-k", type=int, default=5)
    search_parser.add_argument("--vuln-type", help="Filter by vulnerability type")
    
    # Stats command
    stats_parser = subparsers.add_parser("stats", help="Show database statistics")
    
    # By-type command
    type_parser = subparsers.add_parser("by-type", help="Search by vulnerability type")
    type_parser.add_argument("vuln_type", help="Vulnerability type (xss, ssrf, etc.)")
    type_parser.add_argument("--top-k", type=int, default=10)
    
    # By-tech command
    tech_parser = subparsers.add_parser("by-tech", help="Search by technology")
    tech_parser.add_argument("technologies", nargs="+", help="Technologies to search for")
    tech_parser.add_argument("--top-k", type=int, default=10)
    
    args = parser.parse_args()
    
    try:
        client = RAGClient()
        
        if args.command == "search":
            results = client.search(args.query, top_k=args.top_k, vuln_type=args.vuln_type)
            print(f"\nFound {len(results)} similar vulnerabilities:\n")
            for r in results:
                print(f"[{r.severity}] {r.vuln_type}: {r.title[:60]}...")
                print(f"  Similarity: {r.similarity:.3f}")
                if r.source_url:
                    print(f"  URL: {r.source_url}")
                print()
        
        elif args.command == "stats":
            stats = client.get_stats()
            print(f"\nRAG Knowledge Base Statistics:")
            print(f"  Total reports: {stats['total_reports']}")
            print(f"\nTop vulnerability types:")
            for vt, count in sorted(stats['vuln_types'].items(), key=lambda x: -x[1])[:10]:
                print(f"  {vt}: {count}")
            print(f"\nSeverity distribution:")
            for sev, count in sorted(stats['severities'].items(), key=lambda x: -x[1]):
                print(f"  {sev}: {count}")
        
        elif args.command == "by-type":
            results = client.search_by_vuln_type(args.vuln_type, top_k=args.top_k)
            print(f"\nFound {len(results)} {args.vuln_type} vulnerabilities:\n")
            for r in results:
                print(f"[{r.severity}] {r.title[:70]}...")
                if r.source_url:
                    print(f"  URL: {r.source_url}")
                print()
        
        elif args.command == "by-tech":
            results = client.search_by_tech(args.technologies, top_k=args.top_k)
            print(f"\nFound {len(results)} vulnerabilities with {args.technologies}:\n")
            for r in results:
                print(f"[{r.severity}] {r.vuln_type}: {r.title[:60]}...")
                print(f"  Technologies: {', '.join(r.target_technology)}")
                print()
        
        else:
            parser.print_help()
    
    except ValueError as e:
        print(f"Configuration error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

