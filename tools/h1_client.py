#!/usr/bin/env python3
"""
HackerOne Client

Fetches bug bounty program information from HackerOne using:
1. Public GraphQL API (primary method)
2. Public page scraping (fallback)
3. Authenticated API (for private programs, requires API key)

Usage:
    from tools.h1_client import H1Client
    
    client = H1Client()
    program = client.fetch_program("23andme_bbp")
    scope = program.to_scope_json()
"""

import os
import re
import sys
import json
import time
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass


from tools.h1_models import (

# Import stealth HTTP client for WAF evasion
try:
    from tools.http_client import safe_get, safe_post, get_stealth_session
    USE_STEALTH = True
except ImportError:
    import requests
    USE_STEALTH = False
    
    def safe_get(url, **kwargs):
        return requests.get(url, **kwargs)
    
    def safe_post(url, **kwargs):
        return requests.post(url, **kwargs)

    H1Program, ScopeAsset, AssetType, BountyRange, 
    ProgramPolicy, SeverityRating
)


# Environment configuration
H1_API_TOKEN = os.environ.get("H1_API_TOKEN")
H1_API_USER = os.environ.get("H1_API_USER")  # Your H1 username for API auth
H1_RATE_LIMIT = float(os.environ.get("H1_RATE_LIMIT", "1.0"))  # Requests per second

# HackerOne endpoints
H1_GRAPHQL_URL = "https://hackerone.com/graphql"
H1_API_BASE = "https://api.hackerone.com/v1"
H1_PUBLIC_BASE = "https://hackerone.com"


class H1ClientError(Exception):
    """Base exception for H1 client errors"""
    pass


class H1RateLimitError(H1ClientError):
    """Rate limit exceeded"""
    pass


class H1NotFoundError(H1ClientError):
    """Program not found"""
    pass


class H1AuthError(H1ClientError):
    """Authentication required or failed"""
    pass


class H1Client:
    """
    HackerOne API client for fetching bug bounty program information.
    
    Supports multiple methods of data retrieval:
    - GraphQL API (public, most complete data)
    - REST API (requires authentication for private programs)
    - Page scraping (fallback for public programs)
    """
    
    def __init__(
        self,
        api_token: Optional[str] = None,
        api_user: Optional[str] = None,
        rate_limit: float = H1_RATE_LIMIT,
    ):
        self.api_token = api_token or H1_API_TOKEN
        self.api_user = api_user or H1_API_USER
        self.rate_limit = rate_limit
        self._last_request_time = 0.0
        
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; BugBountyAgent/1.0)",
            "Accept": "application/json",
        })
    
    def _rate_limit_wait(self):
        """Enforce rate limiting between requests"""
        now = time.time()
        elapsed = now - self._last_request_time
        min_interval = 1.0 / self.rate_limit
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last_request_time = time.time()
    
    def _graphql_query(self, query: str, variables: Optional[Dict] = None) -> Dict[str, Any]:
        """Execute a GraphQL query against HackerOne"""
        self._rate_limit_wait()
        
        payload = {
            "query": query,
            "variables": variables or {},
        }
        
        headers = {
            "Content-Type": "application/json",
        }
        
        try:
            resp = self.session.post(
                H1_GRAPHQL_URL,
                json=payload,
                headers=headers,
                timeout=30,
            )
            
            if resp.status_code == 429:
                raise H1RateLimitError("Rate limit exceeded. Wait before retrying.")
            
            resp.raise_for_status()
            data = resp.json()
            
            if "errors" in data:
                errors = data["errors"]
                error_msgs = [e.get("message", str(e)) for e in errors]
                raise H1ClientError(f"GraphQL errors: {'; '.join(error_msgs)}")
            
            return data.get("data", {})
            
        except requests.exceptions.RequestException as e:
            raise H1ClientError(f"Request failed: {e}")
    
    def _fetch_program_graphql(self, handle: str) -> Optional[Dict[str, Any]]:
        """
        Fetch program data via HackerOne GraphQL API.
        
        This is the preferred method as it provides the most complete data
        for public programs without authentication.
        """
        # GraphQL query for program details including scope
        # Note: HackerOne's GraphQL schema changes; we use fields known to work
        query = """
        query TeamProfilePage($handle: String!) {
          team(handle: $handle) {
            id
            handle
            name
            url
            state
            offers_bounties
            offers_swag
            
            structured_scopes(first: 100, archived: false) {
              edges {
                node {
                  id
                  asset_type
                  asset_identifier
                  eligible_for_bounty
                  eligible_for_submission
                  instruction
                  max_severity
                  created_at
                }
              }
            }
            
            bounty_table {
              id
              low_label
              medium_label
              high_label
              critical_label
            }
            
            policy
            
            response_efficiency_percentage
            first_response_time
            bounty_time
            resolution_time
            
            launched_at
            updated_at
            
            top_bounty_lower_amount
            top_bounty_upper_amount
            average_bounty_lower_amount
            average_bounty_upper_amount
          }
        }
        """
        
        try:
            data = self._graphql_query(query, {"handle": handle})
            team = data.get("team")
            
            if not team:
                return None
            
            return team
            
        except H1ClientError as e:
            print(f"[H1] GraphQL query failed: {e}", file=sys.stderr)
            return None
    
    def _fetch_public_page(self, handle: str) -> Optional[Dict[str, Any]]:
        """
        Fallback: Scrape public program page for scope information.
        
        Used when GraphQL fails or for additional data not in GraphQL.
        """
        self._rate_limit_wait()
        
        url = f"{H1_PUBLIC_BASE}/{handle}"
        
        try:
            resp = self.session.get(url, timeout=30)
            
            if resp.status_code == 404:
                return None
            
            resp.raise_for_status()
            html = resp.text
            
            # Extract JSON data embedded in page (React/Next.js style)
            # HackerOne embeds initial data in __NEXT_DATA__ script
            data_match = re.search(
                r'<script id="__NEXT_DATA__" type="application/json">(.*?)</script>',
                html,
                re.DOTALL
            )
            
            if data_match:
                try:
                    next_data = json.loads(data_match.group(1))
                    page_props = next_data.get("props", {}).get("pageProps", {})
                    return page_props
                except json.JSONDecodeError:
                    pass
            
            # Fallback: try to extract scope from page structure
            return self._parse_scope_from_html(html, handle)
            
        except requests.exceptions.RequestException as e:
            print(f"[H1] Page fetch failed: {e}", file=sys.stderr)
            return None
    
    def _parse_scope_from_html(self, html: str, handle: str) -> Optional[Dict[str, Any]]:
        """
        Parse scope information from HTML when JSON extraction fails.
        
        This is a last-resort method for very basic data extraction.
        """
        # This is a simplified parser - in production, use BeautifulSoup
        data = {
            "handle": handle,
            "name": handle,
            "in_scope": [],
            "out_of_scope": [],
        }
        
        # Try to find scope tables or lists
        # Look for common patterns in H1 pages
        
        # Pattern: URL/domain in scope markers
        url_pattern = re.compile(
            r'(?:in[\s-]*scope|scope)[^\n]*?'
            r'((?:https?://)?[\w.-]+\.[\w]+(?:/[\w./%-]*)?)',
            re.IGNORECASE
        )
        
        matches = url_pattern.findall(html)
        if matches:
            for url in matches[:20]:  # Limit to first 20
                data["in_scope"].append({
                    "identifier": url,
                    "asset_type": "URL",
                })
        
        return data if data["in_scope"] else None
    
    def _parse_structured_scopes(self, edges: List[Dict]) -> Tuple[List[ScopeAsset], List[ScopeAsset]]:
        """Parse GraphQL structured_scopes into in/out of scope assets"""
        in_scope = []
        out_of_scope = []
        
        for edge in edges:
            node = edge.get("node", {})
            
            # Map H1 asset types to our enum
            asset_type_map = {
                "URL": AssetType.URL,
                "CIDR": AssetType.CIDR,
                "WILDCARD": AssetType.WILDCARD,
                "API": AssetType.API,
                "APPLE_STORE_APP_ID": AssetType.IOS,
                "GOOGLE_PLAY_APP_ID": AssetType.ANDROID,
                "SOURCE_CODE": AssetType.SOURCE_CODE,
                "HARDWARE": AssetType.HARDWARE,
                "OTHER": AssetType.OTHER,
                "DOWNLOADABLE_EXECUTABLES": AssetType.DOWNLOADABLE_EXECUTABLES,
                "SMART_CONTRACT": AssetType.SMART_CONTRACT,
                "TESTNET_SMART_CONTRACT": AssetType.TESTNET_SMART_CONTRACT,
            }
            
            h1_type = node.get("asset_type", "OTHER")
            asset_type = asset_type_map.get(h1_type, AssetType.OTHER)
            
            # Parse max severity if present
            max_sev = node.get("max_severity")
            max_severity = None
            if max_sev:
                try:
                    max_severity = SeverityRating(max_sev.lower())
                except ValueError:
                    pass
            
            asset = ScopeAsset(
                identifier=node.get("asset_identifier", ""),
                asset_type=asset_type,
                eligible_for_bounty=node.get("eligible_for_bounty", True),
                eligible_for_submission=node.get("eligible_for_submission", True),
                instruction=node.get("instruction"),
                max_severity=max_severity,
            )
            
            if asset.eligible_for_submission:
                in_scope.append(asset)
            else:
                out_of_scope.append(asset)
        
        return in_scope, out_of_scope
    
    def _parse_bounty_table(self, bounty_table: Optional[Dict]) -> List[BountyRange]:
        """Parse bounty table into structured ranges"""
        if not bounty_table:
            return []
        
        ranges = []
        
        # Parse labels like "$500 - $1,000"
        def parse_range(label: Optional[str]) -> Tuple[float, float]:
            if not label:
                return (0, 0)
            
            # Remove currency symbols and commas
            cleaned = re.sub(r'[\$€£,]', '', label)
            
            # Try to find two numbers
            numbers = re.findall(r'[\d.]+', cleaned)
            if len(numbers) >= 2:
                return (float(numbers[0]), float(numbers[1]))
            elif len(numbers) == 1:
                val = float(numbers[0])
                return (val, val)
            return (0, 0)
        
        labels = [
            ("low_label", SeverityRating.LOW),
            ("medium_label", SeverityRating.MEDIUM),
            ("high_label", SeverityRating.HIGH),
            ("critical_label", SeverityRating.CRITICAL),
        ]
        
        for key, severity in labels:
            label = bounty_table.get(key)
            if label:
                min_amt, max_amt = parse_range(label)
                if max_amt > 0:
                    ranges.append(BountyRange(
                        severity=severity,
                        min_amount=min_amt,
                        max_amount=max_amt,
                    ))
        
        return ranges
    
    def _parse_policy(self, policy_html: Optional[str], submission_reqs: Optional[str]) -> ProgramPolicy:
        """Parse program policy from HTML/text"""
        policy = ProgramPolicy()
        
        if policy_html:
            html_lower = policy_html.lower()
            
            # Check for automated testing mentions
            if "no automated" in html_lower or "manual testing only" in html_lower:
                policy.allow_automated_testing = False
            
            # Check for rate limit mentions
            rate_match = re.search(r'(\d+)\s*requests?\s*per\s*(second|minute|hour)', html_lower)
            if rate_match:
                count = int(rate_match.group(1))
                unit = rate_match.group(2)
                if unit == "minute":
                    count = count // 60
                elif unit == "hour":
                    count = count // 3600
                policy.testing_rate_limit = f"{count} requests per second"
            
            # Extract excluded vulnerability types
            excluded_patterns = [
                r'out of scope[:\s]*([^<]+)',
                r'not accepted[:\s]*([^<]+)',
                r'excluded[:\s]*([^<]+)',
            ]
            
            for pattern in excluded_patterns:
                match = re.search(pattern, html_lower)
                if match:
                    text = match.group(1)
                    # Common exclusions
                    exclusions = [
                        "social engineering",
                        "phishing",
                        "physical attack",
                        "dos",
                        "denial of service",
                        "rate limiting",
                        "brute force",
                        "self-xss",
                        "missing headers",
                        "clickjacking",
                        "csrf logout",
                        "tabnabbing",
                        "open redirect",
                    ]
                    for excl in exclusions:
                        if excl in text:
                            policy.excluded_vuln_types.append(excl)
            
            # Extract custom rules (list items from policy)
            rule_pattern = re.compile(r'<li[^>]*>(.*?)</li>', re.IGNORECASE | re.DOTALL)
            rules = rule_pattern.findall(policy_html)
            for rule in rules[:20]:  # Limit to 20 rules
                # Clean HTML
                clean_rule = re.sub(r'<[^>]+>', '', rule).strip()
                if clean_rule and len(clean_rule) > 10:
                    policy.custom_rules.append(clean_rule[:500])  # Limit length
        
        return policy
    
    def fetch_program(self, handle: str) -> H1Program:
        """
        Fetch complete program information from HackerOne.
        
        Args:
            handle: The program handle/slug (e.g., "23andme_bbp")
        
        Returns:
            H1Program object with complete scope and policy information
        
        Raises:
            H1NotFoundError: If program doesn't exist
            H1ClientError: On API/network errors
        """
        print(f"[H1] Fetching program: {handle}", file=sys.stderr)
        
        # Try GraphQL first (most complete)
        gql_data = self._fetch_program_graphql(handle)
        
        if gql_data:
            return self._build_program_from_graphql(gql_data)
        
        # Fallback to page scraping
        print(f"[H1] GraphQL failed, trying page scrape for {handle}", file=sys.stderr)
        page_data = self._fetch_public_page(handle)
        
        if page_data:
            return self._build_program_from_page(page_data, handle)
        
        raise H1NotFoundError(f"Program not found: {handle}")
    
    def _build_program_from_graphql(self, data: Dict[str, Any]) -> H1Program:
        """Build H1Program from GraphQL response"""
        handle = data.get("handle", "")
        name = data.get("name") or data.get("profile", {}).get("name") or handle
        
        # Parse structured scopes
        scope_edges = data.get("structured_scopes", {}).get("edges", [])
        in_scope, out_of_scope = self._parse_structured_scopes(scope_edges)
        
        # Parse bounty ranges
        bounty_ranges = self._parse_bounty_table(data.get("bounty_table"))
        
        # Parse policy (may be 'policy' or 'policy_html' depending on API version)
        policy = self._parse_policy(
            data.get("policy") or data.get("policy_html"),
            None,  # submission_requirements removed from newer API
        )
        
        # Parse response times (they come in seconds from API)
        first_response = data.get("first_response_time")
        bounty_time = data.get("bounty_time")
        resolution_time = data.get("resolution_time")
        
        # Parse bounty stats
        avg_bounty = None
        top_bounty = None
        
        avg_lower = data.get("average_bounty_lower_amount")
        avg_upper = data.get("average_bounty_upper_amount")
        if avg_lower is not None and avg_upper is not None:
            avg_bounty = (avg_lower + avg_upper) / 2
        
        top_lower = data.get("top_bounty_lower_amount")
        top_upper = data.get("top_bounty_upper_amount")
        if top_lower is not None and top_upper is not None:
            top_bounty = (top_lower + top_upper) / 2
        
        return H1Program(
            handle=handle,
            name=name,
            url=data.get("url") or f"{H1_PUBLIC_BASE}/{handle}",
            offers_bounties=data.get("offers_bounties", True),
            offers_swag=data.get("offers_swag", False),
            state=data.get("state", "open"),
            in_scope_assets=in_scope,
            out_of_scope_assets=out_of_scope,
            bounty_ranges=bounty_ranges,
            average_bounty=avg_bounty,
            top_bounty=top_bounty,
            policy=policy,
            avg_first_response_time=first_response,
            avg_bounty_time=bounty_time,
            avg_resolution_time=resolution_time,
            launched_at=data.get("launched_at"),
            last_updated=data.get("updated_at"),
            raw_data=data,
        )
    
    def _build_program_from_page(self, data: Dict[str, Any], handle: str) -> H1Program:
        """Build H1Program from scraped page data"""
        # Basic parsing from page structure
        name = data.get("name") or data.get("team", {}).get("name") or handle
        
        in_scope = []
        out_of_scope = []
        
        # Parse in_scope items
        for item in data.get("in_scope", []):
            asset_type_str = item.get("asset_type", "OTHER")
            try:
                asset_type = AssetType(asset_type_str)
            except ValueError:
                asset_type = AssetType.OTHER
            
            in_scope.append(ScopeAsset(
                identifier=item.get("identifier", ""),
                asset_type=asset_type,
                eligible_for_bounty=item.get("eligible_for_bounty", True),
                instruction=item.get("instruction"),
            ))
        
        # Parse out_of_scope items
        for item in data.get("out_of_scope", []):
            asset_type_str = item.get("asset_type", "OTHER")
            try:
                asset_type = AssetType(asset_type_str)
            except ValueError:
                asset_type = AssetType.OTHER
            
            out_of_scope.append(ScopeAsset(
                identifier=item.get("identifier", ""),
                asset_type=asset_type,
                eligible_for_bounty=False,
                eligible_for_submission=False,
                instruction=item.get("instruction"),
            ))
        
        return H1Program(
            handle=handle,
            name=name,
            url=f"{H1_PUBLIC_BASE}/{handle}",
            in_scope_assets=in_scope,
            out_of_scope_assets=out_of_scope,
            raw_data=data,
        )
    
    def search_programs(
        self,
        query: Optional[str] = None,
        offers_bounties: bool = True,
        state: str = "open",
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """
        Search for bug bounty programs on HackerOne.
        
        Args:
            query: Search query (program name, domain, etc.)
            offers_bounties: Filter to programs that pay bounties
            state: Program state filter (open, paused, etc.)
            limit: Maximum number of results
        
        Returns:
            List of basic program info dicts
        """
        search_query = """
        query DirectoryQuery($query: String, $cursor: String, $count: Int) {
          teams(
            first: $count
            after: $cursor
            where: {
              state: {_eq: public_mode}
              submission_state: {_eq: open}
            }
            order_by: {launched_at: desc_nulls_last}
          ) {
            edges {
              node {
                id
                handle
                name
                state
                offers_bounties
                profile {
                  name
                }
              }
            }
          }
        }
        """
        
        try:
            data = self._graphql_query(search_query, {
                "query": query,
                "count": limit,
            })
            
            teams = data.get("teams", {}).get("edges", [])
            results = []
            
            for edge in teams:
                node = edge.get("node", {})
                if offers_bounties and not node.get("offers_bounties"):
                    continue
                
                results.append({
                    "handle": node.get("handle"),
                    "name": node.get("name") or node.get("profile", {}).get("name"),
                    "offers_bounties": node.get("offers_bounties"),
                    "state": node.get("state"),
                })
            
            return results[:limit]
            
        except H1ClientError as e:
            print(f"[H1] Search failed: {e}", file=sys.stderr)
            return []


def fetch_and_save_scope(
    handle: str,
    output_path: str = "scope.json",
    include_full_details: bool = False,
) -> H1Program:
    """
    Convenience function to fetch a program and save its scope.
    
    Args:
        handle: HackerOne program handle
        output_path: Where to save the scope.json file
        include_full_details: Include out-of-scope and all metadata
    
    Returns:
        The fetched H1Program object
    """
    client = H1Client()
    program = client.fetch_program(handle)
    
    # Generate scope.json
    scope = program.to_scope_json(include_out_of_scope=include_full_details)
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(scope, f, indent=2)
    
    print(f"[H1] Saved scope to {output_path}", file=sys.stderr)
    print(f"[H1] Found {len(program.in_scope_assets)} in-scope assets", file=sys.stderr)
    print(f"[H1] Found {len(program.out_of_scope_assets)} out-of-scope assets", file=sys.stderr)
    
    return program


if __name__ == "__main__":
    # Quick test
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python h1_client.py <program_handle>")
        print("Example: python h1_client.py hackerone")
        sys.exit(1)
    
    handle = sys.argv[1]
    program = fetch_and_save_scope(handle, include_full_details=True)
    
    print("\n=== Program Summary ===")
    print(f"Name: {program.name}")
    print(f"Handle: {program.handle}")
    print(f"Offers Bounties: {program.offers_bounties}")
    print(f"In-scope assets: {len(program.in_scope_assets)}")
    for asset in program.in_scope_assets[:5]:
        print(f"  - {asset.asset_type.value}: {asset.identifier}")
    if len(program.in_scope_assets) > 5:
        print(f"  ... and {len(program.in_scope_assets) - 5} more")

