#!/usr/bin/env python3
"""AI Nuclei Triage Helper

Takes a host_profile JSON and uses LLM to select optimal Nuclei templates
based on discovered technologies, endpoints, and attack surface.

Output: JSON with templates, tags, mode, and reasoning for audit.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

import requests

# ===== Config =====
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
LLM_MODEL = os.environ.get("LLM_MODEL", "gpt-4o-mini")

# Template directory structure knowledge (relative to nuclei-templates root)
TEMPLATE_CATEGORIES = {
    # Technology-specific
    "wordpress": ["http/vulnerabilities/wordpress/", "http/exposed-panels/wordpress/"],
    "drupal": ["http/vulnerabilities/drupal/"],
    "joomla": ["http/vulnerabilities/joomla/"],
    "magento": ["http/vulnerabilities/magento/"],
    "jenkins": ["http/vulnerabilities/jenkins/", "http/exposed-panels/jenkins/"],
    "gitlab": ["http/vulnerabilities/gitlab/", "http/exposed-panels/gitlab/"],
    "grafana": ["http/vulnerabilities/grafana/", "http/exposed-panels/grafana/"],
    "kibana": ["http/vulnerabilities/kibana/", "http/exposed-panels/kibana/"],
    "elasticsearch": ["http/vulnerabilities/elasticsearch/", "http/misconfiguration/elasticsearch/"],
    "apache": ["http/vulnerabilities/apache/", "http/cves/"],
    "nginx": ["http/vulnerabilities/nginx/", "http/misconfiguration/nginx/"],
    "tomcat": ["http/vulnerabilities/tomcat/", "http/exposed-panels/tomcat/"],
    "iis": ["http/vulnerabilities/iis/"],
    "php": ["http/vulnerabilities/php/"],
    "nodejs": ["http/vulnerabilities/nodejs/", "javascript/"],
    "python": ["http/vulnerabilities/python/"],
    "java": ["http/vulnerabilities/java/"],
    "spring": ["http/vulnerabilities/spring/", "http/cves/"],
    "struts": ["http/vulnerabilities/struts/"],
    "graphql": ["http/vulnerabilities/graphql/", "http/exposed-panels/graphql/"],
    "mongodb": ["http/vulnerabilities/mongodb/", "http/misconfiguration/mongodb/"],
    "mysql": ["http/vulnerabilities/mysql/"],
    "postgres": ["http/vulnerabilities/postgresql/"],
    "redis": ["http/vulnerabilities/redis/", "http/misconfiguration/redis/"],
    "docker": ["http/vulnerabilities/docker/", "http/exposed-panels/docker/"],
    "kubernetes": ["cloud/kubernetes/", "http/exposed-panels/kubernetes/"],
    "aws": ["cloud/aws/", "http/vulnerabilities/aws/"],
    "azure": ["cloud/azure/"],
    "gcp": ["cloud/gcp/"],
    "jira": ["http/vulnerabilities/jira/", "http/exposed-panels/jira/"],
    "confluence": ["http/vulnerabilities/confluence/", "http/exposed-panels/confluence/"],
    "bitbucket": ["http/vulnerabilities/bitbucket/"],
    "sonarqube": ["http/vulnerabilities/sonarqube/", "http/exposed-panels/sonarqube/"],
    "prometheus": ["http/exposed-panels/prometheus/"],
    "rabbitmq": ["http/vulnerabilities/rabbitmq/", "http/exposed-panels/rabbitmq/"],
    "phpmyadmin": ["http/vulnerabilities/phpmyadmin/", "http/exposed-panels/phpmyadmin/"],
    "weblogic": ["http/vulnerabilities/weblogic/"],
    "websphere": ["http/vulnerabilities/websphere/"],
    "sap": ["http/vulnerabilities/sap/"],
    "oracle": ["http/vulnerabilities/oracle/"],
    "microsoft": ["http/vulnerabilities/microsoft/"],
    "cisco": ["http/vulnerabilities/cisco/", "network/cves/"],
    "fortinet": ["http/vulnerabilities/fortinet/", "ssl/fortinet/"],
    "paloalto": ["http/vulnerabilities/palo-alto/"],
    "f5": ["http/vulnerabilities/f5/"],
    "vmware": ["http/vulnerabilities/vmware/"],
    "citrix": ["http/vulnerabilities/citrix/"],
    "zoho": ["http/vulnerabilities/zoho/"],
    "atlassian": ["http/vulnerabilities/atlassian/"],
    "laravel": ["http/vulnerabilities/laravel/"],
    "symfony": ["http/vulnerabilities/symfony/"],
    "django": ["http/vulnerabilities/django/"],
    "rails": ["http/vulnerabilities/rails/"],
    "nextjs": ["http/vulnerabilities/nextjs/"],
    "react": ["http/vulnerabilities/react/"],
    "angular": ["http/vulnerabilities/angular/"],
    "vue": ["http/vulnerabilities/vue/"],
}

# Attack surface categories
ATTACK_SURFACE_TEMPLATES = {
    "api": [
        "http/vulnerabilities/graphql/",
        "http/fuzzing/",
        "http/misconfiguration/",
        "dast/vulnerabilities/",
    ],
    "auth": [
        "http/default-logins/",
        "http/credential-stuffing/",
        "http/vulnerabilities/",
    ],
    "file_upload": [
        "http/vulnerabilities/",
        "dast/vulnerabilities/",
    ],
    "ssrf_candidates": [
        "dast/vulnerabilities/ssrf/",
        "http/vulnerabilities/",
    ],
    "exposed_panels": [
        "http/exposed-panels/",
    ],
    "misconfigurations": [
        "http/misconfiguration/",
        "ssl/",
    ],
    "secrets": [
        "http/exposures/",
        "file/keys/",
    ],
    "takeovers": [
        "http/takeovers/",
        "dns/",
    ],
}

# High-value CVE patterns to always consider
HIGH_VALUE_CVE_PATTERNS = [
    "http/cves/2024/",
    "http/cves/2023/",
    "http/cves/2022/",
]

SYSTEM_PROMPT = """You are an expert security researcher and nuclei template curator.

Given a host_profile JSON containing:
- Discovered URLs and API endpoints
- Technology fingerprints (frameworks, servers, CMS, etc.)
- Previous findings (if any)
- Attack surface indicators

Your task is to select the OPTIMAL set of Nuclei templates to run for targeted vulnerability discovery.

RULES:
1. Be PRECISE - only select templates relevant to the detected technologies
2. Be EFFICIENT - prioritize high-value, low-noise templates
3. Be SMART - consider attack chains (e.g., if GraphQL detected, include introspection + injection templates)
4. NEVER include templates for technologies NOT detected
5. Include relevant CVE templates for detected software versions when available
6. Consider the API surface - if REST/GraphQL endpoints found, include relevant fuzzing templates

Return STRICT JSON with these keys:
{
  "mode": "targeted",  // or "recon" for broad fingerprinting
  "templates": [
    "http/vulnerabilities/wordpress/",
    "http/cves/2024/CVE-2024-XXXXX.yaml"
  ],
  "tags": ["wordpress", "cve"],  // nuclei tags to filter
  "exclude_tags": ["dos", "fuzz"],  // tags to exclude
  "severity_filter": ["critical", "high", "medium"],  // severity levels
  "reasoning": "Brief explanation of selection logic"
}

If insufficient information to make targeted selections, return mode="recon" with basic fingerprinting templates."""

USER_TEMPLATE = """Host Profile JSON:
```json
{host_profile}
```

Available template categories and their paths:
```json
{template_categories}
```

Attack surface template mappings:
```json
{attack_surface_templates}
```

Select the optimal Nuclei templates for this host based on the detected technologies and attack surface."""


def openai_chat(messages: List[Dict[str, str]]) -> str:
    """Call OpenAI chat completion API."""
    if not OPENAI_API_KEY:
        raise RuntimeError("OPENAI_API_KEY not set")
    
    resp = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": LLM_MODEL,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": 2000,
        },
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"].strip()


def extract_technologies(host_profile: Dict[str, Any]) -> List[str]:
    """Extract technology names from host_profile."""
    techs: List[str] = []
    
    web = host_profile.get("web", {}) or {}
    fingerprints = web.get("fingerprints", {}) or {}
    
    # Direct technology list
    tech_list = fingerprints.get("technologies", []) or []
    techs.extend([t.lower() for t in tech_list if isinstance(t, str)])
    
    # Check nuclei findings for technology info
    nuclei_findings = host_profile.get("nuclei_findings", []) or []
    for finding in nuclei_findings:
        if isinstance(finding, dict):
            template_id = finding.get("template-id", "") or finding.get("templateID", "")
            if template_id:
                # Extract tech hints from template IDs like "wordpress-detect"
                parts = template_id.lower().split("-")
                if parts:
                    techs.append(parts[0])
    
    return list(set(techs))


def extract_attack_surface(host_profile: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze host_profile to determine attack surface characteristics."""
    surface: Dict[str, Any] = {
        "has_api": False,
        "has_graphql": False,
        "has_auth_endpoints": False,
        "has_file_upload": False,
        "has_admin_panel": False,
        "has_exposed_config": False,
        "url_count": 0,
        "api_endpoint_count": 0,
    }
    
    web = host_profile.get("web", {}) or {}
    
    # URL analysis
    urls = web.get("urls", []) or []
    surface["url_count"] = len(urls)
    
    for url in urls:
        url_lower = url.lower()
        if any(x in url_lower for x in ["/api/", "/v1/", "/v2/", "/rest/", "/graphql"]):
            surface["has_api"] = True
        if "/graphql" in url_lower:
            surface["has_graphql"] = True
        if any(x in url_lower for x in ["/admin", "/login", "/auth", "/signin", "/oauth"]):
            surface["has_auth_endpoints"] = True
        if any(x in url_lower for x in ["/upload", "/import", "/file"]):
            surface["has_file_upload"] = True
        if any(x in url_lower for x in ["/admin", "/dashboard", "/panel", "/console"]):
            surface["has_admin_panel"] = True
        if any(x in url_lower for x in [".env", ".git", ".config", "config.", "settings"]):
            surface["has_exposed_config"] = True
    
    # API endpoints
    api_endpoints = web.get("api_endpoints", []) or []
    surface["api_endpoint_count"] = len(api_endpoints)
    if api_endpoints:
        surface["has_api"] = True
    
    # Check for backups/exposures
    backups = web.get("backups", {}) or {}
    if backups.get("count", 0) > 0:
        surface["has_exposed_config"] = True
    
    # JS secrets
    js_secrets = web.get("js_secrets", {}) or {}
    if js_secrets.get("count", 0) > 0:
        surface["has_exposed_config"] = True
    
    return surface


def build_static_template_selection(
    technologies: List[str],
    attack_surface: Dict[str, Any],
) -> Dict[str, Any]:
    """Build a template selection using static rules (fallback when no LLM)."""
    templates: List[str] = []
    tags: List[str] = []
    
    # Technology-based selection
    for tech in technologies:
        tech_lower = tech.lower()
        for key, paths in TEMPLATE_CATEGORIES.items():
            if key in tech_lower or tech_lower in key:
                templates.extend(paths)
                tags.append(key)
    
    # Attack surface based selection
    if attack_surface.get("has_api"):
        templates.extend(ATTACK_SURFACE_TEMPLATES["api"])
        tags.append("api")
    
    if attack_surface.get("has_graphql"):
        templates.append("http/vulnerabilities/graphql/")
        tags.append("graphql")
    
    if attack_surface.get("has_auth_endpoints"):
        templates.extend(ATTACK_SURFACE_TEMPLATES["auth"])
        tags.append("login")
    
    if attack_surface.get("has_admin_panel"):
        templates.extend(ATTACK_SURFACE_TEMPLATES["exposed_panels"])
        tags.append("panel")
    
    if attack_surface.get("has_exposed_config"):
        templates.extend(ATTACK_SURFACE_TEMPLATES["secrets"])
        tags.append("exposure")
    
    # Deduplicate
    templates = list(set(templates))
    tags = list(set(tags))
    
    # Default to recon if nothing specific detected
    if not templates:
        return {
            "mode": "recon",
            "templates": [
                "http/technologies/",
                "http/exposed-panels/",
                "http/misconfiguration/",
                "ssl/",
            ],
            "tags": [],
            "exclude_tags": ["dos", "fuzz"],
            "severity_filter": ["critical", "high", "medium"],
            "reasoning": "No specific technologies detected; running broad recon templates.",
        }
    
    return {
        "mode": "targeted",
        "templates": templates[:20],  # Limit to avoid overwhelming scans
        "tags": tags[:10],
        "exclude_tags": ["dos"],
        "severity_filter": ["critical", "high", "medium"],
        "reasoning": f"Static selection based on detected techs: {', '.join(technologies[:5])}",
    }


def triage_templates(host_profile: Dict[str, Any], use_llm: bool = True) -> Dict[str, Any]:
    """
    Main triage function: analyze host_profile and return template selection.
    
    Args:
        host_profile: The host profile JSON from /mcp/host_profile
        use_llm: Whether to use LLM for intelligent selection (falls back to static rules)
    
    Returns:
        Dict with mode, templates, tags, exclude_tags, severity_filter, reasoning
    """
    technologies = extract_technologies(host_profile)
    attack_surface = extract_attack_surface(host_profile)
    
    # Enrich host_profile summary for LLM
    summary = {
        "host": host_profile.get("host"),
        "technologies": technologies,
        "attack_surface": attack_surface,
        "url_count": attack_surface["url_count"],
        "api_endpoint_count": attack_surface["api_endpoint_count"],
        "web": host_profile.get("web", {}),
    }
    
    if not use_llm or not OPENAI_API_KEY:
        print("[TRIAGE] Using static template selection (no LLM)", file=sys.stderr)
        return build_static_template_selection(technologies, attack_surface)
    
    try:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": USER_TEMPLATE.format(
                host_profile=json.dumps(summary, indent=2),
                template_categories=json.dumps(TEMPLATE_CATEGORIES, indent=2),
                attack_surface_templates=json.dumps(ATTACK_SURFACE_TEMPLATES, indent=2),
            )},
        ]
        
        response = openai_chat(messages)
        
        # Parse JSON from response (handle markdown code blocks)
        if "```json" in response:
            response = response.split("```json")[1].split("```")[0]
        elif "```" in response:
            response = response.split("```")[1].split("```")[0]
        
        result = json.loads(response.strip())
        
        # Validate required fields
        if "templates" not in result:
            result["templates"] = []
        if "mode" not in result:
            result["mode"] = "targeted" if result["templates"] else "recon"
        if "tags" not in result:
            result["tags"] = []
        if "reasoning" not in result:
            result["reasoning"] = "LLM selection"
        
        return result
        
    except Exception as e:
        print(f"[TRIAGE] LLM triage failed: {e}, falling back to static", file=sys.stderr)
        return build_static_template_selection(technologies, attack_surface)


def main():
    parser = argparse.ArgumentParser(description="AI Nuclei Template Triage Helper")
    parser.add_argument(
        "--host-profile",
        required=True,
        help="Path to host_profile JSON file or '-' for stdin",
    )
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Use static rules only, skip LLM",
    )
    parser.add_argument(
        "--output",
        help="Output file path (default: stdout)",
    )
    args = parser.parse_args()
    
    # Load host profile
    if args.host_profile == "-":
        host_profile = json.load(sys.stdin)
    else:
        with open(args.host_profile, "r", encoding="utf-8") as f:
            host_profile = json.load(f)
    
    # Run triage
    result = triage_templates(host_profile, use_llm=not args.no_llm)
    
    # Output
    output_json = json.dumps(result, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_json)
        print(f"[TRIAGE] Wrote template selection to {args.output}", file=sys.stderr)
    else:
        print(output_json)


if __name__ == "__main__":
    main()


