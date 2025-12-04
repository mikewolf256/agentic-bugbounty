#!/usr/bin/env python3
"""
RAG Report Parser - Parse HackerOne disclosed report markdown files into structured data.

This module handles the extraction of structured vulnerability information from
the marcotuliocnd/bugbounty-disclosed-reports repository format.
"""

import os
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path


@dataclass
class ParsedReport:
    """Structured representation of a HackerOne vulnerability report."""
    
    report_id: str
    title: str
    source_url: str = ""
    state: str = ""
    severity: str = ""
    submitted_at: Optional[datetime] = None
    disclosed_at: Optional[datetime] = None
    reporter_username: str = ""
    program_name: str = ""
    team_handle: str = ""
    
    # Extracted vulnerability details
    vuln_type: str = ""
    cwe: str = ""
    target_technology: List[str] = field(default_factory=list)
    attack_vector: str = ""
    payload: str = ""
    impact: str = ""
    steps_to_reproduce: str = ""
    
    # Raw content for fallback and embedding
    raw_content: str = ""
    vulnerability_info: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, handling datetime serialization."""
        d = asdict(self)
        if d.get("submitted_at"):
            d["submitted_at"] = d["submitted_at"].isoformat()
        if d.get("disclosed_at"):
            d["disclosed_at"] = d["disclosed_at"].isoformat()
        return d


# Vulnerability type classification patterns
VULN_TYPE_PATTERNS = {
    "xss": [
        r"\bxss\b", r"cross[- ]?site[- ]?scripting", r"reflected\s+script",
        r"stored\s+script", r"dom[- ]?based", r"script\s+injection"
    ],
    "ssrf": [
        r"\bssrf\b", r"server[- ]?side[- ]?request[- ]?forgery",
        r"internal\s+request", r"url\s+fetch"
    ],
    "sqli": [
        r"\bsqli?\b", r"sql[- ]?injection", r"database\s+injection",
        r"blind\s+sql", r"union\s+select"
    ],
    "idor": [
        r"\bidor\b", r"insecure[- ]?direct[- ]?object",
        r"broken[- ]?access[- ]?control", r"authorization\s+bypass",
        r"bola\b", r"broken\s+object\s+level"
    ],
    "rce": [
        r"\brce\b", r"remote[- ]?code[- ]?execution",
        r"command[- ]?injection", r"os\s+command"
    ],
    "lfi": [
        r"\blfi\b", r"local[- ]?file[- ]?inclusion",
        r"path[- ]?traversal", r"directory[- ]?traversal"
    ],
    "xxe": [
        r"\bxxe\b", r"xml[- ]?external[- ]?entity",
        r"xml\s+injection"
    ],
    "csrf": [
        r"\bcsrf\b", r"cross[- ]?site[- ]?request[- ]?forgery"
    ],
    "open_redirect": [
        r"open[- ]?redirect", r"url[- ]?redirect",
        r"unvalidated[- ]?redirect"
    ],
    "info_disclosure": [
        r"information[- ]?disclosure", r"sensitive[- ]?data[- ]?exposure",
        r"data[- ]?leak", r"pii\s+exposure"
    ],
    "auth_bypass": [
        r"authentication[- ]?bypass", r"auth[- ]?bypass",
        r"login\s+bypass", r"2fa\s+bypass"
    ],
    "rate_limit_bypass": [
        r"rate[- ]?limit[- ]?bypass", r"brute[- ]?force"
    ],
    "redos": [
        r"\bredos\b", r"regex[- ]?dos", r"regular[- ]?expression[- ]?dos",
        r"catastrophic[- ]?backtracking"
    ],
    "dos": [
        r"\bdos\b", r"denial[- ]?of[- ]?service", r"resource[- ]?exhaustion"
    ],
    "subdomain_takeover": [
        r"subdomain[- ]?takeover", r"dangling[- ]?dns", r"cname\s+takeover"
    ],
    "graphql": [
        r"graphql", r"introspection", r"query[- ]?batching"
    ],
    "jwt": [
        r"\bjwt\b", r"json[- ]?web[- ]?token", r"token\s+manipulation"
    ],
    "ssti": [
        r"\bssti\b", r"server[- ]?side[- ]?template[- ]?injection",
        r"template[- ]?injection"
    ],
    "race_condition": [
        r"race[- ]?condition", r"toctou", r"time[- ]?of[- ]?check"
    ],
    "cache_poisoning": [
        r"cache[- ]?poisoning", r"web[- ]?cache[- ]?deception"
    ],
    "request_smuggling": [
        r"request[- ]?smuggling", r"http[- ]?smuggling",
        r"cl\.te", r"te\.cl"
    ],
    "prototype_pollution": [
        r"prototype[- ]?pollution", r"__proto__"
    ],
    "oauth": [
        r"oauth", r"oidc", r"token[- ]?theft", r"redirect_uri"
    ],
    "cors": [
        r"\bcors\b", r"cross[- ]?origin[- ]?resource"
    ],
    "clickjacking": [
        r"clickjacking", r"ui[- ]?redressing", r"x-frame-options"
    ],
    "deserialization": [
        r"deserialization", r"insecure[- ]?deserialization",
        r"object[- ]?injection"
    ],
    "file_upload": [
        r"file[- ]?upload", r"unrestricted[- ]?upload",
        r"arbitrary[- ]?file"
    ],
    "api_abuse": [
        r"api[- ]?abuse", r"api[- ]?key[- ]?leak",
        r"broken[- ]?function[- ]?level"
    ],
    "business_logic": [
        r"business[- ]?logic", r"logic[- ]?flaw",
        r"price[- ]?manipulation"
    ],
}

# Technology detection patterns
TECH_PATTERNS = {
    "graphql": [r"\bgraphql\b"],
    "nodejs": [r"\bnode\.?js\b", r"\bnpm\b", r"\bexpress\b"],
    "python": [r"\bpython\b", r"\bdjango\b", r"\bflask\b", r"\bfastapi\b"],
    "php": [r"\bphp\b", r"\blaravel\b", r"\bsymfony\b", r"\bwordpress\b"],
    "ruby": [r"\bruby\b", r"\brails\b", r"\bsinatra\b"],
    "java": [r"\bjava\b", r"\bspring\b", r"\btomcat\b"],
    "dotnet": [r"\.net\b", r"\basp\.net\b", r"\bc#\b"],
    "go": [r"\bgolang\b", r"\bgo\s+lang"],
    "rust": [r"\brust\b"],
    "aws": [r"\baws\b", r"\bs3\b", r"\bec2\b", r"\blambda\b", r"\bcognito\b"],
    "gcp": [r"\bgcp\b", r"\bgoogle[- ]?cloud\b", r"\bgcs\b"],
    "azure": [r"\bazure\b", r"\bblob\b"],
    "docker": [r"\bdocker\b", r"\bkubernetes\b", r"\bk8s\b"],
    "nginx": [r"\bnginx\b"],
    "apache": [r"\bapache\b"],
    "mysql": [r"\bmysql\b", r"\bmariadb\b"],
    "postgresql": [r"\bpostgres\b", r"\bpostgresql\b"],
    "mongodb": [r"\bmongodb\b", r"\bmongo\b"],
    "redis": [r"\bredis\b"],
    "elasticsearch": [r"\belasticsearch\b", r"\belastic\b"],
    "react": [r"\breact\b", r"\bnext\.?js\b"],
    "angular": [r"\bangular\b"],
    "vue": [r"\bvue\.?js\b", r"\bnuxt\b"],
    "jwt": [r"\bjwt\b", r"json[- ]?web[- ]?token"],
    "oauth": [r"\boauth\b", r"\boidc\b"],
    "cloudflare": [r"\bcloudflare\b"],
    "stripe": [r"\bstripe\b"],
    "twilio": [r"\btwilio\b"],
    "slack": [r"\bslack\b"],
    "github": [r"\bgithub\b"],
    "gitlab": [r"\bgitlab\b"],
    "jenkins": [r"\bjenkins\b"],
    "jira": [r"\bjira\b"],
    "confluence": [r"\bconfluence\b"],
}


def parse_datetime(date_str: str) -> Optional[datetime]:
    """Parse various datetime formats from HackerOne reports."""
    if not date_str:
        return None
    
    # Try common formats
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d",
        "%B %d, %Y",
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(date_str.strip(), fmt)
        except ValueError:
            continue
    
    return None


def classify_vuln_type(text: str) -> str:
    """Classify vulnerability type from text content."""
    text_lower = text.lower()
    
    for vuln_type, patterns in VULN_TYPE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return vuln_type
    
    return "unknown"


def extract_technologies(text: str) -> List[str]:
    """Extract mentioned technologies from text."""
    text_lower = text.lower()
    detected = []
    
    for tech, patterns in TECH_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                detected.append(tech)
                break
    
    return list(set(detected))


def extract_cwe(text: str) -> str:
    """Extract CWE identifier from text."""
    # Match patterns like CWE-79, CWE 79, cwe79
    match = re.search(r"cwe[- ]?(\d+)", text, re.IGNORECASE)
    if match:
        return f"CWE-{match.group(1)}"
    return ""


def extract_payloads(text: str) -> str:
    """Extract code blocks and payloads from markdown."""
    payloads = []
    
    # Extract fenced code blocks
    code_blocks = re.findall(r"```[\w]*\n(.*?)```", text, re.DOTALL)
    payloads.extend(code_blocks)
    
    # Extract inline code that looks like payloads
    inline_code = re.findall(r"`([^`]+)`", text)
    for code in inline_code:
        # Filter for payload-like content
        if any(c in code for c in ["<", ">", "{{", "}}", "SELECT", "UNION", "curl", "http"]):
            payloads.append(code)
    
    # Deduplicate and join
    unique_payloads = []
    for p in payloads:
        p = p.strip()
        if p and p not in unique_payloads and len(p) < 5000:
            unique_payloads.append(p)
    
    return "\n\n".join(unique_payloads[:5])  # Limit to 5 payloads


def parse_report_markdown(content: str, filename: str = "") -> ParsedReport:
    """
    Parse a HackerOne report markdown file into structured data.
    
    Expected format (from marcotuliocnd/bugbounty-disclosed-reports):
    
    # Title
    
    ## Report Details
    - **Report ID**: 1000567
    - **URL**: https://hackerone.com/reports/1000567
    - **State**: Closed
    - **Severity**: medium
    - **Submitted**: 2020-10-07T02:26:35.361Z
    - **Disclosed**: 2020-10-27T19:30:34.805Z
    
    ## Reporter
    - **Username**: mvm
    
    ## Team
    - **Handle**: cs_money
    
    ## Vulnerability Information
    ...
    
    ## Impact
    ...
    """
    report = ParsedReport(
        report_id="",
        title="",
        raw_content=content
    )
    
    # Extract report ID from filename if available
    if filename:
        match = re.match(r"(\d+)_", filename)
        if match:
            report.report_id = match.group(1)
    
    # Parse title (first H1)
    title_match = re.search(r"^#\s+(.+?)$", content, re.MULTILINE)
    if title_match:
        report.title = title_match.group(1).strip()
    
    # Parse Report Details section
    details_section = re.search(
        r"##\s*Report\s*Details.*?(?=##|\Z)", 
        content, 
        re.DOTALL | re.IGNORECASE
    )
    if details_section:
        details = details_section.group(0)
        
        # Extract report ID
        id_match = re.search(r"\*\*Report\s*ID\*\*[:\s]*(\d+)", details)
        if id_match:
            report.report_id = id_match.group(1)
        
        # Extract URL
        url_match = re.search(r"\*\*URL\*\*[:\s]*(https?://[^\s\n]+)", details)
        if url_match:
            report.source_url = url_match.group(1).strip()
        
        # Extract state
        state_match = re.search(r"\*\*State\*\*[:\s]*(\w+)", details)
        if state_match:
            report.state = state_match.group(1).strip()
        
        # Extract severity
        severity_match = re.search(r"\*\*Severity\*\*[:\s]*(\w+)", details)
        if severity_match:
            report.severity = severity_match.group(1).strip().lower()
        
        # Extract timestamps
        submitted_match = re.search(r"\*\*Submitted\*\*[:\s]*([^\n]+)", details)
        if submitted_match:
            report.submitted_at = parse_datetime(submitted_match.group(1))
        
        disclosed_match = re.search(r"\*\*Disclosed\*\*[:\s]*([^\n]+)", details)
        if disclosed_match:
            report.disclosed_at = parse_datetime(disclosed_match.group(1))
    
    # Parse Reporter section
    reporter_section = re.search(
        r"##\s*Reporter.*?(?=##|\Z)", 
        content, 
        re.DOTALL | re.IGNORECASE
    )
    if reporter_section:
        reporter = reporter_section.group(0)
        username_match = re.search(r"\*\*Username\*\*[:\s]*(\w+)", reporter)
        if username_match:
            report.reporter_username = username_match.group(1).strip()
    
    # Parse Team section
    team_section = re.search(
        r"##\s*Team.*?(?=##|\Z)", 
        content, 
        re.DOTALL | re.IGNORECASE
    )
    if team_section:
        team = team_section.group(0)
        handle_match = re.search(r"\*\*Handle\*\*[:\s]*(\w+)", team)
        if handle_match:
            report.team_handle = handle_match.group(1).strip()
        name_match = re.search(r"\*\*Name\*\*[:\s]*([^\n]+)", team)
        if name_match:
            report.program_name = name_match.group(1).strip()
    
    # Parse Vulnerability Information section
    vuln_section = re.search(
        r"##\s*Vulnerability\s*Information.*?(?=##\s*Impact|\Z)", 
        content, 
        re.DOTALL | re.IGNORECASE
    )
    if vuln_section:
        report.vulnerability_info = vuln_section.group(0)
    
    # Parse Impact section
    impact_section = re.search(
        r"##\s*Impact.*?(?=##|\Z)", 
        content, 
        re.DOTALL | re.IGNORECASE
    )
    if impact_section:
        # Clean up the impact text
        impact_text = impact_section.group(0)
        impact_text = re.sub(r"##\s*Impact\s*", "", impact_text).strip()
        report.impact = impact_text[:2000]  # Limit length
    
    # Parse Steps to Reproduce
    steps_section = re.search(
        r"##\s*Steps?\s*[Tt]o\s*[Rr]eproduce.*?(?=##|\Z)", 
        content, 
        re.DOTALL | re.IGNORECASE
    )
    if steps_section:
        steps_text = steps_section.group(0)
        steps_text = re.sub(r"##\s*Steps?\s*[Tt]o\s*[Rr]eproduce\s*", "", steps_text).strip()
        report.steps_to_reproduce = steps_text[:5000]  # Limit length
    
    # Classify vulnerability type from title and content
    search_text = f"{report.title} {report.vulnerability_info} {report.impact}"
    report.vuln_type = classify_vuln_type(search_text)
    
    # Extract technologies
    report.target_technology = extract_technologies(content)
    
    # Extract CWE
    report.cwe = extract_cwe(content)
    
    # Extract payloads
    report.payload = extract_payloads(content)
    
    # Generate attack vector summary from title and vulnerability info
    attack_vector_parts = []
    if report.title:
        attack_vector_parts.append(report.title)
    if report.vulnerability_info:
        # Get first 500 chars of vuln info
        vuln_summary = report.vulnerability_info[:500]
        # Clean up markdown
        vuln_summary = re.sub(r"##.*?\n", "", vuln_summary)
        vuln_summary = re.sub(r"\*\*", "", vuln_summary)
        vuln_summary = vuln_summary.strip()
        if vuln_summary:
            attack_vector_parts.append(vuln_summary)
    
    report.attack_vector = " | ".join(attack_vector_parts)[:1000]
    
    return report


def parse_reports_directory(reports_dir: str) -> List[ParsedReport]:
    """Parse all markdown reports in a directory."""
    reports = []
    reports_path = Path(reports_dir)
    
    if not reports_path.exists():
        raise FileNotFoundError(f"Reports directory not found: {reports_dir}")
    
    # Find all markdown files
    md_files = list(reports_path.glob("**/*.md"))
    
    print(f"Found {len(md_files)} markdown files")
    
    for md_file in md_files:
        try:
            content = md_file.read_text(encoding="utf-8")
            report = parse_report_markdown(content, md_file.name)
            
            # Skip if no report ID could be extracted
            if not report.report_id:
                continue
            
            reports.append(report)
            
        except Exception as e:
            print(f"Error parsing {md_file}: {e}")
            continue
    
    print(f"Successfully parsed {len(reports)} reports")
    return reports


def generate_embedding_text(report: ParsedReport) -> str:
    """
    Generate the text to embed for a report.
    
    We combine key fields to create a rich embedding that captures:
    - What vulnerability type it is
    - How it was exploited
    - What impact it had
    - What technologies were involved
    """
    parts = []
    
    if report.title:
        parts.append(f"Title: {report.title}")
    
    if report.vuln_type:
        parts.append(f"Vulnerability Type: {report.vuln_type}")
    
    if report.severity:
        parts.append(f"Severity: {report.severity}")
    
    if report.cwe:
        parts.append(f"CWE: {report.cwe}")
    
    if report.target_technology:
        parts.append(f"Technologies: {', '.join(report.target_technology)}")
    
    if report.attack_vector:
        parts.append(f"Attack Vector: {report.attack_vector}")
    
    if report.impact:
        # Truncate long impacts
        impact = report.impact[:500]
        parts.append(f"Impact: {impact}")
    
    if report.steps_to_reproduce:
        # Truncate long repro steps
        steps = report.steps_to_reproduce[:500]
        parts.append(f"Reproduction: {steps}")
    
    if report.payload:
        # Include a snippet of payload
        payload = report.payload[:300]
        parts.append(f"Payload: {payload}")
    
    return "\n".join(parts)


if __name__ == "__main__":
    import argparse
    import json
    
    parser = argparse.ArgumentParser(description="Parse HackerOne disclosed reports")
    parser.add_argument("--reports-dir", required=True, help="Directory containing report markdown files")
    parser.add_argument("--output", default="parsed_reports.json", help="Output JSON file")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of reports to parse (0 = all)")
    
    args = parser.parse_args()
    
    reports = parse_reports_directory(args.reports_dir)
    
    if args.limit > 0:
        reports = reports[:args.limit]
    
    # Convert to JSON-serializable format
    output_data = [r.to_dict() for r in reports]
    
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, default=str)
    
    print(f"Wrote {len(output_data)} reports to {args.output}")
    
    # Print summary stats
    vuln_types = {}
    for r in reports:
        vt = r.vuln_type or "unknown"
        vuln_types[vt] = vuln_types.get(vt, 0) + 1
    
    print("\nVulnerability type distribution:")
    for vt, count in sorted(vuln_types.items(), key=lambda x: -x[1])[:15]:
        print(f"  {vt}: {count}")

