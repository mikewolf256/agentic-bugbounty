# {{title}}

**Bounty Program:** {{program_name}}  
**Target / Endpoint:** `{{affected_endpoint}}`  
**Severity (CVSS v3):** {{cvss_score}} ({{cvss_vector}})  
**CWE:** {{cwe}}  
**Confidence:** {{confidence}}  
**Suggested bounty (USD):** ${{recommended_bounty_usd}}

---

## Summary
{{summary}}

---

## Quick reproduction

{{quick_repro}}


## Full reproduction

**Request**

{{request_raw}}


**Response**

{{response_raw}}


## Impact
{{impact}}

## Recommended remediation
{{remediation}}

## Evidence & Notes
- Scan id: `{{scan_id}}`
- Research header: `{{h1_alias}}`
- Rate limit: {{rate_limit_rps}} req/s
- Public IP: `{{public_ip}}`
- Timestamp: `{{timestamp}}`

## Pre-submission checklist
- [ ] Single testing IP
- [ ] Non-destructive PoC
- [ ] H1 alias header present
- [ ] CVSS vector verified
- [ ] No leaked credential validation
