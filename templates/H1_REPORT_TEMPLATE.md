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

## Proof of Concept

**Validation Status:** {{validation_status}}  
**POC Quality:** {{poc_quality_score}}  
**Validation Engines:** {{validation_engines}}

### Validation Evidence

{{validation_evidence_sections}}

### Request/Response Capture

{{request_response_capture}}

### Screenshot Evidence

{{screenshot_evidence}}

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
- POC Validated: {{poc_validated}}
- Validation Evidence Complete: {{validation_evidence_complete}}

## Pre-submission checklist
- [ ] Single testing IP
- [ ] Non-destructive PoC
- [ ] H1 alias header present
- [ ] CVSS vector verified
- [ ] No leaked credential validation
- [ ] POC validation evidence included
- [ ] Request/response capture provided (if applicable)
- [ ] Validation engine results documented
- [ ] Scope compliance verified
