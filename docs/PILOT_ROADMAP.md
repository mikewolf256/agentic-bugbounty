# Pilot-Ready Roadmap: Security Assessment Service

**Goal:** Complete the minimum viable features to start taking on paid pilot client work.

**Timeline:** 2-3 weeks to pilot-ready

---

## Current State Summary

### ✅ Ready for Production
| Component | Status | Notes |
|-----------|--------|-------|
| Core Scanning Engine | ✅ Complete | 40+ vulnerability testers |
| AI Triage | ✅ Complete | GPT-4o-based CVSS scoring |
| RAG Knowledge Base | ✅ Complete | 10k+ historical reports |
| Validation Pipeline | ✅ Complete | Dalfox, SQLmap, etc. |
| Human Review Workflow | ✅ Complete | Discord alerts, CLI approval |
| Markdown Reports | ✅ Complete | Basic report generator exists |
| Scope Management | ✅ Complete | JSON scope configuration |

### ⚠️ Needs Enhancement for Client Work
| Component | Status | Gap |
|-----------|--------|-----|
| PDF Reports | ⚠️ Partial | ReportLab integration incomplete |
| Executive Summaries | ⚠️ Partial | Need polish for enterprise clients |
| Rate Limiting | ⚠️ Partial | Needs per-client configuration |
| False Positive Reduction | ⚠️ Partial | Need higher confidence thresholds |

### ❌ Missing for Client Work
| Component | Priority | Notes |
|-----------|----------|-------|
| Client Engagement Templates | P0 | Proposal, contract, SOW |
| Professional PDF Output | P0 | Executive + Technical PDFs |
| Client Profile Management | P1 | Track clients, assessments |
| Retest Workflow | P1 | Verify fixes after remediation |
| Screenshot/Video PoCs | P1 | Visual evidence for reports |

---

## Phase 1: MVP for First Pilot (Week 1)

**Goal:** Be able to run an assessment and deliver a professional report

### P1.1 — Professional PDF Reports (2-3 days)

**Why:** Clients expect professional deliverables, not markdown files.

**Tasks:**
- [ ] Complete ReportLab PDF generation in `tools/report_generator.py`
- [ ] Add company branding (logo, colors, fonts)
- [ ] Generate Executive Summary PDF (2-3 pages max)
- [ ] Generate Technical Report PDF (detailed findings)
- [ ] Include charts: severity distribution, risk score visualization
- [ ] Add PoC screenshots/evidence section

**Deliverables:**
```
reports/
├── COMPANY_executive_summary.pdf  (for C-level)
├── COMPANY_technical_report.pdf   (for security team)
└── COMPANY_raw_findings.json      (for their tools)
```

**Test Criteria:**
- PDF opens correctly in all readers
- Professional appearance (not "tool output")
- All findings include remediation steps

### P1.2 — Client Engagement Templates (1 day)

**Why:** Need standardized documents for professional client interaction.

**Tasks:**
- [ ] Create proposal template (`docs/templates/proposal_template.md`)
- [ ] Create Statement of Work template (`docs/templates/sow_template.md`)
- [ ] Create authorization letter template (`docs/templates/authorization_template.md`)
- [ ] Create NDA template reference

**Templates needed:**

```markdown
# Proposal Template
- Company overview
- Assessment scope
- Methodology
- Deliverables
- Timeline
- Pricing
- Terms

# Statement of Work (SOW)
- Detailed scope (URLs, IP ranges, exclusions)
- Testing methodology
- Rate limiting agreements
- Communication protocol
- Deliverable timeline
- Payment terms

# Authorization Letter
- Written permission to test
- Scope boundaries
- Emergency contacts
- Data handling agreement
```

### P1.3 — End-to-End Pilot Workflow (1 day)

**Why:** Need a tested, repeatable process.

**Tasks:**
- [ ] Create `scripts/run_client_assessment.sh` wrapper script
- [ ] Test full flow: scope → scan → triage → report
- [ ] Document exact commands for client assessment
- [ ] Create pre-flight checklist

**Pilot Workflow:**
```bash
# 1. Configure client scope
cp templates/client_scope.json data/scopes/CLIENT_NAME.json
# Edit scope with client targets

# 2. Run assessment
./scripts/run_client_assessment.sh CLIENT_NAME

# 3. Review findings
python tools/validation_cli.py list --scope CLIENT_NAME

# 4. Generate reports
python tools/report_generator.py \
  --findings data/output/CLIENT_NAME/triage_*.json \
  --target "Client Name" \
  --format pdf \
  --output reports/CLIENT_NAME/
```

### P1.4 — Quality Assurance Pass (1 day)

**Why:** Can't deliver false positives to paying clients.

**Tasks:**
- [ ] Review confidence thresholds in triage
- [ ] Add manual validation step for all critical findings
- [ ] Test against known-vulnerable targets (labs)
- [ ] Document false positive rates by vulnerability type

**Quality Gates:**
```yaml
client_assessment:
  require_validation: true
  min_confidence: "high"
  min_cvss: 7.0
  manual_review_critical: true
```

---

## Phase 2: First Pilot Execution (Week 2)

### P2.1 — Find Pilot Client

**Target Profile:**
- Medium-sized company (not Fortune 500 yet)
- Web-heavy infrastructure
- Security-conscious but not mature program
- Existing relationship/warm intro preferred

**Outreach:**
- [ ] Identify 5-10 target companies
- [ ] Draft personalized outreach emails
- [ ] Leverage LinkedIn/network connections
- [ ] Offer discounted "pilot" rate

**Pilot Pricing:**
- Single application: $2,500 - $5,000 (vs normal $10K+)
- Value: Case study, testimonial, reference

### P2.2 — Execute Pilot Assessment

**Timeline:** 3-5 business days

```
Day 1: Scope definition + authorization
Day 2-3: Automated scanning + triage
Day 4: Manual validation + PoC creation
Day 5: Report generation + delivery
```

**Deliverables:**
1. Executive Summary (PDF) - for leadership
2. Technical Report (PDF) - for security team
3. Raw Findings (JSON) - for integration
4. Remediation call - walk through findings

### P2.3 — Post-Pilot Improvements

**Collect:**
- Client feedback
- Time spent per task
- False positive count
- Gaps in coverage

**Iterate:**
- Improve based on feedback
- Refine report templates
- Adjust pricing based on effort

---

## Phase 3: Operational Scale (Week 3+)

### P3.1 — Client Management System

**Tasks:**
- [ ] Create client database (JSON/SQLite)
- [ ] Track: company, contacts, assessments, invoices
- [ ] Assessment history and findings archive

**Schema:**
```json
{
  "client_id": "uuid",
  "company_name": "Example Corp",
  "contacts": [...],
  "assessments": [
    {
      "id": "uuid",
      "date": "2025-01-15",
      "scope": ["example.com"],
      "findings_count": 12,
      "status": "completed"
    }
  ],
  "invoices": [...]
}
```

### P3.2 — Retest Workflow

**Why:** Clients need verification that fixes work.

**Tasks:**
- [ ] Create retest profile (faster, targeted)
- [ ] Compare new results to original findings
- [ ] Generate "remediation verification" report

### P3.3 — Screenshot/Video PoC Capture

**Why:** Visual proof is more compelling.

**Tasks:**
- [ ] Integrate Playwright/Puppeteer for automated screenshots
- [ ] Capture XSS, SSRF, auth bypass visually
- [ ] Generate video PoCs for complex attack chains

### P3.4 — MITRE ATT&CK Mapping (Optional)

**Why:** Enterprise clients love frameworks.

**Tasks:**
- [ ] Map findings to MITRE techniques
- [ ] Generate ATT&CK Navigator JSON
- [ ] Include in executive reports

---

## Pre-Pilot Checklist

### Technical Readiness

- [ ] PDF report generation working
- [ ] Full assessment tested on lab targets
- [ ] Rate limiting configured
- [ ] All critical validators working
- [ ] Report quality reviewed

### Business Readiness

- [ ] Proposal template ready
- [ ] SOW template ready
- [ ] Authorization template ready
- [ ] Pricing defined
- [ ] Payment terms defined

### Operational Readiness

- [ ] Assessment workflow documented
- [ ] Time estimates accurate
- [ ] Backup plan for tool failures
- [ ] Communication protocol defined
- [ ] Support contact available

---

## Immediate Next Steps (This Week)

### Day 1-2: PDF Reports
```bash
# Complete PDF generation
pip install reportlab pillow

# Test report generation
python tools/report_generator.py \
  --findings tests/sample_findings.json \
  --target "Test Company" \
  --format pdf \
  --output tests/sample_report.pdf
```

### Day 3: Client Templates
```bash
# Create template directory
mkdir -p docs/templates

# Create proposal, SOW, authorization templates
```

### Day 4: End-to-End Test
```bash
# Run against local labs
docker-compose -f labs/docker-compose.yml up -d

# Execute full assessment workflow
./scripts/run_client_assessment.sh test_client

# Review output quality
```

### Day 5: Quality Review
```bash
# Review findings accuracy
# Test false positive rate
# Validate PoC quality
```

---

## Success Metrics

### Pilot Success Criteria

| Metric | Target |
|--------|--------|
| Assessment completion | < 5 days |
| False positive rate | < 10% |
| Critical findings accuracy | 100% validated |
| Client satisfaction | Would recommend |
| Time to report | < 24 hours post-scan |

### Revenue Targets

| Phase | Target |
|-------|--------|
| Pilot (Month 1) | $2,500 - $5,000 |
| Early clients (Month 2-3) | $10,000 - $25,000/month |
| Scale (Month 4+) | $50,000+/month |

---

## Risk Mitigation

### Technical Risks

| Risk | Mitigation |
|------|------------|
| False positives | Manual validation for all critical |
| Missed vulnerabilities | Multiple scanner coverage |
| Tool failures | Fallback manual testing |
| Rate limiting blocks | Pre-agreed limits, monitoring |

### Business Risks

| Risk | Mitigation |
|------|------------|
| Scope creep | Clear SOW with boundaries |
| Liability | Authorization letter, insurance |
| Non-payment | 50% upfront, net-15 terms |
| Competition | Focus on speed + quality |

---

## Files to Create

```
docs/
├── PILOT_ROADMAP.md          (this file)
├── templates/
│   ├── proposal_template.md
│   ├── sow_template.md
│   └── authorization_template.md
├── SERVICE_BUSINESS_GUIDE.md (exists)
└── COMMERCIAL_FORK_GUIDE.md  (exists)

scripts/
└── run_client_assessment.sh

profiles/
└── client-assessment.yaml

data/
├── clients/
│   └── (client profiles)
└── scopes/
    └── (client scopes)
```

---

## Summary

**Minimum for first pilot:**
1. ✅ Scanning engine (done)
2. ✅ AI triage (done)
3. ⏳ PDF reports (1-2 days)
4. ⏳ Client templates (1 day)
5. ⏳ E2E workflow test (1 day)

**Estimated time to pilot-ready:** 3-5 days of focused work

**First pilot target:** Week 2-3

**Revenue potential:** $2,500 - $5,000 for pilot, scaling to $25K+/month

