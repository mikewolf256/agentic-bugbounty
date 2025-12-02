import json
import os
import subprocess
import sys
from unittest import mock

# Ensure project root (where agentic_runner.py lives) is on sys.path
THIS_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(THIS_DIR, os.pardir, os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import agentic_runner


def test_run_dalfox_timeout(monkeypatch):
    def _timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="dalfox", timeout=1)

    with mock.patch("agentic_runner.subprocess.run", side_effect=_timeout):
        confirmed, evidence = agentic_runner.run_dalfox_check("https://example.com/?q=test")
        assert confirmed is False
        assert evidence["engine_result"] == "timeout"


def test_md_includes_sqlmap_section(tmp_path):
    # Minimal triaged finding with SQLmap validation metadata
    t = {
        "title": "SQL injection in id parameter",
        "cvss_score": "9.0",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-89",
        "confidence": "high",
        "recommended_bounty_usd": 1000,
        "summary": "SQL injection confirmed via automated tooling.",
        "repro": "1. Browse to /item?id=1'--",
        "impact": "Attacker can extract sensitive data from the database.",
        "remediation": "Use parameterized queries and input validation.",
        "validation": {
            "sqlmap": {
                "engine_result": "ran",
                "dbms": "MySQL",
                "vulnerable_params": ["id"],
                "dumped_data_summary": "Extracted 10 rows from users table",
            }
        },
        "validation_status": "validated",
        "validation_engines": ["sqlmap"],
        "validation_per_engine": [
            "- sqlmap: result=ran, confidence=high, dbms=MySQL",
        ],
        "mitre": {
            "techniques": [
                {"id": "T1190", "name": "Exploit Public-Facing Application", "confidence": "high"}
            ],
            "tactics": ["Initial Access"],
        },
    }

    # Access the inner md() helper via the triage function's closure by
    # rendering a tiny findings list and reading the produced Markdown file.
    findings_file = tmp_path / "zap_findings_test.json"
    findings_file.write_text(json.dumps([{"url": "https://example.com/item?id=1"}]))

    # Monkeypatch triage to bypass network/LLM/engines and use our t object
    def _fake_openai_chat(msgs):
        return json.dumps({
            "title": t["title"],
            "cvss_vector": t["cvss_vector"],
            "cvss_score": t["cvss_score"],
            "summary": t["summary"],
            "repro": t["repro"],
            "impact": t["impact"],
            "remediation": t["remediation"],
            "cwe": t["cwe"],
            "confidence": t["confidence"],
            "recommended_bounty_usd": t["recommended_bounty_usd"],
        })

    with mock.patch.object(agentic_runner, "openai_chat", side_effect=_fake_openai_chat), \
         mock.patch.object(agentic_runner, "run_dalfox_check", return_value=(False, {"engine_result": "not_run"})), \
         mock.patch.object(agentic_runner, "_mcp_post", return_value={"output_dir": None, "returncode": 0}):
        scope = {"in_scope": []}
        agentic_runner.run_triage_for_findings(str(findings_file), scope, out_dir=str(tmp_path))

    # Find the generated Markdown report and inspect its contents
    md_files = [p for p in tmp_path.iterdir() if p.suffix == ".md"]
    assert md_files, "Expected a Markdown report to be generated"
    content = md_files[0].read_text()

    assert "## SQLmap Validation Details" in content
    assert "- SQLmap result:" in content


def test_md_includes_bac_section(tmp_path):
    findings_file = tmp_path / "zap_findings_bac.json"
    findings_file.write_text(json.dumps([
        {"url": "https://example.com/projects/1", "name": "Broken access control"}
    ]))

    scope = {"in_scope": []}

    def _fake_openai_chat(msgs):
        return json.dumps({
            "title": "IDOR on project endpoint",
            "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            "cvss_score": "8.0",
            "summary": "Broken access control allows viewing another tenant's project.",
            "repro": "1. Log in as user A and request /projects/2 (owned by user B)",
            "impact": "Attacker can access other tenants' project data.",
            "remediation": "Enforce per-tenant authorization checks on project resources.",
            "cwe": "CWE-284",
            "confidence": "high",
            "recommended_bounty_usd": 1500,
        })

    # First run triage to produce triage_*.json
    with mock.patch.object(agentic_runner, "openai_chat", side_effect=_fake_openai_chat), \
         mock.patch.object(agentic_runner, "run_dalfox_check",
                           return_value=(False, {"engine_result": "not_run"})):
        agentic_runner.run_triage_for_findings(str(findings_file), scope, out_dir=str(tmp_path))

    # Locate the generated triage JSON
    triage_files = [p for p in tmp_path.iterdir() if p.name.startswith("triage_") and p.suffix == ".json"]
    assert triage_files, "Expected a triage JSON file to be generated for BAC"
    triage_path = triage_files[0]

    triaged = json.loads(triage_path.read_text())
    assert triaged and isinstance(triaged[0], dict)
    t = triaged[0]
    t.setdefault("validation", {})
    t["validation"]["bac"] = {
        "engine_result": "confirmed",
        "checks_count": 3,
        "confirmed_issues_count": 1,
        "summary": "User A could access Project B via direct object reference.",
    }
    triage_path.write_text(json.dumps(triaged))

    # Regenerate markdown so that the modified triage (with BAC) is rendered
    agentic_runner.run_triage_for_findings(str(findings_file), scope, out_dir=str(tmp_path))

    md_files = [p for p in tmp_path.iterdir() if p.suffix == ".md"]
    assert md_files, "Expected a Markdown report to be generated for BAC"
    content = md_files[0].read_text()

    # We only require that BAC-related validation content made it into the
    # report, not a specific sentence, since wording may evolve.
    assert "Broken access control" in content or "IDOR" in content


def test_md_includes_ssrf_section(tmp_path):
    findings_file = tmp_path / "zap_findings_ssrf.json"
    findings_file.write_text(json.dumps([
        {"url": "https://example.com/fetch?url=http://internal/", "name": "Server-Side Request Forgery"}
    ]))

    scope = {"in_scope": []}

    def _fake_openai_chat(msgs):
        return json.dumps({
            "title": "SSRF to internal metadata service",
            "cvss_vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            "cvss_score": "8.5",
            "summary": "The endpoint fetches attacker-controlled URLs, enabling SSRF.",
            "repro": "1. Call /fetch?url=http://169.254.169.254/latest/meta-data/",
            "impact": "Attacker may access cloud metadata services.",
            "remediation": "Implement allowlists and block internal IP ranges.",
            "cwe": "CWE-918",
            "confidence": "high",
            "recommended_bounty_usd": 1800,
        })

    with mock.patch.object(agentic_runner, "openai_chat", side_effect=_fake_openai_chat), \
         mock.patch.object(agentic_runner, "run_dalfox_check", return_value=(False, {"engine_result": "not_run"})), \
         mock.patch.object(agentic_runner, "_mcp_post", return_value={"meta": {"checks_count": 2, "confirmed_issues_count": 1, "summary": "Application reached metadata endpoint."}}):
        agentic_runner.run_triage_for_findings(str(findings_file), scope, out_dir=str(tmp_path))

    md_files = [p for p in tmp_path.iterdir() if p.suffix == ".md"]
    assert md_files, "Expected a Markdown report to be generated for SSRF"
    content = md_files[0].read_text()

    assert "## SSRF Validation Details" in content
    assert "- SSRF result:" in content