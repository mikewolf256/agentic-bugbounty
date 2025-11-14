def test_export_report_creates_markdown_and_index(tmp_path, monkeypatch):
    """/mcp/export_report should read findings JSON and emit markdown + index files."""

    # Use temp output dir for reports and findings and align module-level OUTPUT_DIR
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
    mcp_zap_server.OUTPUT_DIR = str(tmp_path)
    client = TestClient(mcp_zap_server.app)

    # Set a scope so generate_h1_markdown uses the program name
    scope_payload = {
        "program_name": "unit-test-program",
        "primary_targets": ["example.com"],
        "secondary_targets": [],
        "rules": {},
    }
    r = client.post("/mcp/set_scope", json=scope_payload)
    assert r.status_code == 200

    scan_id = "scan123"
    findings_path = tmp_path / f"zap_findings_{scan_id}.json"
    findings = [
        {
            "id": "f1",
            "url": "https://example.com/one",
            "name": "XSS in param q",
            "risk": "High",
            "evidence": "<script>alert(1)</script>",
        },
        {
            "id": "f2",
            "url": "https://example.com/two",
            "name": "SQL injection",
            "risk": "High",
            "evidence": "' OR 1=1 --",
        },
    ]
    findings_path.write_text(json.dumps(findings))

    resp = client.get(f"/mcp/export_report/{scan_id}")
    assert resp.status_code == 200
    data = resp.json()

    # Index file should exist and list the report files
    index_path = tmp_path / f"{scan_id}_reports_index.json"
    assert data["index"] == str(index_path)
    assert index_path.exists()
    listed_reports = json.loads(index_path.read_text())
    assert len(listed_reports) == 2

    # Each listed report should exist and contain the program name
    for report_file in listed_reports:
        p = tmp_path / os.path.basename(report_file)
        assert p.exists()
        content = p.read_text()
        assert "unit-test-program" in content

    # Sanity-check that the URLs from findings appear in the markdown
    all_md = "\n".join((tmp_path / os.path.basename(f)).read_text() for f in listed_reports)
    assert "https://example.com/one" in all_md
    assert "https://example.com/two" in all_md
import json
import os
import sys
from unittest import mock

from fastapi.testclient import TestClient

# Ensure the project root (where mcp_zap_server.py lives) is on sys.path
THIS_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(THIS_DIR, os.pardir, os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import mcp_zap_server


def test_mcp_set_scope_and_reject_out_of_scope_target(tmp_path, monkeypatch):
    """Basic sanity test for the MCP ZAP FastAPI app.

    - Calls /mcp/set_scope with a minimal allowed host
    - Calls /mcp/start_zap_scan with an out-of-scope host to ensure scope
      enforcement works at the HTTP layer (we don't require a real ZAP instance
      for this test).
    """

    # Point OUTPUT_DIR to a temp directory to avoid polluting real output_zap
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))

    client = TestClient(mcp_zap_server.app)

    scope_payload = {
        "program_name": "test-program",
        "primary_targets": ["example.com"],
        "secondary_targets": [],
        "rules": {},
    }

    # 1) Set scope
    resp = client.post("/mcp/set_scope", json=scope_payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["program"] == "test-program"

    # 2) Try to start a scan on an out-of-scope target -> 400
    zap_req = {
        "targets": ["out-of-scope.test"],
    }
    resp2 = client.post("/mcp/start_zap_scan", json=zap_req)
    assert resp2.status_code == 400
    err = resp2.json()
    assert "not in scope" in err.get("detail", "")

def _set_minimal_scope(client):
    scope_payload = {
        "program_name": "test-program",
        "primary_targets": ["example.com"],
        "secondary_targets": [],
        "rules": {},
    }
    r = client.post("/mcp/set_scope", json=scope_payload)
    assert r.status_code == 200

def test_run_js_miner_in_scope(tmp_path, monkeypatch):
    """/mcp/run_js_miner should enforce scope and call _spawn_job with the right args."""

    # Use temp output dir
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))

    client = TestClient(mcp_zap_server.app)
    _set_minimal_scope(client)

    # Mock _spawn_job to avoid running the real script
    with mock.patch("mcp_zap_server._spawn_job", return_value="job-123") as mock_spawn:
        body = {
            "base_url": "https://example.com/app",
        }
        resp = client.post("/mcp/run_js_miner", json=body)
        assert resp.status_code == 200
        data = resp.json()
        assert data["job_id"] == "job-123"
        assert "artifact_dir" in data

    # Validate _spawn_job was called with expected command
    mock_spawn.assert_called_once()
    args, kwargs = mock_spawn.call_args
    cmd_argv = args[0]
    job_kind = kwargs.get("job_kind")
    assert job_kind == "js_miner"
    # tools/js_miner.py should be in the command
    assert "tools/js_miner.py" in cmd_argv
    # base-url should be present
    assert "--base-url" in cmd_argv
    assert "https://example.com/app" in cmd_argv

def test_run_reflector_in_scope(tmp_path, monkeypatch):
    """/mcp/run_reflector should enforce scope and call _spawn_job with the right args."""

    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
    client = TestClient(mcp_zap_server.app)
    _set_minimal_scope(client)

    with mock.patch("mcp_zap_server._spawn_job", return_value="job-456") as mock_spawn:
        body = {
            "url": "https://example.com/path?x=1",
        }
        resp = client.post("/mcp/run_reflector", json=body)
        assert resp.status_code == 200
        data = resp.json()
        assert data["job_id"] == "job-456"

    mock_spawn.assert_called_once()
    args, kwargs = mock_spawn.call_args
    cmd_argv = args[0]
    job_kind = kwargs.get("job_kind")
    assert job_kind == "reflector"
    assert "tools/reflector_tester.py" in cmd_argv
    assert "--url" in cmd_argv
    assert "https://example.com/path?x=1" in cmd_argv

def test_run_backup_hunt_in_scope_with_wordlist(tmp_path, monkeypatch):
    """/mcp/run_backup_hunt should include optional wordlist and enforce scope."""

    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
    client = TestClient(mcp_zap_server.app)
    _set_minimal_scope(client)

    with mock.patch("mcp_zap_server._spawn_job", return_value="job-789") as mock_spawn:
        body = {
            "target": "https://example.com/",
            "wordlist": "wordlists/backups.txt",
        }
        resp = client.post("/mcp/run_backup_hunt", json=body)
        assert resp.status_code == 200
        data = resp.json()
        assert data["job_id"] == "job-789"

    mock_spawn.assert_called_once()
    args, kwargs = mock_spawn.call_args
    cmd_argv = args[0]
    job_kind = kwargs.get("job_kind")
    assert job_kind == "backup_hunt"
    assert "tools/backup_hunt.py" in cmd_argv
    assert "--target" in cmd_argv
    assert "https://example.com/" in cmd_argv
    # wordlist flag and value must be present
    assert "--wordlist" in cmd_argv
    assert "wordlists/backups.txt" in cmd_argv


    def test_run_ffuf_success(tmp_path, monkeypatch):
        """/mcp/run_ffuf should build the correct ffuf command and parse JSON output."""

        monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
        client = TestClient(mcp_zap_server.app)

        # Fake ffuf JSON output file
        ffuf_out = tmp_path / "ffuf_123.json"
        ffuf_out.write_text(json.dumps({"results": [{"url": "https://example.com/"}]}))

        # Pretend subprocess.run succeeded
        class P:
            returncode = 0
            stdout = "ok"
            stderr = ""

        with mock.patch("mcp_zap_server.subprocess.run", return_value=P()) as mock_run:
            body = {
                "target": "https://example.com/FUZZ",
                "wordlist": "wordlists/test.txt",
                "headers": {"X-Test": "1"},
                "rate": 10,
            }
            resp = client.post("/mcp/run_ffuf", json=body)
            assert resp.status_code == 200
            data = resp.json()
            cmd = data["cmd"]

            # Verify core ffuf flags
            assert cmd[0] == "ffuf"
            assert "-u" in cmd and "https://example.com/FUZZ" in cmd
            assert "-w" in cmd and "wordlists/test.txt" in cmd
            assert "-of" in cmd and "json" in cmd

            # Verify headers include X-HackerOne-Research and our custom header
            header_args = " ".join(cmd)
            assert "X-HackerOne-Research" in header_args
            assert "X-Test: 1" in header_args


    def test_run_sqlmap_with_data_and_headers(tmp_path, monkeypatch):
        """/mcp/run_sqlmap should include headers, delay, and optional data in the command."""

        monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
        client = TestClient(mcp_zap_server.app)

        class P:
            returncode = 0
            stdout = "SQLMAP OUTPUT" * 10
            stderr = ""

        with mock.patch("mcp_zap_server.subprocess.run", return_value=P()) as mock_run:
            body = {
                "target": "https://example.com/item?id=1",
                "data": "id=1",
                "headers": {"X-Test": "1"},
            }
            resp = client.post("/mcp/run_sqlmap", json=body)
            assert resp.status_code == 200
            data = resp.json()
            assert data["returncode"] == 0
            # stdout is truncated to 2000 chars in the handler
            assert "SQLMAP OUTPUT" in data["stdout"]

            # Inspect constructed command
            args, kwargs = mock_run.call_args
            cmd_argv = args[0]
            assert cmd_argv[0] == "sqlmap"
            assert "-u" in cmd_argv and "https://example.com/item?id=1" in cmd_argv
            assert "--data" in cmd_argv and "id=1" in cmd_argv
            # Header string should contain our header and X-HackerOne-Research
            header_index = cmd_argv.index("--headers") + 1
            header_str = cmd_argv[header_index]
            assert "X-Test: 1" in header_str
            assert "X-HackerOne-Research" in header_str


    def test_interactsh_new_success(monkeypatch):
        """/mcp/interactsh_new should call interactsh-client and parse JSON output."""

        client = TestClient(mcp_zap_server.app)

        class P:
            returncode = 0
            stdout = json.dumps({"domain": "abc.oast.site"})
            stderr = ""

        with mock.patch("mcp_zap_server.subprocess.run", return_value=P()) as mock_run:
            resp = client.post("/mcp/interactsh_new")
            assert resp.status_code == 200
            data = resp.json()
            assert data["interact"]["domain"] == "abc.oast.site"

            args, kwargs = mock_run.call_args
            cmd_argv = args[0]
            # First element is either INTERACTSH_CLIENT env or default 'interactsh-client'
            assert cmd_argv[1:] == ["create", "--json"]


    def test_export_report_creates_markdown_and_index(tmp_path, monkeypatch):
        """/mcp/export_report should read findings JSON and emit markdown + index files."""

        # Use temp output dir for reports and findings
        monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
        client = TestClient(mcp_zap_server.app)

        # Set a scope so generate_h1_markdown uses the program name
        scope_payload = {
            "program_name": "unit-test-program",
            "primary_targets": ["example.com"],
            "secondary_targets": [],
            "rules": {},
        }
        r = client.post("/mcp/set_scope", json=scope_payload)
        assert r.status_code == 200

        scan_id = "scan123"
        findings_path = tmp_path / f"zap_findings_{scan_id}.json"
        findings = [
            {
                "id": "f1",
                "url": "https://example.com/one",
                "name": "XSS in param q",
                "risk": "High",
                "evidence": "<script>alert(1)</script>",
            },
            {
                "id": "f2",
                "url": "https://example.com/two",
                "name": "SQL injection",
                "risk": "High",
                "evidence": "' OR 1=1 --",
            },
        ]
        findings_path.write_text(json.dumps(findings))

        resp = client.get(f"/mcp/export_report/{scan_id}")
        assert resp.status_code == 200
        data = resp.json()

        # Index file should exist and list the report files
        index_path = tmp_path / f"{scan_id}_reports_index.json"
        assert data["index"] == str(index_path)
        assert index_path.exists()
        listed_reports = json.loads(index_path.read_text())
        assert len(listed_reports) == 2

        # Each listed report should exist and contain the program name
        for report_file in listed_reports:
            p = tmp_path / os.path.basename(report_file)
            assert p.exists()
            content = p.read_text()
            assert "unit-test-program" in content
            # Also sanity-check that the URL from findings appears in at least one report
        all_md = "\n".join((tmp_path / os.path.basename(f)).read_text() for f in listed_reports)
        assert "https://example.com/one" in all_md
        assert "https://example.com/two" in all_md
