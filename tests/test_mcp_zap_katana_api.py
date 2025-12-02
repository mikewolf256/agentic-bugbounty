import json
import os
import shutil
import tempfile
from typing import Dict, Any, List

import pytest
from fastapi.testclient import TestClient
import mcp_zap_server


pytestmark = pytest.mark.xfail(
    reason="Legacy MCP server API; refactored mcp_zap_server now used for P0 flow",
    strict=False,
)


@pytest.fixture(autouse=True)
def _isolate_output_dir(monkeypatch, tmp_path):
    """
    Point OUTPUT_DIR to a temp directory for each test so we don't touch real data.
    """
    outdir = tmp_path / "output_zap"
    outdir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(mcp_zap_server, "OUTPUT_DIR", str(outdir), raising=False)
    # Also update ARTIFACTS_DIR if present
    if hasattr(mcp_zap_server, "ARTIFACTS_DIR"):
        monkeypatch.setattr(
            mcp_zap_server,
            "ARTIFACTS_DIR",
            os.path.join(str(outdir), "artifacts"),
            raising=False,
        )
        os.makedirs(mcp_zap_server.ARTIFACTS_DIR, exist_ok=True)
    yield
    # cleanup
    shutil.rmtree(str(outdir), ignore_errors=True)


@pytest.fixture
def client():
    return TestClient(mcp_zap_server.app)


@pytest.fixture
def scoped_program(monkeypatch):
    """
    Set SCOPE so _enforce_scope(host) allows localhost:3000.
    """
    scope = mcp_zap_server.ScopeConfig(
        program_name="test",
        primary_targets=["localhost:3000"],
        secondary_targets=[],
        rules={},
    )
    monkeypatch.setattr(mcp_zap_server, "SCOPE", scope, raising=True)
    return scope


def _write_katana_file(output_dir: str, target: str, all_urls: List[str], api_candidates: List[Dict[str, Any]]):
    path = os.path.join(output_dir, "katana_nuclei_http_localhost:3000.json")
    data = {
        "target": target,
        "katana": {
            "count": len(all_urls),
            "all_urls": all_urls,
            "api_candidates": api_candidates,
        },
        "nuclei_findings": [],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return path


def _write_host_profile_snapshot(output_dir: str, host: str, profile: Dict[str, Any], ts: int):
    base = host.replace(":", "_")
    hist_dir = os.path.join(output_dir, "host_history")
    os.makedirs(hist_dir, exist_ok=True)
    fname = f"{base}_{ts}.json"
    with open(os.path.join(hist_dir, fname), "w", encoding="utf-8") as fh:
        json.dump(profile, fh)


def test_host_profile_ingests_katana_web_surface(client, scoped_program, tmp_path, monkeypatch):
    # Arrange: create a fake Katana output for localhost:3000
    output_dir = mcp_zap_server.OUTPUT_DIR
    urls = [
        "http://localhost:3000",
        "http://localhost:3000/runtime.js",
        "http://localhost:3000/api/v1/users",
    ]
    api_candidates = [
        {"url": "http://localhost:3000/api/v1/users", "method": "GET", "reasons": ["path_indicator"]},
    ]
    _write_katana_file(output_dir, "http://localhost:3000", urls, api_candidates)

    # Act
    resp = client.post("/mcp/host_profile", json={"host": "localhost:3000"})
    assert resp.status_code == 200
    body = resp.json()

    # Assert
    web = body.get("web", {})
    assert "urls" in web
    assert "http://localhost:3000/runtime.js" in web["urls"]
    assert "api_endpoints" in web
    assert any(ep["url"] == "http://localhost:3000/api/v1/users" for ep in web["api_endpoints"])


def test_host_delta_web_surface_delta(client, scoped_program, tmp_path, monkeypatch):
    host = "localhost:3000"
    output_dir = mcp_zap_server.OUTPUT_DIR

    # Previous snapshot
    prev_profile = {
        "host": host,
        "created": 1000,
        "web": {
            "urls": ["http://localhost:3000", "http://localhost:3000/runtime.js"],
            "api_endpoints": [
                {"url": "http://localhost:3000/api/v1/users", "method": "GET"},
            ],
        },
    }
    _write_host_profile_snapshot(output_dir, host, prev_profile, ts=1000)

    # Current snapshot
    curr_profile = {
        "host": host,
        "created": 2000,
        "web": {
            "urls": [
                "http://localhost:3000",
                "http://localhost:3000/runtime.js",
                "http://localhost:3000/main.js",
            ],
            "api_endpoints": [
                {"url": "http://localhost:3000/api/v1/users", "method": "GET"},
                {"url": "http://localhost:3000/api/v1/admin", "method": "POST"},
            ],
        },
    }
    _write_host_profile_snapshot(output_dir, host, curr_profile, ts=2000)

    # Act
    resp = client.post("/mcp/host_delta", json={"host": host})
    assert resp.status_code == 200
    body = resp.json()

    web_delta = body.get("web", {})
    assert "urls_added" in web_delta
    assert "urls_removed" in web_delta
    assert "api_endpoints_added" in web_delta
    assert "api_endpoints_removed" in web_delta

    assert "http://localhost:3000/main.js" in web_delta["urls_added"]
    assert web_delta["urls_removed"] == []

    added_apis = web_delta["api_endpoints_added"]
    assert {"url": "http://localhost:3000/api/v1/admin", "method": "POST"} in added_apis
    assert web_delta["api_endpoints_removed"] == []


def test_run_api_recon_happy_path(client, scoped_program, monkeypatch, tmp_path):
    host = "localhost:3000"
    output_dir = mcp_zap_server.OUTPUT_DIR

    # Fake host_profile snapshot with one API endpoint
    profile = {
        "host": host,
        "created": 3000,
        "web": {
            "api_endpoints": [
                {"url": "http://localhost:3000/api/v1/users", "method": "GET"},
            ]
        },
    }
    _write_host_profile_snapshot(output_dir, host, profile, ts=3000)

    # Mock requests.get / options
    class DummyResp:
        def __init__(self, status_code, headers=None):
            self.status_code = status_code
            self.headers = headers or {}

    def fake_get(url, timeout=15):
        assert url == "http://localhost:3000/api/v1/users"
        return DummyResp(200, {})

    def fake_options(url, timeout=15):
        assert url == "http://localhost:3000/api/v1/users"
        return DummyResp(200, {"Allow": "GET,OPTIONS"})

    monkeypatch.setattr(mcp_zap_server, "requests", type("R", (), {"get": fake_get, "options": fake_options}))

    # Act
    resp = client.post("/mcp/run_api_recon", json={"host": host})
    assert resp.status_code == 200
    body = resp.json()

    assert body["host"] == host
    assert body["endpoints_count"] == 1
    findings_file = body["findings_file"]
    assert os.path.exists(findings_file)

    with open(findings_file, "r", encoding="utf-8") as fh:
        probes = json.load(fh)

    assert len(probes) == 1
    probe = probes[0]
    assert probe["url"] == "http://localhost:3000/api/v1/users"
    assert probe["status_get"] == 200
    assert probe["status_options"] == 200
    assert probe["allow_header"] == "GET,OPTIONS"


def test_run_api_recon_no_endpoints(client, scoped_program, tmp_path):
    # No host_profile snapshot -> 404
    resp = client.post("/mcp/run_api_recon", json={"host": "localhost:3000"})
    assert resp.status_code == 404
