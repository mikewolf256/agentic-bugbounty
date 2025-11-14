import json
from unittest import mock

import agentic_runner


def test_run_dalfox_timeout(monkeypatch):
    def _timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="dalfox", timeout=1)

    with mock.patch("agentic_runner.subprocess.run", side_effect=_timeout):
        confirmed, evidence = agentic_runner.run_dalfox_check("https://example.com/?q=test")
        assert confirmed is False
        assert evidence["engine_result"] == "timeout"