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