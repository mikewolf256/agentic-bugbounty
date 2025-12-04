#!/bin/bash
set -e

# Choose worker script based on mode
if [ "${WORKER_MODE:-aws}" = "local" ]; then
    echo "[ENTRYPOINT] Starting WhatWeb worker (local mode)..."
    WORKER_SCRIPT="/app/worker-local.py"
else
    echo "[ENTRYPOINT] Starting WhatWeb worker (AWS mode)..."
    WORKER_SCRIPT="/app/worker.py"
fi

# Run the worker
python3 "$WORKER_SCRIPT"
exit_code=$?

echo "[ENTRYPOINT] Worker exited with code $exit_code"
exit $exit_code

