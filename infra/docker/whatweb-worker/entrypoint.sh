#!/bin/bash
set -e

echo "[ENTRYPOINT] Starting WhatWeb worker..."

# Run the worker
python3 /app/worker.py
exit_code=$?

echo "[ENTRYPOINT] Worker exited with code $exit_code"
exit $exit_code

