#!/usr/bin/env python3
"""Compatibility shim while renaming mcp_zap_server -> mcp_server.

This module simply re-exports the FastAPI app and all symbols from
``mcp_zap_server`` so existing imports keep working. It uses a direct
absolute import so it functions correctly as a top-level module inside
the container.
"""

from mcp_zap_server import *  # type: ignore
