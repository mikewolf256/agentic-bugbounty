#!/usr/bin/env python3
"""Compatibility shim: mcp_zap_server -> mcp_server.

This module re-exports everything from mcp_server for backward compatibility.
The actual implementation is in mcp_server.py.
"""

from mcp_server import *  # type: ignore
