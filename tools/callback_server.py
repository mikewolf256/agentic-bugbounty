#!/usr/bin/env python3
"""Centralized Callback Server

HTTP/DNS callback server for out-of-band vulnerability validation (SSRF, XXE, etc.).
Shared by all scan containers/workers.

Features:
- Receive callback hits with unique tokens
- Correlate hits to scan jobs by job_id
- Collect evidence (request details, IPs, user-agents)
- Support HTTP, HTTPS, and DNS callbacks
- Real-time hit tracking and querying
"""

import os
import time
import random
import string
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

app = FastAPI(title="Callback Server", version="1.0.0")

# In-memory storage (replace with Redis/DB in production)
_hits: Dict[str, List[Dict[str, Any]]] = defaultdict(list)  # job_id -> list of hits
_registrations: Dict[str, Dict[str, Any]] = {}  # job_id -> registration info
_tokens: Dict[str, str] = {}  # token -> job_id mapping


class JobRegistration(BaseModel):
    """Registration request for a new scan job"""
    job_id: str
    tool: str
    target: str
    callback_url: Optional[str] = None
    timeout: int = 300  # seconds


class CallbackHit(BaseModel):
    """Callback hit data"""
    token: str
    job_id: str
    timestamp: float
    method: str
    path: str
    headers: Dict[str, str]
    query_params: Dict[str, str]
    remote_addr: str
    user_agent: str
    body: Optional[str] = None


def generate_callback_token(job_id: str) -> str:
    """Generate unique callback token: {job_id}_{timestamp}_{random}
    
    Args:
        job_id: Unique job identifier
        
    Returns:
        Unique callback token
    """
    timestamp = int(time.time())
    random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    token = f"{job_id}_{timestamp}_{random_suffix}"
    _tokens[token] = job_id
    return token


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "ok",
        "service": "callback-server",
        "version": "1.0.0",
        "registrations": len(_registrations),
        "total_hits": sum(len(hits) for hits in _hits.values())
    }


@app.get("/hit/{token}", response_class=PlainTextResponse)
async def receive_hit(token: str, request: Request):
    """Receive callback hit and correlate to job_id
    
    This endpoint receives HTTP callbacks from vulnerable targets.
    It extracts the token, correlates it to a job_id, and stores evidence.
    
    Args:
        token: Callback token from URL path
        request: FastAPI request object with full request details
        
    Returns:
        Simple response to avoid detection
    """
    # Extract job_id from token mapping
    job_id = _tokens.get(token)
    if not job_id:
        # Try to extract from token format: {job_id}_{timestamp}_{random}
        parts = token.split("_")
        if len(parts) >= 3:
            # Reconstruct job_id (may contain underscores)
            # Assume last 2 parts are timestamp and random
            job_id = "_".join(parts[:-2])
        else:
            job_id = token  # Fallback to token itself
    
    # Collect evidence
    hit_data = {
        "token": token,
        "job_id": job_id,
        "timestamp": time.time(),
        "method": request.method,
        "path": str(request.url.path),
        "headers": dict(request.headers),
        "query_params": dict(request.query_params),
        "remote_addr": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", "unknown"),
        "body": None
    }
    
    # Try to read body if present
    try:
        body = await request.body()
        if body:
            hit_data["body"] = body.decode("utf-8", errors="ignore")[:1000]  # Limit size
    except Exception:
        pass
    
    # Store hit
    _hits[job_id].append(hit_data)
    
    # Return simple response to avoid detection
    return "OK"


@app.get("/api/hits/{job_id}")
async def get_hits(job_id: str) -> Dict[str, Any]:
    """Get all hits for a job_id
    
    Args:
        job_id: Job identifier
        
    Returns:
        Dict with hits list and metadata
    """
    hits = _hits.get(job_id, [])
    
    # Clean up old hits (older than 1 hour)
    cutoff_time = time.time() - 3600
    hits = [h for h in hits if h["timestamp"] > cutoff_time]
    _hits[job_id] = hits
    
    return {
        "job_id": job_id,
        "hits_count": len(hits),
        "hits": hits,
        "registration": _registrations.get(job_id)
    }


@app.post("/api/register")
async def register_job(registration: JobRegistration) -> Dict[str, str]:
    """Register a new job for callback tracking
    
    Args:
        registration: Job registration details
        
    Returns:
        Dict with token and callback URL
    """
    job_id = registration.job_id
    
    # Generate callback token
    token = generate_callback_token(job_id)
    
    # Store registration
    _registrations[job_id] = {
        "job_id": job_id,
        "tool": registration.tool,
        "target": registration.target,
        "callback_url": registration.callback_url,
        "timeout": registration.timeout,
        "registered_at": time.time(),
        "token": token
    }
    
    # Build callback URL
    base_url = registration.callback_url or os.environ.get("CALLBACK_BASE_URL", "http://localhost:8080")
    callback_url = f"{base_url.rstrip('/')}/hit/{token}"
    
    return {
        "job_id": job_id,
        "token": token,
        "callback_url": callback_url
    }


@app.get("/api/stats")
async def get_stats() -> Dict[str, Any]:
    """Get callback server statistics
    
    Returns:
        Dict with statistics
    """
    total_hits = sum(len(hits) for hits in _hits.values())
    active_jobs = len([r for r in _registrations.values() 
                      if time.time() - r["registered_at"] < r.get("timeout", 300)])
    
    return {
        "total_registrations": len(_registrations),
        "active_jobs": active_jobs,
        "total_hits": total_hits,
        "jobs_with_hits": len([j for j, hits in _hits.items() if hits]),
        "tokens_count": len(_tokens)
    }


@app.delete("/api/cleanup")
async def cleanup_old_data(max_age_hours: int = 24) -> Dict[str, Any]:
    """Clean up old registrations and hits
    
    Args:
        max_age_hours: Maximum age in hours for data to keep
        
    Returns:
        Dict with cleanup statistics
    """
    cutoff_time = time.time() - (max_age_hours * 3600)
    
    # Clean up old registrations
    old_registrations = [j for j, r in _registrations.items() 
                        if r["registered_at"] < cutoff_time]
    for job_id in old_registrations:
        del _registrations[job_id]
        if job_id in _hits:
            del _hits[job_id]
    
    # Clean up old tokens
    # Note: We can't easily determine token age, so we'll clean based on job_id
    
    return {
        "cleaned_registrations": len(old_registrations),
        "remaining_registrations": len(_registrations),
        "remaining_hits": sum(len(hits) for hits in _hits.values())
    }


if __name__ == "__main__":
    import uvicorn
    
    port = int(os.environ.get("CALLBACK_PORT", "8080"))
    host = os.environ.get("CALLBACK_HOST", "0.0.0.0")
    
    print(f"Starting callback server on {host}:{port}")
    print(f"Environment: CALLBACK_BASE_URL={os.environ.get('CALLBACK_BASE_URL', 'http://localhost:8080')}")
    
    uvicorn.run(app, host=host, port=port)

