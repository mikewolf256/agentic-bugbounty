#!/usr/bin/env python3
"""Session Analyzer

Tests session security:
- Session fixation
- Session hijacking
- Session replay
"""

from typing import Dict, Any, Optional

# Import stealth HTTP client for WAF evasion
try:
    from tools.http_client import safe_get, safe_post, get_stealth_session
    USE_STEALTH = True
except ImportError:
    import requests
    USE_STEALTH = False
    
    def safe_get(url, **kwargs):
        return requests.get(url, **kwargs)
    
    def safe_post(url, **kwargs):
        return requests.post(url, **kwargs)



def test_session_fixation(target_url: str, login_url: str, credentials: Dict[str, str]) -> Dict[str, Any]:
    """Test for session fixation
    
    Args:
        target_url: Target URL
        login_url: Login endpoint
        credentials: Login credentials
        
    Returns:
        Dict with test results
    """
    result = {
        "test": "session_fixation",
        "vulnerable": False,
        "evidence": None
    }
    
    # Get initial session
    session1 = requests.Session()
    initial_cookie = session1.cookies.get_dict()
    
    # Login
    session1.post(login_url, data=credentials)
    post_login_cookie = session1.cookies.get_dict()
    
    # If session ID didn't change after login, vulnerable to fixation
    if initial_cookie and post_login_cookie:
        initial_sid = initial_cookie.get("sessionid") or initial_cookie.get("session")
        post_sid = post_login_cookie.get("sessionid") or post_login_cookie.get("session")
        
        if initial_sid and initial_sid == post_sid:
            result["vulnerable"] = True
            result["evidence"] = {
                "session_id": initial_sid,
                "note": "Session ID unchanged after login"
            }
    
    return result


def analyze_session(target_url: str, session_cookie: str) -> Dict[str, Any]:
    """Analyze session cookie
    
    Args:
        target_url: Target URL
        session_cookie: Session cookie value
        
    Returns:
        Dict with analysis results
    """
    result = {
        "vulnerable": False,
        "issues": []
    }
    
    # Check if session is predictable
    if len(session_cookie) < 32:
        result["vulnerable"] = True
        result["issues"].append("short_session_id")
    
    # Check if session looks like base64 encoded (might be predictable)
    try:
        import base64
        decoded = base64.b64decode(session_cookie + "==")
        # If decodable, might be predictable
        result["issues"].append("base64_encoded_session")
    except Exception:
        pass
    
    return result

