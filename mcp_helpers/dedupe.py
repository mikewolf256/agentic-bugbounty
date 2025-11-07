# mcp_helpers/dedupe.py
import hashlib
from typing import List, Dict, Any, Set

LOW_VALUE_ALERTS = {
    "Missing X-Frame-Options header",
    "X-Content-Type-Options header missing",
    "Strict-Transport-Security header not set",
    "Cookie without Secure flag",
    "Information disclosure - debug error messages",
    "Insecure HTTP method",
    "Server reveals version",
}

FOCUS_AREAS = {
    "SQL Injection", "Cross Site Scripting", "Server Side Request Forgery",
    "Remote Code Execution", "XML External Entity", "File upload",
    "Authentication Bypass", "Broken Access Control", "AWS", "S3",
    "credential", "Exposure"
}

def _fingerprint(f: Dict[str, Any]) -> str:
    s = "|".join([
        str(f.get("name","")),
        str(f.get("url","")),
        str(f.get("param","") or ""),
        str(f.get("evidence","") or "")[:200],
    ])
    return hashlib.sha1(s.encode("utf-8")).hexdigest()

def _normalize_confidence(val) -> float:
    """
    Map common ZAP strings to a numeric scale:
      informational=0, low=1, medium=2, high=3.
    If already numeric, pass through.
    """
    if val is None:
        return 0.0
    if isinstance(val, (int, float)):
        return float(val)
    s = str(val).strip().lower()
    mapping = {
        "informational": 0.0, "info": 0.0,
        "low": 1.0,
        "medium": 2.0, "moderate": 2.0,
        "high": 3.0
    }
    return float(mapping.get(s, 1.0))  # default to low-ish

def is_low_value(f: Dict[str, Any]) -> bool:
    name = str(f.get("name","") or "")
    for noise in LOW_VALUE_ALERTS:
        if noise.lower() in name.lower():
            return True
    conf = _normalize_confidence(f.get("confidence"))
    # treat missing evidence + low confidence as low value
    if not f.get("evidence") and conf < 2.0:
        return True
    return False

def is_focus_area(f: Dict[str, Any]) -> bool:
    name = str(f.get("name","") or "")
    desc = str(f.get("description","") or "")
    combined = (name + " " + desc).lower()
    for kw in FOCUS_AREAS:
        if kw.lower() in combined:
            return True
    return False

def filter_and_dedupe(findings: List[Dict[str, Any]], keep_noise: bool=False) -> List[Dict[str, Any]]:
    seen: Set[str] = set()
    out: List[Dict[str, Any]] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        if not keep_noise and is_low_value(f) and not is_focus_area(f):
            continue
        fp = _fingerprint(f)
        if fp in seen:
            continue
        seen.add(fp)
        out.append(f)
    return out
