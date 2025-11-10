# mcp_helpers/dedupe.py
# -*- coding: utf-8 -*-
"""
Noise filter + deduper for scanner findings.

Exports:
    filter_and_dedupe(findings: list[dict], keep_noise: bool = False) -> list[dict]

Notes:
- Designed to work with ZAP/Nuclei-like dicts (name/risk/confidence/url/param/evidence).
- Confidence is normalized to a small numeric scale to support filtering decisions.
"""

from __future__ import annotations
import re
import hashlib
from typing import Dict, Any, Iterable

# Common low-value/“out of scope” buckets for most programs
LOW_VALUE_ALERTS = {
    # Headers & best-practices
    "x-frame-options header not set",
    "content-security-policy (csp) not set",
    "strict-transport-security header not set",
    "x-content-type-options header missing",
    "x-xss-protection header",
    "cookie without secure flag",
    "cookie without httponly flag",
    "incomplete or no cache-control and pragma http header set",
    "information disclosure - debug error messages",
    "information disclosure - sensitive information in url",
    "information disclosure - suspicious comments",

    # Clickjacking / framing
    "frameable response (potential clickjacking)", "clickjacking",

    # Mixed content / tls trivia
    "mixed content", "weak ciphers", "tls version", "ssl certificate",

    # Version banners
    "server leaks information via 'x-powered-by' http response header field",
    "server version disclosure", "x-aspnet-version header",
}

# Regexes for broader matching
LOW_VALUE_REGEXES = [
    re.compile(r"missing\s+security\s+headers?", re.I),
    re.compile(r"cors(\s|-)misconfig", re.I),                 # often low impact unless proven exploit
    re.compile(r"robots\.txt", re.I),
    re.compile(r"directory listing", re.I),
    re.compile(r"csrf\s*token\s*missing", re.I),              # often noisy without exploit path
    re.compile(r"open redirect.*?self", re.I),                # self-redirects / benign
    re.compile(r"clickjacking", re.I),
    re.compile(r"verbose\s+server\s+banner", re.I),
]

# Keywords that usually indicate real impact (used by callers, but safe to keep here)
FOCUS_KEYWORDS = [
    "sql injection", "sqli", "cross site scripting", "xss",
    "server side request forgery", "ssrf",
    "remote code execution", "rce",
    "authentication bypass", "broken access control",
    "xml external entities", "xxe",
    "file upload", "path traversal", "lfi", "rfi",
    "credential", "token", "secret", "aws", "s3", "idor", "insecure direct object reference",
]


def _norm_text(v: Any) -> str:
    return (str(v or "")).strip()


def normalize_confidence(conf: Any) -> float:
    """
    Map various confidence forms to a small numeric scale:
        0.0 = unknown/low, 1.0 = medium, 2.0 = high, 3.0 = confirmed
    Accepts strings ("Low","High","Confirmed","Tentative"), ints, floats.
    """
    if conf is None:
        return 0.0
    if isinstance(conf, (int, float)):
        # Some tools give 0..3 or 0..100. Normalize roughly.
        try:
            val = float(conf)
        except Exception:
            return 0.0
        if val <= 1:
            return val  # assume already normalized
        if val <= 3:
            return val
        # scale 0..100 into 0..3
        return max(0.0, min(3.0, (val / 100.0) * 3.0))
    s = _norm_text(conf).lower()
    if s in ("certain", "confirmed", "true positive"):
        return 3.0
    if s in ("high", "firm", "likely"):
        return 2.0
    if s in ("medium", "moderate"):
        return 1.0
    if s in ("low", "tentative", "unknown", "unsure", "info", "informational"):
        return 0.0
    # fallback: try float
    try:
        return float(s)
    except Exception:
        return 0.0


def _is_low_value_name(name: str) -> bool:
    n = name.lower()
    if n in LOW_VALUE_ALERTS:
        return True
    for rx in LOW_VALUE_REGEXES:
        if rx.search(n):
            return True
    return False


def _has_meaningful_evidence(f: Dict[str, Any]) -> bool:
    ev = _norm_text(f.get("evidence") or f.get("otherinfo") or f.get("other_info") or f.get("desc"))
    # Evidence considered meaningful if any non-trivial content
    return len(ev) >= 10


def is_low_value(f: Dict[str, Any]) -> bool:
    """
    Heuristic low-value filter:
    - Known low-value name patterns
    - AND/OR: lacks evidence + low confidence
    """
    name = _norm_text(f.get("name") or f.get("alert") or f.get("title"))
    if _is_low_value_name(name):
        return True

    conf_num = normalize_confidence(f.get("confidence"))
    if not _has_meaningful_evidence(f) and conf_num < 1.0:
        return True

    # Extremely low tool "risk"
    risk = _norm_text(f.get("risk") or f.get("severity")).lower()
    if risk in ("informational", "info", "none"):
        return True

    return False


def make_fingerprint(f: Dict[str, Any]) -> str:
    """
    Stable fingerprint using (name, host, base url, param, evidence slice).
    """
    name = _norm_text(f.get("name") or f.get("alert") or f.get("title"))
    url = _norm_text(f.get("url") or f.get("uri") or f.get("endpoint"))
    # Keep host separate to avoid schema variance
    host = _norm_text(f.get("host") or f.get("hostname") or url.split("/")[2] if "://" in url else "")
    param = _norm_text(f.get("param") or f.get("parameter"))
    # Evidence slice to reduce duplicates with same text
    evidence = _norm_text(f.get("evidence") or f.get("otherinfo") or "")[:160]

    key = "|".join([name.lower(), host.lower(), url.lower(), param.lower(), evidence.lower()])
    return hashlib.sha256(key.encode("utf-8", "ignore")).hexdigest()


def filter_and_dedupe(findings: Iterable[Dict[str, Any]], keep_noise: bool = False) -> list[Dict[str, Any]]:
    """
    Returns a new list of findings with:
      - low-value items removed (unless keep_noise=True)
      - duplicates removed by fingerprint
    """
    seen = set()
    out = []

    for f in findings or []:
        # Normalize some convenience fields for downstream steps
        f["_confidence_num"] = normalize_confidence(f.get("confidence"))

        if not keep_noise and is_low_value(f):
            continue

        fp = make_fingerprint(f)
        if fp in seen:
            continue
        seen.add(fp)
        out.append(f)

    return out
