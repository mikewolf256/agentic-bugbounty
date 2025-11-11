# simple dedupe helpers for agentic-bugbounty
import json, re, os

MIN_PRE_CVSS = float(os.environ.get('MIN_PRE_CVSS','6.0'))

def is_low_value(finding):
    # robustly interpret confidence
    conf = finding.get('confidence', 0)
    try:
        conf_val = float(conf)
    except Exception:
        conf_map = {'low':1,'medium':2,'high':3}
        conf_val = conf_map.get(str(conf).lower(), 0)
    # treat missing evidence as low
    evidence = finding.get('evidence') or finding.get('otherinfo') or ''
    if not evidence and conf_val < 2:
        return True
    # check pre-cvss estimate if present
    pre = finding.get('pre_cvss') or finding.get('cvss_estimate') or 0
    try:
        pref = float(pre)
    except Exception:
        pref = 0
    if pref and pref < MIN_PRE_CVSS:
        return True
    return False

def is_focus(finding):
    # tags we always keep
    name = (finding.get('name') or '').lower()
    cwe = str(finding.get('cweid') or '')
    if any(k in name for k in ['xss','ssrf','sql','injection','rce','idor','access control','authentication']): return True
    if '79' in cwe or '89' in cwe or '89' in name: return True
    return False

def filter_and_dedupe(findings, keep_noise=False):
    out = []
    seen = set()
    for f in findings:
        key = (f.get('url') or '') + '|' + (f.get('param') or '') + '|' + (f.get('name') or '')
        if key in seen: continue
        seen.add(key)
        if not keep_noise and is_low_value(f) and not is_focus(f):
            continue
        out.append(f)
    return out
