import hashlib
from typing import List, Dict, Any, Set
LOW_VALUE_ALERTS = {
    "Missing X-Frame-Options header","X-Content-Type-Options header missing",
    "Strict-Transport-Security header not set","Cookie without Secure flag",
    "Information disclosure - debug error messages","Insecure HTTP method","Server reveals version"
}
FOCUS_AREAS = {"SQL Injection","Cross Site Scripting","Server Side Request Forgery",
               "Remote Code Execution","XML External Entity","File upload","Authentication Bypass",
               "Broken Access Control","AWS","S3","credential","Exposure"}
def _fp(f: Dict[str, Any]) -> str:
    s="|".join([f.get("name",""),f.get("url",""),f.get("param","") or "", (f.get("evidence","") or "")[:200]])
    return hashlib.sha1(s.encode("utf-8")).hexdigest()
def is_low_value(f: Dict[str,Any])->bool:
    name=f.get("name","") or ""
    if any(n.lower() in name.lower() for n in LOW_VALUE_ALERTS): return True
    if not f.get("evidence") and float(f.get("confidence",0))<2: return True
    return False
def is_focus(f: Dict[str,Any])->bool:
    text=(f.get("name","")+ " " + (f.get("description","") or "")).lower()
    return any(kw.lower() in text for kw in FOCUS_AREAS)
def filter_and_dedupe(findings: List[Dict[str,Any]], keep_noise: bool=False)->List[Dict[str,Any]]:
    seen:Set[str]=set(); out:List[Dict[str,Any]]=[]
    for f in findings:
        if not keep_noise and is_low_value(f) and not is_focus(f): continue
        fp=_fp(f)
        if fp in seen: continue
        seen.add(fp); out.append(f)
    return out
