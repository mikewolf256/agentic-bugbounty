from typing import Tuple, Dict, Any
CWE_TO_VECTOR = {
    "SQL Injection": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.0),
    "Cross Site Scripting": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "Server Side Request Forgery": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.0),
    "Remote Code Execution": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "XML External Entity": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),
    "Authentication Bypass": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", 8.8),
    "Broken Access Control": ("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N", 7.5),
    "Default": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", 4.3)
}
def suggest_cvss(f: Dict[str, Any])->Tuple[str, float]:
    name=(f.get("name") or "").lower(); cwe=f.get("cweid","")
    for k,v in CWE_TO_VECTOR.items():
        if k.lower() in name: return v
    if cwe:
        if "79" in str(cwe): return CWE_TO_VECTOR["Cross Site Scripting"]
        if "89" in str(cwe): return CWE_TO_VECTOR["SQL Injection"]
    return CWE_TO_VECTOR["Default"]
