import os, json, re, time
from pathlib import Path

SECRET_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key|secret|token)\s*[:=]\s*["\']([A-Za-z0-9_\-]{8,})["\']'),
    re.compile(r'(?i)(DB_(USER|PASS|PASSWORD|NAME)|database|username|password)\s*[:=]\s*["\'](.{3,}?)["\']'),
    re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}')
]

def mask_secret(s: str) -> str:
    if not s: return s
    s = str(s)
    return s[:4] + "…" + s[-4:] if len(s) > 12 else "****"

def redact_text(s: str) -> str:
    if not s: return s
    out = s
    for p in SECRET_PATTERNS:
        out = p.sub(lambda m: m.group(0).split('=')[0] + "=[REDACTED]", out)
    # simple Authorization header mask
    out = out.replace('Authorization: Bearer ', 'Authorization: Bearer ****')
    out = out.replace('Authorization: Basic ', 'Authorization: Basic ****')
    return out

def write_artifact(path: str, content: bytes=None, text: str=None, meta: dict=None, redact: bool=True):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if text is not None:
        data = redact_text(text) if redact else text
        p.write_text(data, encoding='utf-8')
    elif content is not None:
        p.write_bytes(content)
    # meta
    meta = meta or {}
    meta.setdefault('redaction_applied', bool(redact))
    meta.setdefault('ts', int(time.time()))
    meta_path = str(p.with_suffix(p.suffix + '.meta.json'))
    try:
        with open(meta_path, 'w', encoding='utf-8') as fh:
            json.dump(meta, fh, indent=2)
    except Exception as e:
        print('Failed to write meta', e)
