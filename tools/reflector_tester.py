#!/usr/bin/env python3
import argparse, requests, time, json, os
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from utils.artifact import write_artifact

MARKER = 'H1_MARKER_9f3b'

def build_url_with_param(url, param, value):
    u = urlparse(url)
    qs = dict(parse_qsl(u.query, keep_blank_values=True))
    qs[param] = value
    return urlunparse((u.scheme, u.netloc, u.path, u.params, urlencode(qs, doseq=True), u.fragment))

def check_reflection(url):
    try:
        r = requests.get(url, timeout=15)
        txt = r.text or ''
        return r.status_code, txt, r.headers
    except Exception as e:
        return None, '', {}

def run(target, outdir):
    os.makedirs(outdir, exist_ok=True)
    params = ['redirect','next','url','to','app_id','id','q','return','dest','callback']
    findings = []
    for p in params:
        u = build_url_with_param(target, p, MARKER)
        st, txt, headers = check_reflection(u)
        meta = {'param': p, 'url': u, 'status': st}
        write_artifact(os.path.join(outdir, f'ref_{p}.html'), text=txt, meta=meta)
        if MARKER in (txt or ''):
            # check unsanitized presence of < or >
            unsafe = any(sym in txt for sym in ['<','>','<script','svg','onload'])
            findings.append({'param': p, 'url': u, 'status': st, 'unsafe': unsafe})
    write_artifact(os.path.join(outdir, 'reflection_summary.json'), text=json.dumps(findings, indent=2))
    print('Reflection findings:', findings)
    return findings

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--url', required=True)
    ap.add_argument('--output', required=True)
    args = ap.parse_args()
    run(args.url, args.output)
