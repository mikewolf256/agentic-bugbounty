#!/usr/bin/env python3
import argparse, requests, re, os, json, time
from urllib.parse import urljoin, urlparse
from pathlib import Path
from utils.artifact import write_artifact

# regex fixed — properly escaped quotes
JS_RE = re.compile(r'https?://[^"\']+\.js|/[^"\']+\.js')
URL_RE = re.compile(r'https?://[^"\')\s]+|"/[^")\s]+"')

def fetch(url, timeout=15):
    try:
        r = requests.get(url, timeout=timeout)
        return r.status_code, r.text, r.headers
    except Exception:
        return None, '', {}

def collect_js_from_page(base_url, html):
    found = set()
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, flags=re.I):
        found.add(m.group(1))
    for m in re.finditer(r'https?://[^"\']+\.js', html):
        found.add(m.group(0))
    return list(found)

def parse_endpoints_from_js(js_text, base_url):
    endpoints = set()
    for m in re.finditer(r'\b(/[a-zA-Z0-9_\-/]{3,})\b', js_text):
        s = m.group(1)
        if any(x in s.lower() for x in ['/api', '/backend', '/upload', '/uploads', '/storage', '/media', '/auth', '/admin']):
            endpoints.add(s)
    for m in re.finditer(r'https?://[^"\']+', js_text):
        endpoints.add(m.group(0))
    out = []
    for e in endpoints:
        if e.startswith('http'):
            out.append(e)
        else:
            out.append(urljoin(base_url, e))
    return sorted(set(out))

def run(base_url, outdir):
    Path(outdir).mkdir(parents=True, exist_ok=True)
    status, html, headers = fetch(base_url)
    write_artifact(os.path.join(outdir, 'page.html'), text=html, meta={'source': base_url, 'cmd': 'fetch page'})
    js_list = collect_js_from_page(base_url, html)
    candidates = set(js_list)
    endpoints = set()
    creds = []
    for js in candidates:
        js_url = js if js.startswith('http') else urljoin(base_url, js)
        st, txt, _ = fetch(js_url)
        if st is None:
            continue
        fn = os.path.join(outdir, 'js', js_url.replace('://', '_').replace('/', '_')[:200] + '.js')
        write_artifact(fn, text=txt, meta={'source': js_url})
        for e in parse_endpoints_from_js(txt, base_url):
            endpoints.add(e)
        for m in re.finditer(r'([A-Za-z0-9_\-]{8,}:?[A-Za-z0-9_\-]{8,})', txt):
            token = m.group(0)
            if any(x in token.lower() for x in ['key', 'token', 'secret', 'api']) or len(token) > 20:
                creds.append({'context': js_url, 'snippet': token[:64]})
    endpoints_list = sorted(endpoints)
    write_artifact(os.path.join(outdir, 'endpoints.json'), text=json.dumps(endpoints_list, indent=2))
    if creds:
        write_artifact(os.path.join(outdir, 'creds.json'), text=json.dumps(creds, indent=2))
    print('Wrote', os.path.join(outdir, 'endpoints.json'))
    return endpoints_list

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--base-url', required=True)
    ap.add_argument('--output-dir', required=True)
    args = ap.parse_args()
    # keep backwards compatibility with older callers that used --output
    outdir = args.output_dir
    run(args.base_url, outdir)

