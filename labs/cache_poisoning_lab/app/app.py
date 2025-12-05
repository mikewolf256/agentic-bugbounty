#!/usr/bin/env python3
"""Cache Poisoning Lab - Vulnerable caching for testing.

This intentionally vulnerable application demonstrates cache poisoning vulnerabilities:
- HTTP cache key injection
- Cache poisoning via headers (X-Forwarded-Host)
- Cache poisoning via query parameters

DO NOT deploy this in production!
"""

from flask import Flask, request, jsonify, render_template_string, make_response
from flask_caching import Cache

app = Flask(__name__)
app.config['CACHE_TYPE'] = 'simple'
cache = Cache(app)

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Cache Poisoning Lab</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #333; }
        .form { margin: 20px 0; }
        input { width: 100%; padding: 10px; margin: 5px 0; }
        button { padding: 10px 20px; margin-top: 10px; }
        .result { background: #f5f5f5; padding: 15px; margin: 10px 0; white-space: pre-wrap; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Cache Poisoning Lab</h1>
        {content}
    </div>
</body>
</html>
"""

@app.route('/')
@cache.cached(timeout=60, key_prefix=lambda: request.host)
def home():
    """VULNERABLE: Cacheable homepage"""
    host = request.headers.get('Host', 'localhost')
    x_forwarded_host = request.headers.get('X-Forwarded-Host', '')
    
    content = f"""
        <p>This application contains intentional cache poisoning vulnerabilities for testing.</p>
        <p>Host: {host}</p>
        <p>X-Forwarded-Host: {x_forwarded_host}</p>
        <h2>Endpoints:</h2>
        <ul>
            <li><a href="/">Home</a> - Cacheable homepage</li>
            <li><a href="/page">Page</a> - Cacheable page endpoint</li>
            <li><a href="/api/data">Data API</a> - API endpoint with caching</li>
        </ul>
        <h2>Cache Poisoning Testing Lab</h2>
        <p>This lab contains intentional cache poisoning vulnerabilities:</p>
        <ul>
            <li>HTTP cache key injection</li>
            <li>Cache poisoning via headers</li>
            <li>Cache poisoning via query parameters</li>
        </ul>
        <p>Try: <code>X-Forwarded-Host: evil.com</code></p>
    """
    
    resp = make_response(BASE_TEMPLATE.replace('{content}', content))
    resp.headers['Cache-Control'] = 'public, max-age=60'
    return resp


@app.route('/page')
@cache.cached(timeout=60, query_string=True)
def page():
    """VULNERABLE: Cacheable page with query parameters"""
    page_id = request.args.get('id', 'default')
    x_forwarded_host = request.headers.get('X-Forwarded-Host', '')
    
    content = f"""
        <h2>Page Content</h2>
        <div class="result">
            Page ID: {page_id}
            X-Forwarded-Host: {x_forwarded_host}
            <strong>This page is cached based on query parameters</strong>
        </div>
    """
    
    resp = make_response(BASE_TEMPLATE.replace('{content}', content))
    resp.headers['Cache-Control'] = 'public, max-age=60'
    # VULNERABLE: X-Forwarded-Host used in cache key
    if x_forwarded_host:
        resp.headers['X-Cache-Key'] = f"page-{page_id}-{x_forwarded_host}"
    return resp


@app.route('/api/data')
@cache.cached(timeout=60, query_string=True)
def api_data():
    """VULNERABLE: API endpoint with caching"""
    param = request.args.get('param', 'default')
    x_forwarded_host = request.headers.get('X-Forwarded-Host', '')
    
    data = {
        "param": param,
        "x_forwarded_host": x_forwarded_host,
        "cached": True
    }
    
    resp = jsonify(data)
    resp.headers['Cache-Control'] = 'public, max-age=60'
    # VULNERABLE: Header used in response (could be cached)
    if x_forwarded_host:
        resp.headers['X-Forwarded-Host'] = x_forwarded_host
    return resp


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

