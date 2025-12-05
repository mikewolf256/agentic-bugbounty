#!/usr/bin/env python3
"""DNS Rebinding Lab - Vulnerable SSRF-like endpoint for testing.

This intentionally vulnerable application demonstrates DNS rebinding vulnerabilities:
- DNS rebinding to bypass same-origin policy
- Internal network access via DNS rebinding
- Cloud metadata access simulation

DO NOT deploy this in production!
"""

from flask import Flask, request, jsonify, render_template_string
import requests
from urllib.parse import urlparse

app = Flask(__name__)

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>DNS Rebinding Lab</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #333; }
        .form { margin: 20px 0; }
        input { width: 100%; padding: 10px; margin: 5px 0; }
        button { padding: 10px 20px; margin-top: 10px; }
        .result { background: #f5f5f5; padding: 15px; margin: 10px 0; white-space: pre-wrap; }
        .error { background: #fee; color: #c00; padding: 15px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>DNS Rebinding Lab</h1>
        {content}
    </div>
</body>
</html>
"""

# Simulated internal endpoints
INTERNAL_ENDPOINTS = {
    "http://internal.local/admin": {"status": "admin_panel", "data": "Internal admin panel"},
    "http://internal.local/metadata": {"status": "metadata", "data": "AWS metadata endpoint"},
    "http://169.254.169.254/latest/meta-data/": {"status": "cloud_metadata", "data": "Cloud metadata"}
}

@app.route('/')
def home():
    content = """
        <p>This application contains intentional DNS rebinding vulnerabilities for testing.</p>
        <h2>Endpoints:</h2>
        <ul>
            <li><a href="/">Home</a> - This page</li>
            <li><a href="/fetch">Fetch</a> - Vulnerable SSRF-like endpoint</li>
            <li><a href="/internal">Internal</a> - Internal endpoint simulation</li>
        </ul>
        <h2>DNS Rebinding Testing Lab</h2>
        <p>This lab contains intentional DNS rebinding vulnerabilities:</p>
        <ul>
            <li>DNS rebinding to bypass same-origin policy</li>
            <li>Internal network access via DNS rebinding</li>
            <li>Cloud metadata access simulation</li>
        </ul>
        <p>Try fetching: <code>http://internal.local/admin</code></p>
    """
    return BASE_TEMPLATE.replace('{content}', content)


@app.route('/fetch', methods=['GET', 'POST'])
def fetch():
    """VULNERABLE: SSRF-like endpoint vulnerable to DNS rebinding"""
    if request.method == 'GET':
        content = """
            <h2>Fetch URL</h2>
            <form method="POST">
                <div class="form">
                    <label>URL to Fetch:</label>
                    <input type="text" name="url" placeholder="http://internal.local/admin" value="http://internal.local/admin">
                </div>
                <button type="submit">Fetch</button>
            </form>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    
    url = request.form.get('url') or request.args.get('url') or (request.get_json() or {}).get('url', '')
    
    if not url:
        return BASE_TEMPLATE.replace('{content}', '<div class="error">No URL provided</div>')
    
    # VULNERABLE: No DNS rebinding protection
    # VULNERABLE: No internal network blocking
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        # Check if it's an internal endpoint (simulation)
        if url in INTERNAL_ENDPOINTS:
            result = INTERNAL_ENDPOINTS[url]
            content = f"""
                <h2>Fetch Result</h2>
                <div class="result">
                    URL: {url}
                    Status: {result['status']}
                    Data: {result['data']}
                    <strong>DNS Rebinding: Internal network accessed!</strong>
                </div>
                <a href="/fetch">Fetch Another</a>
            """
            return BASE_TEMPLATE.replace('{content}', content)
        
        # Try to fetch external URL
        resp = requests.get(url, timeout=5, allow_redirects=False)
        content = f"""
            <h2>Fetch Result</h2>
            <div class="result">
                URL: {url}
                Status Code: {resp.status_code}
                Content: {resp.text[:500]}
            </div>
            <a href="/fetch">Fetch Another</a>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    except Exception as e:
        return BASE_TEMPLATE.replace('{content}', f'<div class="error">Error: {str(e)}</div>')


@app.route('/internal')
def internal():
    """Simulated internal endpoint"""
    return jsonify({
        "status": "internal_endpoint",
        "message": "This is an internal endpoint",
        "dns_rebinding": "Accessible via DNS rebinding"
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

