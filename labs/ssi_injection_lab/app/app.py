#!/usr/bin/env python3
"""SSI Injection Lab - Vulnerable Server-Side Includes for testing.

This intentionally vulnerable application demonstrates SSI injection vulnerabilities:
- SSI injection in templates/static content
- Command execution via SSI
- File inclusion via SSI

DO NOT deploy this in production!
"""

from flask import Flask, request, jsonify, render_template_string
import subprocess
import os

app = Flask(__name__)

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>SSI Injection Lab</title>
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
        <h1>SSI Injection Lab</h1>
        {content}
    </div>
</body>
</html>
"""

def process_ssi(content):
    """VULNERABLE: Process SSI directives without sanitization"""
    import re
    
    # VULNERABLE: Process SSI exec directives
    def replace_exec(match):
        cmd = match.group(1)
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            return result.stdout + result.stderr
        except:
            return f"Error executing: {cmd}"
    
    # VULNERABLE: Process SSI include directives
    def replace_include(match):
        file_path = match.group(1)
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except:
            return f"Error including: {file_path}"
    
    # Process <!--#exec cmd="..."-->
    content = re.sub(r'<!--#exec\s+cmd="([^"]+)"\s*-->', replace_exec, content, flags=re.IGNORECASE)
    
    # Process <!--#include file="..."-->
    content = re.sub(r'<!--#include\s+file="([^"]+)"\s*-->', replace_include, content, flags=re.IGNORECASE)
    
    return content


@app.route('/')
def home():
    content = """
        <p>This application contains intentional SSI injection vulnerabilities for testing.</p>
        <h2>Endpoints:</h2>
        <ul>
            <li><a href="/">Home</a> - This page</li>
            <li><a href="/page">Page</a> - Vulnerable page endpoint</li>
            <li><a href="/render">Render</a> - Template rendering endpoint</li>
        </ul>
        <h2>SSI Injection Testing Lab</h2>
        <p>This lab contains intentional SSI injection vulnerabilities:</p>
        <ul>
            <li>SSI injection in templates/static content</li>
            <li>Command execution via SSI</li>
            <li>File inclusion via SSI</li>
        </ul>
        <p>Try: <code><!--#exec cmd="id"--></code></p>
    """
    return BASE_TEMPLATE.replace('{content}', content)


@app.route('/page', methods=['GET'])
def page():
    """VULNERABLE: Page endpoint with SSI injection"""
    page_content = request.args.get('page', '')
    
    if not page_content:
        content = """
            <h2>Page Content</h2>
            <form method="GET">
                <div class="form">
                    <label>Page Content:</label>
                    <input type="text" name="page" placeholder='<!--#exec cmd="id"-->'>
                </div>
                <button type="submit">Render</button>
            </form>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    
    # VULNERABLE: SSI directives processed without sanitization
    processed = process_ssi(page_content)
    
    content = f"""
        <h2>Rendered Page</h2>
        <div class="result">{processed}</div>
        <a href="/page">Try Another</a>
    """
    return BASE_TEMPLATE.replace('{content}', content)


@app.route('/render', methods=['GET', 'POST'])
def render():
    """VULNERABLE: Template rendering with SSI injection"""
    if request.method == 'GET':
        content = """
            <h2>Render Template</h2>
            <form method="POST">
                <div class="form">
                    <label>Template Content:</label>
                    <textarea name="template" rows="10" placeholder='<!--#exec cmd="id"-->'></textarea>
                </div>
                <button type="submit">Render</button>
            </form>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    
    template = request.form.get('template', '') or (request.get_json() or {}).get('template', '')
    
    if not template:
        return BASE_TEMPLATE.replace('{content}', '<div class="error">No template provided</div>')
    
    # VULNERABLE: SSI processing
    rendered = process_ssi(template)
    
    content = f"""
        <h2>Rendered Template</h2>
        <div class="result">{rendered}</div>
        <a href="/render">Render Another</a>
    """
    return BASE_TEMPLATE.replace('{content}', content)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

