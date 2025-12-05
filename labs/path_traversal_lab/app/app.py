#!/usr/bin/env python3
"""Path Traversal Lab - Vulnerable file operations for testing.

This intentionally vulnerable application demonstrates path traversal vulnerabilities:
- Directory traversal (../, ..\\, encoded variants)
- Local file inclusion (LFI)
- Remote file inclusion (RFI)
- Blind LFI via time delays

DO NOT deploy this in production!
"""

import os
import time
from flask import Flask, request, jsonify, render_template_string, send_file
from urllib.parse import unquote

app = Flask(__name__)

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Path Traversal Lab</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #333; }
        .form { margin: 20px 0; }
        input, textarea { width: 100%; padding: 10px; margin: 5px 0; }
        button { padding: 10px 20px; margin-top: 10px; }
        .result { background: #f5f5f5; padding: 15px; margin: 10px 0; white-space: pre-wrap; }
        .error { background: #fee; color: #c00; padding: 15px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Path Traversal Lab</h1>
        {content}
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    content = """
        <p>This application contains intentional path traversal vulnerabilities for testing.</p>
        <h2>Endpoints:</h2>
        <ul>
            <li><a href="/">Home</a> - This page</li>
            <li><a href="/read">Read File</a> - Vulnerable file reading</li>
            <li><a href="/include">Include File</a> - File inclusion endpoint</li>
        </ul>
        <h2>Path Traversal Testing Lab</h2>
        <p>This lab contains intentional path traversal vulnerabilities:</p>
        <ul>
            <li>Directory traversal (../, ..\\, encoded variants)</li>
            <li>Local file inclusion (LFI) - /etc/passwd, /proc/version</li>
            <li>Remote file inclusion (RFI) - callback URL inclusion</li>
        </ul>
        <p>Try reading files like: <code>/etc/passwd</code>, <code>/proc/version</code></p>
    """
    return BASE_TEMPLATE.replace('{content}', content)


@app.route('/read', methods=['GET', 'POST'])
def read():
    """VULNERABLE: Path traversal via file reading"""
    if request.method == 'GET':
        content = """
            <h2>Read File</h2>
            <form method="POST">
                <div class="form">
                    <label>File Path:</label>
                    <input type="text" name="file" placeholder="/etc/passwd" value="/etc/passwd">
                </div>
                <button type="submit">Read File</button>
            </form>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    
    file_path = request.form.get('file') or request.args.get('file', '')
    if not file_path:
        return BASE_TEMPLATE.replace('{content}', '<div class="error">No file path provided</div>')
    
    # VULNERABLE: No path traversal protection
    file_path = unquote(file_path)
    
    try:
        # VULNERABLE: Direct file reading without path validation
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content_data = f.read()
        
        content = f"""
            <h2>File Content</h2>
            <div class="result">File: {file_path}

Content:
{content_data[:1000]}</div>
            <a href="/read">Read Another File</a>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    except FileNotFoundError:
        return BASE_TEMPLATE.replace('{content}', f'<div class="error">File not found: {file_path}</div>')
    except PermissionError:
        return BASE_TEMPLATE.replace('{content}', f'<div class="error">Permission denied: {file_path}</div>')
    except Exception as e:
        return BASE_TEMPLATE.replace('{content}', f'<div class="error">Error: {str(e)}</div>')


@app.route('/include', methods=['GET', 'POST'])
def include():
    """VULNERABLE: File inclusion with path traversal"""
    if request.method == 'GET':
        content = """
            <h2>Include File</h2>
            <form method="POST">
                <div class="form">
                    <label>File to Include:</label>
                    <input type="text" name="file" placeholder="../../etc/passwd" value="../../etc/passwd">
                </div>
                <button type="submit">Include File</button>
            </form>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    
    file_path = request.form.get('file') or request.args.get('file', '')
    if not file_path:
        return BASE_TEMPLATE.replace('{content}', '<div class="error">No file path provided</div>')
    
    # VULNERABLE: Path traversal in file inclusion
    file_path = unquote(file_path)
    base_dir = '/tmp/includes'
    os.makedirs(base_dir, exist_ok=True)
    
    # VULNERABLE: Joining paths without validation
    full_path = os.path.join(base_dir, file_path)
    
    try:
        # VULNERABLE: Normalizing path but still vulnerable
        normalized = os.path.normpath(full_path)
        
        # Check if it's a remote file inclusion attempt
        if file_path.startswith('http://') or file_path.startswith('https://'):
            import urllib.request
            with urllib.request.urlopen(file_path, timeout=5) as response:
                content_data = response.read().decode('utf-8', errors='ignore')
        else:
            with open(normalized, 'r', encoding='utf-8', errors='ignore') as f:
                content_data = f.read()
        
        content = f"""
            <h2>Included File Content</h2>
            <div class="result">File: {file_path}

Content:
{content_data[:1000]}</div>
            <a href="/include">Include Another File</a>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    except Exception as e:
        return BASE_TEMPLATE.replace('{content}', f'<div class="error">Error: {str(e)}</div>')


@app.route('/api/file', methods=['GET', 'POST'])
def api_file():
    """VULNERABLE: API endpoint for file operations"""
    file_path = request.args.get('file') or (request.get_json() or {}).get('file', '')
    
    if not file_path:
        return jsonify({"error": "No file path provided"}), 400
    
    # VULNERABLE: Path traversal in API
    file_path = unquote(file_path)
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        return jsonify({
            "file": file_path,
            "content": content[:1000],
            "size": len(content)
        })
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404
    except PermissionError:
        return jsonify({"error": "Permission denied"}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

