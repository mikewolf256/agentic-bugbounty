#!/usr/bin/env python3
"""Command Injection Lab - Vulnerable command execution for testing.

This intentionally vulnerable application demonstrates command injection vulnerabilities:
- OS command injection in GET/POST parameters
- Command injection in file upload filenames
- Command injection via system calls

DO NOT deploy this in production!
"""

import os
import subprocess
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Command Injection Lab</title>
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
        <h1>Command Injection Lab</h1>
        {content}
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    content = """
        <p>This application contains intentional command injection vulnerabilities for testing.</p>
        <h2>Endpoints:</h2>
        <ul>
            <li><a href="/">Home</a> - This page</li>
            <li><a href="/execute">Execute Command</a> - Vulnerable command execution</li>
            <li><a href="/upload">Upload File</a> - File upload with vulnerable filename handling</li>
        </ul>
        <h2>Command Injection Testing Lab</h2>
        <p>This lab contains intentional command injection vulnerabilities:</p>
        <ul>
            <li>OS command injection in GET/POST parameters</li>
            <li>Command injection in file upload filenames</li>
            <li>Command injection via system calls</li>
        </ul>
        <p>Try submitting commands like: <code>id</code>, <code>whoami</code>, <code>uname -a</code></p>
    """
    return BASE_TEMPLATE.replace('{content}', content)


@app.route('/execute', methods=['GET', 'POST'])
def execute():
    """VULNERABLE: Command injection via GET/POST parameters"""
    if request.method == 'GET':
        content = """
            <h2>Execute Command</h2>
            <form method="POST">
                <div class="form">
                    <label>Command:</label>
                    <input type="text" name="cmd" placeholder="id" value="id">
                </div>
                <button type="submit">Execute</button>
            </form>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    
    # VULNERABLE: Direct command execution without sanitization
    cmd = request.form.get('cmd') or request.args.get('cmd', '')
    if not cmd:
        return BASE_TEMPLATE.replace('{content}', '<div class="error">No command provided</div>')
    
    try:
        # VULNERABLE: Using shell=True allows command injection
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        output = result.stdout + result.stderr
        content = f"""
            <h2>Command Execution Result</h2>
            <div class="result">Command: {cmd}
Return Code: {result.returncode}

Output:
{output}</div>
            <a href="/execute">Try Another Command</a>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    except subprocess.TimeoutExpired:
        return BASE_TEMPLATE.replace('{content}', '<div class="error">Command timed out</div>')
    except Exception as e:
        return BASE_TEMPLATE.replace('{content}', f'<div class="error">Error: {str(e)}</div>')


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    """VULNERABLE: Command injection via file upload filename"""
    if request.method == 'GET':
        content = """
            <h2>Upload File</h2>
            <form method="POST" enctype="multipart/form-data">
                <div class="form">
                    <label>File:</label>
                    <input type="file" name="file">
                </div>
                <button type="submit">Upload</button>
            </form>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    
    if 'file' not in request.files:
        return BASE_TEMPLATE.replace('{content}', '<div class="error">No file provided</div>')
    
    file = request.files['file']
    if file.filename == '':
        return BASE_TEMPLATE.replace('{content}', '<div class="error">No file selected</div>')
    
    # VULNERABLE: Using filename in shell command without sanitization
    filename = file.filename
    upload_dir = '/tmp/uploads'
    os.makedirs(upload_dir, exist_ok=True)
    
    # VULNERABLE: Filename used in shell command
    filepath = os.path.join(upload_dir, filename)
    file.save(filepath)
    
    # VULNERABLE: Command execution with filename
    try:
        result = subprocess.run(f'ls -la {filepath}', shell=True, capture_output=True, text=True, timeout=5)
        output = result.stdout + result.stderr
        content = f"""
            <h2>File Upload Result</h2>
            <div class="result">Filename: {filename}
File saved to: {filepath}

File listing:
{output}</div>
            <a href="/upload">Upload Another File</a>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    except Exception as e:
        return BASE_TEMPLATE.replace('{content}', f'<div class="error">Error: {str(e)}</div>')


@app.route('/api/run', methods=['POST'])
def api_run():
    """VULNERABLE: API endpoint with command execution"""
    data = request.get_json() or {}
    cmd = data.get('command') or request.form.get('command', '')
    
    if not cmd:
        return jsonify({"error": "No command provided"}), 400
    
    try:
        # VULNERABLE: Direct command execution
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return jsonify({
            "command": cmd,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

