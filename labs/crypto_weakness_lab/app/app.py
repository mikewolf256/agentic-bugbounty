#!/usr/bin/env python3
"""Crypto Weakness Lab - Vulnerable cryptographic implementations for testing.

This intentionally vulnerable application demonstrates cryptographic weakness vulnerabilities:
- Weak hashing algorithms (MD5, SHA1) in responses
- Weak encryption
- Predictable session tokens
- Short session cookies

DO NOT deploy this in production!
"""

from flask import Flask, request, jsonify, render_template_string, session, make_response
import hashlib
import time
import secrets

app = Flask(__name__)
app.secret_key = 'insecure-secret-key'

# Sequential token counter (VULNERABLE)
token_counter = 0

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Crypto Weakness Lab</title>
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
        <h1>Crypto Weakness Lab</h1>
        {content}
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    content = """
        <p>This application contains intentional cryptographic weakness vulnerabilities for testing.</p>
        <h2>Endpoints:</h2>
        <ul>
            <li><a href="/">Home</a> - This page</li>
            <li><a href="/login">Login</a> - Generates weak tokens</li>
            <li><a href="/api/token">Get Token</a> - Predictable token generation</li>
            <li><a href="/hash">Hash</a> - Weak hashing (MD5/SHA1)</li>
        </ul>
        <h2>Crypto Weakness Testing Lab</h2>
        <p>This lab contains intentional cryptographic weaknesses:</p>
        <ul>
            <li>Weak hashing algorithms (MD5, SHA1)</li>
            <li>Predictable session tokens</li>
            <li>Short session cookies</li>
        </ul>
    """
    return BASE_TEMPLATE.replace('{content}', content)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """VULNERABLE: Login with weak token generation"""
    if request.method == 'GET':
        content = """
            <h2>Login</h2>
            <form method="POST">
                <div class="form">
                    <label>Username:</label>
                    <input type="text" name="username" placeholder="admin" value="admin">
                </div>
                <button type="submit">Login</button>
            </form>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    
    username = request.form.get('username', '')
    
    # VULNERABLE: Sequential token generation
    global token_counter
    token_counter += 1
    token = f"TOKEN{token_counter:06d}"  # Predictable sequential token
    
    # VULNERABLE: Short session cookie
    session['username'] = username
    session['token'] = token
    
    resp = make_response(BASE_TEMPLATE.replace('{content}', f'<div class="result">Logged in as {username}<br>Token: {token}</div>'))
    resp.set_cookie('session_token', token, max_age=3600)  # VULNERABLE: Short, predictable token
    
    return resp


@app.route('/api/token', methods=['GET'])
def get_token():
    """VULNERABLE: Predictable token generation"""
    global token_counter
    token_counter += 1
    
    # VULNERABLE: Sequential token
    token = f"TOKEN{token_counter:06d}"
    
    # VULNERABLE: Weak hash (MD5)
    token_hash = hashlib.md5(token.encode()).hexdigest()
    
    return jsonify({
        "token": token,
        "token_hash": token_hash,
        "algorithm": "MD5"  # VULNERABLE: Weak algorithm
    })


@app.route('/hash', methods=['GET', 'POST'])
def hash_endpoint():
    """VULNERABLE: Weak hashing endpoint"""
    if request.method == 'GET':
        content = """
            <h2>Hash Data</h2>
            <form method="POST">
                <div class="form">
                    <label>Data to Hash:</label>
                    <input type="text" name="data" placeholder="test" value="test">
                </div>
                <div class="form">
                    <label>Algorithm:</label>
                    <select name="algorithm">
                        <option value="md5">MD5 (Weak)</option>
                        <option value="sha1">SHA1 (Weak)</option>
                        <option value="sha256">SHA256 (Strong)</option>
                    </select>
                </div>
                <button type="submit">Hash</button>
            </form>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    
    data = request.form.get('data', '')
    algorithm = request.form.get('algorithm', 'md5').lower()
    
    # VULNERABLE: Using weak algorithms
    if algorithm == 'md5':
        hash_value = hashlib.md5(data.encode()).hexdigest()
    elif algorithm == 'sha1':
        hash_value = hashlib.sha1(data.encode()).hexdigest()
    elif algorithm == 'sha256':
        hash_value = hashlib.sha256(data.encode()).hexdigest()
    else:
        hash_value = hashlib.md5(data.encode()).hexdigest()
    
    content = f"""
        <h2>Hash Result</h2>
        <div class="result">
            Data: {data}
            Algorithm: {algorithm.upper()}
            Hash: {hash_value}
        </div>
        <a href="/hash">Hash Another</a>
    """
    return BASE_TEMPLATE.replace('{content}', content)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

