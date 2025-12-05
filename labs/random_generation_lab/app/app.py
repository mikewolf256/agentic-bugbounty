#!/usr/bin/env python3
"""Random Generation Lab - Vulnerable random number generation for testing.

This intentionally vulnerable application demonstrates random number generation vulnerabilities:
- Predictable session tokens (sequential)
- Predictable CSRF tokens
- Predictable user IDs
- Weak random number generation

DO NOT deploy this in production!
"""

from flask import Flask, request, jsonify, render_template_string, session
import time
import random

app = Flask(__name__)
app.secret_key = 'insecure-secret-key'

# VULNERABLE: Sequential counters
session_counter = 0
csrf_counter = 0
user_id_counter = 1000

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Random Generation Lab</title>
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
        <h1>Random Generation Lab</h1>
        {content}
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    content = """
        <p>This application contains intentional random number generation vulnerabilities for testing.</p>
        <h2>Endpoints:</h2>
        <ul>
            <li><a href="/">Home</a> - This page</li>
            <li><a href="/login">Login</a> - Generates predictable tokens</li>
            <li><a href="/api/token">Get Token</a> - Sequential token generation</li>
            <li><a href="/api/user">Create User</a> - Predictable user IDs</li>
        </ul>
        <h2>Random Generation Testing Lab</h2>
        <p>This lab contains intentional random generation vulnerabilities:</p>
        <ul>
            <li>Predictable session tokens (sequential)</li>
            <li>Predictable CSRF tokens</li>
            <li>Predictable user IDs</li>
        </ul>
    """
    return BASE_TEMPLATE.replace('{content}', content)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """VULNERABLE: Login with predictable token generation"""
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
    
    # VULNERABLE: Sequential session token
    global session_counter
    session_counter += 1
    session_token = f"SESSION{session_counter:08d}"
    
    # VULNERABLE: Sequential CSRF token
    global csrf_counter
    csrf_counter += 1
    csrf_token = f"CSRF{csrf_counter:08d}"
    
    session['username'] = username
    session['token'] = session_token
    session['csrf_token'] = csrf_token
    
    content = f"""
        <div class="result">
            Logged in as: {username}
            Session Token: {session_token}
            CSRF Token: {csrf_token}
            <strong>Tokens are sequential and predictable!</strong>
        </div>
        <a href="/">Home</a>
    """
    return BASE_TEMPLATE.replace('{content}', content)


@app.route('/api/token', methods=['GET'])
def get_token():
    """VULNERABLE: Sequential token generation"""
    global csrf_counter
    csrf_counter += 1
    
    # VULNERABLE: Sequential token
    token = f"TOKEN{csrf_counter:010d}"
    
    # VULNERABLE: Time-based but predictable
    timestamp = int(time.time())
    time_token = f"{timestamp}{csrf_counter:04d}"
    
    return jsonify({
        "token": token,
        "time_token": time_token,
        "counter": csrf_counter,
        "predictable": True
    })


@app.route('/api/user', methods=['POST'])
def create_user():
    """VULNERABLE: User creation with predictable IDs"""
    data = request.get_json() or request.form.to_dict()
    username = data.get('username', '')
    
    if not username:
        return jsonify({"error": "Username required"}), 400
    
    # VULNERABLE: Sequential user ID
    global user_id_counter
    user_id_counter += 1
    user_id = user_id_counter
    
    # VULNERABLE: Weak random (using time as seed)
    random.seed(int(time.time()))
    weak_random = random.randint(1000, 9999)
    
    return jsonify({
        "success": True,
        "username": username,
        "user_id": user_id,
        "weak_random": weak_random,
        "predictable": True
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

