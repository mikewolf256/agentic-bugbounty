#!/usr/bin/env python3
"""Mass Assignment Lab - Vulnerable object property assignment for testing.

This intentionally vulnerable application demonstrates mass assignment vulnerabilities:
- Mass assignment of object properties
- Privilege escalation via mass assignment
- Sensitive field manipulation (admin, role, permissions)

DO NOT deploy this in production!
"""

from flask import Flask, request, jsonify, render_template_string, session

app = Flask(__name__)
app.secret_key = 'insecure-secret-key'

# Simulated user database
users = {
    "alice": {"username": "alice", "email": "alice@example.com", "role": "user", "admin": False, "balance": 100.0},
    "bob": {"username": "bob", "email": "bob@example.com", "role": "user", "admin": False, "balance": 50.0}
}

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Mass Assignment Lab</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #333; }
        .form { margin: 20px 0; }
        input { width: 100%; padding: 10px; margin: 5px 0; }
        button { padding: 10px 20px; margin-top: 10px; }
        .result { background: #f5f5f5; padding: 15px; margin: 10px 0; white-space: pre-wrap; }
        .error { background: #fee; color: #c00; padding: 15px; margin: 10px 0; }
        .success { background: #efe; color: #0c0; padding: 15px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Mass Assignment Lab</h1>
        {content}
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    username = session.get('username', 'Not logged in')
    content = f"""
        <p>This application contains intentional mass assignment vulnerabilities for testing.</p>
        <p><strong>Current user:</strong> {username}</p>
        <h2>Endpoints:</h2>
        <ul>
            <li><a href="/">Home</a> - This page</li>
            <li><a href="/login">Login</a> - Login endpoint</li>
            <li><a href="/api/user/create">Create User</a> - Vulnerable user creation</li>
            <li><a href="/api/user/update">Update User</a> - Vulnerable user update</li>
        </ul>
        <h2>Mass Assignment Testing Lab</h2>
        <p>This lab contains intentional mass assignment vulnerabilities:</p>
        <ul>
            <li>Mass assignment of object properties</li>
            <li>Privilege escalation via mass assignment</li>
            <li>Sensitive field manipulation (admin, role)</li>
        </ul>
        <p>Try creating/updating user with: <code>{"admin": true, "role": "admin"}</code></p>
    """
    return BASE_TEMPLATE.replace('{content}', content)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login endpoint"""
    if request.method == 'GET':
        content = """
            <h2>Login</h2>
            <form method="POST">
                <div class="form">
                    <label>Username:</label>
                    <input type="text" name="username" placeholder="alice" value="alice">
                </div>
                <button type="submit">Login</button>
            </form>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    
    username = request.form.get('username', '')
    if username in users:
        session['username'] = username
        return BASE_TEMPLATE.replace('{content}', f'<div class="success">Logged in as {username}</div><a href="/">Home</a>')
    return BASE_TEMPLATE.replace('{content}', '<div class="error">Invalid username</div>')


@app.route('/api/user/create', methods=['POST'])
def create_user():
    """VULNERABLE: User creation with mass assignment"""
    data = request.get_json() or request.form.to_dict()
    
    username = data.get('username', '')
    if not username:
        return jsonify({"error": "Username required"}), 400
    
    if username in users:
        return jsonify({"error": "User already exists"}), 400
    
    # VULNERABLE: All fields from request are assigned without whitelist
    new_user = {
        "username": username,
        "email": data.get('email', ''),
        "role": data.get('role', 'user'),  # VULNERABLE: Can set to 'admin'
        "admin": data.get('admin', False),  # VULNERABLE: Can set to True
        "balance": float(data.get('balance', 0.0))
    }
    
    users[username] = new_user
    
    return jsonify({
        "success": True,
        "message": "User created",
        "user": new_user
    })


@app.route('/api/user/update', methods=['PUT', 'POST'])
def update_user():
    """VULNERABLE: User update with mass assignment"""
    username = session.get('username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    
    if username not in users:
        return jsonify({"error": "User not found"}), 404
    
    data = request.get_json() or request.form.to_dict()
    
    # VULNERABLE: All fields from request are updated without whitelist
    user = users[username]
    
    # VULNERABLE: Sensitive fields can be updated
    if 'email' in data:
        user['email'] = data['email']
    if 'role' in data:  # VULNERABLE: Role can be changed
        user['role'] = data['role']
    if 'admin' in data:  # VULNERABLE: Admin flag can be set
        user['admin'] = data.get('admin', False)
    if 'balance' in data:  # VULNERABLE: Balance can be manipulated
        user['balance'] = float(data['balance'])
    
    return jsonify({
        "success": True,
        "message": "User updated",
        "user": user
    })


@app.route('/api/profile', methods=['GET', 'POST'])
def profile():
    """VULNERABLE: Profile update with mass assignment"""
    username = session.get('username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    
    if request.method == 'GET':
        return jsonify({"user": users.get(username, {})})
    
    data = request.get_json() or request.form.to_dict()
    user = users[username]
    
    # VULNERABLE: Mass assignment without field whitelist
    for key, value in data.items():
        if key != 'username':  # Only protection
            user[key] = value
    
    return jsonify({
        "success": True,
        "message": "Profile updated",
        "user": user
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

