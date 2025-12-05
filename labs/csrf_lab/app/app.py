#!/usr/bin/env python3
"""CSRF Lab - Vulnerable state-changing endpoints for testing.

This intentionally vulnerable application demonstrates CSRF vulnerabilities:
- Missing CSRF tokens on state-changing endpoints
- Weak CSRF token validation
- Missing SameSite cookie protection
- Missing Origin/Referer header validation

DO NOT deploy this in production!
"""

from flask import Flask, request, jsonify, render_template_string, session
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Simulated user database
users = {
    "alice": {"email": "alice@example.com", "balance": 1000.0, "admin": False},
    "bob": {"email": "bob@example.com", "balance": 500.0, "admin": False}
}

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>CSRF Lab</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #333; }
        .form { margin: 20px 0; }
        input { width: 100%; padding: 10px; margin: 5px 0; }
        button { padding: 10px 20px; margin-top: 10px; }
        .result { background: #f5f5f5; padding: 15px; margin: 10px 0; }
        .error { background: #fee; color: #c00; padding: 15px; margin: 10px 0; }
        .success { background: #efe; color: #0c0; padding: 15px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>CSRF Lab</h1>
        {content}
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    username = session.get('username', 'Not logged in')
    content = f"""
        <p>This application contains intentional CSRF vulnerabilities for testing.</p>
        <p><strong>Current user:</strong> {username}</p>
        <h2>Endpoints:</h2>
        <ul>
            <li><a href="/">Home</a> - This page</li>
            <li><a href="/login">Login</a> - Login endpoint</li>
            <li><a href="/api/user/update">Update User</a> - Vulnerable user update</li>
            <li><a href="/api/purchase">Purchase</a> - Vulnerable purchase endpoint</li>
            <li><a href="/api/transfer">Transfer</a> - Vulnerable money transfer</li>
        </ul>
        <h2>CSRF Testing Lab</h2>
        <p>This lab contains intentional CSRF vulnerabilities:</p>
        <ul>
            <li>Missing CSRF tokens on state-changing endpoints</li>
            <li>Missing SameSite cookie protection</li>
            <li>Missing Origin/Referer header validation</li>
        </ul>
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


@app.route('/api/user/update', methods=['POST'])
def update_user():
    """VULNERABLE: User update without CSRF protection"""
    username = session.get('username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.get_json() or request.form.to_dict()
    email = data.get('email', '')
    
    # VULNERABLE: No CSRF token validation
    # VULNERABLE: No Origin/Referer header check
    
    if email:
        users[username]['email'] = email
    
    return jsonify({
        "success": True,
        "message": "User updated",
        "user": users[username]
    })


@app.route('/api/user/delete', methods=['DELETE', 'POST'])
def delete_user():
    """VULNERABLE: User deletion without CSRF protection"""
    username = session.get('username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    
    # VULNERABLE: No CSRF protection
    confirm = request.args.get('confirm') or (request.get_json() or {}).get('confirm', '')
    
    if confirm == 'yes':
        # Simulate deletion
        return jsonify({"success": True, "message": "User deleted"})
    
    return jsonify({"error": "Confirmation required"}), 400


@app.route('/api/purchase', methods=['POST'])
def purchase():
    """VULNERABLE: Purchase endpoint without CSRF protection"""
    username = session.get('username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.get_json() or request.form.to_dict()
    amount = float(data.get('amount', 0))
    item = data.get('item', '')
    
    # VULNERABLE: No CSRF token validation
    
    if amount > 0 and item:
        users[username]['balance'] -= amount
        return jsonify({
            "success": True,
            "message": f"Purchased {item} for ${amount:.2f}",
            "balance": users[username]['balance']
        })
    
    return jsonify({"error": "Invalid purchase"}), 400


@app.route('/api/transfer', methods=['POST'])
def transfer():
    """VULNERABLE: Money transfer without CSRF protection"""
    username = session.get('username')
    if not username:
        return jsonify({"error": "Not authenticated"}), 401
    
    data = request.get_json() or request.form.to_dict()
    to_user = data.get('to', '')
    amount = float(data.get('amount', 0))
    
    # VULNERABLE: No CSRF protection
    # VULNERABLE: No Origin/Referer validation
    
    if to_user in users and amount > 0:
        if users[username]['balance'] >= amount:
            users[username]['balance'] -= amount
            users[to_user]['balance'] += amount
            return jsonify({
                "success": True,
                "message": f"Transferred ${amount:.2f} to {to_user}",
                "balance": users[username]['balance']
            })
        return jsonify({"error": "Insufficient balance"}), 400
    
    return jsonify({"error": "Invalid transfer"}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

