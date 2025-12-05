#!/usr/bin/env python3
"""Parameter Pollution Lab - Vulnerable parameter handling for testing.

This intentionally vulnerable application demonstrates HTTP parameter pollution vulnerabilities:
- Duplicate parameters with different values
- Parameter override behavior
- Server-side parameter handling issues

DO NOT deploy this in production!
"""

from flask import Flask, request, jsonify, render_template_string
from urllib.parse import parse_qs

app = Flask(__name__)

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Parameter Pollution Lab</title>
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
        <h1>Parameter Pollution Lab</h1>
        {content}
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    content = """
        <p>This application contains intentional parameter pollution vulnerabilities for testing.</p>
        <h2>Endpoints:</h2>
        <ul>
            <li><a href="/">Home</a> - This page</li>
            <li><a href="/api/user">User API</a> - Vulnerable user endpoint</li>
            <li><a href="/api/action">Action API</a> - Vulnerable action endpoint</li>
        </ul>
        <h2>Parameter Pollution Testing Lab</h2>
        <p>This lab contains intentional parameter pollution vulnerabilities:</p>
        <ul>
            <li>Duplicate parameters with different values</li>
            <li>Parameter override behavior</li>
            <li>Server-side parameter handling issues</li>
        </ul>
        <p>Try: <code>?user=alice&user=admin</code></p>
    """
    return BASE_TEMPLATE.replace('{content}', content)


@app.route('/api/user', methods=['GET'])
def user():
    """VULNERABLE: User endpoint with parameter pollution"""
    # VULNERABLE: Flask's request.args.get() returns first value
    # But request.args.getlist() returns all values
    user = request.args.get('user', 'anonymous')
    role = request.args.get('role', 'user')
    
    # VULNERABLE: Last parameter might override (depending on implementation)
    # In Flask, get() returns first, but we can check for pollution
    all_users = request.args.getlist('user')
    all_roles = request.args.getlist('role')
    
    result = {
        "user": user,
        "role": role,
        "all_users": all_users,  # Show all values
        "all_roles": all_roles,
        "pollution_detected": len(all_users) > 1 or len(all_roles) > 1
    }
    
    if request.headers.get('Accept') == 'application/json':
        return jsonify(result)
    
    content = f"""
        <h2>User Info</h2>
        <div class="result">
            User: {user}
            Role: {role}
            All Users: {all_users}
            All Roles: {all_roles}
            Pollution Detected: {result['pollution_detected']}
        </div>
        <p>Try: <code>?user=alice&user=admin&role=user&role=admin</code></p>
    """
    return BASE_TEMPLATE.replace('{content}', content)


@app.route('/api/action', methods=['POST'])
def action():
    """VULNERABLE: Action endpoint with parameter pollution"""
    # VULNERABLE: Parameter pollution in POST data
    action_type = request.form.get('action', '') or (request.get_json() or {}).get('action', '')
    target = request.form.get('target', '') or (request.get_json() or {}).get('target', '')
    
    # Check for pollution
    all_actions = request.form.getlist('action') or (request.get_json() or {}).get('action', [])
    all_targets = request.form.getlist('target') or (request.get_json() or {}).get('target', [])
    
    if isinstance(all_actions, str):
        all_actions = [all_actions]
    if isinstance(all_targets, str):
        all_targets = [all_targets]
    
    result = {
        "action": action_type,
        "target": target,
        "all_actions": all_actions,
        "all_targets": all_targets,
        "pollution_detected": len(all_actions) > 1 or len(all_targets) > 1
    }
    
    return jsonify(result)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

