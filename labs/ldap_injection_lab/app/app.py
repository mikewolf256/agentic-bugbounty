#!/usr/bin/env python3
"""LDAP Injection Lab - Vulnerable LDAP queries for testing.

This intentionally vulnerable application demonstrates LDAP injection vulnerabilities:
- LDAP injection in authentication endpoints
- LDAP injection in search endpoints
- Authentication bypass via LDAP injection
- Information disclosure via LDAP injection

DO NOT deploy this in production!
"""

from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# Simulated LDAP directory
ldap_users = {
    "cn=admin,dc=example,dc=com": {"password": "admin123", "role": "admin", "email": "admin@example.com"},
    "cn=alice,dc=example,dc=com": {"password": "alice123", "role": "user", "email": "alice@example.com"},
    "cn=bob,dc=example,dc=com": {"password": "bob123", "role": "user", "email": "bob@example.com"}
}

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>LDAP Injection Lab</title>
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
        <h1>LDAP Injection Lab</h1>
        {content}
    </div>
</body>
</html>
"""

def simulate_ldap_search(filter_str):
    """Simulate LDAP search with injection vulnerability"""
    results = []
    # VULNERABLE: Filter constructed from user input without sanitization
    # In real LDAP, this would be: (cn=*)(userPassword=*))
    for dn, attrs in ldap_users.items():
        # Simple simulation - check if filter matches
        if '*' in filter_str or filter_str in dn:
            results.append({"dn": dn, **attrs})
    return results


@app.route('/')
def home():
    content = """
        <p>This application contains intentional LDAP injection vulnerabilities for testing.</p>
        <h2>Endpoints:</h2>
        <ul>
            <li><a href="/">Home</a> - This page</li>
            <li><a href="/login">Login</a> - Vulnerable LDAP authentication</li>
            <li><a href="/api/search">Search</a> - Vulnerable LDAP search</li>
        </ul>
        <h2>LDAP Injection Testing Lab</h2>
        <p>This lab contains intentional LDAP injection vulnerabilities:</p>
        <ul>
            <li>LDAP injection in authentication endpoints</li>
            <li>LDAP injection in search endpoints</li>
            <li>Authentication bypass via LDAP injection</li>
        </ul>
        <p>Try login with: <code>admin)(&</code> or <code>*</code></p>
    """
    return BASE_TEMPLATE.replace('{content}', content)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """VULNERABLE: LDAP authentication with injection"""
    if request.method == 'GET':
        content = """
            <h2>Login</h2>
            <form method="POST">
                <div class="form">
                    <label>Username:</label>
                    <input type="text" name="username" placeholder="admin">
                </div>
                <div class="form">
                    <label>Password:</label>
                    <input type="password" name="password" placeholder="password">
                </div>
                <button type="submit">Login</button>
            </form>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    
    username = request.form.get('username', '') or (request.get_json() or {}).get('username', '')
    password = request.form.get('password', '') or (request.get_json() or {}).get('password', '')
    
    # VULNERABLE: LDAP filter constructed from user input without sanitization
    # Real filter would be: (cn={username})(userPassword={password}))
    # Injection: username = "admin)(&" would create: (cn=admin)(&)(userPassword=...))
    
    # Simulate LDAP query
    filter_str = f"(cn={username})"
    results = simulate_ldap_search(filter_str)
    
    # VULNERABLE: Password check also vulnerable
    for result in results:
        if result.get('password') == password or '*' in username or '*' in password:
            content = f"""
                <div class="success">Login successful!</div>
                <div class="result">
                    DN: {result.get('dn', 'N/A')}
                    Role: {result.get('role')}
                    Email: {result.get('email')}
                </div>
            """
            return BASE_TEMPLATE.replace('{content}', content)
    
    return BASE_TEMPLATE.replace('{content}', '<div class="error">Login failed</div>')


@app.route('/api/search', methods=['GET', 'POST'])
def search():
    """VULNERABLE: LDAP search with injection"""
    if request.method == 'GET':
        filter_str = request.args.get('filter', '(cn=*)')
    else:
        data = request.get_json() or {}
        filter_str = data.get('filter', '(cn=*)')
    
    # VULNERABLE: Filter used directly without sanitization
    results = simulate_ldap_search(filter_str)
    
    # Remove passwords from results
    safe_results = []
    for result in results:
        safe_result = {k: v for k, v in result.items() if k != 'password'}
        safe_results.append(safe_result)
    
    return jsonify({
        "filter": filter_str,
        "results": safe_results,
        "count": len(safe_results)
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

