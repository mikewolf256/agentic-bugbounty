#!/usr/bin/env python3
"""NoSQL Injection Lab - Vulnerable MongoDB queries for testing.

This intentionally vulnerable application demonstrates NoSQL injection vulnerabilities:
- MongoDB injection ($ne, $gt, $regex)
- Authentication bypass via NoSQL injection
- Boolean-based blind injection
- Data extraction via injection

DO NOT deploy this in production!
"""

from flask import Flask, request, jsonify, render_template_string
from pymongo import MongoClient
import json

app = Flask(__name__)

# Simulated MongoDB database (using in-memory dict)
db = {
    "users": [
        {"username": "admin", "password": "admin123", "role": "admin", "email": "admin@example.com"},
        {"username": "alice", "password": "alice123", "role": "user", "email": "alice@example.com"},
        {"username": "bob", "password": "bob123", "role": "user", "email": "bob@example.com"}
    ],
    "products": [
        {"name": "Product 1", "price": 10.0, "category": "electronics"},
        {"name": "Product 2", "price": 20.0, "category": "books"}
    ]
}

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>NoSQL Injection Lab</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #333; }
        .form { margin: 20px 0; }
        input, textarea { width: 100%; padding: 10px; margin: 5px 0; }
        button { padding: 10px 20px; margin-top: 10px; }
        .result { background: #f5f5f5; padding: 15px; margin: 10px 0; white-space: pre-wrap; }
        .error { background: #fee; color: #c00; padding: 15px; margin: 10px 0; }
        .success { background: #efe; color: #0c0; padding: 15px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>NoSQL Injection Lab</h1>
        {content}
    </div>
</body>
</html>
"""

def simulate_mongo_query(collection, query):
    """Simulate MongoDB query with NoSQL injection vulnerability"""
    results = []
    for doc in db.get(collection, []):
        match = True
        for key, value in query.items():
            if isinstance(value, dict):
                # Handle MongoDB operators
                if '$ne' in value:
                    if doc.get(key) == value['$ne']:
                        match = False
                elif '$gt' in value:
                    if not (doc.get(key) > value['$gt']):
                        match = False
                elif '$regex' in value:
                    import re
                    if not re.search(value['$regex'], str(doc.get(key, ''))):
                        match = False
            else:
                if doc.get(key) != value:
                    match = False
        if match:
            results.append(doc)
    return results


@app.route('/')
def home():
    content = """
        <p>This application contains intentional NoSQL injection vulnerabilities for testing.</p>
        <h2>Endpoints:</h2>
        <ul>
            <li><a href="/">Home</a> - This page</li>
            <li><a href="/login">Login</a> - Vulnerable login endpoint</li>
            <li><a href="/api/search">Search</a> - Vulnerable search endpoint</li>
        </ul>
        <h2>NoSQL Injection Testing Lab</h2>
        <p>This lab contains intentional NoSQL injection vulnerabilities:</p>
        <ul>
            <li>MongoDB injection ($ne, $gt, $regex)</li>
            <li>Authentication bypass via NoSQL injection</li>
            <li>Data extraction via injection</li>
        </ul>
        <p>Try login with: <code>{"username": {"$ne": null}, "password": {"$ne": null}}</code></p>
    """
    return BASE_TEMPLATE.replace('{content}', content)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """VULNERABLE: Login with NoSQL injection"""
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
            <p>Or send JSON: <code>{"username": {"$ne": null}, "password": {"$ne": null}}</code></p>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    
    # VULNERABLE: Direct JSON parsing without sanitization
    if request.is_json:
        data = request.get_json()
    else:
        data = {
            "username": request.form.get('username', ''),
            "password": request.form.get('password', '')
        }
    
    username = data.get('username', '')
    password = data.get('password', '')
    
    # VULNERABLE: Query constructed from user input without sanitization
    query = {"username": username, "password": password}
    
    # VULNERABLE: If username/password are dicts, they're used directly in query
    if isinstance(username, dict):
        query["username"] = username
    if isinstance(password, dict):
        query["password"] = password
    
    results = simulate_mongo_query("users", query)
    
    if results:
        user = results[0]
        content = f"""
            <div class="success">Login successful!</div>
            <div class="result">
                Username: {user.get('username')}
                Role: {user.get('role')}
                Email: {user.get('email')}
            </div>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    
    return BASE_TEMPLATE.replace('{content}', '<div class="error">Login failed</div>')


@app.route('/api/search', methods=['GET', 'POST'])
def search():
    """VULNERABLE: Search endpoint with NoSQL injection"""
    if request.method == 'GET':
        return jsonify({"error": "Use POST with JSON body"}), 400
    
    data = request.get_json() or {}
    query = data.get('query', {})
    
    # VULNERABLE: Query used directly without sanitization
    results = simulate_mongo_query("users", query)
    
    # Remove sensitive fields
    safe_results = []
    for doc in results:
        safe_doc = {k: v for k, v in doc.items() if k != 'password'}
        safe_results.append(safe_doc)
    
    return jsonify({
        "results": safe_results,
        "count": len(safe_results)
    })


@app.route('/api/user', methods=['GET', 'POST'])
def user():
    """VULNERABLE: User endpoint with NoSQL injection"""
    if request.method == 'GET':
        username = request.args.get('username', '')
        if not username:
            return jsonify({"error": "Username required"}), 400
        
        query = {"username": username}
        results = simulate_mongo_query("users", query)
        
        if results:
            user = results[0]
            return jsonify({
                "username": user.get('username'),
                "email": user.get('email'),
                "role": user.get('role')
            })
        return jsonify({"error": "User not found"}), 404
    
    # POST with JSON injection
    data = request.get_json() or {}
    query = data.get('filter', {})
    
    # VULNERABLE: Filter used directly
    results = simulate_mongo_query("users", query)
    safe_results = [{k: v for k, v in doc.items() if k != 'password'} for doc in results]
    
    return jsonify({"users": safe_results})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

