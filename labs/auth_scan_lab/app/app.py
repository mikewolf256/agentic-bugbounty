"""
Auth Scan Lab - Comprehensive Authentication Vulnerability Testing Lab

This lab contains intentional vulnerabilities for testing security scanners:

1. DEFAULT_CREDENTIALS - admin/admin login
2. WEAK_JWT_SECRET - JWT signed with "secret123"
3. JWT_ALGORITHM_NONE - Accepts alg:none tokens
4. MISSING_RATE_LIMIT - No brute force protection
5. USERNAME_ENUMERATION - Different responses for valid/invalid users
6. PREDICTABLE_SESSION - Sequential session IDs
7. IDOR_USER_DATA - Access any user's data by ID
8. IDOR_ORDER_DATA - Access any order by ID
9. PRIVILEGE_ESCALATION - User can set own role to admin
10. INSECURE_PASSWORD_RESET - Predictable reset tokens
11. SESSION_IN_URL - Token passed in query string
12. MISSING_SECURE_COOKIE - Session cookie without Secure/HttpOnly
13. EXPOSED_ADMIN_PANEL - /admin accessible without auth check
14. HORIZONTAL_PRIVILEGE_ESCALATION - Access other tenant's data
15. VERTICAL_PRIVILEGE_ESCALATION - User accesses admin endpoints
"""

from flask import Flask, request, jsonify, make_response, render_template_string
import jwt
import hashlib
import time
import base64
import json
import re

app = Flask(__name__)

# Intentionally weak JWT secret (WEAK_JWT_SECRET)
JWT_SECRET = "secret123"

# In-memory database
USERS = {
    1: {
        "id": 1, 
        "username": "admin", 
        "password": "admin",  # DEFAULT_CREDENTIALS
        "email": "admin@example.com",
        "role": "admin",
        "tenant": "system",
        "api_key": "ak_admin_12345"
    },
    2: {
        "id": 2,
        "username": "alice",
        "password": "alice123",
        "email": "alice@example.com",
        "role": "user",
        "tenant": "tenant_a",
        "api_key": "ak_alice_67890"
    },
    3: {
        "id": 3,
        "username": "bob",
        "password": "bob456",
        "email": "bob@example.com",
        "role": "user",
        "tenant": "tenant_b",
        "api_key": "ak_bob_11111"
    },
}

ORDERS = {
    1: {"id": 1, "user_id": 2, "amount": 100, "items": ["Widget A"], "status": "completed"},
    2: {"id": 2, "user_id": 2, "amount": 250, "items": ["Widget B", "Gadget C"], "status": "pending"},
    3: {"id": 3, "user_id": 3, "amount": 75, "items": ["Gadget D"], "status": "completed"},
}

# Predictable session store (PREDICTABLE_SESSION)
SESSION_COUNTER = 1000
SESSIONS = {}  # session_id -> user_id

# Predictable password reset tokens (INSECURE_PASSWORD_RESET)
RESET_TOKENS = {}  # token -> user_id

# Track login attempts (but don't actually limit - MISSING_RATE_LIMIT)
LOGIN_ATTEMPTS = {}


def generate_session_id():
    """Generate predictable session ID (PREDICTABLE_SESSION)"""
    global SESSION_COUNTER
    SESSION_COUNTER += 1
    return f"sess_{SESSION_COUNTER}"


def generate_reset_token(user_id):
    """Generate predictable reset token (INSECURE_PASSWORD_RESET)"""
    # Token is just base64(user_id:timestamp) - easily guessable
    timestamp = int(time.time())
    token_data = f"{user_id}:{timestamp}"
    return base64.b64encode(token_data.encode()).decode()


def create_jwt(user, algorithm="HS256"):
    """Create JWT token (potentially with weak config)"""
    payload = {
        "user_id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "tenant": user["tenant"],
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }
    
    if algorithm == "none":
        # JWT_ALGORITHM_NONE vulnerability
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        return f"{header}.{payload_b64}."
    
    return jwt.encode(payload, JWT_SECRET, algorithm=algorithm)


def verify_jwt(token):
    """Verify JWT - intentionally accepts alg:none (JWT_ALGORITHM_NONE)"""
    try:
        # Check for alg:none bypass
        parts = token.split(".")
        if len(parts) >= 2:
            try:
                header_padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
                header = json.loads(base64.urlsafe_b64decode(header_padded))
                if header.get("alg", "").lower() == "none":
                    # Accept unsigned token! (JWT_ALGORITHM_NONE)
                    payload_padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                    return json.loads(base64.urlsafe_b64decode(payload_padded))
            except:
                pass
        
        # Normal verification with weak secret
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_current_user():
    """Extract user from various auth methods"""
    # Check JWT in Authorization header
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth.split(" ", 1)[1]
        payload = verify_jwt(token)
        if payload:
            return USERS.get(payload.get("user_id"))
    
    # Check session cookie (MISSING_SECURE_COOKIE - no httponly/secure)
    session_id = request.cookies.get("session_id")
    if session_id and session_id in SESSIONS:
        return USERS.get(SESSIONS[session_id])
    
    # Check token in URL (SESSION_IN_URL vulnerability)
    url_token = request.args.get("token") or request.args.get("session")
    if url_token:
        payload = verify_jwt(url_token)
        if payload:
            return USERS.get(payload.get("user_id"))
        if url_token in SESSIONS:
            return USERS.get(SESSIONS[url_token])
    
    # Check API key
    api_key = request.headers.get("X-API-Key")
    if api_key:
        for user in USERS.values():
            if user.get("api_key") == api_key:
                return user
    
    return None


# ============ PUBLIC ENDPOINTS ============

@app.route("/")
def index():
    """Home page with links to all vulnerable endpoints"""
    return render_template_string("""
<!DOCTYPE html>
<html>
<head><title>Auth Scan Lab</title></head>
<body>
    <h1>Authentication Vulnerability Lab</h1>
    <h2>Endpoints:</h2>
    <ul>
        <li><a href="/login">POST /login</a> - Login (admin/admin)</li>
        <li><a href="/api/users/1">GET /api/users/:id</a> - Get user (IDOR)</li>
        <li><a href="/api/orders/1">GET /api/orders/:id</a> - Get order (IDOR)</li>
        <li><a href="/api/profile">GET /api/profile</a> - Current user profile</li>
        <li><a href="/api/profile">PUT /api/profile</a> - Update profile (priv esc)</li>
        <li><a href="/admin">GET /admin</a> - Admin panel</li>
        <li><a href="/admin/users">GET /admin/users</a> - List all users</li>
        <li><a href="/forgot-password">POST /forgot-password</a> - Password reset</li>
        <li><a href="/reset-password">POST /reset-password</a> - Reset with token</li>
        <li><a href="/api/search?q=test">GET /api/search?q=</a> - Search endpoint</li>
    </ul>
    <h2>Known Vulnerabilities:</h2>
    <ul>
        <li>DEFAULT_CREDENTIALS: admin/admin</li>
        <li>WEAK_JWT_SECRET: "secret123"</li>
        <li>JWT_ALGORITHM_NONE: Accepts alg:none</li>
        <li>MISSING_RATE_LIMIT: No brute force protection</li>
        <li>USERNAME_ENUMERATION: Different error messages</li>
        <li>IDOR: /api/users/:id, /api/orders/:id</li>
        <li>PRIVILEGE_ESCALATION: Can set role via PUT /api/profile</li>
        <li>INSECURE_PASSWORD_RESET: Predictable tokens</li>
        <li>SESSION_IN_URL: Accepts ?token= parameter</li>
        <li>MISSING_SECURE_COOKIE: No HttpOnly/Secure flags</li>
        <li>EXPOSED_ADMIN_PANEL: /admin accessible</li>
    </ul>
</body>
</html>
    """)


@app.route("/robots.txt")
def robots():
    """Expose sensitive paths in robots.txt"""
    return """User-agent: *
Disallow: /admin/
Disallow: /api/internal/
Disallow: /backup/
Disallow: /.git/
Disallow: /config.php.bak
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Login endpoint with multiple vulnerabilities:
    - DEFAULT_CREDENTIALS (admin/admin)
    - MISSING_RATE_LIMIT
    - USERNAME_ENUMERATION
    """
    if request.method == "GET":
        return render_template_string("""
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
    <h1>Login</h1>
    <form method="POST">
        <input name="username" placeholder="Username"><br>
        <input name="password" type="password" placeholder="Password"><br>
        <button type="submit">Login</button>
    </form>
</body>
</html>
        """)
    
    data = request.get_json() if request.is_json else request.form
    username = data.get("username", "")
    password = data.get("password", "")
    
    # Track attempts but don't limit (MISSING_RATE_LIMIT)
    LOGIN_ATTEMPTS[username] = LOGIN_ATTEMPTS.get(username, 0) + 1
    
    # Find user
    user = None
    for u in USERS.values():
        if u["username"] == username:
            user = u
            break
    
    # USERNAME_ENUMERATION: Different messages for valid/invalid users
    if not user:
        return jsonify({"error": "User not found", "code": "USER_NOT_FOUND"}), 401
    
    if user["password"] != password:
        return jsonify({"error": "Invalid password", "code": "INVALID_PASSWORD"}), 401
    
    # Create session with insecure cookie
    session_id = generate_session_id()
    SESSIONS[session_id] = user["id"]
    
    # Create JWT
    token = create_jwt(user)
    
    resp = make_response(jsonify({
        "success": True,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"]
        },
        "token": token,
        "session_id": session_id
    }))
    
    # MISSING_SECURE_COOKIE: No HttpOnly or Secure flags
    resp.set_cookie("session_id", session_id)
    resp.headers["X-Auth-Token"] = token
    
    return resp


@app.route("/logout", methods=["POST"])
def logout():
    """Logout endpoint"""
    session_id = request.cookies.get("session_id")
    if session_id and session_id in SESSIONS:
        del SESSIONS[session_id]
    
    resp = make_response(jsonify({"success": True}))
    resp.delete_cookie("session_id")
    return resp


# ============ USER API ENDPOINTS ============

@app.route("/api/users/<int:user_id>")
def get_user(user_id):
    """
    IDOR vulnerability - any authenticated user can access any user's data
    """
    current = get_current_user()
    if not current:
        return jsonify({"error": "Authentication required"}), 401
    
    # IDOR: No check that current user should access this user
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Expose sensitive data
    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "tenant": user["tenant"],
        "api_key": user["api_key"]  # Exposing API key!
    })


@app.route("/api/profile", methods=["GET", "PUT"])
def profile():
    """
    Profile endpoint with privilege escalation vulnerability
    """
    current = get_current_user()
    if not current:
        return jsonify({"error": "Authentication required"}), 401
    
    if request.method == "GET":
        return jsonify({
            "id": current["id"],
            "username": current["username"],
            "email": current["email"],
            "role": current["role"]
        })
    
    # PUT - PRIVILEGE_ESCALATION: User can set their own role!
    data = request.get_json() or {}
    
    if "email" in data:
        USERS[current["id"]]["email"] = data["email"]
    if "role" in data:
        # No authorization check - user can make themselves admin!
        USERS[current["id"]]["role"] = data["role"]
    if "tenant" in data:
        USERS[current["id"]]["tenant"] = data["tenant"]
    
    return jsonify({"success": True, "user": USERS[current["id"]]})


@app.route("/api/orders/<int:order_id>")
def get_order(order_id):
    """
    IDOR vulnerability - access any order without ownership check
    """
    current = get_current_user()
    if not current:
        return jsonify({"error": "Authentication required"}), 401
    
    # IDOR: No check that order belongs to current user
    order = ORDERS.get(order_id)
    if not order:
        return jsonify({"error": "Order not found"}), 404
    
    return jsonify(order)


@app.route("/api/orders")
def list_orders():
    """List orders - should filter by user but doesn't properly"""
    current = get_current_user()
    if not current:
        return jsonify({"error": "Authentication required"}), 401
    
    # Bug: Returns all orders regardless of user
    return jsonify({"orders": list(ORDERS.values())})


# ============ ADMIN ENDPOINTS ============

@app.route("/admin")
def admin_panel():
    """
    EXPOSED_ADMIN_PANEL - accessible without proper auth check
    """
    current = get_current_user()
    
    # Weak check: just looks for any authenticated user
    # Should check for admin role but doesn't!
    
    return render_template_string("""
<!DOCTYPE html>
<html>
<head><title>Admin Panel</title></head>
<body>
    <h1>Admin Dashboard</h1>
    <p>Welcome to the admin panel!</p>
    <ul>
        <li><a href="/admin/users">Manage Users</a></li>
        <li><a href="/admin/orders">Manage Orders</a></li>
        <li><a href="/admin/config">System Config</a></li>
        <li><a href="/admin/logs">View Logs</a></li>
    </ul>
    <h3>System Info:</h3>
    <pre>
    Database: PostgreSQL 13.4
    Server: Python/Flask
    Environment: production
    Debug: enabled
    Secret Key: {{ secret }}
    </pre>
</body>
</html>
    """, secret=JWT_SECRET)


@app.route("/admin/users")
def admin_users():
    """
    Admin endpoint - should require admin role
    VERTICAL_PRIVILEGE_ESCALATION: Regular users can access
    """
    current = get_current_user()
    
    # Bug: No role check!
    return jsonify({
        "users": [
            {
                "id": u["id"],
                "username": u["username"],
                "email": u["email"],
                "role": u["role"],
                "api_key": u["api_key"]
            }
            for u in USERS.values()
        ]
    })


@app.route("/admin/config")
def admin_config():
    """Exposed configuration endpoint"""
    return jsonify({
        "database": {
            "host": "db.internal",
            "port": 5432,
            "username": "app_user",
            "password": "db_password_123"  # Exposed credentials!
        },
        "jwt_secret": JWT_SECRET,
        "api_keys": [u["api_key"] for u in USERS.values()],
        "debug": True
    })


# ============ PASSWORD RESET ============

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """
    Password reset with INSECURE_PASSWORD_RESET vulnerability
    Token is predictable: base64(user_id:timestamp)
    """
    if request.method == "GET":
        return render_template_string("""
<!DOCTYPE html>
<html>
<head><title>Forgot Password</title></head>
<body>
    <h1>Forgot Password</h1>
    <form method="POST">
        <input name="email" placeholder="Email"><br>
        <button type="submit">Reset Password</button>
    </form>
</body>
</html>
        """)
    
    data = request.get_json() if request.is_json else request.form
    email = data.get("email", "")
    
    # Find user by email
    user = None
    for u in USERS.values():
        if u["email"] == email:
            user = u
            break
    
    if not user:
        # USERNAME_ENUMERATION via password reset
        return jsonify({"error": "Email not found"}), 404
    
    # Generate predictable token
    token = generate_reset_token(user["id"])
    RESET_TOKENS[token] = user["id"]
    
    # In real app this would be emailed - here we just return it
    return jsonify({
        "success": True,
        "message": "Reset link sent",
        "debug_token": token,  # Exposed for testing
        "reset_url": f"/reset-password?token={token}"
    })


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    """Reset password with token"""
    token = request.args.get("token") or (request.get_json() or {}).get("token")
    
    if request.method == "GET":
        return render_template_string("""
<!DOCTYPE html>
<html>
<head><title>Reset Password</title></head>
<body>
    <h1>Reset Password</h1>
    <form method="POST">
        <input type="hidden" name="token" value="{{ token }}">
        <input name="password" type="password" placeholder="New Password"><br>
        <button type="submit">Reset</button>
    </form>
</body>
</html>
        """, token=token or "")
    
    data = request.get_json() if request.is_json else request.form
    token = data.get("token", token)
    new_password = data.get("password", "")
    
    if not token or token not in RESET_TOKENS:
        return jsonify({"error": "Invalid or expired token"}), 400
    
    user_id = RESET_TOKENS[token]
    if user_id in USERS:
        USERS[user_id]["password"] = new_password
        del RESET_TOKENS[token]
        return jsonify({"success": True, "message": "Password updated"})
    
    return jsonify({"error": "User not found"}), 404


# ============ SEARCH & MISC ============

@app.route("/api/search")
def search():
    """Search endpoint - also vulnerable to injection"""
    q = request.args.get("q", "")
    current = get_current_user()
    
    results = []
    for user in USERS.values():
        if q.lower() in user["username"].lower() or q.lower() in user["email"].lower():
            results.append({
                "id": user["id"],
                "username": user["username"],
                "email": user["email"]
            })
    
    return jsonify({"query": q, "results": results})


@app.route("/api/internal/debug")
def internal_debug():
    """Internal debug endpoint - should not be accessible"""
    return jsonify({
        "sessions": {k: v for k, v in SESSIONS.items()},
        "reset_tokens": {k: v for k, v in RESET_TOKENS.items()},
        "login_attempts": LOGIN_ATTEMPTS,
        "users": {uid: {"username": u["username"], "password": u["password"]} for uid, u in USERS.items()}
    })


@app.route("/health")
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "service": "auth_scan_lab"})


@app.route("/.well-known/security.txt")
def security_txt():
    """Security.txt with contact info"""
    return """Contact: security@example.com
Expires: 2025-12-31T23:59:59.000Z
Preferred-Languages: en
Canonical: https://example.com/.well-known/security.txt
"""


# Quick login helpers for testing
@app.route("/login/admin")
def quick_login_admin():
    """Quick login as admin for testing"""
    user = USERS[1]
    session_id = generate_session_id()
    SESSIONS[session_id] = user["id"]
    token = create_jwt(user)
    
    resp = make_response(jsonify({
        "user": {"id": user["id"], "username": user["username"], "role": user["role"]},
        "token": token,
        "session_id": session_id
    }))
    resp.set_cookie("session_id", session_id)
    resp.headers["X-Auth-Token"] = token
    return resp


@app.route("/login/alice")
def quick_login_alice():
    """Quick login as alice for testing"""
    user = USERS[2]
    session_id = generate_session_id()
    SESSIONS[session_id] = user["id"]
    token = create_jwt(user)
    
    resp = make_response(jsonify({
        "user": {"id": user["id"], "username": user["username"], "role": user["role"]},
        "token": token,
        "session_id": session_id
    }))
    resp.set_cookie("session_id", session_id)
    resp.headers["X-Auth-Token"] = token
    return resp


@app.route("/login/bob")
def quick_login_bob():
    """Quick login as bob for testing"""
    user = USERS[3]
    session_id = generate_session_id()
    SESSIONS[session_id] = user["id"]
    token = create_jwt(user)
    
    resp = make_response(jsonify({
        "user": {"id": user["id"], "username": user["username"], "role": user["role"]},
        "token": token,
        "session_id": session_id
    }))
    resp.set_cookie("session_id", session_id)
    resp.headers["X-Auth-Token"] = token
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

