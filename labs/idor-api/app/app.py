#!/usr/bin/env python3
"""IDOR API Lab - Vulnerable REST API for testing IDOR/BOLA detection.

This intentionally vulnerable API demonstrates:
- Horizontal IDOR on user profiles
- Horizontal IDOR on documents
- Missing authentication on admin endpoints

DO NOT deploy this in production!
"""

from flask import Flask, request, jsonify

app = Flask(__name__)

# Simulated database
USERS = {
    1: {"id": 1, "username": "alice", "email": "alice@example.com", "role": "user", "ssn": "123-45-6789"},
    2: {"id": 2, "username": "bob", "email": "bob@example.com", "role": "user", "ssn": "987-65-4321"},
    3: {"id": 3, "username": "charlie", "email": "charlie@example.com", "role": "admin", "ssn": "555-55-5555"},
}

DOCUMENTS = {
    1: {"id": 1, "owner_id": 1, "title": "Alice's Secret Doc", "content": "Alice's confidential information"},
    2: {"id": 2, "owner_id": 1, "title": "Alice's Tax Return", "content": "Alice's financial data"},
    3: {"id": 3, "owner_id": 2, "title": "Bob's Private Notes", "content": "Bob's personal notes"},
    4: {"id": 4, "owner_id": 3, "title": "Admin Report", "content": "Sensitive admin report"},
}

# Simulated tokens (user_id -> token)
TOKENS = {
    "user1_token_abc123": 1,
    "user2_token_def456": 2,
    "admin_token_xyz789": 3,
}


def get_current_user_id():
    """Get user ID from Authorization header (simplified)."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        return TOKENS.get(token)
    return None


@app.route('/')
def home():
    return jsonify({
        "name": "IDOR Lab API",
        "version": "1.0",
        "endpoints": [
            {"path": "/api/users/{id}", "method": "GET", "description": "Get user profile"},
            {"path": "/api/documents/{id}", "method": "GET", "description": "Get document"},
            {"path": "/api/admin/users", "method": "GET", "description": "List all users (admin)"},
        ],
        "test_token": "user1_token_abc123"
    })


@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """VULNERABLE: No authorization check - any user can access any profile."""
    # Should check: current_user_id == user_id
    # But we don't, causing IDOR
    
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Returning sensitive data without authorization
    return jsonify(user)


@app.route('/api/documents/<int:doc_id>', methods=['GET'])
def get_document(doc_id):
    """VULNERABLE: No authorization check - any user can access any document."""
    # Should check: current_user_id == document.owner_id
    # But we don't, causing IDOR
    
    doc = DOCUMENTS.get(doc_id)
    if not doc:
        return jsonify({"error": "Document not found"}), 404
    
    # Returning document without checking ownership
    return jsonify(doc)


@app.route('/api/admin/users', methods=['GET'])
def admin_list_users():
    """VULNERABLE: No authentication required for admin endpoint."""
    # Should check: current_user.role == 'admin'
    # But we don't check anything, allowing unauthenticated access
    
    # Return all users (sensitive data exposure)
    return jsonify({
        "users": list(USERS.values()),
        "total": len(USERS)
    })


@app.route('/api/me', methods=['GET'])
def get_current_user():
    """Get current user's profile (authenticated endpoint for comparison)."""
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify(user)


@app.route('/api/my-documents', methods=['GET'])
def get_my_documents():
    """Get current user's documents (authenticated endpoint for comparison)."""
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    user_docs = [doc for doc in DOCUMENTS.values() if doc["owner_id"] == user_id]
    return jsonify({"documents": user_docs})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

