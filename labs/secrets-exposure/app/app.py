#!/usr/bin/env python3
"""Secrets Exposure Lab - Vulnerable application with exposed secrets.

This intentionally vulnerable application demonstrates:
- Exposed .env file with credentials
- Hardcoded API keys in JavaScript
- Exposed backup files
- Exposed .git directory

DO NOT deploy this in production!
"""

from flask import Flask, send_from_directory, render_template_string
import os

app = Flask(__name__, static_folder='static')

# Simulated sensitive files content
ENV_CONTENT = """# Production Environment Configuration
# DO NOT COMMIT THIS FILE!

DATABASE_URL=postgres://admin:SuperSecret123!@db.internal.example.com:5432/production
REDIS_URL=redis://:RedisPass456@cache.internal.example.com:6379/0

# API Keys
STRIPE_SECRET_KEY=sk_live_51ABC123DEF456GHI789JKL
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Third-party services
SENDGRID_API_KEY=SG.abcdefghijklmnop.qrstuvwxyz123456789
TWILIO_AUTH_TOKEN=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6

# Internal secrets
JWT_SECRET=my-super-secret-jwt-key-that-should-not-be-exposed
ADMIN_PASSWORD=admin123!
"""

BACKUP_CONTENT = """-- Database Backup
-- Generated: 2024-01-15

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50),
    email VARCHAR(100),
    password_hash VARCHAR(255),
    ssn VARCHAR(11)
);

INSERT INTO users VALUES (1, 'admin', 'admin@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4p', '123-45-6789');
INSERT INTO users VALUES (2, 'alice', 'alice@example.com', '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36', '987-65-4321');

CREATE TABLE credit_cards (
    id SERIAL PRIMARY KEY,
    user_id INT,
    card_number VARCHAR(20),
    cvv VARCHAR(4),
    expiry VARCHAR(10)
);

INSERT INTO credit_cards VALUES (1, 1, '4111111111111111', '123', '12/25');
INSERT INTO credit_cards VALUES (2, 2, '5500000000000004', '456', '03/26');
"""

GIT_CONFIG = """[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = true
[remote "origin"]
    url = https://github.com/company/internal-app.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[user]
    name = Developer
    email = dev@company.com
[credential]
    helper = store
"""


@app.route('/')
def home():
    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
    <title>Secrets Lab</title>
    <script src="/static/config.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .container {{ max-width: 800px; margin: 0 auto; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to Our App</h1>
        <p>This is a simple web application.</p>
        <p id="api-status">Checking API status...</p>
    </div>
    <script>
        // Using the API key from config.js
        document.getElementById('api-status').textContent = 
            'API Key loaded: ' + (window.API_CONFIG ? 'Yes' : 'No');
    </script>
</body>
</html>
    """)


@app.route('/.env')
def env_file():
    """VULNERABLE: Exposed .env file with credentials."""
    return ENV_CONTENT, 200, {'Content-Type': 'text/plain'}


@app.route('/backup.sql')
def backup_file():
    """VULNERABLE: Exposed database backup."""
    return BACKUP_CONTENT, 200, {'Content-Type': 'text/plain'}


@app.route('/.git/config')
def git_config():
    """VULNERABLE: Exposed .git configuration."""
    return GIT_CONFIG, 200, {'Content-Type': 'text/plain'}


@app.route('/.git/HEAD')
def git_head():
    """VULNERABLE: Exposed .git HEAD."""
    return "ref: refs/heads/main\n", 200, {'Content-Type': 'text/plain'}


@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

