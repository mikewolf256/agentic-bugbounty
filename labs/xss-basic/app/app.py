#!/usr/bin/env python3
"""XSS Basic Lab - Vulnerable Flask application for testing XSS detection.

This intentionally vulnerable application demonstrates common XSS patterns:
- Reflected XSS via search parameter
- Error page XSS
- Profile name XSS

DO NOT deploy this in production!
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

# Base HTML template
BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>XSS Lab - {title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .container {{ max-width: 800px; margin: 0 auto; }}
        h1 {{ color: #333; }}
        .search-box { padding: 10px; margin: 20px 0; }}
        input[type="text"] { padding: 8px; width: 300px; }}
        button {{ padding: 8px 16px; }}
        .result {{ background: #f5f5f5; padding: 15px; margin: 10px 0; }}
        .error {{ background: #fee; color: #c00; padding: 15px; margin: 10px 0; }}
        nav { margin-bottom: 30px; }}
        nav a { margin-right: 15px; color: #0066cc; }}
    </style>
</head>
<body>
    <div class="container">
        <nav>
            <a href="/">Home</a>
            <a href="/search">Search</a>
            <a href="/profile?name=Guest">Profile</a>
        </nav>
        {content}
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    content = """
        <h1>XSS Basic Lab</h1>
        <p>Welcome to the XSS testing lab. This application contains intentional XSS vulnerabilities.</p>
        <h2>Endpoints:</h2>
        <ul>
            <li><a href="/search?q=test">Search</a> - Reflected XSS via query parameter</li>
            <li><a href="/error?msg=Something%20went%20wrong">Error</a> - XSS in error messages</li>
            <li><a href="/profile?name=John">Profile</a> - XSS in user profile display</li>
        </ul>
    """
    return render_template_string(BASE_TEMPLATE.format(title="Home", content=content))


@app.route('/search')
def search():
    # VULNERABLE: Direct reflection of user input
    query = request.args.get('q', '')
    
    if query:
        # Intentionally vulnerable - no escaping
        results = f"""
            <h1>Search Results</h1>
            <div class="search-box">
                <form>
                    <input type="text" name="q" value="{query}" placeholder="Search...">
                    <button type="submit">Search</button>
                </form>
            </div>
            <div class="result">
                <p>You searched for: {query}</p>
                <p>No results found for "{query}"</p>
            </div>
        """
    else:
        results = """
            <h1>Search</h1>
            <div class="search-box">
                <form>
                    <input type="text" name="q" placeholder="Search...">
                    <button type="submit">Search</button>
                </form>
            </div>
        """
    
    return render_template_string(BASE_TEMPLATE.format(title="Search", content=results))


@app.route('/error')
def error_page():
    # VULNERABLE: Error message reflection
    msg = request.args.get('msg', 'An error occurred')
    
    # Intentionally vulnerable - no escaping
    content = f"""
        <h1>Error</h1>
        <div class="error">
            <strong>Error:</strong> {msg}
        </div>
        <p><a href="/">Return to home</a></p>
    """
    
    return render_template_string(BASE_TEMPLATE.format(title="Error", content=content))


@app.route('/profile')
def profile():
    # VULNERABLE: User name reflection
    name = request.args.get('name', 'Guest')
    
    # Intentionally vulnerable - no escaping
    content = f"""
        <h1>User Profile</h1>
        <div class="result">
            <p><strong>Name:</strong> {name}</p>
            <p><strong>Welcome, {name}!</strong></p>
        </div>
        <p>Edit your profile: <a href="/profile?name={name}">{name}'s profile</a></p>
    """
    
    return render_template_string(BASE_TEMPLATE.format(title=f"Profile - {name}", content=content))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

