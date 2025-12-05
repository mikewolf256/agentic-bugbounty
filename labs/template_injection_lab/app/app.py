#!/usr/bin/env python3
"""Template Injection Lab - Vulnerable template rendering for SSTI testing.

This intentionally vulnerable application demonstrates SSTI vulnerabilities:
- Jinja2 template injection
- Unsafe template rendering

DO NOT deploy this in production!
"""

from flask import Flask, request, render_template_string, jsonify
from jinja2 import Template

app = Flask(__name__)

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Template Injection Lab</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .container {{ max-width: 800px; margin: 0 auto; }}
        h1 {{ color: #333; }}
        .form {{ margin: 20px 0; }}
        input, textarea {{ width: 100%; padding: 8px; margin: 5px 0; }}
        button {{ padding: 10px 20px; margin-top: 10px; }}
        .result {{ background: #f5f5f5; padding: 15px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Template Injection Lab</h1>
        {content}
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    content = """
        <h2>SSTI Testing Lab</h2>
        <p>This lab contains intentional template injection vulnerabilities:</p>
        <ul>
            <li><a href="/render">Render Template</a> - Jinja2 template injection</li>
            <li><a href="/search">Search</a> - Template in search results</li>
            <li><a href="/api/render">Render API</a> - API endpoint with SSTI</li>
        </ul>
    """
    return BASE_TEMPLATE.format(content=content)


@app.route('/render', methods=['GET', 'POST'])
def render_template():
    """VULNERABLE: Jinja2 template injection"""
    if request.method == 'GET':
        content = """
            <h2>Render Template</h2>
            <form method="POST">
                <div class="form">
                    <label>Template:</label>
                    <textarea name="template" placeholder="Hello {{ name }}">Hello {{ name }}</textarea>
                    <label>Name:</label>
                    <input type="text" name="name" value="World">
                </div>
                <button type="submit">Render</button>
            </form>
        """
        return BASE_TEMPLATE.format(content=content)
    
    # VULNERABLE: Direct template rendering without sanitization
    template_str = request.form.get('template', 'Hello {{ name }}')
    name = request.form.get('name', 'World')
    
    try:
        # VULNERABLE: render_template_string with user input
        rendered = render_template_string(template_str, name=name)
        
        content = f"""
            <h2>Rendered Template</h2>
            <div class="result">
                <h3>Result:</h3>
                <pre>{rendered}</pre>
            </div>
            <p><a href="/render">Render another template</a></p>
        """
        return BASE_TEMPLATE.format(content=content)
    except Exception as e:
        error_content = f"""
            <h2>Render Error</h2>
            <div class="result">
                <strong>Error:</strong> {str(e)}
            </div>
            <p><a href="/render">Try again</a></p>
        """
        return BASE_TEMPLATE.format(content=error_content)


@app.route('/search')
def search():
    """VULNERABLE: Template injection in search results"""
    query = request.args.get('q', '')
    
    if not query:
        content = """
            <h2>Search</h2>
            <form method="GET">
                <div class="form">
                    <input type="text" name="q" placeholder="Search...">
                </div>
                <button type="submit">Search</button>
            </form>
        """
        return BASE_TEMPLATE.format(content=content)
    
    # VULNERABLE: User input directly in template
    template_str = f"<h2>Search Results for: {query}</h2><p>No results found for '{{{{ query }}}}'</p>"
    
    try:
        rendered = render_template_string(template_str, query=query)
        
        content = f"""
            <div class="result">
                {rendered}
            </div>
            <p><a href="/search">New search</a></p>
        """
        return BASE_TEMPLATE.format(content=content)
    except Exception as e:
        return BASE_TEMPLATE.format(content=f"<div class='result'>Error: {str(e)}</div>")


@app.route('/api/render', methods=['POST'])
def api_render():
    """VULNERABLE: API endpoint with template injection"""
    data = request.get_json() or {}
    template_str = data.get('template', 'Hello {{ name }}')
    context = data.get('context', {})
    
    try:
        # VULNERABLE: Template rendering with user input
        template = Template(template_str)
        rendered = template.render(**context)
        
        return jsonify({
            "success": True,
            "rendered": rendered
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

