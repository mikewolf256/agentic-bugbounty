#!/usr/bin/env python3
"""Deserialization Lab - Vulnerable deserialization for testing.

This intentionally vulnerable application demonstrates deserialization vulnerabilities:
- Python pickle deserialization RCE
- YAML deserialization
- JSON deserialization issues

DO NOT deploy this in production!
"""

from flask import Flask, request, jsonify
import pickle
import yaml
import json
import base64

app = Flask(__name__)

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Deserialization Lab</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .container {{ max-width: 800px; margin: 0 auto; }}
        h1 {{ color: #333; }}
        .form {{ margin: 20px 0; }}
        textarea {{ width: 100%; height: 200px; padding: 10px; }}
        button {{ padding: 10px 20px; margin-top: 10px; }}
        .result {{ background: #f5f5f5; padding: 15px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Deserialization Lab</h1>
        {content}
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    content = """
        <h2>Deserialization Testing Lab</h2>
        <p>This lab contains intentional deserialization vulnerabilities:</p>
        <ul>
            <li><a href="/pickle">Pickle Deserialize</a> - Python pickle RCE</li>
            <li><a href="/yaml">YAML Deserialize</a> - YAML deserialization</li>
            <li><a href="/api/deserialize">Deserialize API</a> - API endpoint</li>
        </ul>
    """
    return BASE_TEMPLATE.format(content=content)


@app.route('/pickle', methods=['GET', 'POST'])
def pickle_deserialize():
    """VULNERABLE: Python pickle deserialization"""
    if request.method == 'GET':
        content = """
            <h2>Pickle Deserialize</h2>
            <form method="POST">
                <div class="form">
                    <label>Pickle Data (base64):</label>
                    <textarea name="data" placeholder="Base64 encoded pickle data"></textarea>
                </div>
                <button type="submit">Deserialize</button>
            </form>
        """
        return BASE_TEMPLATE.format(content=content)
    
    # VULNERABLE: Deserialize user-provided pickle data
    data = request.form.get('data', '')
    
    if not data:
        return BASE_TEMPLATE.format(content="<div class='result'>No data provided</div>")
    
    try:
        # VULNERABLE: Direct pickle deserialization
        pickle_data = base64.b64decode(data)
        obj = pickle.loads(pickle_data)
        
        content = f"""
            <h2>Deserialized Object</h2>
            <div class="result">
                <p>Type: {type(obj).__name__}</p>
                <p>Value: {str(obj)}</p>
            </div>
        """
        return BASE_TEMPLATE.format(content=content)
    except Exception as e:
        error_content = f"""
            <h2>Deserialization Error</h2>
            <div class="result">
                <strong>Error:</strong> {str(e)}
            </div>
        """
        return BASE_TEMPLATE.format(content=error_content)


@app.route('/yaml', methods=['GET', 'POST'])
def yaml_deserialize():
    """VULNERABLE: YAML deserialization"""
    if request.method == 'GET':
        content = """
            <h2>YAML Deserialize</h2>
            <form method="POST">
                <div class="form">
                    <label>YAML Data:</label>
                    <textarea name="data" placeholder='name: test
value: 123'></textarea>
                </div>
                <button type="submit">Deserialize</button>
            </form>
        """
        return BASE_TEMPLATE.format(content=content)
    
    # VULNERABLE: YAML deserialization with unsafe loader
    data = request.form.get('data', '')
    
    if not data:
        return BASE_TEMPLATE.format(content="<div class='result'>No data provided</div>")
    
    try:
        # VULNERABLE: Using unsafe YAML loader
        obj = yaml.load(data, Loader=yaml.Loader)  # Unsafe!
        
        content = f"""
            <h2>Deserialized YAML</h2>
            <div class="result">
                <pre>{json.dumps(obj, indent=2)}</pre>
            </div>
        """
        return BASE_TEMPLATE.format(content=content)
    except Exception as e:
        error_content = f"""
            <h2>Deserialization Error</h2>
            <div class="result">
                <strong>Error:</strong> {str(e)}
            </div>
        """
        return BASE_TEMPLATE.format(content=error_content)


@app.route('/api/deserialize', methods=['POST'])
def api_deserialize():
    """VULNERABLE: API endpoint for deserialization"""
    data = request.get_json() or {}
    format_type = data.get('format', 'pickle')
    payload = data.get('data', '')
    
    if not payload:
        return jsonify({"error": "No data provided"}), 400
    
    try:
        if format_type == 'pickle':
            # VULNERABLE: Pickle deserialization
            pickle_data = base64.b64decode(payload)
            obj = pickle.loads(pickle_data)
            return jsonify({
                "success": True,
                "type": type(obj).__name__,
                "value": str(obj)
            })
        elif format_type == 'yaml':
            # VULNERABLE: YAML deserialization
            obj = yaml.load(payload, Loader=yaml.Loader)
            return jsonify({
                "success": True,
                "data": obj
            })
        else:
            return jsonify({"error": "Unsupported format"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

