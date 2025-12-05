#!/usr/bin/env python3
"""File Upload Lab - Vulnerable file upload for testing.

This intentionally vulnerable application demonstrates insecure file upload vulnerabilities:
- File type validation bypass (double extensions, MIME spoofing)
- Path traversal in filenames
- Executable file uploads
- Missing file size limits

DO NOT deploy this in production!
"""

import os
from flask import Flask, request, jsonify, render_template_string, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = '/app/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>File Upload Lab</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #333; }
        .form { margin: 20px 0; }
        input { width: 100%; padding: 10px; margin: 5px 0; }
        button { padding: 10px 20px; margin-top: 10px; }
        .result { background: #f5f5f5; padding: 15px; margin: 10px 0; }
        .error { background: #fee; color: #c00; padding: 15px; margin: 10px 0; }
        .success { background: #efe; color: #0c0; padding: 15px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>File Upload Lab</h1>
        {content}
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    content = """
        <p>This application contains intentional file upload vulnerabilities for testing.</p>
        <h2>Endpoints:</h2>
        <ul>
            <li><a href="/">Home</a> - This page</li>
            <li><a href="/upload">Upload File</a> - Vulnerable file upload</li>
            <li><a href="/uploads">List Uploads</a> - View uploaded files</li>
        </ul>
        <h2>File Upload Testing Lab</h2>
        <p>This lab contains intentional file upload vulnerabilities:</p>
        <ul>
            <li>File type validation bypass (double extensions: .php.jpg)</li>
            <li>MIME type spoofing</li>
            <li>Path traversal in filenames</li>
            <li>Executable file uploads</li>
        </ul>
        <p>Try uploading files with double extensions or path traversal in filename</p>
    """
    return BASE_TEMPLATE.replace('{content}', content)


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    """VULNERABLE: File upload with validation bypasses"""
    if request.method == 'GET':
        content = """
            <h2>Upload File</h2>
            <form method="POST" enctype="multipart/form-data">
                <div class="form">
                    <label>File:</label>
                    <input type="file" name="file">
                </div>
                <button type="submit">Upload</button>
            </form>
        """
        return BASE_TEMPLATE.replace('{content}', content)
    
    if 'file' not in request.files:
        return BASE_TEMPLATE.replace('{content}', '<div class="error">No file provided</div>')
    
    file = request.files['file']
    if file.filename == '':
        return BASE_TEMPLATE.replace('{content}', '<div class="error">No file selected</div>')
    
    filename = file.filename
    
    # VULNERABLE: Only basic filename sanitization, allows path traversal
    # secure_filename doesn't prevent all path traversal
    filename = secure_filename(filename)
    
    # VULNERABLE: No file type validation
    # VULNERABLE: No file size limit
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    content = f"""
        <div class="success">File uploaded successfully!</div>
        <div class="result">
            <strong>Filename:</strong> {filename}<br>
            <strong>Saved to:</strong> {filepath}<br>
            <strong>Access at:</strong> <a href="/uploads/{filename}">/uploads/{filename}</a>
        </div>
        <a href="/upload">Upload Another File</a>
    """
    return BASE_TEMPLATE.replace('{content}', content)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """Serve uploaded files"""
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        return f"Error serving file: {str(e)}", 404


@app.route('/uploads')
def list_uploads():
    """List all uploaded files"""
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    file_list = '\n'.join([f'<li><a href="/uploads/{f}">{f}</a></li>' for f in files])
    content = f"""
        <h2>Uploaded Files</h2>
        <ul>{file_list}</ul>
        <a href="/upload">Upload New File</a>
    """
    return BASE_TEMPLATE.replace('{content}', content)


@app.route('/api/upload', methods=['POST'])
def api_upload():
    """VULNERABLE: API endpoint for file upload"""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    return jsonify({
        "success": True,
        "filename": filename,
        "path": filepath,
        "url": f"/uploads/{filename}"
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

