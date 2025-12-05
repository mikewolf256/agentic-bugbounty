#!/usr/bin/env python3
"""Cloud Lab - Mock cloud metadata endpoints for testing cloud vulnerability detection.

This intentionally vulnerable application simulates cloud metadata endpoints:
- AWS metadata endpoints (169.254.169.254)
- GCP metadata endpoints
- Azure metadata endpoints
- Storage bucket misconfigurations
- IAM credential exposure

DO NOT deploy this in production!
"""

from flask import Flask, request, jsonify

app = Flask(__name__)

# Mock credentials (for testing only)
MOCK_AWS_CREDENTIALS = {
    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "Token": "mock-token-12345"
}

MOCK_GCP_CREDENTIALS = {
    "access_token": "ya29.mock-gcp-token",
    "expires_in": 3600
}

MOCK_AZURE_CREDENTIALS = {
    "access_token": "mock-azure-token",
    "client_id": "mock-client-id"
}

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Cloud Metadata Lab</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .container {{ max-width: 800px; margin: 0 auto; }}
        h1 {{ color: #333; }}
        .result {{ background: #f5f5f5; padding: 15px; margin: 10px 0; }}
        pre {{ background: #fff; padding: 10px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Cloud Metadata Lab</h1>
        {content}
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    content = """
        <h2>Cloud Metadata Testing Lab</h2>
        <p>This lab simulates cloud metadata endpoints:</p>
        <ul>
            <li><a href="/latest/meta-data/">AWS Metadata</a></li>
            <li><a href="/computeMetadata/v1/">GCP Metadata</a></li>
            <li><a href="/metadata/instance">Azure Metadata</a></li>
            <li><a href="/s3/bucket">S3 Bucket</a></li>
        </ul>
        <p>Accessible via SSRF or direct access</p>
    """
    return BASE_TEMPLATE.format(content=content)


# AWS Metadata Endpoints
@app.route('/latest/meta-data/')
def aws_metadata_root():
    """AWS metadata root"""
    return """ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
hostname
iam/
instance-id
instance-type
local-hostname
local-ipv4
mac
metrics/
network/
placement/
profile
public-hostname
public-ipv4
public-keys/
reservation-id
security-groups
services/"""


@app.route('/latest/meta-data/iam/security-credentials/')
def aws_iam_roles():
    """AWS IAM roles"""
    return "test-role"


@app.route('/latest/meta-data/iam/security-credentials/<role>')
def aws_iam_credentials(role):
    """VULNERABLE: AWS IAM credentials exposure"""
    return jsonify(MOCK_AWS_CREDENTIALS)


@app.route('/latest/meta-data/instance-id')
def aws_instance_id():
    """AWS instance ID"""
    return "i-1234567890abcdef0"


@app.route('/latest/meta-data/ami-id')
def aws_ami_id():
    """AWS AMI ID"""
    return "ami-12345678"


@app.route('/latest/user-data')
def aws_user_data():
    """AWS user data"""
    return "#!/bin/bash\necho 'User data script'"


# GCP Metadata Endpoints
@app.route('/computeMetadata/v1/')
def gcp_metadata_root():
    """GCP metadata root"""
    return """instance/
project/"""


@app.route('/computeMetadata/v1/instance/')
def gcp_instance_root():
    """GCP instance metadata root"""
    return """id
name
zone
machine-type
network-interfaces/"""


@app.route('/computeMetadata/v1/instance/service-accounts/')
def gcp_service_accounts():
    """GCP service accounts"""
    return "default/\n"


@app.route('/computeMetadata/v1/instance/service-accounts/default/token')
def gcp_access_token():
    """VULNERABLE: GCP access token exposure"""
    return jsonify(MOCK_GCP_CREDENTIALS)


# Azure Metadata Endpoints
@app.route('/metadata/instance')
def azure_metadata():
    """Azure metadata endpoint"""
    headers = {'Metadata': 'true'}  # Azure requires this header
    if request.headers.get('Metadata') != 'true':
        return jsonify({"error": "Missing Metadata header"}), 400
    
    return jsonify({
        "compute": {
            "vmId": "mock-vm-id",
            "subscriptionId": "mock-subscription-id",
            "resourceGroupName": "mock-resource-group"
        }
    })


@app.route('/metadata/identity/oauth2/token')
def azure_token():
    """VULNERABLE: Azure token endpoint"""
    if request.headers.get('Metadata') != 'true':
        return jsonify({"error": "Missing Metadata header"}), 400
    
    return jsonify(MOCK_AZURE_CREDENTIALS)


# S3 Bucket Simulation
@app.route('/s3/bucket')
def s3_bucket():
    """VULNERABLE: Mock S3 bucket (publicly accessible)"""
    return jsonify({
        "name": "test-bucket",
        "public": True,
        "files": [
            {"name": "config.json", "size": 1024},
            {"name": "backup.sql", "size": 2048}
        ]
    })


@app.route('/s3/bucket/<path:file_path>')
def s3_file(file_path):
    """VULNERABLE: Mock S3 file access"""
    if file_path == "config.json":
        return jsonify({
            "database": {
                "host": "db.example.com",
                "password": "insecure_password"
            }
        })
    return jsonify({"error": "File not found"}), 404


# SSRF endpoint for testing
@app.route('/fetch')
def fetch_url():
    """VULNERABLE: SSRF endpoint that fetches URLs"""
    url = request.args.get('url', '')
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    try:
        import requests
        resp = requests.get(url, timeout=5)
        return jsonify({
            "url": url,
            "status_code": resp.status_code,
            "content": resp.text[:1000]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

