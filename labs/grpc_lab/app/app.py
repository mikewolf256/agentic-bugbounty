#!/usr/bin/env python3
"""gRPC Lab - Vulnerable gRPC service for testing.

This intentionally vulnerable application demonstrates gRPC vulnerabilities:
- Unauthenticated endpoints
- Service enumeration
- Sensitive data exposure

DO NOT deploy this in production!
"""

from flask import Flask
import grpc
from concurrent import futures
import sys
import os

# Add app directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))

# These will be imported after proto generation
user_pb2 = None
user_pb2_grpc = None

app = Flask(__name__)

# Mock user data
USERS = {
    1: {"id": 1, "name": "Alice", "email": "alice@example.com", "api_key": "ak_alice_123", "secret": "secret123"},
    2: {"id": 2, "name": "Bob", "email": "bob@example.com", "api_key": "ak_bob_456", "secret": "secret456"},
}

def create_user_service():
    """Create UserService class after gRPC code is generated"""
    class UserServiceImpl(user_pb2_grpc.UserServiceServicer):
        """VULNERABLE: gRPC service without authentication"""
        
        def GetUser(self, request, context):
            """VULNERABLE: No authentication check"""
            user_id = request.user_id
            user = USERS.get(user_id)
            
            if user:
                return user_pb2.UserResponse(
                    id=user['id'],
                    name=user['name'],
                    email=user['email']
                )
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details('User not found')
            return user_pb2.UserResponse()
        
        def ListUsers(self, request, context):
            """VULNERABLE: No authentication, no rate limiting"""
            limit = request.limit if request.limit > 0 else 100
            
            users = []
            for user in list(USERS.values())[:limit]:
                users.append(user_pb2.UserResponse(
                    id=user['id'],
                    name=user['name'],
                    email=user['email']
                ))
            
            return user_pb2.ListUsersResponse(users=users)
        
        def GetUserData(self, request, context):
            """VULNERABLE: Exposes sensitive data without auth"""
            user_id = request.user_id
            user = USERS.get(user_id)
            
            if user:
                # VULNERABLE: Exposes API keys and secrets
                return user_pb2.UserDataResponse(
                    id=user['id'],
                    name=user['name'],
                    email=user['email'],
                    api_key=user['api_key'],
                    secret=user['secret']
                )
            context.set_code(grpc.StatusCode.NOT_FOUND)
            return user_pb2.UserDataResponse()
    
    return UserServiceImpl


def serve_grpc():
    """Start gRPC server"""
    if user_pb2_grpc is None:
        print("Error: gRPC code not generated")
        return
    
    UserServiceImpl = create_user_service()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    user_pb2_grpc.add_UserServiceServicer_to_server(UserServiceImpl(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    print("gRPC server started on port 50051")
    server.wait_for_termination()


BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>gRPC Lab</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .container {{ max-width: 800px; margin: 0 auto; }}
        h1 {{ color: #333; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>gRPC Lab</h1>
        {content}
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    content = """
        <h2>gRPC Testing Lab</h2>
        <p>This lab contains intentional gRPC vulnerabilities:</p>
        <ul>
            <li>Unauthenticated gRPC endpoints</li>
            <li>Service enumeration</li>
            <li>Sensitive data exposure (API keys, secrets)</li>
        </ul>
        <h3>gRPC Endpoint:</h3>
        <p><code>grpc_lab:50051</code></p>
        <h3>Services:</h3>
        <ul>
            <li><code>UserService.GetUser</code> - Get user by ID (no auth)</li>
            <li><code>UserService.ListUsers</code> - List all users (no auth)</li>
            <li><code>UserService.GetUserData</code> - Get user data with secrets (no auth)</li>
        </ul>
        <p>Use <code>grpcurl</code> to test:</p>
        <pre>
grpcurl -plaintext grpc_lab:50051 list
grpcurl -plaintext grpc_lab:50051 user.UserService.GetUser
        </pre>
    """
    return BASE_TEMPLATE.format(content=content)


if __name__ == '__main__':
    import threading
    
    # Try to import generated gRPC code
    try:
        import user_pb2
        import user_pb2_grpc
    except ImportError:
        # Generate gRPC code from proto file if not already generated
        proto_dir = os.path.join(os.path.dirname(__file__), 'proto')
        proto_file = os.path.join(proto_dir, 'user.proto')
        
        if os.path.exists(proto_file):
            import subprocess
            try:
                subprocess.run([
                    'python', '-m', 'grpc_tools.protoc',
                    '-I', proto_dir,
                    '--python_out=.',
                    '--grpc_python_out=.',
                    proto_file
                ], check=True, cwd=os.path.dirname(__file__))
                # Re-import after generation
                import user_pb2
                import user_pb2_grpc
            except Exception as e:
                print(f"Error: Could not generate gRPC code: {e}")
                print("gRPC server will not start")
                sys.exit(1)
        else:
            print("Error: Proto file not found")
            sys.exit(1)
    
    # Update global variables
    globals()['user_pb2'] = user_pb2
    globals()['user_pb2_grpc'] = user_pb2_grpc
    
    # Start gRPC server in background thread
    grpc_thread = threading.Thread(target=serve_grpc, daemon=True)
    grpc_thread.start()
    
    # Start Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)
