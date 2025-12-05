#!/usr/bin/env python3
"""WebSocket Security Lab - Vulnerable WebSocket endpoints for testing.

This intentionally vulnerable application demonstrates WebSocket security vulnerabilities:
- Missing authentication on WebSocket connections
- Message injection (XSS via WebSocket)
- Missing origin validation
- Subprotocol negotiation issues

DO NOT deploy this in production!
"""

from flask import Flask, request, render_template_string
from flask_socketio import SocketIO, emit, disconnect
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'insecure-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")  # VULNERABLE: Allows all origins

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>WebSocket Security Lab</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #333; }
        #messages { height: 300px; overflow-y: scroll; border: 1px solid #ccc; padding: 10px; margin: 10px 0; }
        input { width: 70%; padding: 10px; }
        button { padding: 10px 20px; }
    </style>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
</head>
<body>
    <div class="container">
        <h1>WebSocket Security Lab</h1>
        {content}
        <div id="messages"></div>
        <input type="text" id="messageInput" placeholder="Type a message...">
        <button onclick="sendMessage()">Send</button>
    </div>
    <script>
        const socket = io();
        const messagesDiv = document.getElementById('messages');
        
        socket.on('message', function(data) {
            const msg = document.createElement('div');
            msg.innerHTML = data.message;  // VULNERABLE: XSS via WebSocket
            messagesDiv.appendChild(msg);
        });
        
        function sendMessage() {
            const input = document.getElementById('messageInput');
            socket.emit('message', {message: input.value});
            input.value = '';
        }
    </script>
</body>
</html>
"""

@app.route('/')
def home():
    content = """
        <p>This application contains intentional WebSocket security vulnerabilities for testing.</p>
        <h2>WebSocket Testing Lab</h2>
        <p>This lab contains intentional WebSocket vulnerabilities:</p>
        <ul>
            <li>Missing authentication on WebSocket connections</li>
            <li>Message injection (XSS via WebSocket)</li>
            <li>Missing origin validation</li>
        </ul>
        <p>Connect to WebSocket and try sending: <code>&lt;script&gt;alert(1)&lt;/script&gt;</code></p>
    """
    return BASE_TEMPLATE.replace('{content}', content)


@socketio.on('connect')
def handle_connect():
    """VULNERABLE: No authentication required"""
    # VULNERABLE: No origin validation
    # VULNERABLE: No authentication check
    emit('message', {'message': 'Connected to WebSocket'})
    print(f"Client connected: {request.sid}")


@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")


@socketio.on('message')
def handle_message(data):
    """VULNERABLE: Message injection without sanitization"""
    message = data.get('message', '')
    
    # VULNERABLE: Message broadcasted without sanitization
    # This allows XSS injection via WebSocket messages
    socketio.emit('message', {'message': message})
    print(f"Message received: {message}")


@socketio.on('chat')
def handle_chat(data):
    """VULNERABLE: Chat endpoint with message injection"""
    message = data.get('message', '')
    username = data.get('username', 'Anonymous')
    
    # VULNERABLE: No sanitization
    socketio.emit('message', {
        'message': f'<strong>{username}:</strong> {message}'
    })


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)

