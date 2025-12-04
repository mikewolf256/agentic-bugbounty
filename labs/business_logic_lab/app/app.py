#!/usr/bin/env python3
"""Business Logic Lab - E-commerce-like app with intentional business logic flaws.

This intentionally vulnerable application demonstrates business logic vulnerabilities:
- Pricing manipulation (negative prices, quantity manipulation)
- Workflow bypasses (skipping checkout steps)
- Rate limit bypasses
- State transition vulnerabilities

DO NOT deploy this in production!
"""

from flask import Flask, request, jsonify, session, redirect, url_for
import json

app = Flask(__name__)
app.secret_key = 'insecure_secret_key_for_testing'

# In-memory database
CART = {}
ORDERS = {}
USERS = {
    "user1": {"id": 1, "balance": 100.0},
    "user2": {"id": 2, "balance": 50.0}
}
RATE_LIMIT = {}  # Simple rate limiting (vulnerable)

BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Business Logic Lab</title>
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
        <h1>Business Logic Lab</h1>
        {content}
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    content = """
        <h2>E-Commerce Testing Lab</h2>
        <p>This lab contains intentional business logic vulnerabilities:</p>
        <ul>
            <li><a href="/cart">Cart</a> - Pricing manipulation</li>
            <li><a href="/checkout">Checkout</a> - Workflow bypasses</li>
            <li><a href="/api/purchase">Purchase API</a> - Direct purchase endpoint</li>
            <li><a href="/api/rate-limit">Rate Limit Test</a> - Rate limit bypass</li>
        </ul>
    """
    return BASE_TEMPLATE.replace("{content}", content)


@app.route('/cart', methods=['GET', 'POST'])
def cart():
    """VULNERABLE: Pricing manipulation"""
    if request.method == 'GET':
        content = """
            <h2>Add to Cart</h2>
            <form method="POST">
                <div class="form">
                    <label>Item ID:</label>
                    <input type="text" name="item_id" value="1">
                    <label>Price:</label>
                    <input type="number" name="price" value="10.00" step="0.01">
                    <label>Quantity:</label>
                    <input type="number" name="quantity" value="1">
                </div>
                <button type="submit">Add to Cart</button>
            </form>
        """
        return BASE_TEMPLATE.replace("{content}", content)
    
    # VULNERABLE: Accepts user-provided price without validation
    item_id = request.form.get('item_id', '1')
    price = float(request.form.get('price', '10.0'))  # No validation!
    quantity = int(request.form.get('quantity', '1'))
    
    # Store in cart
    cart_id = session.get('cart_id', 'default')
    if cart_id not in CART:
        CART[cart_id] = []
    
    CART[cart_id].append({
        'item_id': item_id,
        'price': price,  # VULNERABLE: User can set any price
        'quantity': quantity
    })
    
    total = sum(item['price'] * item['quantity'] for item in CART[cart_id])
    
    content = f"""
        <h2>Cart Updated</h2>
        <div class="result">
            <p>Item {item_id} added: ${price} x {quantity}</p>
            <p><strong>Total: ${total:.2f}</strong></p>
        </div>
        <p><a href="/cart">Add more items</a> | <a href="/checkout">Checkout</a></p>
    """
    return BASE_TEMPLATE.replace("{content}", content)


@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    """VULNERABLE: Workflow bypass - can skip steps"""
    if request.method == 'GET':
        cart_id = session.get('cart_id', 'default')
        items = CART.get(cart_id, [])
        
        if not items:
            return redirect('/cart')
        
        total = sum(item['price'] * item['quantity'] for item in items)
        
        content = f"""
            <h2>Checkout</h2>
            <div class="result">
                <h3>Order Summary:</h3>
                <p>Items: {len(items)}</p>
                <p><strong>Total: ${total:.2f}</strong></p>
            </div>
            <form method="POST">
                <input type="hidden" name="step" value="payment">
                <button type="submit">Proceed to Payment</button>
            </form>
            <p><a href="/api/complete-order?skip_payment=true">Skip Payment (Direct)</a></p>
        """
        return BASE_TEMPLATE.replace("{content}", content)
    
    # VULNERABLE: Can skip payment step
    step = request.form.get('step', 'payment')
    skip_payment = request.args.get('skip_payment') == 'true'
    
    if skip_payment or step == 'complete':
        # VULNERABLE: Can complete order without payment
        order_id = len(ORDERS) + 1
        cart_id = session.get('cart_id', 'default')
        items = CART.get(cart_id, [])
        
        ORDERS[order_id] = {
            'items': items,
            'total': sum(item['price'] * item['quantity'] for item in items),
            'status': 'completed',
            'payment_skipped': skip_payment
        }
        
        content = f"""
            <h2>Order Complete!</h2>
            <div class="result">
                <p>Order ID: {order_id}</p>
                <p>Status: Completed</p>
                <p>Payment: {'Skipped' if skip_payment else 'Processed'}</p>
            </div>
        """
        return BASE_TEMPLATE.replace("{content}", content)
    
    return redirect('/checkout')


@app.route('/api/purchase', methods=['POST'])
def api_purchase():
    """VULNERABLE: Direct purchase endpoint with price manipulation"""
    data = request.get_json() or {}
    
    # VULNERABLE: Accepts user-provided price
    item_id = data.get('item_id', '1')
    price = float(data.get('price', 10.0))  # No server-side validation!
    quantity = int(data.get('quantity', 1))
    
    total = price * quantity
    
    # VULNERABLE: Confirms the manipulated price
    return jsonify({
        "success": True,
        "item_id": item_id,
        "price": price,
        "quantity": quantity,
        "total": total,
        "message": f"Purchase confirmed: ${total:.2f}"
    })


@app.route('/api/rate-limit', methods=['GET', 'POST'])
def rate_limit_test():
    """VULNERABLE: Rate limit bypass"""
    client_ip = request.remote_addr
    
    # VULNERABLE: Rate limit can be bypassed by changing IP header
    bypass_ip = request.headers.get('X-Forwarded-For', client_ip)
    if bypass_ip:
        client_ip = bypass_ip.split(',')[0].strip()
    
    # Simple rate limiting
    if client_ip not in RATE_LIMIT:
        RATE_LIMIT[client_ip] = {'count': 0, 'reset_time': 0}
    
    import time
    current_time = time.time()
    
    # Reset if 1 minute passed
    if current_time > RATE_LIMIT[client_ip]['reset_time']:
        RATE_LIMIT[client_ip]['count'] = 0
        RATE_LIMIT[client_ip]['reset_time'] = current_time + 60
    
    # Check limit (5 requests per minute)
    if RATE_LIMIT[client_ip]['count'] >= 5:
        return jsonify({"error": "Rate limit exceeded"}), 429
    
    RATE_LIMIT[client_ip]['count'] += 1
    
    return jsonify({
        "success": True,
        "requests": RATE_LIMIT[client_ip]['count'],
        "message": "Request processed"
    })


@app.route('/api/state-transition', methods=['POST'])
def state_transition():
    """VULNERABLE: State transition vulnerability"""
    data = request.get_json() or {}
    order_id = data.get('order_id', 1)
    new_state = data.get('state', 'pending')
    
    # VULNERABLE: Can transition to any state without validation
    if order_id not in ORDERS:
        ORDERS[order_id] = {'status': 'pending'}
    
    # VULNERABLE: No state machine validation
    ORDERS[order_id]['status'] = new_state
    
    return jsonify({
        "success": True,
        "order_id": order_id,
        "old_status": ORDERS[order_id].get('status', 'unknown'),
        "new_status": new_state
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

