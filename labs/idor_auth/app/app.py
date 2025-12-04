from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

USERS = {
    1: {"id": 1, "name": "Alice", "tenant": "A"},
    2: {"id": 2, "name": "Bob", "tenant": "B"},
}

SESSIONS = {
    "token-alice": 1,
    "token-bob": 2,
}


def current_user():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth.split(" ", 1)[1]
        uid = SESSIONS.get(token)
        if uid:
            return USERS.get(uid)
    return None


@app.route("/login/alice")
def login_alice():
    resp = make_response(jsonify({"ok": True, "user": USERS[1]}))
    # Expose a demo token header for the lab harness to capture
    resp.headers["X-Demo-Token"] = "token-alice"
    return resp


@app.route("/api/users/<int:user_id>")
def get_user(user_id):
    user = current_user()
    victim = USERS.get(user_id)
    # IDOR: we do not check tenant or match with current user_id
    if not user or not victim:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify(victim)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
