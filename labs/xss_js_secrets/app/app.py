from flask import Flask, request, render_template

app = Flask(__name__)


@app.route("/")
def index():
    return "XSS + JS secrets lab"


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # Intentionally reflected unsanitized for lab purposes
    return render_template("search.html", q=q)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
