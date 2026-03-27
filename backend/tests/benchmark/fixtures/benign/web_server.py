"""Benign: Standard Flask web server."""
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/api/data", methods=["GET"])
def get_data():
    page = request.args.get("page", 1, type=int)
    return jsonify({"page": page, "items": []})

@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
