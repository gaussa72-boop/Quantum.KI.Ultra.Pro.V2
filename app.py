from flask import Flask, jsonify

app = Flask(__name__)


@app.get("/")
def home():
    return jsonify({
        "status": "ok",
        "project": "Quantum.KI.Ultra.Pro.V2",
        "service": "online",
    })


@app.get("/health")
@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "project": "Quantum.KI.Ultra.Pro.V2",
        "service": "online",
    })


if __name__ == "__main__":
    import os
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")), debug=False)
