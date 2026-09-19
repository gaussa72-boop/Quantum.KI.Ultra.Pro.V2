from flask import Flask, jsonify
import os

app = Flask(__name__)

SERVICE_INFO = {
    "project": "Quantum.KI.Ultra.Pro.V2",
    "service": "IONOS 7",
    "status": "online",
    "version": "2.0-render",
}

@app.get("/")
def home():
    return jsonify(SERVICE_INFO)

@app.get("/health")
@app.get("/api/health")
def health():
    return jsonify({**SERVICE_INFO, "health": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")), debug=False)
