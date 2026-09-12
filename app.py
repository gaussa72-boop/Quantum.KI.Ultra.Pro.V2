import os
from flask import Flask, jsonify, request
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

app = Flask(__name__)
api_key = os.getenv("OPENAI_API_KEY", "").strip()
client = OpenAI(api_key=api_key) if api_key else None
MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")


@app.route("/")
def home():
    return jsonify({"status": "ok", "project": "Quantum.KI.Ultra.Pro.V2"})


@app.route("/health")
def health():
    return jsonify({"status": "ok", "project": "Quantum.KI.Ultra.Pro.V2", "openai_configured": client is not None})


@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json(silent=True) or {}
    user_message = (data.get("message") or "").strip()
    if not user_message:
        return jsonify({"error": "message is required"}), 400
    if client is None:
        return jsonify({"response": "OpenAI ist nicht konfiguriert. Setze OPENAI_API_KEY in Render."}), 503
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": "Du bist UltraKI Pro V2, eine professionelle KI."},
                {"role": "user", "content": user_message},
            ],
        )
        return jsonify({"response": response.choices[0].message.content or "Keine Antwort erhalten."})
    except Exception:
        app.logger.exception("OpenAI request failed")
        return jsonify({"error": "KI-Schnittstelle momentan nicht erreichbar."}), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")), debug=False)
