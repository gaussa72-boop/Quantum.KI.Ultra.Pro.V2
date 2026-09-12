import os

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from openai import OpenAI

load_dotenv()

app = Flask(__name__)

API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini"
client = OpenAI(api_key=API_KEY) if API_KEY else None

SYSTEM_PROMPT = "Du bist Quantum.KI.Ultra.Pro.V2, eine professionelle, hilfreiche KI. Antworte klar, zuverlässig und auf Deutsch, wenn der Nutzer Deutsch schreibt."


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
        "openai_configured": client is not None,
        "model": MODEL,
    })


@app.post("/chat")
@app.post("/api/chat")
def chat():
    data = request.get_json(silent=True) or {}
    user_message = str(data.get("message") or "").strip()

    if not user_message:
        return jsonify({"error": "message is required"}), 400

    if client is None:
        return jsonify({
            "error": "OpenAI ist nicht konfiguriert.",
            "hint": "OPENAI_API_KEY in Render als Secret setzen.",
        }), 503

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            temperature=0.7,
        )
        content = response.choices[0].message.content or "Keine Antwort erhalten."
        return jsonify({"response": content})
    except Exception:
        app.logger.exception("OpenAI request failed")
        return jsonify({"error": "KI-Schnittstelle momentan nicht erreichbar."}), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")), debug=False)
