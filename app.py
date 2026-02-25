import os
import sqlite3
import base64
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from openai import OpenAI
from dotenv import load_dotenv

# Konfiguration
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "quantum_secret_99")
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# --- ULTRA KI LOGIK (Aus deinen Dateien) ---
def transform_logic(text):
    # Die 3-fache Base64 Transformation aus deiner ultra_full_chatapp.py
    data = text.encode()
    for _ in range(3):
        data = base64.b64encode(data[::-1])
    return data.decode()

def get_db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

# Datenbank Initialisierung
def init_db():
    with get_db() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS chats (id INTEGER PRIMARY KEY, assistant TEXT, message TEXT, encrypted TEXT)")
init_db()

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/chat', methods=['POST'])
def chat():
    data = request.json
    user_input = data.get("message")
    assistant_name = data.get("assistant")

    # Verschlüsselung
    enc_version = transform_logic(user_input)

    # KI Antwort
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": f"Du bist {assistant_name}, eine hochentwickelte KI."},
                {"role": "user", "content": user_input}
            ]
        )
        ai_reply = response.choices[0].message.content
    except Exception as e:
        ai_reply = f"Quanten-Fehler: {str(e)}"

    return jsonify({
        "reply": ai_reply,
        "encryption_preview": enc_version[:20] + "..."
    })

if __name__ == '__main__':
    app.run(debug=True)
