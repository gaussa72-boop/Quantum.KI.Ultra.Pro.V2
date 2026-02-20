from openai import OpenAI
import os
from dotenv import load_dotenv

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
from flask import Flask, request, jsonify
from openai import OpenAI
import os

app = Flask(__name__)

# API Key hier direkt einsetzen (nur lokal!)
client = OpenAI(api_key="DEIN_OPENAI_API_KEY_HIER")

@app.route("/")
def home():
    return "UltraKI Pro V2 läuft!"

@app.route("/chat", methods=["POST"])
def chat():
    user_message = request.json.get("message")

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "Du bist UltraKI Pro V2, eine professionelle KI."},
            {"role": "user", "content": user_message}
        ]
    )

    return jsonify({
        "response": response.choices[0].message.content
    })

if __name__ == "__main__":
    app.run(debug=True)
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
