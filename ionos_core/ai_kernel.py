import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Funktion für IONOS-AI
def ionos_ai(prompt):
    return f"[IONOS-7 Kern]: Quantenscan läuft... Verarbeitung von '{prompt[:20]}...' [Antwort simuliert]"

# Funktion für URSPIRIT-AI (Storytelling)
def urspirit_ai(prompt):
    return f"[URSPIRIT]: Eine Geschichte webt sich aus dem Äther... '{prompt[:20]}...' [Antwort simuliert]"

# Funktion für MIRROR-AI (Analyse)
def mirror_ai(prompt):
    return f"[MIRROR]: Reflektion der Absicht erkannt... '{prompt[:20]}...' [Antwort simuliert]"