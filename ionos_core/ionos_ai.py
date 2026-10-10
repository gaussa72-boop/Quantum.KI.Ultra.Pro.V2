import os
from typing import Optional
from openai import OpenAI
from .quanten_memory import get_memory_string, save_fact
from .project_memory import get_project_status


def _client() -> Optional[OpenAI]:
    openai_key = os.getenv("OPENAI_API_KEY")
    router_key = os.getenv("OPENROUTER_API_KEY")
    key = openai_key or router_key
    base_url = os.getenv("OPENAI_BASE_URL") or ("https://openrouter.ai/api/v1" if router_key and not openai_key else None)
    return OpenAI(api_key=key, base_url=base_url) if key else None


def _fallback(message: str) -> str:
    lower = message.lower()
    if "wer bist du" in lower:
        return "Ich bin IONOS-7, der integrierte KI-Kern von Quantum KI Ultra Pro V2."
    if "status" in lower:
        return get_project_status()
    return f"IONOS-7 empfängt: {message}"


def run(message: str, model: Optional[str] = None) -> str:
    client = _client()
    memory = get_memory_string()
    project = get_project_status()
    if client is None:
        return _fallback(message)
    try:
        response = client.chat.completions.create(
            model=model or os.getenv("OPENROUTER_MODEL") or os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            messages=[
                {"role": "system", "content": "Du bist IONOS-7. Antworte klar, hilfreich und technisch korrekt. Projektstatus: " + project + " Benutzergedächtnis: " + memory},
                {"role": "user", "content": message},
            ],
        )
        reply = response.choices[0].message.content or "Keine Antwort erhalten."
        lower = message.lower()
        if "ich heiße" in lower:
            name = message.split("ich heiße", 1)[1].strip(" .,!?")
            if name:
                save_fact("Name", name)
        return reply
    except Exception:
        return _fallback(message)
