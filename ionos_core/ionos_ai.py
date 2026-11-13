import os
from typing import Optional
from openai import OpenAI
from .quanten_memory import get_memory_string, save_fact
from .project_memory import get_project_status


def _client() -> Optional[OpenAI]:
    openai_key = os.getenv("OPENAI_API_KEY", "").strip()
    router_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    provider = os.getenv("AI_PROVIDER", "openai").strip().lower()
    if provider == "openrouter" and router_key:
        return OpenAI(api_key=router_key, base_url="https://openrouter.ai/api/v1")
    if openai_key:
        return OpenAI(api_key=openai_key)
    if router_key:
        return OpenAI(api_key=router_key, base_url="https://openrouter.ai/api/v1")
    return None


def _fallback(message: str) -> str:
    lower = message.lower()
    if "wer bist du" in lower:
        return "Ich bin IONOS-7, der integrierte KI-Kern von Quantum KI Ultra Pro V2."
    if "status" in lower:
        return get_project_status()
    return f"IONOS-7 empfängt: {message}"


def run(message: str, model: Optional[str] = None) -> str:
    if os.getenv("AI_ENABLED", "true").strip().lower() != "true":
        raise RuntimeError("IONOS-7 KI ist mit AI_ENABLED=false deaktiviert.")
    client = _client()
    if client is None:
        raise RuntimeError("OPENAI_API_KEY oder OPENROUTER_API_KEY fehlt in Render.")
    memory = get_memory_string()
    project = get_project_status()
    try:
        model_name = model or os.getenv("OPENROUTER_MODEL") or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        if os.getenv("OPENROUTER_API_KEY") and not os.getenv("OPENAI_API_KEY") and "/" not in model_name:
            model_name = "openai/" + model_name
        response = client.chat.completions.create(
            model=model_name,
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
    except Exception as exc:
        raise ValueError("IONOS-7 KI-Anfrage fehlgeschlagen. Prüfe API-Key, Modellzugriff und Guthaben.") from exc
