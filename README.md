# Quantum KI Ultra Pro V2 — konsolidierte Hauptversion

Dies ist das kanonische Hauptprojekt für die zusammengeführten KI-Anwendungen **Quantum KI Ultra Pro V2**, **IONOS-7**, **UltraKI.AI** und **Ultra KI V2**. Das bestehende kosmische Chat-Interface und die Game-Engine bleiben erhalten.

## Integrierte Funktionen
- KI-Chat mit optionalem OpenAI-kompatiblem Anbieter und OpenRouter
- IONOS-7-Chat-Endpunkt mit lokalem Fallback und TinyDB-Projektgedächtnis
- sichere Registrierung und Anmeldung mit PBKDF2-Passwort-Hashing und Bearer-Sessions
- Game-Engine-Oberfläche
- Health- und Status-Endpunkte

## Start
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="set-a-long-random-secret"
gunicorn --bind 0.0.0.0:$PORT app:app
```

## API
- `GET /health`, `GET /api/health`
- `POST /api/chat` — allgemeiner KI-Chat
- `GET /api/ionos7/status`, `POST /api/ionos7/chat`
- `POST /api/auth/register`, `POST /api/auth/login`
- `GET /api/auth/me`, `POST /api/auth/logout`
- `GET /engine`

## Konfiguration
- `OPENAI_API_KEY` oder `OPENROUTER_API_KEY`
- `OPENAI_MODEL` (Standard: `gpt-4o-mini`)
- `SECRET_KEY` für produktive Sitzungen
- Optional `AUTH_DB_PATH` auf einem persistenten Datenträger für dauerhaft gespeicherte Benutzerkonten
- `ENABLE_WEB_SEARCH=true|false`

Die Datenbankdateien auf einem normalen Render-Dateisystem sind nicht automatisch dauerhaft. Für dauerhafte Konten ist ein persistenter Datenträger erforderlich.

## Herkunft / Konsolidierung
- `IONOS-7` — Kernmodule und Gedächtnis wurden nach `ionos_core/` übernommen.
- `UltraKI.AI` und `ultra-ki-v2` — Chat- und Account-Funktionen wurden in diese Hauptanwendung integriert; das bestehende kosmische UI bleibt führend.
- Die alten Repositories bleiben vorerst als Quellhistorie bestehen. Die Bereinigung löscht keine Repository-Historie automatisch.
