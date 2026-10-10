import os
from collections import defaultdict, deque
from time import monotonic
from flask import Flask, jsonify, request, send_from_directory, redirect
from openai import OpenAI
from auth_core import register_user, login_user, resolve_user, logout_user
from ionos_core.ionos_ai import run as run_ionos7

app = Flask(__name__)

# SECURITY HARDENING
_SEC_RATE_LIMIT={}
from time import monotonic
@app.before_request
def _sec_before():
    if request.content_length and request.content_length>1048576:return jsonify(error="Request too large."),413
    if request.path.startswith("/.git/") or request.path.startswith("/.env"):return jsonify(error="Not Found."),404
    ip=request.remote_addr or "unknown";now=monotonic();b=_SEC_RATE_LIMIT.setdefault(ip,[]);b[:]=[t for t in b if now-t<60];limit=30 if request.method in {"POST","PUT","PATCH","DELETE"} else 120
    if len(b)>=limit:return jsonify(error="Too many requests. Please try again later."),429
    b.append(now)
@app.after_request
def _sec_headers(response):
    response.headers.setdefault("X-Content-Type-Options","nosniff");response.headers.setdefault("X-Frame-Options","DENY");response.headers.setdefault("Referrer-Policy","strict-origin-when-cross-origin");response.headers.setdefault("Permissions-Policy","camera=(), microphone=(), geolocation=()");response.headers.setdefault("Cross-Origin-Opener-Policy","same-origin");response.headers.setdefault("Strict-Transport-Security","max-age=31536000; includeSubDomains");response.headers.pop("Server",None);return response


# --- Security hardening ---
from collections import defaultdict, deque
from time import monotonic
from html import escape as html_escape

_SECURITY_RATE = defaultdict(deque)
_SECURITY_WINDOW = 60
_SECURITY_MAX = 120
_SECURITY_POST_MAX = 30
_SECURITY_MAX_BODY = 1024 * 1024

@app.before_request
def _security_before_request():
    if request.content_length and request.content_length > _SECURITY_MAX_BODY:
        return jsonify(error="Request too large."), 413
    path = request.path or "/"
    blocked = {"/.env","/.git/config","/server.py","/app.py","/main.py","/package.json","/requirements.txt","/render.yaml","/Procfile"}
    if path in blocked or path.startswith("/.git/") or path.startswith("/.env"):
        return jsonify(error="Not Found."), 404
    ip = request.remote_addr or "unknown"
    now = monotonic()
    q = _SECURITY_RATE[ip]
    while q and now - q[0] > _SECURITY_WINDOW:
        q.popleft()
    limit = _SECURITY_POST_MAX if request.method in {"POST","PUT","PATCH","DELETE"} else _SECURITY_MAX
    if len(q) >= limit:
        return jsonify(error="Too many requests. Please try again later."), 429
    q.append(now)

@app.after_request
def _security_headers(response):
    response.headers.setdefault("X-Content-Type-Options","nosniff")
    response.headers.setdefault("X-Frame-Options","DENY")
    response.headers.setdefault("Referrer-Policy","strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy","camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy","same-origin")
    response.headers.setdefault("Strict-Transport-Security","max-age=31536000; includeSubDomains")
    response.headers.setdefault("Cache-Control","no-store" if request.path.startswith("/api/") else "public, max-age=300")
    response.headers.pop("Server", None)
    return response
# --- End security hardening ---
MODEL = os.getenv("OPENAI_MODEL", "gpt-5.6")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "").strip()
WEB = os.getenv("ENABLE_WEB_SEARCH", "true").lower() == "true"
AI_ENABLED = os.getenv("AI_ENABLED", "true").lower() == "true"
MAX_INPUT = max(1000, min(int(os.getenv("MAX_INPUT_CHARS", "12000")), 30000))
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY")) if os.getenv("OPENAI_API_KEY") else None
router_client = OpenAI(api_key=OPENROUTER_API_KEY, base_url="https://openrouter.ai/api/v1") if OPENROUTER_API_KEY else None
SYSTEM = """Du bist Quantum KI Ultra Pro V2, ein leistungsfähiger Forschungs-, Coding- und Projektassistent.
Antworte in der Sprache des Nutzers. Arbeite strukturiert und konkret. Trenne Fakten, Annahmen und Unsicherheit.
Nutze Web-Recherche für aktuelle Informationen, wenn sie aktiviert ist. Erfinde keine Quellen, Daten, Aktionen oder Ergebnisse.
Bei Code: achte auf Sicherheit, Wartbarkeit, Tests, Fehlerbehandlung und Deployment. Liefere direkt umsetzbare Lösungen."""
RATE = defaultdict(lambda: deque(maxlen=30))

def allow(ip):
    now = monotonic()
    q = RATE[ip]
    while q and now - q[0] > 60: q.popleft()
    if len(q) >= 20: return False
    q.append(now)
    return True

def clean_history(history):
    if not isinstance(history, list): return []
    out = []
    for item in history[-12:]:
        if not isinstance(item, dict): continue
        role, content = item.get("role"), item.get("content")
        if role in {"user", "assistant"} and isinstance(content, str) and content.strip():
            out.append({"role": role, "content": content[:MAX_INPUT]})
    return out

def ask(message, history, selected_model=None):
    if not AI_ENABLED: return "Die KI ist derzeit deaktiviert."
    if not client and not router_client: return "OPENAI_API_KEY oder OPENROUTER_API_KEY ist in Render nicht gesetzt."
    try:
        clean = clean_history(history)
        if router_client:
            model = selected_model or os.getenv("OPENROUTER_MODEL") or (MODEL if "/" in MODEL else "openai/" + MODEL)
            if "/" not in model:
                model = "openai/" + model
            response = router_client.chat.completions.create(
                model=model,
                messages=[{"role": "system", "content": SYSTEM}, *clean, {"role": "user", "content": message}],
            )
            return response.choices[0].message.content or "Keine Antwort erhalten."
        kwargs = {
            "model": (selected_model or MODEL),
            "store": False,
            "input": [{"role": "system", "content": SYSTEM}, *clean, {"role": "user", "content": message}],
        }
        if WEB:
            kwargs["tools"] = [{"type": "web_search", "search_context_size": "medium"}]
            kwargs["tool_choice"] = "auto"
        response = client.responses.create(**kwargs)
        return response.output_text or "Keine Antwort erhalten."
    except Exception:
        app.logger.exception("AI API failure")
        return "Die KI-Schnittstelle ist momentan nicht erreichbar. Prüfe API-Key, Guthaben und Render-Logs."

@app.get("/")
def home():
    host = request.host.split(":", 1)[0].lower()
    if request.method == "GET" and host in {"ionos-7.onrender.com", "quantum-ki-ultra-pro-v2-renewed.onrender.com"}:
        query = ("?" + request.query_string.decode("utf-8", "ignore")) if request.query_string else ""
        return redirect("https://quantum-ki-ultra-pro-v2.onrender.com" + request.path + query, code=302)
    return send_from_directory("templates", "index.html")


@app.get("/login")
def login_page():
    return send_from_directory("templates", "login.html")

@app.get("/register")
def register_page():
    return send_from_directory("templates", "register.html")

@app.get("/dashboard")
def dashboard_page():
    return send_from_directory("templates", "dashboard.html")

@app.get("/engine")
def engine(): return send_from_directory(".", "game_engine.html")

@app.get("/game_engine.js")
def engine_js(): return send_from_directory(".", "game_engine.js")



@app.post("/api/auth/register")
def api_auth_register():
    data = request.get_json(silent=True) or {}
    try:
        user = register_user(data.get("username"), data.get("email"), data.get("password"))
        return jsonify({"ok": True, "user": user}), 201
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

@app.post("/api/auth/login")
def api_auth_login():
    data = request.get_json(silent=True) or {}
    try:
        result = login_user(data.get("identifier") or data.get("username") or data.get("email"), data.get("password"))
        return jsonify({"ok": True, **result}), 200
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 401

@app.get("/api/auth/me")
def api_auth_me():
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
    user = resolve_user(token)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"ok": True, "user": user}), 200

@app.post("/api/auth/logout")
def api_auth_logout():
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
    logout_user(token)
    return jsonify({"ok": True}), 200

@app.get("/api/ionos7/status")
def ionos7_status():
    return jsonify({
        "project": "IONOS-7",
        "integrated_into": "Quantum.KI.Ultra.Pro.V2",
        "status": "ready",
        "ai_enabled": AI_ENABLED,
        "provider_configured": bool(client or router_client),
        "shared_chat_api": "/api/ionos7/chat",
        "shared_health_api": "/health"
    })

@app.post("/api/ionos7/chat")
def ionos7_chat():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    if not allow(ip):
        return jsonify({"error": "Zu viele Anfragen. Bitte kurz warten."}), 429
    data = request.get_json(silent=True) or {}
    message = str(data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "message is required"}), 400
    if len(message) > MAX_INPUT:
        return jsonify({"error": f"message is too long (max {MAX_INPUT} characters)"}), 413
    prompt = "Du bist IONOS-7, der integrierte Forschungs- und Projektassistent. Antworte passend zur Sprache des Nutzers. " + message
    reply = run_ionos7(message, data.get("model") or os.getenv("OPENAI_MODEL", "gpt-4o-mini"))
    return jsonify({"ok": True, "project": "IONOS-7", "reply": reply, "model": data.get("model") or MODEL})

@app.get("/health")
@app.get("/api/health")
def health():
    return jsonify({"status":"ok","project":"QUANTUM KI ULTRA PRO V2","model":MODEL,"ai_enabled":AI_ENABLED,"web_search":WEB,"openai_configured":bool(client or router_client)})

@app.post("/api/chat")
@app.post("/chat")
def chat():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    if not allow(ip): return jsonify({"error":"Zu viele Anfragen. Bitte kurz warten."}), 429
    data = request.get_json(silent=True) or {}
    message = str(data.get("message") or "").strip()
    selected_model=str(data.get("model") or MODEL).strip()
    if not message: return jsonify({"error":"message is required"}), 400
    if len(message) > MAX_INPUT: return jsonify({"error":f"message is too long (max {MAX_INPUT} characters)"}), 413
    return jsonify({"ok":True,"reply":ask(message, data.get("history"), data.get("model")),"model":data.get("model") or MODEL,"web_search":WEB})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
