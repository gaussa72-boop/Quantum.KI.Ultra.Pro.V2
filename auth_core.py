"""Minimal account/session API core for the consolidated Quantum KI app.
Passwords are PBKDF2-hashed; only SHA-256 hashes of bearer tokens are stored.
For persistent production accounts, configure AUTH_DB_PATH on a persistent Render disk.
"""
import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from contextlib import closing

DB_PATH = os.getenv("AUTH_DB_PATH", os.path.join(os.path.dirname(__file__), "auth.db"))
ITERATIONS = 310_000
SESSION_TTL = 30 * 24 * 60 * 60

def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def _init():
    folder = os.path.dirname(DB_PATH)
    if folder:
        os.makedirs(folder, exist_ok=True)
    with closing(_connect()) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            salt BLOB NOT NULL,
            password_hash BLOB NOT NULL,
            created_at INTEGER NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at INTEGER NOT NULL
        )""")
        conn.commit()

_init()

def register_user(username, email, password):
    username = str(username or "").strip()
    email = str(email or "").strip().lower()
    password = str(password or "")
    if not 3 <= len(username) <= 40 or any(ch.isspace() for ch in username):
        raise ValueError("Benutzername muss 3–40 Zeichen ohne Leerzeichen haben.")
    if len(email) > 254 or "@" not in email or "." not in email.rsplit("@", 1)[-1]:
        raise ValueError("Bitte eine gültige E-Mail-Adresse eingeben.")
    if len(password) < 12 or len(password) > 256:
        raise ValueError("Passwort muss mindestens 12 Zeichen haben.")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    with closing(_connect()) as conn:
        try:
            cur = conn.execute(
                "INSERT INTO users(username,email,salt,password_hash,created_at) VALUES(?,?,?,?,?)",
                (username, email, salt, digest, int(time.time()))
            )
            conn.commit()
            return {"id": cur.lastrowid, "username": username, "email": email}
        except sqlite3.IntegrityError:
            raise ValueError("Benutzername oder E-Mail ist bereits registriert.")

def login_user(identifier, password):
    identifier = str(identifier or "").strip()
    password = str(password or "")
    with closing(_connect()) as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE",
            (identifier, identifier)
        ).fetchone()
        if not user:
            raise ValueError("Anmeldung fehlgeschlagen.")
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), user["salt"], ITERATIONS)
        if not hmac.compare_digest(candidate, user["password_hash"]):
            raise ValueError("Anmeldung fehlgeschlagen.")
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = int(time.time())
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        conn.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)",
                     (token_hash, user["id"], now + SESSION_TTL))
        conn.commit()
        return {"token": token, "token_type": "Bearer", "expires_in": SESSION_TTL,
                "user": {"id": user["id"], "username": user["username"], "email": user["email"]}}

def resolve_user(token):
    token = str(token or "").strip()
    if not token or len(token) > 512:
        return None
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = int(time.time())
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT u.id,u.username,u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>=?",
            (token_hash, now)
        ).fetchone()
        if not row:
            return None
        return dict(row)

def logout_user(token):
    token = str(token or "").strip()
    if not token or len(token) > 512:
        return
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with closing(_connect()) as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
        conn.commit()
