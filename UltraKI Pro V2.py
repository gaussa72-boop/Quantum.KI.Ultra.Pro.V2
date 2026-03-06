UltraKI - Pro - V2 /
│
├── app.py
├── requirements.txt
├──.env
├── database.db
│
├── templates /
│     ├── login.html
│     ├── register.html
│     ├── dashboard.html
│     └── admin.html
│
└── static /
├── style.css
└── script.js

from flask import Flask, render_template, request, redirect, session, jsonify
import sqlite3
import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

from flask import Flask, render_template, request, redirect, session, jsonify, url_for
import sqlite3
import os
from dotenv import load_dotenv
from openai import OpenAI
from werkzeug.security import generate_password_hash, check_password_hash

# Laden der Umgebungsvariablen (.env Datei)
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "ein-sehr-sicherer-schluessel-123")


# -----------------------
# Datenbank Setup
# -----------------------
def get_db_connection():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        role TEXT,
        message TEXT
    )""")
    conn.commit()
    conn.close()


init_db()


# -----------------------
# Routen & Logik
# -----------------------

@app.route("/")
def index():
    # Leitet den Nutzer direkt zum Login weiter, wenn er die Seite aufruft
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        # Passwörter werden nun sicher gehasht gespeichert
        password = generate_password_hash(request.form["password"])

        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            conn.close()
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return "Benutzername existiert bereits!"

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        # Abgleich des gehashten Passworts
        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))
        return "Ungültige Anmeldedaten!"

    return render_template("login.html")

< !DOCTYPE
html >
< html
lang = "de" >
< head >
< meta
charset = "UTF-8" >
< meta
name = "viewport"
content = "width=device-width, initial-scale=1.0" >
< title > UltraKI
Pro
V2 - Magisches
Portal < / title >
< style >
:root
{
    --magic - gold:  # ffd700;
        --magic - purple:  # 6a0dad;
--neon - cyan:  # 00f2ff;
--bg - dark:  # 0a0a12;
}

body
{
    background - color: var(--bg - dark);
background - image:
radial - gradient(circle
at
50 % 50 %, rgba(106, 13, 173, 0.2)
0 %, transparent
80 %),
url('https://www.transparenttextures.com/patterns/sacred-geometry.png'); / *Heilige
Geometrie
Textur * /
color: white;
font - family: 'Segoe UI', Tahoma, Geneva, Verdana, sans - serif;
margin: 0;
display: flex;
flex - direction: column;
height: 100
vh;
overflow: hidden;
}

/ *Das
Allsehende
Auge & Pyramide
im
Hintergrund * /
.background - magic
{
    position: absolute;
top: 50 %;
left: 50 %;
transform: translate(-50 %, -50 %);
z - index: -1;
opacity: 0.15;
filter: drop - shadow(0
0
20
px
var(--magic - gold));
pointer - events: none;
}

header
{
    text - align: center;
padding: 20
px;
background: rgba(0, 0, 0, 0.6);
border - bottom: 2
px
solid
var(--magic - gold);
box - shadow: 0
0
15
px
var(--magic - purple);
}

h1
{
    margin: 0;
text - transform: uppercase;
letter - spacing: 5
px;
background: linear - gradient(90
deg,  # ff00ff, #00f2ff, #ffd700);
-webkit - background - clip: text;
-webkit - text - fill - color: transparent;
text - shadow: 2
px
2
px
10
px
rgba(255, 215, 0, 0.5);
}

# chat-container {
flex: 1;
overflow - y: auto;
padding: 20
px;
display: flex;
flex - direction: column;
gap: 15
px;
background: rgba(10, 10, 18, 0.8);
backdrop - filter: blur(5
px);
}

.message
{
    max - width: 80 %;
padding: 15
px;
border - radius: 15
px;
position: relative;
animation: shatterIn
0.5
s
ease - out;
}

@keyframes


shatterIn
{
    0 % {transform: scale(0) rotate(-10deg); opacity: 0;
filter: blur(10
px);}
100 % {transform: scale(1) rotate(0);
opacity: 1;
filter: blur(0);}
}

.user - message
{
    align - self: flex - end;
background: linear - gradient(135
deg, var(--magic - purple),  # 2b0054);
border: 1
px
solid
var(--neon - cyan);
box - shadow: -5
px
5
px
15
px
rgba(0, 242, 255, 0.3);
}

.ai - message
{
    align - self: flex - start;
background: linear - gradient(135
deg,  # 1a1a1a, #333);
border: 1
px
solid
var(--magic - gold);
box - shadow: 5
px
5
px
15
px
rgba(255, 215, 0, 0.2);
}

/ *Input
Bereich * /
.input - area
{
    padding: 20px;
background: rgba(0, 0, 0, 0.8);
display: flex;
gap: 10
px;
border - top: 2
px
solid
var(--magic - purple);
}

input
{
    flex: 1;
background:  # 1a1a1a;
border: 1
px
solid
var(--magic - gold);
padding: 15
px;
color: white;
border - radius: 5
px;
outline: none;
}

button
{
    background: linear - gradient(45deg, var(--magic - gold),  # b8860b);
border: none;
padding: 10
px
25
px;
color: black;
font - weight: bold;
cursor: pointer;
border - radius: 5
px;
transition: 0.3
s;
}

button: hover
{
    transform: scale(1.05);
box - shadow: 0
0
20
px
var(--magic - gold);
}
< / style >
    < / head >
        < body >

        < svg


class ="background-magic" width="400" height="400" viewBox="0 0 100 100" >

< polygon
points = "50,15 90,85 10,85"
fill = "none"
stroke = "#ffd700"
stroke - width = "0.5" / >
< circle
cx = "50"
cy = "55"
r = "10"
fill = "none"
stroke = "#00f2ff"
stroke - width = "0.5" / >
< circle
cx = "50"
cy = "55"
r = "3"
fill = "#ffd700" / >
< / svg >

< header >
< h1 > UltraKI
Pro
V2 < / h1 >
< small > Eingeloggt
als: {{username}} | < a
href = "/logout"
style = "color: var(--neon-cyan)" > Portal
verlassen < / a > < / small >
< / header >

< div
id = "chat-container" >
< div


class ="message ai-message" > Willkommen im magischen Zirkel.Stelle deine Frage...< / div >

< / div >

< div


class ="input-area" >

< input
type = "text"
id = "user-input"
placeholder = "Schreibe deine Nachricht an die KI..." >
< button
onclick = "sendMessage()" > SENDEN < / button >
< / div >

< script >
async function
sendMessage()
{
    const
input = document.getElementById('user-input');
const
container = document.getElementById('chat-container');
const
message = input.value;
if (!message)
return;

// User
Nachricht
anzeigen
container.innerHTML += ` < div


class ="message user-message" > ${message} < / div > `;


input.value = '';
container.scrollTop = container.scrollHeight;

// API
Call
const
response = await fetch('/chat', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({message: message})
});
const
data = await response.json();

// KI
Nachricht
anzeigen
container.innerHTML += ` < div


class ="message ai-message" > ${data.reply} < / div > `;


container.scrollTop = container.scrollHeight;
}
< / script >
    < / body >
        < / html >


@app.route("/chat", methods=["POST"])


def chat():
    if "user_id" not in session:
        return jsonify({"error": "Nicht eingeloggt"})

    user_input = request.json.get("message")
    user_id = session["user_id"]

    conn = get_db_connection()
    c = conn.cursor()

    # Chat-Historie für den Kontext laden
    c.execute("SELECT role, message FROM chats WHERE user_id=? ORDER BY id DESC LIMIT 10", (user_id,))
    history = c.fetchall()

    # Historie für die OpenAI API formatieren
    messages = [{"role": "system", "content": "Du bist die UltraKI Pro V2, ein hilfreicher Assistent."}]
    for row in reversed(history):
        messages.append({"role": row["role"], "content": row["message"]})

    messages.append({"role": "user", "content": user_input})

    # OpenAI API Aufruf
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=messages
    )
    ai_reply = response.choices[0].message.content

    # Speichern in der Datenbank
    c.execute("INSERT INTO chats (user_id, role, message) VALUES (?, ?, ?)", (user_id, "user", user_input))
    c.execute("INSERT INTO chats (user_id, role, message) VALUES (?, ?, ?)", (user_id, "assistant", ai_reply))
    conn.commit()
    conn.close()

    return jsonify({"reply": ai_reply})


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
