/ KI_Assistent_Projekt /
│
├─ index.html < - dein
Hauptfile(HTML + Canvas + Chat)
├─ style.css < - optional: Styles
aus
HTML
auslagern
├─ scripts /
│   ├─ chat.js < - Chat - Funktion
│   └─ geometry.js < - animierte
heilige
Geometrien
│
├─ assets /
│   ├─ ionos7.png < - Cartoon
Alien
Bild
│   └─ singulos.png < - Schwarzes
Loch
Bild
│
└─ backend /
├─ server.py < - Python
FastAPI
Server
├─ requirements.txt < - pip
dependencies
└─ modules /
├─ quest_gen.py
├─ dlc_gen.py
└─ flower_of_life.py
async function
sendMessageToBackend(message, mode="analysis")
{
    const
response = await fetch('http://127.0.0.1:8000/ionos', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({message: message, mode: mode})
});
const
data = await response.json();
return data.response;
}
