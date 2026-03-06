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
< title > KI - Assistenz: SINGULOS & IONOS - 7 < / title >
< style >
body
{
    margin: 0;
background: radial - gradient(circle
at
center,  # 0b0c10, #1f2833);
font - family: 'Segoe UI', sans - serif;
color:  # fff;
overflow: hidden;
}

.container
{
    display: flex;
flex - direction: column;
align - items: center;
padding: 20
px;
z - index: 2;
position: relative;
}

h1
{
    font - size: 2rem;
color:  # f39c12;
text - shadow: 0
0
15
px  # f39c12;
}

canvas
{
    position: absolute;
top: 0;
left: 0;
z - index: 1;
}

.assistant
{
    position: relative;
width: 400
px;
max - width: 90 %;
margin: 20
px
0;
}

.assistant
img
{
    width: 100 %;
border - radius: 15
px;
box - shadow: 0
0
20
px  # ff6f61, 0 0 50px #3498db;
}

.speech - bubble
{
    position: absolute;
top: 10
px;
left: 50 %;
transform: translateX(-50 %);
background: rgba(0, 0, 0, 0.7);
padding: 15
px;
border - radius: 15
px;
text - align: center;
font - size: 1
rem;
color:  # f1c40f;
text - shadow: 0
0
5
px  # f1c40f;
}

.chat - box
{
    width: 400px;
max - width: 90 %;
background: rgba(0, 0, 0, 0.8);
border - radius: 15
px;
padding: 15
px;
display: flex;
flex - direction: column;
gap: 10
px;
box - shadow: 0
0
20
px  # 00ffff;
}

.chat - box
input
{
    padding: 10px;
border - radius: 10
px;
border: none;
outline: none;
font - size: 1
rem;
}

.chat - box
button
{
    padding: 10px;
border - radius: 10
px;
border: none;
background:  # f39c12;
color:  # 000;
font - weight: bold;
cursor: pointer;
transition: 0.3
s;
}

.chat - box
button: hover
{
    background:  # e67e22;
}
< / style >
    < / head >
        < body >
        < canvas
id = "geometryCanvas" > < / canvas >

                            < div


class ="container" >

< h1 > KI - Assistenz: SINGULOS & IONOS - 7 < / h1 >

< div


class ="assistant" >

< img
src = "https://i.ibb.co/6nq1y4X/a-digital-painting-in-a-sci-fi-and-dark-cosmic-fan.png"
alt = "SINGULOS" >
< div


class ="speech-bubble" > Analysiere...Quantensingularität aktiv.Welche Geheimnisse wollt ihr enthüllen…? < / div >

< / div >

< div


class ="assistant" >

< img
src = "https://i.ibb.co/Zx6dQkg/a-digital-illustration-features-ionos-7-a-cartoon.png"
alt = "IONOS-7" >
< div


class ="speech-bubble" > Willkommen, Pilot! Bereit für bunte Geometrien und Quantenmissionen! < / div >

< / div >

< div


class ="chat-box" >

< input
type = "text"
id = "userInput"
placeholder = "Schreibe deine Anweisung an die KI..." >
< button
onclick = "sendMessage()" > Senden < / button >
< div
id = "chatOutput" > < / div >
< / div >
< / div >

< script >
// Chat - Funktion
function
sendMessage()
{
    const
input = document.getElementById('userInput').value;
const
output = document.getElementById('chatOutput');
if (input.trim() === '')
return;

const
userMsg = document.createElement('p');
userMsg.textContent = "Du: " + input;
userMsg.style.color = "#00ffff";
output.appendChild(userMsg);

const
response = document.createElement('p');
response.textContent = "KI-Assistent: Antwort generiert für \"" + input + "\"";
response.style.color = "#f1c40f";
output.appendChild(response);

document.getElementById('userInput').value = '';
output.scrollTop = output.scrollHeight;
}

// Canvas
für
heilige
Geometrie
const
canvas = document.getElementById('geometryCanvas');
const
ctx = canvas.getContext('2d');
canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

let
geometries = [];
const
colors = ['#ff00ff', '#00ffff', '#f39c12', '#ff0000', '#00ff00'];

function
createGeometries(count=10)
{
for (let i=0;i < count;i++){
    geometries.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        radius: 50 + Math.random() * 100,
        angle: Math.random() * Math.PI * 2,
        speed: 0.01 + Math.random() * 0.02,
        color: colors[Math.floor(Math.random() * colors.length)]
    });
}
}
createGeometries(15);

function
draw()
{
ctx.clearRect(0, 0, canvas.width, canvas.height);
geometries.forEach(g= > {
    ctx.save();
ctx.translate(g.x, g.y);
ctx.rotate(g.angle);
ctx.strokeStyle = g.color;
ctx.lineWidth = 3;
ctx.beginPath();
for (let i=0;i < 6;i++)
{
    const
angle = i * Math.PI / 3;
ctx.moveTo(0, 0);
ctx.lineTo(g.radius * Math.cos(angle), g.radius * Math.sin(angle));
}
ctx.stroke();
ctx.restore();
g.angle += g.speed;
});
requestAnimationFrame(draw);
}
draw();

// Anpassung
bei
Resize
window.addEventListener('resize', () = > {
    canvas.width = window.innerWidth;
canvas.height = window.innerHeight;
});
< / script >
    < / body >
        < / html >
