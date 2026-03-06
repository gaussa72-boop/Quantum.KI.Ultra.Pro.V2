Game
Engine(Unity)
↓
IONOS - 7
Plugin
↓
Lokaler
KI
Server(Python)
↓
Module:
- Quest
Generator
- DLC
Generator
- Mod
Analyzer
- Lernmodul
- Quanten - Lebensblume - Simulator
pip
install
fastapi
uvicorn
pydantic
from fastapi import FastAPI
from pydantic import BaseModel
import random

app = FastAPI()


class PlayerInput(BaseModel):
    message: str
    mode: str


def generate_response(message, mode):
    if mode == "quest":
        return f"Neue Mission generiert basierend auf: {message}"
    elif mode == "dlc":
        return f"DLC Idee: Invasion der Quantenwesen im Gebiet {message}"
    elif mode == "analysis":
        return f"Analyse abgeschlossen für {message}"
    else:
        return "IONOS-7 wartet auf deine Anweisung."


@app.post("/ionos")
def ionos_response(data: PlayerInput):
    response = generate_response(data.message, data.mode)
    return {"response": response}


uvicorn
server: app - -reload
using
UnityEngine;
using
UnityEngine.Networking;
using
System.Collections;

public


class IonosConnector: MonoBehaviour


{
    public
void
SendMessageToAI(string
message, string
mode)
{
    StartCoroutine(PostRequest(message, mode));
}

IEnumerator
PostRequest(string
message, string
mode)
{
    string
json = "{\"message\":\"" + message + "\", \"mode\":\"" + mode + "\"}";

UnityWebRequest
request = new
UnityWebRequest("http://127.0.0.1:8000/ionos", "POST");
byte[]
bodyRaw = System.Text.Encoding.UTF8.GetBytes(json);
request.uploadHandler = new
UploadHandlerRaw(bodyRaw);
request.downloadHandler = new
DownloadHandlerBuffer();
request.SetRequestHeader("Content-Type", "application/json");

yield
return request.SendWebRequest();

Debug.Log(request.downloadHandler.text);
}using
UnityEngine;
using
UnityEngine.Networking;
using
System.Collections;

public


class IonosConnector: MonoBehaviour


{
    public
void
SendMessageToAI(string
message, string
mode)
{
    StartCoroutine(PostRequest(message, mode));
}

IEnumerator
PostRequest(string
message, string
mode)
{
    string
json = "{\"message\":\"" + message + "\", \"mode\":\"" + mode + "\"}";

UnityWebRequest
request = new
UnityWebRequest("http://127.0.0.1:8000/ionos", "POST");
byte[]
bodyRaw = System.Text.Encoding.UTF8.GetBytes(json);
request.uploadHandler = new
UploadHandlerRaw(bodyRaw);
request.downloadHandler = new
DownloadHandlerBuffer();
request.SetRequestHeader("Content-Type", "application/json");

yield
return request.SendWebRequest();

Debug.Log(request.downloadHandler.text);
}
}
}
