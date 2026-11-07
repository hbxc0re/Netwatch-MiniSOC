import asyncio
import json
import os
import random
import time
from pathlib import Path
from typing import Dict, Any, List

import httpx
import toml
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="NetWatch Unified Cybersecurity Mini-SOC")

CONFIG_DIR = Path.home() / ".config" / "netwatch"
POLICY_PATH = CONFIG_DIR / "policy.toml"

SOC_HOST_IP = os.getenv("SOC_HOST_IP", "192.0.2.10")
DEST_LAT = float(os.getenv("DEST_LAT", "39.8283"))
DEST_LON = float(os.getenv("DEST_LON", "-98.5795"))

GEO_SOURCES = [
    {"ip": "185.220.101.5", "lat": 51.1657, "lon": 10.4515, "country": "Germany"},
    {"ip": "194.26.29.112", "lat": 55.7558, "lon": 37.6173, "country": "Russia"},
    {"ip": "114.119.130.15", "lat": 39.9042, "lon": 116.4074, "country": "China"},
    {"ip": "45.154.255.88", "lat": 52.1326, "lon": 5.2913, "country": "Netherlands"},
]

TPOT_TEMPLATES = [
    {
        "honeypot": "Cowrie",
        "protocol": "SSH",
        "dst_port": 22,
        "action": "CAPTURED",
        "sig": "T-Pot [Cowrie] SSH Brute-Force & Shell Interaction",
        "payload": "root / admin123 -> uname -a"
    },
    {
        "honeypot": "Dionaea",
        "protocol": "SMB",
        "dst_port": 445,
        "action": "QUARANTINED",
        "sig": "T-Pot [Dionaea] EternalBlue MS17-010 SMB Exploit",
        "payload": f"SMB2 TREE_CONNECT Request \\\\{SOC_HOST_IP}\\IPC$"
    }
]

def build_event(geo=None, tpl=None):
    if not geo: geo = random.choice(GEO_SOURCES)
    if not tpl: tpl = random.choice(TPOT_TEMPLATES)
    score = random.randint(84, 99)
    return {
        "timestamp": time.strftime("%H:%M:%S"),
        "severity": "CRITICAL" if score >= 91 else "HIGH",
        "risk_score": score,
        "honeypot": tpl["honeypot"],
        "protocol": tpl["protocol"],
        "src_port": random.randint(32768, 65000),
        "dst_port": tpl["dst_port"],
        "signature": tpl["sig"],
        "src_ip": geo["ip"],
        "dst_ip": f"{SOC_HOST_IP}:{tpl['dst_port']}",
        "lat": geo["lat"],
        "lon": geo["lon"],
        "dst_lat": DEST_LAT,
        "dst_lon": DEST_LON,
        "country": geo["country"],
        "action": tpl["action"],
        "payload": tpl["payload"],
        "ai_summary": f"T-Pot {tpl['honeypot']} sensor intercepted {tpl['protocol']} attack from {geo['country']} ({geo['ip']}).",
        "playbook": {"t1": "Verify logs.", "t2": "Check firewall.", "t3": "Push IOC to CrowdSec."}
    }

state: Dict[str, Any] = {
    "daemon_running": True,
    "security_events": [build_event(), build_event()],
    "metrics": {"total_threats_blocked": 184, "active_rules": 8, "risk_index": "Elevated", "intel_status": "T-Pot Synced"},
}
connected_clients: List[WebSocket] = []

@app.get("/api/state")
async def get_state():
    return JSONResponse(state)

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    connected_clients.append(ws)
    try:
        while True: await ws.receive_text()
    except WebSocketDisconnect:
        if ws in connected_clients: connected_clients.remove(ws)

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def index():
    return FileResponse("static/index.html")