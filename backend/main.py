from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from typing import List
from datetime import datetime
import os

app = FastAPI()

# 1. TERA ORIGINAL CORS SETTINGS (Wahi rehne diya hai)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. FRONTEND CONNECTORS (Ye naya hai)
# Ye line IP address kholte hi 'frontend' folder se index.html utha legi
@app.get("/")
async def read_index():
    return FileResponse('frontend/index.html')

# Ye line CSS aur JS files ko server se link karegi
# (Make sure tere folders ka naam 'frontend' hi ho)
app.mount("/frontend", StaticFiles(directory="frontend"), name="frontend")

# 3. TERA ORIGINAL CONNECTION MANAGER (Same to same)
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str, sender: WebSocket):
        for connection in self.active_connections:
            if connection != sender:
                await connection.send_text(message)

manager = ConnectionManager()

# 4. TERA ORIGINAL WEBSOCKET ENDPOINT (Wahi logic hai)
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # TIME-GATE CHECK (1 AM to 5 AM)
    current_hour = datetime.now().hour
    if not (1 <= current_hour < 5):
        await websocket.close(code=1008, reason="The void is closed.")
        return

    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await manager.broadcast(data, sender=websocket)
    except WebSocketDisconnect:
        manager.disconnect(websocket)