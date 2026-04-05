import sqlite3
import json
import uuid
import os
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from passlib.context import CryptContext
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth

# IST timezone
IST = timezone(timedelta(hours=5, minutes=30))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="super-secret-1am-void")

# OAuth Setup
oauth = OAuth()
oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID', 'placeholder_id'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET', 'placeholder_secret'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# Database setup
DB_FILE = "void_users.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    ''')
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN session_token TEXT')
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()

init_db()

class User(BaseModel):
    username: str
    password: str

@app.post("/api/signup")
async def signup(user: User):
    if not user.username or not user.password:
        return JSONResponse(status_code=400, content={"error": "Username and password required."})
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (user.username,))
    if cursor.fetchone():
        conn.close()
        return JSONResponse(status_code=400, content={"error": "Username already exists."})
    
    hashed_password = pwd_context.hash(user.password)
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user.username, hashed_password))
    conn.commit()
    conn.close()
    
    return {"message": "Signup successful."}

@app.post("/api/login")
async def login(user: User):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username=?", (user.username,))
    row = cursor.fetchone()
    
    if not row or not pwd_context.verify(user.password, row[0]):
        conn.close()
        return JSONResponse(status_code=400, content={"error": "Invalid username or password."})
    
    session_token = str(uuid.uuid4())
    cursor.execute("UPDATE users SET session_token=? WHERE username=?", (session_token, user.username))
    conn.commit()
    conn.close()
    
    response = JSONResponse(content={"message": "Login successful."})
    response.set_cookie(key="session_token", value=session_token, httponly=True, samesite="Lax")
    return response

@app.get("/auth/google")
async def auth_google(request: Request):
    redirect_uri = request.url_for('auth_google_callback')
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/google/callback")
async def auth_google_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
        userinfo = token.get('userinfo')
    except Exception:
        return RedirectResponse(url="/")
        
    if not userinfo:
        return RedirectResponse(url="/")
        
    email = userinfo.get('email')
    if not email:
        return RedirectResponse(url="/")
        
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Check if user exists
    cursor.execute("SELECT * FROM users WHERE username=?", (email,))
    user = cursor.fetchone()
    
    if not user:
        # Create user with empty password
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (email, ""))
        
    # Generate secure session token
    session_token = str(uuid.uuid4())
    cursor.execute("UPDATE users SET session_token=? WHERE username=?", (session_token, email))
    conn.commit()
    conn.close()
    
    response = RedirectResponse(url="/")
    response.set_cookie(key="session_token", value=session_token, httponly=True, samesite="Lax")
    return response

@app.get("/api/me")
async def get_current_user(request: Request):
    session_token = request.cookies.get("session_token")
    if not session_token:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
        
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE session_token=?", (session_token,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return JSONResponse(status_code=401, content={"error": "Invalid session"})
        
    return {"username": row[0]}

# Connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                pass

manager = ConnectionManager()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    current_time = datetime.now(IST)
    current_hour = current_time.hour
    # The void is only accessible between 01:00 AM and 04:59 AM
    # i.e., hour 1, 2, 3, or 4 (IST)
    if not (1 <= current_hour < 5):
        await websocket.close(code=1008, reason="The void is closed.")
        return

    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                # Ensure the message has sender and text fields before broadcasting
                if "sender" in msg and "text" in msg:
                    await manager.broadcast(data)
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Mount frontend
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")