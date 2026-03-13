import asyncio
import json
import logging
import os
import random
import sqlite3
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from telethon import TelegramClient, errors
from telethon.tl.types import Channel, Chat

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

DATA_DIR = os.environ.get("DATA_DIR", ".")
DB_PATH = os.path.join(DATA_DIR, "broadcast.db")
SESSION_FILE = os.path.join(DATA_DIR, "user_session")

client = None
phone_code_hash = None
broadcast_status = {"running": False, "total": 0, "sent": 0, "failed": 0, "current_chat": "", "log": [], "finished": False}

def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS chat_lists (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, chats TEXT NOT NULL, created_at TEXT NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS templates (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, text TEXT NOT NULL, created_at TEXT NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS broadcast_history (id INTEGER PRIMARY KEY AUTOINCREMENT, message TEXT NOT NULL, total INTEGER, sent INTEGER, failed INTEGER, started_at TEXT, finished_at TEXT)""")
    conn.commit()
    conn.close()

@asynccontextmanager
async def lifespan(app):
    init_db()
    yield
    if client and client.is_connected():
        await client.disconnect()

app = FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

def get_client():
    if client is None:
        raise HTTPException(status_code=400, detail="Not connected.")
    return client

class ConfigRequest(BaseModel):
    api_id: int
    api_hash: str

class PhoneRequest(BaseModel):
    phone: str

class CodeRequest(BaseModel):
    code: str
    password: str = None

class BroadcastRequest(BaseModel):
    chat_ids: list
    message: str
    delay: float = 5.0
    random_delay: bool = False
    max_per_minute: int = 10

class SaveListRequest(BaseModel):
    name: str
    chat_ids: list

class SaveTemplateRequest(BaseModel):
    name: str
    text: str

@app.post("/api/connect")
async def connect(req: ConfigRequest):
    global client
    if client and client.is_connected():
        await client.disconnect()
    client = TelegramClient(SESSION_FILE, req.api_id, req.api_hash)
    await client.connect()
    is_auth = await client.is_user_authorized()
    return {"connected": True, "authorized": is_auth}

@app.post("/api/send_code")
async def send_code(req: PhoneRequest):
    global phone_code_hash
    c = get_client()
    result = await c.send_code_request(req.phone)
    phone_code_hash = result.phone_code_hash
    return {"sent": True}

@app.post("/api/verify_code")
async def verify_code(req: CodeRequest):
    global phone_code_hash
    c = get_client()
    try:
        await c.sign_in(phone=None, code=req.code, phone_code_hash=phone_code_hash)
    except errors.SessionPasswordNeededError:
        if not req.password:
            raise HTTPException(status_code=401, detail="2FA password required")
        await c.sign_in(password=req.password)
    me = await c.get_me()
    return {"authorized": True, "name": f"{me.first_name or ''} {me.last_name or ''}".strip(), "username": me.username}

@app.get("/api/me")
async def get_me():
    c = get_client()
    if not await c.is_user_authorized():
        raise HTTPException(status_code=401, detail="Not authorized")
    me = await c.get_me()
    return {"name": f"{me.first_name or ''} {me.last_name or ''}".strip(), "username": me.username, "id": me.id}

@app.post("/api/logout")
async def logout():
    global client
    if client:
        await client.log_out()
        client = None
    return {"logged_out": True}

@app.get("/api/chats")
async def get_chats():
    c = get_client()
    chats = []
    async for dialog in c.iter_dialogs():
        entity = dialog.entity
        if isinstance(entity, (Channel, Chat)):
            chats.append({"id": dialog.id, "name": dialog.name, "type": "channel" if isinstance(entity, Channel) and entity.broadcast else "group", "members": getattr(entity, "participants_count", None), "username": getattr(entity, "username", None)})
    return {"chats": chats}

@app.post("/api/broadcast/start")
async def start_broadcast(req: BroadcastRequest):
    global broadcast_status
    if broadcast_status["running"]:
        raise HTTPException(status_code=409, detail="Already running")
    broadcast_status = {"running": True, "total": len(req.chat_ids), "sent": 0, "failed": 0, "current_chat": "", "log": [], "finished": False}
    asyncio.create_task(_run_broadcast(req))
    return {"started": True}

@app.post("/api/broadcast/stop")
async def stop_broadcast():
    broadcast_status["running"] = False
    return {"stopped": True}

@app.get("/api/broadcast/status")
async def get_status():
    return broadcast_status

async def _run_broadcast(req: BroadcastRequest):
    global broadcast_status
    c = get_client()
    started_at = datetime.utcnow().isoformat()
    sent_times = []
    for i, chat_id in enumerate(req.chat_ids):
        if not broadcast_status["running"]:
            broadcast_status["log"].append("Stopped by user")
            break
        now = time.time()
        sent_times = [t for t in sent_times if now - t < 60]
        if len(sent_times) >= req.max_per_minute:
            wait = 60 - (now - sent_times[0])
            broadcast_status["log"].append(f"Rate limit - waiting {wait:.0f}s")
            await asyncio.sleep(wait)
        try:
            entity = await c.get_entity(chat_id)
            name = getattr(entity, "title", str(chat_id))
            broadcast_status["current_chat"] = name
            await c.send_message(entity, req.message)
            broadcast_status["sent"] += 1
            sent_times.append(time.time())
            broadcast_status["log"].append(f"Sent: {name}")
        except Exception as e:
            broadcast_status["failed"] += 1
            broadcast_status["log"].append(f"Failed [{chat_id}]: {e}")
        if i < len(req.chat_ids) - 1 and broadcast_status["running"]:
            delay = req.delay + (random.uniform(0, 10) if req.random_delay else 0)
            broadcast_status["log"].append(f"Waiting {delay:.1f}s")
            await asyncio.sleep(delay)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO broadcast_history (message, total, sent, failed, started_at, finished_at) VALUES (?,?,?,?,?,?)", (req.message[:200], broadcast_status["total"], broadcast_status["sent"], broadcast_status["failed"], started_at, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    broadcast_status["running"] = False
    broadcast_status["finished"] = True
    broadcast_status["current_chat"] = ""
    broadcast_status["log"].append(f"Done. Sent: {broadcast_status['sent']}, Failed: {broadcast_status['failed']}")

@app.get("/api/lists")
def get_lists():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id, name, chats, created_at FROM chat_lists ORDER BY id DESC").fetchall()
    conn.close()
    return {"lists": [{"id": r[0], "name": r[1], "chats": json.loads(r[2]), "created_at": r[3]} for r in rows]}

@app.post("/api/lists")
def save_list(req: SaveListRequest):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO chat_lists (name, chats, created_at) VALUES (?,?,?)", (req.name, json.dumps(req.chat_ids), datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return {"saved": True}

@app.delete("/api/lists/{list_id}")
def delete_list(list_id: int):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM chat_lists WHERE id=?", (list_id,))
    conn.commit()
    conn.close()
    return {"deleted": True}

@app.get("/api/templates")
def get_templates():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id, name, text, created_at FROM templates ORDER BY id DESC").fetchall()
    conn.close()
    return {"templates": [{"id": r[0], "name": r[1], "text": r[2], "created_at": r[3]} for r in rows]}

@app.post("/api/templates")
def save_template(req: SaveTemplateRequest):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO templates (name, text, created_at) VALUES (?,?,?)", (req.name, req.text, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return {"saved": True}

@app.delete("/api/templates/{tid}")
def delete_template(tid: int):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM templates WHERE id=?", (tid,))
    conn.commit()
    conn.close()
    return {"deleted": True}

@app.get("/api/history")
def get_history():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id, message, total, sent, failed, started_at, finished_at FROM broadcast_history ORDER BY id DESC LIMIT 50").fetchall()
    conn.close()
    return {"history": [{"id": r[0], "message": r[1], "total": r[2], "sent": r[3], "failed": r[4], "started_at": r[5], "finished_at": r[6]} for r in rows]}

@app.get("/health")
def health():
    return {"status": "ok"}
