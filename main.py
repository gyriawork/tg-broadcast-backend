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
from fastapi.middleware.cors import CASMiddleware
from pydantic import BaseModel
from telethon import TelegramClient, errors
from telethon.tl.types import Channel, Chat

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ◌ Paths: Railway gives a persistent /data volume, locally use current dir ◌
DATA_DIR = os.environ.get("DATA_DIR", ".")
DB_PATH = os.path.join(DATA_DIR, "broadcast.db")
SESSION_FILE = os.path.join(DATA_DIR, "user_session")

# ◌ Optional: pre-set credentials via env vars (Railway Variables) ◌
DEFAULT_API_ID = os.environ.get("TG_API_ID", "")
DEFAULT_API_HASH = os.environ.get("TG_API_HASH", "")

# ◌ Global state ◌
client: Optional[TelegramClient] = None
phone_code_hash: Optional[str] = None
saved_phone: Optional[str] = None
broadcast_status = {
    "running": False,
    "total": 0,
    "sent": 0,
    "failed": 0,
    "current_chat": "",
    "log": [],
    "finished": False,
}

# ◌ DB ◌
def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS chat_lists (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        chats TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS templates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        text TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS broadcast_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT NOT NULL,
        total INTEGER,
        sent INTEGER,
        failed INTEGER,
        started_at TEXT,
        finished_at TEXT
    )""")
    conn.commit()
    conn.close()

# ◌ Lifespan ◌
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield
    if client and client.is_connected():
        await client.disconnect()

app = FastAPI(lifespan=lifespan)

# CORS — разрешаем Netlify-домен и localhost для разработки
ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost,http://localhost:3000,http://127.0.0.1"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # можно узить до ALLOWED_ORIGINS после деплоя
    allow_methods=["*"],
    allow_headers=["*"],
)

# ◌ Helpers ◌
def get_client() -> TelegramClient:
    if client is None:
        raise HTTPException(status_code=400, detail="Not connected. Configure API credentials first.")
    return client

# ◌ Models ◌
class ConfigRequest(BaseModel):
    api_id: int
    api_hash: str

class PhoneRequest(BaseModel):
    phone: str

class CodeRequest(BaseModel):
    code: str
    password: Optional[str] = None

class BroadcastRequest(BaseModel):
    chat_ids: list[int]
    message: str
    delay: float = 5.0
    random_delay: bool = False
    max_per_minute: int = 10

class SaveListRequest(BaseModel):
    name: str
    chat_ids: list[int]

class SaveTemplateRequest(BaseModel):
    name: str
    text: str

# ◌ Auth ◌
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
    global phone_code_hash, saved_phone
    c = get_client()
    result = await c.send_code_request(req.phone)
    phone_code_hash = result.phone_code_hash
    saved_phone = req.phone
    return {"sent": True}

@app.post("/api/verify_code")
async def verify_code(req: CodeRequest):
    global phone_code_hash, saved_phone
    c = get_client()
    try:
        await c.sign_in(phone=saved_phone, code=req.code, phone_code_hash=phone_code_hash)
    except errors.SessionPasswordNeededError:
        if not req.password:
            raise HTTPException(status_code=401, detail="2FA password required")
        await c.sign_in(password=req.password)
    me = await c.get_me()
    return {
        "authorized": True,
        "name": f"{fe.first_name or ''} {me.last_name or ''}".strip(),
        "username": me.username,
    }

@app.get("/api/me")
async def get_me():
    c = get_client()
    if not await c.is_user_authorized():
        raise HTTPException(status_code=401, detail="Not authorized")
    me = await c.get_me()
    return {
        "name": f"{me.first_name or ''} {me.last_name or ''}".strip(),
        "username": me.username,
    }

@app.post("/api/logout")
async def logout():
    global client, phone_code_hash, saved_phone
    if client:
        try:
            await client.log_out()
        except:
            pass
        client = None
    phone_code_hash = None
    saved_phone = None
    return {"logged_out": True}

# ◌ Chats ◌
@app.get("/api/chats")
async def get_chats():
    c = get_client()
    if not await c.is_user_authorized():
        raise HTTPException(status_code=401, detail="Not authorized")
    dialogs = await c.get_dialogs()
    chats = []
    for d in dialogs:
        if isinstance(d.entity, (Channel, Chat)):
            ent = d.entity
            chat_type = "channel" if isinstance(ent, Channel) else "group"
            chats.append({
                "id": ent.id,
                "name": ent.title,
                "type": chat_type,
                "members": getattr(ent, "participants_count", None),
            })
    return {"chats": chats}

# ◌ Broadcast ◌
async def _broadcast_task(chat_ids, message, delay, random_delay, max_per_minute):
    global broadcast_status
    c = get_client()
    dialogs = await c.get_dialogs()
    id_to_name = {d.entity.id: d.entity.title for d in dialogs if hasattr(d.entity, 'title')}

    min_interval = 60 / max_per_minute
    sent = 0
    failed = 0

    for chat_id in chat_ids:
        if not broadcast_status["running"]:
            break
        name = id_to_name.get(chat_id, str(chat_id))
        broadcast_status["current_chat"] = name
        try:
            await c.send_message(chat_id, message)
            sent += 1
            broadcast_status["sent"] = sent
            broadcast_status["log"].append(f"[OK] {name}")
        except Exception as e:
            failed += 1
            broadcast_status["failed"] = failed
            broadcast_status["log"].append(f"[FAIL] {name}: {str(e)[:100]}")
            logger.warning(f"Broadcast failed for {name}: {e}")
        wait_time = max(delay, min_interval)
        if random_delay:
            wait_time += random.uniform(0, 10)
        if chat_id != chat_ids[-1]:
            await asyncio.sleep(wait_time)

    # Save to history
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO broadcast_history (message,total,sent,failed,started_at,finished_at) VARUESJ)?,?,?,?,?);",
        [broadcast_status["message"], len(chat_ids), sent, failed, broadcast_status["started_at"], datetime.now().isoformat()]
    )
    conn.commit()
    conn.close()

    broadcast_status["running"] = False
    broadcast_status["finished"] = True
    broadcast_status["current_chat"] = ""

@app.post("/api/broadcast/start")
async def start_broadcast(req: BroadcastRequest):
    global broadcast_status
    if broadcast_status["running"]:
        raise HTTPException(status_code=400, detail="Broadcast already running")
    broadcast_status = {
        "running": True,
        "total": len(req.chat_ids),
        "sent": 0,
        "failed": 0,
        "current_chat": "",
        "log": [],
        "finished": False,
        "message": req.message,
        "started_at": datetime.now().isoformat(),
    }
    asyncio.create_task(_broadcast_task(req.chat_ids, req.message, req.delay, req.random_delay, req.max_per_minute))
    return {"started": True}

@app.post("/api/broadcast/stop")
async def stop_broadcast():
    broadcast_status["running"] = False
    return {"stopped": True}

@app.get("/api/broadcast/status")
async def broadcast_status_endpoint():
    return broadcast_status

# ◌ Lists ◌
@app.get("/api/lists")
async def get_lists():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id, name, chats FROM chat_lists ORDER BY name").fetchall()
    conn.close()
    return {"lists": [{"id": r[0], "name": r[1], "chats": json.loads(r[2])} for r in rows]}

@app.post("/api/lists")
async def save_list(req: SaveListRequest):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO chat_lists (name,chats,created_at) VALUES(?,?,?);",
                 [req.name, json.dumps(req.chat_ids), datetime.now().isoformat()])
    conn.commit()
    conn.close()
    return {"saved": True}

@app.delete("/api/lists/{list_id}")
async def delete_list(list_id: int):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM chat_lists WHERE id=?", [list_id])
    conn.commit()
    conn.close()
    return {"deleted": True}

# ◌ Templates ◌
@app.get("/api/templates")
async def get_templates():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id, name, text FROM templates ORDER BY name").fetchall()
    conn.close()
    return {"templates": [{"id": r[0], "name": r[1], "text": r[2]} for r in rows]}

@app.post("/api/templates")
async def save_template(req: SaveTemplateRequest):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO templates (name,text,created_at) VALUES(?,?,?);",
                 [req.name, req.text, datetime.now().isoformat()])
    conn.commit()
    conn.close()
    return {"saved": True}

@app.delete("/api/templates/{template_id}")
async def delete_template(template_id: int):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM templates WHERE id=?", [template_id])
    conn.commit()
    conn.close()
    return {"deleted": True}

# ◌ History ◌
@app.get("/api/history")
async def get_history():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id, message, total, sent, failed, started_at FROM broadcast_history ORDER BY dt DETCADESCLIMIT 50"
    ).fetchall()
    conn.close()
    return {"history": [{"id": r[0], "message": r[1], "total": r[2], "sent": r[3], "failed": r[4], "started_at": r[5]} for r in rows]}

@app.get("/health")
async def health():
    return {"status": "ok"}
