import asyncio
import json
import logging
import os
import random
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, HTTPException, UploadFile, File, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from telethon import TelegramClient, errors
from telethon.tl.types import Channel, Chat

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

DATA_DIR = os.environ.get("DATA_DIR", ".")
DB_PATH = os.path.join(DATA_DIR, "broadcast.db")
SESSIONS_DIR = os.path.join(DATA_DIR, "sessions")
DEFAULT_API_ID = os.environ.get("TG_API_ID", "")
DEFAULT_API_HASH = os.environ.get("TG_API_HASH", "")

# ── Multi-session state ────────────────────────────────────────────────────────
clients: dict[str, TelegramClient] = {}
broadcast_statuses: dict[str, dict] = {}
phone_code_hashes: dict[str, str] = {}
saved_phones: dict[str, str] = {}
uploaded_files: dict[str, dict] = {}


def _default_status() -> dict:
    return {"running": False, "total": 0, "sent": 0, "failed": 0,
            "current_chat": "", "log": [], "finished": False}


def get_session_token(x_session_token: Optional[str] = Header(default=None)) -> str:
    if not x_session_token:
        raise HTTPException(status_code=401, detail="X-Session-Token header required")
    return x_session_token


def get_client(token: str) -> TelegramClient:
    c = clients.get(token)
    if c is None:
        raise HTTPException(status_code=400, detail="Not connected. Call /api/connect first.")
    return c


# ── DB ─────────────────────────────────────────────────────────────────────────
def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(SESSIONS_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS chat_lists (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, chats TEXT NOT NULL, created_at TEXT NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS templates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, text TEXT NOT NULL, created_at TEXT NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS broadcast_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_token TEXT,
        message TEXT NOT NULL, total INTEGER, sent INTEGER, failed INTEGER,
        started_at TEXT, finished_at TEXT)""")
    # Add session_token column if upgrading from old DB
    try:
        c.execute("ALTER TABLE broadcast_history ADD COLUMN session_token TEXT")
    except Exception:
        pass
    conn.commit()
    conn.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield
    for c in clients.values():
        if c.is_connected():
            await c.disconnect()


app = FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                   allow_headers=["*", "X-Session-Token"], expose_headers=["X-Session-Token"])


# ── Auth endpoints ─────────────────────────────────────────────────────────────
class ConfigRequest(BaseModel):
    api_id: int
    api_hash: str

class PhoneRequest(BaseModel):
    phone: str

class CodeRequest(BaseModel):
    code: str
    password: Optional[str] = None


@app.post("/api/connect")
async def connect(req: ConfigRequest, x_session_token: Optional[str] = Header(default=None)):
    # Generate token if not provided
    token = x_session_token or str(uuid.uuid4())

    c = clients.get(token)
    if c and c.is_connected():
        await c.disconnect()

    session_path = os.path.join(SESSIONS_DIR, token)
    c = TelegramClient(session_path, req.api_id, req.api_hash)
    await c.connect()
    clients[token] = c
    broadcast_statuses[token] = _default_status()

    is_auth = await c.is_user_authorized()
    return {"connected": True, "authorized": is_auth, "session_token": token}


@app.post("/api/send_code")
async def send_code(req: PhoneRequest, x_session_token: Optional[str] = Header(default=None)):
    token = get_session_token(x_session_token)
    c = get_client(token)
    result = await c.send_code_request(req.phone)
    phone_code_hashes[token] = result.phone_code_hash
    saved_phones[token] = req.phone
    return {"sent": True}


@app.post("/api/verify_code")
async def verify_code(req: CodeRequest, x_session_token: Optional[str] = Header(default=None)):
    token = get_session_token(x_session_token)
    c = get_client(token)
    try:
        await c.sign_in(phone=saved_phones.get(token), code=req.code,
                        phone_code_hash=phone_code_hashes.get(token))
    except errors.SessionPasswordNeededError:
        if not req.password:
            raise HTTPException(status_code=401, detail="2FA password required")
        await c.sign_in(password=req.password)
    me = await c.get_me()
    return {"authorized": True,
            "name": f"{me.first_name or ''} {me.last_name or ''}".strip(),
            "username": me.username}


@app.get("/api/me")
async def get_me(x_session_token: Optional[str] = Header(default=None)):
    token = get_session_token(x_session_token)
    c = get_client(token)
    if not await c.is_user_authorized():
        raise HTTPException(status_code=401, detail="Not authorized")
    me = await c.get_me()
    return {"name": f"{me.first_name or ''} {me.last_name or ''}".strip(),
            "username": me.username, "id": me.id}


@app.post("/api/logout")
async def logout(x_session_token: Optional[str] = Header(default=None)):
    token = get_session_token(x_session_token)
    c = clients.pop(token, None)
    if c:
        await c.log_out()
    broadcast_statuses.pop(token, None)
    uploaded_files.pop(token, None)
    return {"logged_out": True}


# ── Chats ──────────────────────────────────────────────────────────────────────
@app.get("/api/chats")
async def get_chats(x_session_token: Optional[str] = Header(default=None)):
    token = get_session_token(x_session_token)
    c = get_client(token)
    chats = []
    async for dialog in c.iter_dialogs():
        entity = dialog.entity
        if isinstance(entity, (Channel, Chat)):
            chats.append({
                "id": dialog.id, "name": dialog.name,
                "type": "channel" if isinstance(entity, Channel) and entity.broadcast else "group",
                "members": getattr(entity, "participants_count", None),
                "username": getattr(entity, "username", None),
            })
    return {"chats": chats}


# ── Upload ─────────────────────────────────────────────────────────────────────
@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...),
                      x_session_token: Optional[str] = Header(default=None)):
    token = get_session_token(x_session_token)
    upload_dir = os.path.join(DATA_DIR, "uploads", token)
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, file.filename)
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)
    uploaded_files[token] = {"path": file_path, "name": file.filename,
                              "mime": file.content_type, "size": len(content)}
    return {"uploaded": True, "name": file.filename, "size": len(content), "mime": file.content_type}


@app.delete("/api/upload")
async def clear_upload(x_session_token: Optional[str] = Header(default=None)):
    token = get_session_token(x_session_token)
    uf = uploaded_files.pop(token, None)
    if uf and os.path.exists(uf["path"]):
        os.remove(uf["path"])
    return {"cleared": True}


@app.get("/api/upload")
async def get_upload(x_session_token: Optional[str] = Header(default=None)):
    token = get_session_token(x_session_token)
    uf = uploaded_files.get(token)
    if not uf:
        return {"file": None}
    return {"file": {"name": uf["name"], "size": uf["size"], "mime": uf["mime"]}}


# ── Broadcast ──────────────────────────────────────────────────────────────────
class BroadcastRequest(BaseModel):
    chat_ids: list[int]
    message: str
    delay: float = 5.0
    random_delay: bool = False
    max_per_minute: int = 10


@app.post("/api/broadcast/start")
async def start_broadcast(req: BroadcastRequest,
                           x_session_token: Optional[str] = Header(default=None)):
    token = get_session_token(x_session_token)
    status = broadcast_statuses.get(token, _default_status())
    if status["running"]:
        raise HTTPException(status_code=409, detail="Broadcast already running")
    broadcast_statuses[token] = {
        "running": True, "total": len(req.chat_ids),
        "sent": 0, "failed": 0, "current_chat": "", "log": [], "finished": False,
    }
    asyncio.create_task(_run_broadcast(token, req))
    return {"started": True}


@app.post("/api/broadcast/stop")
async def stop_broadcast(x_session_token: Optional[str] = Header(default=None)):
    token = get_session_token(x_session_token)
    if token in broadcast_statuses:
        broadcast_statuses[token]["running"] = False
    return {"stopped": True}


@app.get("/api/broadcast/status")
async def get_status(x_session_token: Optional[str] = Header(default=None)):
    token = get_session_token(x_session_token)
    return broadcast_statuses.get(token, _default_status())


async def _run_broadcast(token: str, req: BroadcastRequest):
    c = get_client(token)
    status = broadcast_statuses[token]
    started_at = datetime.utcnow().isoformat()
    uf = uploaded_files.get(token)
    sent_times = []

    for i, chat_id in enumerate(req.chat_ids):
        if not status["running"]:
            status["log"].append("Stopped by user")
            break
        now = time.time()
        sent_times = [t for t in sent_times if now - t < 60]
        if len(sent_times) >= req.max_per_minute:
            wait = 60 - (now - sent_times[0])
            status["log"].append(f"Rate limit — waiting {wait:.0f}s")
            await asyncio.sleep(wait)
        try:
            entity = await asyncio.wait_for(c.get_entity(chat_id), timeout=15)
            name = getattr(entity, "title", str(chat_id))
            status["current_chat"] = name
            if uf and os.path.exists(uf["path"]):
                await c.send_file(entity, uf["path"], caption=req.message or None)
            else:
                await c.send_message(entity, req.message)
            status["sent"] += 1
            sent_times.append(time.time())
            status["log"].append(f"[OK] {name}")
        except Exception as e:
            status["failed"] += 1
            status["log"].append(f"[FAIL] [{chat_id}]: {e}")

        if i < len(req.chat_ids) - 1 and status["running"]:
            delay = req.delay + (random.uniform(0, 10) if req.random_delay else 0)
            status["log"].append(f"[WAIT] {delay:.1f}s...")
            await asyncio.sleep(delay)

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO broadcast_history (session_token, message, total, sent, failed, started_at, finished_at) VALUES (?,?,?,?,?,?,?)",
        (token, req.message[:200], status["total"], status["sent"], status["failed"],
         started_at, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    status["running"] = False
    status["finished"] = True
    status["current_chat"] = ""
    status["log"].append(f"[DONE] Sent: {status['sent']}, Failed: {status['failed']}")


# ── Lists ──────────────────────────────────────────────────────────────────────
class SaveListRequest(BaseModel):
    name: str
    chat_ids: list[int]

@app.get("/api/lists")
def get_lists():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id, name, chats, created_at FROM chat_lists ORDER BY id DESC").fetchall()
    conn.close()
    return {"lists": [{"id": r[0], "name": r[1], "chats": json.loads(r[2]), "created_at": r[3]} for r in rows]}

@app.post("/api/lists")
def save_list(req: SaveListRequest):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO chat_lists (name, chats, created_at) VALUES (?,?,?)",
                 (req.name, json.dumps(req.chat_ids), datetime.utcnow().isoformat()))
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


# ── Templates ──────────────────────────────────────────────────────────────────
class SaveTemplateRequest(BaseModel):
    name: str
    text: str

@app.get("/api/templates")
def get_templates():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id, name, text, created_at FROM templates ORDER BY id DESC").fetchall()
    conn.close()
    return {"templates": [{"id": r[0], "name": r[1], "text": r[2], "created_at": r[3]} for r in rows]}

@app.post("/api/templates")
def save_template(req: SaveTemplateRequest):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO templates (name, text, created_at) VALUES (?,?,?)",
                 (req.name, req.text, datetime.utcnow().isoformat()))
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


# ── History ────────────────────────────────────────────────────────────────────
@app.get("/api/history")
def get_history(x_session_token: Optional[str] = Header(default=None)):
    token = x_session_token  # optional — if no token show all
    conn = sqlite3.connect(DB_PATH)
    if token:
        rows = conn.execute(
            "SELECT id, message, total, sent, failed, started_at, finished_at FROM broadcast_history "
            "WHERE session_token=? OR session_token IS NULL ORDER BY id DESC LIMIT 50", (token,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, message, total, sent, failed, started_at, finished_at FROM broadcast_history "
            "ORDER BY id DESC LIMIT 50"
        ).fetchall()
    conn.close()
    return {"history": [
        {"id": r[0], "message": r[1], "total": r[2], "sent": r[3],
         "failed": r[4], "started_at": r[5], "finished_at": r[6]}
        for r in rows
    ]}


@app.get("/health")
def health():
    return {"status": "ok", "sessions": len(clients)}
