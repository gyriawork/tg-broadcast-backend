import asyncio
import json
import logging
import os
import random
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from telethon import TelegramClient, errors
from telethon.tl.types import Channel, Chat

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
DATA_DIR     = os.environ.get("DATA_DIR", ".")
DB_PATH      = os.path.join(DATA_DIR, "broadcast.db")
SESSIONS_DIR = os.path.join(DATA_DIR, "sessions")

# ── JWT / password config ─────────────────────────────────────────────────────
JWT_SECRET    = os.environ.get("JWT_SECRET", "change-me-in-production-please")
JWT_ALGORITHM = "HS256"
JWT_EXP_HOURS = 72
pwd_ctx       = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)

# ── Global per-session state ──────────────────────────────────────────────────
tg_clients:       dict[str, TelegramClient] = {}
broadcast_statuses: dict[str, dict]         = {}
phone_code_hashes:  dict[str, str]          = {}
saved_phones:       dict[str, str]          = {}
uploaded_files:     dict[str, dict]         = {}

# ── DB ────────────────────────────────────────────────────────────────────────
def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(SESSIONS_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # ── app users (RBAC) ──
    c.execute("""CREATE TABLE IF NOT EXISTS app_users (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        username  TEXT    NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role      TEXT    NOT NULL DEFAULT 'user',
        created_at TEXT   NOT NULL,
        created_by INTEGER
    )""")
    # Seed default admin if table empty
    row = c.execute("SELECT COUNT(*) FROM app_users").fetchone()
    if row[0] == 0:
        default_pw = os.environ.get("ADMIN_PASSWORD", "admin123")
        hashed = pwd_ctx.hash(default_pw)
        c.execute(
            "INSERT INTO app_users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
            ("admin", hashed, "admin", datetime.utcnow().isoformat())
        )
        logger.info(f"Created default admin — password: {default_pw}")
    # ── chat lists ──
    c.execute("""CREATE TABLE IF NOT EXISTS chat_lists (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        chats TEXT NOT NULL,
        created_at TEXT NOT NULL,
        owner_app_user_id INTEGER
    )""")
    # ── templates ──
    c.execute("""CREATE TABLE IF NOT EXISTS templates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        text TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""")
    # ── broadcast history ──
    c.execute("""CREATE TABLE IF NOT EXISTS broadcast_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT NOT NULL,
        total INTEGER,
        sent INTEGER,
        failed INTEGER,
        started_at TEXT,
        finished_at TEXT,
        tg_session_token TEXT,
        app_user_id INTEGER,
        app_username TEXT
    )""")
    # migrate: add columns if missing
    cols = [r[1] for r in c.execute("PRAGMA table_info(broadcast_history)").fetchall()]
    if "tg_session_token" not in cols:
        c.execute("ALTER TABLE broadcast_history ADD COLUMN tg_session_token TEXT")
    if "app_user_id" not in cols:
        c.execute("ALTER TABLE broadcast_history ADD COLUMN app_user_id INTEGER")
    if "app_username" not in cols:
        c.execute("ALTER TABLE broadcast_history ADD COLUMN app_username TEXT")
    conn.commit()
    conn.close()

# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield
    for c in tg_clients.values():
        if c.is_connected():
            await c.disconnect()

app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

# ── JWT helpers ───────────────────────────────────────────────────────────────
def create_jwt(user_id: int, username: str, role: str) -> str:
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXP_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

def get_current_app_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> dict:
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return decode_jwt(credentials.credentials)

def require_admin(user: dict = Depends(get_current_app_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user

# ── TG session helpers ────────────────────────────────────────────────────────
def get_tg_session_token(x_session_token: Optional[str] = Header(None)) -> str:
    if not x_session_token:
        raise HTTPException(status_code=400, detail="Missing X-Session-Token header")
    return x_session_token

def get_tg_client(token: str) -> TelegramClient:
    c = tg_clients.get(token)
    if not c:
        raise HTTPException(status_code=400, detail="No Telegram session. Connect first.")
    return c

def get_broadcast_status(token: str) -> dict:
    if token not in broadcast_statuses:
        broadcast_statuses[token] = {
            "running": False, "total": 0, "sent": 0, "failed": 0,
            "current_chat": "", "log": [], "finished": False,
        }
    return broadcast_statuses[token]

# ═════════════════════════════════════════════════════════════════════════════
# ── RBAC: App auth endpoints ──────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════════════════════

class AppLoginRequest(BaseModel):
    username: str
    password: str

class CreateUserRequest(BaseModel):
    username: str
    role: str = "user"         # "user" | "admin"
    password: Optional[str] = None  # if None — auto-generate

@app.post("/api/auth/login")
def app_login(req: AppLoginRequest):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id, username, password_hash, role FROM app_users WHERE username=?",
        (req.username,)
    ).fetchone()
    conn.close()
    if not row or not pwd_ctx.verify(req.password, row[2]):
        raise HTTPException(status_code=401, detail="Wrong username or password")
    token = create_jwt(row[0], row[1], row[3])
    return {"token": token, "username": row[1], "role": row[3], "id": row[0]}

@app.get("/api/auth/me")
def app_me(user: dict = Depends(get_current_app_user)):
    return {"id": user["sub"], "username": user["username"], "role": user["role"]}

@app.get("/api/auth/users")
def list_users(admin: dict = Depends(require_admin)):
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id, username, role, created_at, created_by FROM app_users ORDER BY id"
    ).fetchall()
    conn.close()
    return {"users": [
        {"id": r[0], "username": r[1], "role": r[2], "created_at": r[3], "created_by": r[4]}
        for r in rows
    ]}

@app.post("/api/auth/users")
def create_user(req: CreateUserRequest, admin: dict = Depends(require_admin)):
    password = req.password or secrets.token_urlsafe(12)
    hashed = pwd_ctx.hash(password)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "INSERT INTO app_users (username, password_hash, role, created_at, created_by) VALUES (?,?,?,?,?)",
            (req.username, hashed, req.role, datetime.utcnow().isoformat(), int(admin["sub"]))
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=409, detail="Username already exists")
    conn.close()
    return {"created": True, "username": req.username, "password": password, "role": req.role}

@app.delete("/api/auth/users/{user_id}")
def delete_user(user_id: int, admin: dict = Depends(require_admin)):
    if str(user_id) == str(admin["sub"]):
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM app_users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return {"deleted": True}

@app.put("/api/auth/users/{user_id}/password")
def reset_password(user_id: int, admin: dict = Depends(require_admin)):
    new_pw = secrets.token_urlsafe(12)
    hashed = pwd_ctx.hash(new_pw)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE app_users SET password_hash=? WHERE id=?", (hashed, user_id))
    conn.commit()
    conn.close()
    return {"password": new_pw}

# ═════════════════════════════════════════════════════════════════════════════
# ── Telegram session endpoints ────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════════════════════

class ConfigRequest(BaseModel):
    api_id: int
    api_hash: str
    session_token: Optional[str] = None

class PhoneRequest(BaseModel):
    phone: str

class CodeRequest(BaseModel):
    code: str
    password: Optional[str] = None

@app.post("/api/connect")
async def connect(req: ConfigRequest, _: dict = Depends(get_current_app_user)):
    token = req.session_token or secrets.token_hex(16)
    if token in tg_clients and tg_clients[token].is_connected():
        await tg_clients[token].disconnect()
    session_path = os.path.join(SESSIONS_DIR, token)
    c = TelegramClient(session_path, req.api_id, req.api_hash)
    await c.connect()
    tg_clients[token] = c
    is_auth = await c.is_user_authorized()
    return {"connected": True, "authorized": is_auth, "session_token": token}

@app.post("/api/send_code")
async def send_code(req: PhoneRequest, token: str = Depends(get_tg_session_token),
                    _: dict = Depends(get_current_app_user)):
    c = get_tg_client(token)
    result = await c.send_code_request(req.phone)
    phone_code_hashes[token] = result.phone_code_hash
    saved_phones[token] = req.phone
    return {"sent": True}

@app.post("/api/verify_code")
async def verify_code(req: CodeRequest, token: str = Depends(get_tg_session_token),
                      _: dict = Depends(get_current_app_user)):
    c = get_tg_client(token)
    try:
        await c.sign_in(phone=saved_phones.get(token), code=req.code,
                        phone_code_hash=phone_code_hashes.get(token))
    except errors.SessionPasswordNeededError:
        if not req.password:
            raise HTTPException(status_code=401, detail="2FA password required")
        await c.sign_in(password=req.password)
    me = await c.get_me()
    return {
        "authorized": True,
        "name": f"{me.first_name or ''} {me.last_name or ''}".strip(),
        "username": me.username,
    }

@app.get("/api/me")
async def get_tg_me(token: str = Depends(get_tg_session_token),
                    _: dict = Depends(get_current_app_user)):
    c = get_tg_client(token)
    if not await c.is_user_authorized():
        raise HTTPException(status_code=401, detail="Not authorized")
    me = await c.get_me()
    return {
        "name": f"{me.first_name or ''} {me.last_name or ''}".strip(),
        "username": me.username,
        "id": me.id,
    }

@app.post("/api/logout")
async def logout(token: str = Depends(get_tg_session_token),
                 _: dict = Depends(get_current_app_user)):
    c = tg_clients.pop(token, None)
    if c:
        try:
            await c.log_out()
        except Exception:
            pass
    for d in [broadcast_statuses, phone_code_hashes, saved_phones, uploaded_files]:
        d.pop(token, None)
    return {"logged_out": True}

# ── Chats ─────────────────────────────────────────────────────────────────────
@app.get("/api/chats")
async def get_chats(token: str = Depends(get_tg_session_token),
                    _: dict = Depends(get_current_app_user)):
    c = get_tg_client(token)
    chats = []
    async for dialog in c.iter_dialogs():
        entity = dialog.entity
        if isinstance(entity, (Channel, Chat)):
            chats.append({
                "id": dialog.id,
                "name": dialog.name,
                "type": "channel" if isinstance(entity, Channel) and entity.broadcast else "group",
                "members": getattr(entity, "participants_count", None),
                "username": getattr(entity, "username", None),
            })
    return {"chats": chats}

# ── File upload ───────────────────────────────────────────────────────────────
@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...),
                      token: str = Depends(get_tg_session_token),
                      _: dict = Depends(get_current_app_user)):
    upload_dir = os.path.join(DATA_DIR, "uploads", token)
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, file.filename)
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)
    uploaded_files[token] = {
        "path": file_path, "name": file.filename,
        "mime": file.content_type, "size": len(content),
    }
    return {"uploaded": True, "name": file.filename, "size": len(content), "mime": file.content_type}

@app.delete("/api/upload")
async def clear_upload(token: str = Depends(get_tg_session_token),
                       _: dict = Depends(get_current_app_user)):
    uf = uploaded_files.pop(token, None)
    if uf and os.path.exists(uf["path"]):
        os.remove(uf["path"])
    return {"cleared": True}

@app.get("/api/upload")
async def get_upload(token: str = Depends(get_tg_session_token),
                     _: dict = Depends(get_current_app_user)):
    uf = uploaded_files.get(token)
    if not uf:
        return {"file": None}
    return {"file": {"name": uf["name"], "size": uf["size"], "mime": uf["mime"]}}

# ── Broadcast ─────────────────────────────────────────────────────────────────
class BroadcastRequest(BaseModel):
    chat_ids: list[int]
    message: Optional[str] = None
    delay: float = 5.0
    random_delay: bool = False
    max_per_minute: int = 10
    file_id: Optional[str] = None
    # Admin-only: broadcast using another user's TG session
    as_session_token: Optional[str] = None

@app.post("/api/broadcast/start")
async def start_broadcast(req: BroadcastRequest,
                          token: str = Depends(get_tg_session_token),
                          app_user: dict = Depends(get_current_app_user)):
    # Admin can broadcast as another TG session
    effective_token = token
    if req.as_session_token and app_user.get("role") == "admin":
        effective_token = req.as_session_token

    status = get_broadcast_status(effective_token)
    if status["running"]:
        raise HTTPException(status_code=409, detail="Broadcast already running")

    broadcast_statuses[effective_token] = {
        "running": True, "total": len(req.chat_ids), "sent": 0, "failed": 0,
        "current_chat": "", "log": [], "finished": False,
    }
    asyncio.create_task(_run_broadcast(req, effective_token, app_user))
    return {"started": True}

@app.post("/api/broadcast/stop")
async def stop_broadcast(token: str = Depends(get_tg_session_token),
                         _: dict = Depends(get_current_app_user)):
    if token in broadcast_statuses:
        broadcast_statuses[token]["running"] = False
    return {"stopped": True}

@app.get("/api/broadcast/status")
async def get_status(token: str = Depends(get_tg_session_token),
                     _: dict = Depends(get_current_app_user)):
    return get_broadcast_status(token)

async def _run_broadcast(req: BroadcastRequest, token: str, app_user: dict):
    c = get_tg_client(token)
    uf = uploaded_files.get(token)
    status = broadcast_statuses[token]
    started_at = datetime.utcnow().isoformat()
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
            entity = await c.get_entity(chat_id)
            name = getattr(entity, "title", str(chat_id))
            status["current_chat"] = name
            if uf and os.path.exists(uf["path"]):
                await c.send_file(entity, uf["path"], caption=req.message or None)
            else:
                await c.send_message(entity, req.message)
            status["sent"] += 1
            sent_times.append(time.time())
            status["log"].append(f"OK: {name}")
        except Exception as e:
            status["failed"] += 1
            status["log"].append(f"FAIL [{chat_id}]: {e}")

        if i < len(req.chat_ids) - 1 and status["running"]:
            delay = req.delay + (random.uniform(0, 10) if req.random_delay else 0)
            await asyncio.sleep(delay)

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO broadcast_history
           (message, total, sent, failed, started_at, finished_at, tg_session_token, app_user_id, app_username)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (
            (req.message or "")[:200], status["total"], status["sent"], status["failed"],
            started_at, datetime.utcnow().isoformat(),
            token, int(app_user["sub"]), app_user["username"]
        )
    )
    conn.commit()
    conn.close()

    status["running"] = False
    status["finished"] = True
    status["current_chat"] = ""
    status["log"].append(f"Done. Sent: {status['sent']}, Failed: {status['failed']}")

# ── Lists ─────────────────────────────────────────────────────────────────────
class SaveListRequest(BaseModel):
    name: str
    chat_ids: list[int]

@app.get("/api/lists")
def get_lists(app_user: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    if app_user["role"] == "admin":
        rows = conn.execute(
            "SELECT id, name, chats, created_at FROM chat_lists ORDER BY id DESC"
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, name, chats, created_at FROM chat_lists WHERE owner_app_user_id=? ORDER BY id DESC",
            (int(app_user["sub"]),)
        ).fetchall()
    conn.close()
    return {"lists": [{"id": r[0], "name": r[1], "chats": json.loads(r[2]), "created_at": r[3]} for r in rows]}

@app.post("/api/lists")
def save_list(req: SaveListRequest, app_user: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO chat_lists (name, chats, created_at, owner_app_user_id) VALUES (?,?,?,?)",
        (req.name, json.dumps(req.chat_ids), datetime.utcnow().isoformat(), int(app_user["sub"]))
    )
    conn.commit()
    conn.close()
    return {"saved": True}

@app.delete("/api/lists/{list_id}")
def delete_list(list_id: int, app_user: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    if app_user["role"] == "admin":
        conn.execute("DELETE FROM chat_lists WHERE id=?", (list_id,))
    else:
        conn.execute("DELETE FROM chat_lists WHERE id=? AND owner_app_user_id=?",
                     (list_id, int(app_user["sub"])))
    conn.commit()
    conn.close()
    return {"deleted": True}

# ── Templates ─────────────────────────────────────────────────────────────────
class SaveTemplateRequest(BaseModel):
    name: str
    text: str

@app.get("/api/templates")
def get_templates(_: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id, name, text, created_at FROM templates ORDER BY id DESC").fetchall()
    conn.close()
    return {"templates": [{"id": r[0], "name": r[1], "text": r[2], "created_at": r[3]} for r in rows]}

@app.post("/api/templates")
def save_template(req: SaveTemplateRequest, _: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO templates (name, text, created_at) VALUES (?,?,?)",
                 (req.name, req.text, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return {"saved": True}

@app.delete("/api/templates/{tid}")
def delete_template(tid: int, _: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM templates WHERE id=?", (tid,))
    conn.commit()
    conn.close()
    return {"deleted": True}

# ── History ───────────────────────────────────────────────────────────────────
@app.get("/api/history")
def get_history(app_user: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    if app_user["role"] == "admin":
        # Admin sees all history with username
        rows = conn.execute(
            """SELECT id, message, total, sent, failed, started_at, finished_at, app_username
               FROM broadcast_history ORDER BY id DESC LIMIT 100"""
        ).fetchall()
        result = [
            {"id": r[0], "message": r[1], "total": r[2], "sent": r[3],
             "failed": r[4], "started_at": r[5], "finished_at": r[6],
             "started_by": r[7] or "unknown"}
            for r in rows
        ]
    else:
        # User sees only their own history
        rows = conn.execute(
            """SELECT id, message, total, sent, failed, started_at, finished_at
               FROM broadcast_history WHERE app_user_id=? ORDER BY id DESC LIMIT 50""",
            (int(app_user["sub"]),)
        ).fetchall()
        result = [
            {"id": r[0], "message": r[1], "total": r[2], "sent": r[3],
             "failed": r[4], "started_at": r[5], "finished_at": r[6],
             "started_by": app_user["username"]}
            for r in rows
        ]
    conn.close()
    return {"history": result}

# ── Admin: list active TG sessions ───────────────────────────────────────────
@app.get("/api/admin/sessions")
def admin_sessions(admin: dict = Depends(require_admin)):
    return {"sessions": list(tg_clients.keys())}

# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "sessions": len(tg_clients)}
