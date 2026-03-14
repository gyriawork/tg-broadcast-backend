import asyncio
import json
import logging
import os
import random
import secrets
import shutil
import sqlite3
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
import jwt as pyjwt

from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Depends, Header
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from telethon import TelegramClient, errors
from telethon.tl.types import Channel, Chat, User as TgUser

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
bearer_scheme = HTTPBearer(auto_error=False)

# ── Upload config ─────────────────────────────────────────────────────────────
MAX_UPLOAD_BYTES  = 50 * 1024 * 1024   # 50 MB hard limit
UPLOAD_TTL_HOURS  = 24                  # auto-delete files older than 24h

# ── Login rate limiting ───────────────────────────────────────────────────────
_login_attempts: dict[str, list[float]] = {}   # ip -> [timestamps]
LOGIN_WINDOW_SEC  = 60
LOGIN_MAX_ATTEMPTS = 10

def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def verify_password(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    except Exception:
        return False

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
        hashed = hash_password(default_pw)
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
    # ── migrations: add columns if missing ──
    existing_cols = {row[1] for row in c.execute("PRAGMA table_info(chat_lists)")}
    if "owner_app_user_id" not in existing_cols:
        c.execute("ALTER TABLE chat_lists ADD COLUMN owner_app_user_id INTEGER")
        logger.info("Migrated chat_lists: added owner_app_user_id")
    hist_cols = {row[1] for row in c.execute("PRAGMA table_info(broadcast_history)")}
    if "app_user_id" not in hist_cols:
        c.execute("ALTER TABLE broadcast_history ADD COLUMN app_user_id INTEGER")
        logger.info("Migrated broadcast_history: added app_user_id")
    if "app_username" not in hist_cols:
        c.execute("ALTER TABLE broadcast_history ADD COLUMN app_username TEXT")
        logger.info("Migrated broadcast_history: added app_username")
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
    if "log" not in cols:
        c.execute("ALTER TABLE broadcast_history ADD COLUMN log TEXT")
        logger.info("Migrated broadcast_history: added log")
    conn.commit()
    conn.close()

# ── Lifespan ──────────────────────────────────────────────────────────────────
async def _sqlite_backup_loop():
    """Daily SQLite backup to /data/backups/"""
    backup_dir = os.path.join(DATA_DIR, "backups")
    os.makedirs(backup_dir, exist_ok=True)
    while True:
        await asyncio.sleep(86400)  # 24h
        try:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            dst = os.path.join(backup_dir, f"broadcast_{ts}.db")
            src_conn = sqlite3.connect(DB_PATH)
            dst_conn = sqlite3.connect(dst)
            src_conn.backup(dst_conn)
            src_conn.close()
            dst_conn.close()
            # Keep only last 7 backups
            backups = sorted(
                [f for f in os.listdir(backup_dir) if f.endswith(".db")],
                reverse=True
            )
            for old in backups[7:]:
                os.remove(os.path.join(backup_dir, old))
            logger.info(f"SQLite backup saved: {dst}")
        except Exception as e:
            logger.error(f"SQLite backup failed: {e}")

async def _cleanup_old_uploads():
    """Delete upload folders older than UPLOAD_TTL_HOURS. Runs every hour."""
    while True:
        await asyncio.sleep(3600)
        cutoff = time.time() - UPLOAD_TTL_HOURS * 3600
        uploads_root = os.path.join(DATA_DIR, "uploads")
        if not os.path.isdir(uploads_root):
            continue
        for folder in os.listdir(uploads_root):
            folder_path = os.path.join(uploads_root, folder)
            try:
                if os.path.isdir(folder_path) and os.path.getmtime(folder_path) < cutoff:
                    shutil.rmtree(folder_path, ignore_errors=True)
                    uploaded_files.pop(folder, None)
                    logger.info(f"Cleaned up old upload folder: {folder}")
            except Exception as e:
                logger.warning(f"Cleanup error for {folder}: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    asyncio.create_task(_cleanup_old_uploads())
    asyncio.create_task(_sqlite_backup_loop())
    yield
    # Graceful shutdown: stop running broadcasts and save to history
    for token, status in list(broadcast_statuses.items()):
        if status.get("running"):
            status["running"] = False
            status["finished"] = True
            status["log"].append("Stopped: server shutdown")
            try:
                conn = sqlite3.connect(DB_PATH)
                conn.execute(
                    """INSERT INTO broadcast_history
                       (message, total, sent, failed, started_at, finished_at, tg_session_token, log)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    ("(shutdown)", status["total"], status["sent"], status["failed"],
                     datetime.utcnow().isoformat(), datetime.utcnow().isoformat(),
                     token, json.dumps(status["log"]))
                )
                conn.commit()
                conn.close()
            except Exception as e:
                logger.error(f"Shutdown save failed: {e}")
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
    return pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_jwt(token: str) -> dict:
    try:
        return pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except pyjwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

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
def app_login(req: AppLoginRequest, request: Request):
    # Rate limit by IP
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    attempts = _login_attempts.get(ip, [])
    attempts = [t for t in attempts if now - t < LOGIN_WINDOW_SEC]
    if len(attempts) >= LOGIN_MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many login attempts — wait a minute")
    attempts.append(now)
    _login_attempts[ip] = attempts

    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id, username, password_hash, role FROM app_users WHERE username=?",
        (req.username,)
    ).fetchone()
    conn.close()
    if not row or not verify_password(req.password, row[2]):
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
    hashed = hash_password(password)
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

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

@app.put("/api/auth/me/password")
def change_my_password(req: ChangePasswordRequest, current: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT password_hash FROM app_users WHERE id=?", (int(current["sub"]),)).fetchone()
    if not row or not verify_password(req.old_password, row[0]):
        conn.close()
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    conn.execute("UPDATE app_users SET password_hash=? WHERE id=?", (hash_password(req.new_password), int(current["sub"])))
    conn.commit()
    conn.close()
    return {"ok": True}

@app.put("/api/auth/users/{user_id}/password")
def reset_password(user_id: int, admin: dict = Depends(require_admin)):
    new_pw = secrets.token_urlsafe(12)
    hashed = hash_password(new_pw)
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
    try:
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
            elif isinstance(entity, TgUser) and not entity.bot and not entity.is_self:
                first = entity.first_name or ""
                last  = entity.last_name or ""
                name  = (first + " " + last).strip() or entity.username or str(dialog.id)
                chats.append({
                    "id": dialog.id,
                    "name": name,
                    "type": "user",
                    "members": None,
                    "username": getattr(entity, "username", None),
                })
    except errors.AuthKeyUnregisteredError:
        # Session file is invalid — clean up and tell client to re-auth
        tg_clients.pop(token, None)
        session_path = os.path.join(DATA_DIR, "sessions", f"{token}.session")
        if os.path.exists(session_path):
            os.remove(session_path)
        raise HTTPException(status_code=401, detail="Session expired — please reconnect your Telegram account")
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
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large — max {MAX_UPLOAD_BYTES // (1024*1024)} MB allowed"
        )
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

    def validate_message(self):
        if self.message and len(self.message) > 4096:
            raise HTTPException(status_code=400, detail="Message exceeds 4096 characters (Telegram limit)")

@app.post("/api/broadcast/start")
async def start_broadcast(req: BroadcastRequest,
                          token: str = Depends(get_tg_session_token),
                          app_user: dict = Depends(get_current_app_user)):
    # Admin can broadcast as another TG session
    effective_token = token
    if req.as_session_token and app_user.get("role") == "admin":
        effective_token = req.as_session_token

    req.validate_message()
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
           (message, total, sent, failed, started_at, finished_at, tg_session_token, app_user_id, app_username, log)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (
            (req.message or "")[:200], status["total"], status["sent"], status["failed"],
            started_at, datetime.utcnow().isoformat(),
            token, int(app_user["sub"]), app_user["username"],
            json.dumps(status["log"])
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
        rows = conn.execute(
            """SELECT id, message, total, sent, failed, started_at, finished_at, app_username, log
               FROM broadcast_history ORDER BY id DESC LIMIT 100"""
        ).fetchall()
        result = [
            {"id": r[0], "message": r[1], "total": r[2], "sent": r[3],
             "failed": r[4], "started_at": r[5], "finished_at": r[6],
             "started_by": r[7] or "unknown",
             "log": json.loads(r[8]) if r[8] else []}
            for r in rows
        ]
    else:
        rows = conn.execute(
            """SELECT id, message, total, sent, failed, started_at, finished_at, log
               FROM broadcast_history WHERE app_user_id=? ORDER BY id DESC LIMIT 50""",
            (int(app_user["sub"]),)
        ).fetchall()
        result = [
            {"id": r[0], "message": r[1], "total": r[2], "sent": r[3],
             "failed": r[4], "started_at": r[5], "finished_at": r[6],
             "started_by": app_user["username"],
             "log": json.loads(r[7]) if r[7] else []}
            for r in rows
        ]
    conn.close()
    return {"history": result}

# ── Admin: list active TG sessions ───────────────────────────────────────────
@app.get("/api/admin/sessions")
def admin_sessions(admin: dict = Depends(require_admin)):
    result = []
    for token, client in tg_clients.items():
        label = saved_phones.get(token, token[:8] + "...")
        result.append({"token": token, "label": label})
    return {"sessions": result}

# ── SSE: broadcast progress stream ───────────────────────────────────────────
@app.get("/api/broadcast/stream")
async def broadcast_stream(request: Request,
                            token: str = Depends(get_tg_session_token),
                            jwt: Optional[str] = None):
    # EventSource can't send headers — accept JWT as query param for SSE only
    if jwt:
        decode_jwt(jwt)  # validates, raises 401 if invalid
    else:
        # fall back to Authorization header
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            decode_jwt(auth[7:])
        else:
            raise HTTPException(status_code=401, detail="Not authenticated")
    async def event_generator():
        last_sent = 0
        last_log_len = 0
        while True:
            status = get_broadcast_status(token)
            log_len = len(status.get("log", []))
            # Send update if something changed
            if log_len != last_log_len or status.get("sent", 0) != last_sent:
                last_sent = status.get("sent", 0)
                last_log_len = log_len
                data = json.dumps({
                    "running": status["running"],
                    "finished": status["finished"],
                    "total": status["total"],
                    "sent": status["sent"],
                    "failed": status["failed"],
                    "current_chat": status["current_chat"],
                    "log": status["log"][-20:],  # last 20 lines only
                })
                yield f"data: {data}\n\n"
            if not status["running"] and status["finished"]:
                # Send final state then close
                yield f"data: {json.dumps({**status, 'log': status['log'][-20:]})}\n\n"
                break
            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )

# ── Admin: manual backup ─────────────────────────────────────────────────────
@app.post("/api/admin/backup")
async def manual_backup(admin: dict = Depends(require_admin)):
    backup_dir = os.path.join(DATA_DIR, "backups")
    os.makedirs(backup_dir, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    dst = os.path.join(backup_dir, f"broadcast_{ts}.db")
    src_conn = sqlite3.connect(DB_PATH)
    dst_conn = sqlite3.connect(dst)
    src_conn.backup(dst_conn)
    src_conn.close()
    dst_conn.close()
    size = os.path.getsize(dst)
    return {"backup": dst, "size_bytes": size, "created_at": ts}

# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    backup_dir = os.path.join(DATA_DIR, "backups")
    backups = sorted(os.listdir(backup_dir)) if os.path.exists(backup_dir) else []
    return {"status": "ok", "sessions": len(tg_clients), "last_backup": backups[-1] if backups else None}
