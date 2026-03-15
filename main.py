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

from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Depends, Header, Query
from fastapi.responses import StreamingResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from telethon import TelegramClient, errors
from telethon.tl.types import Channel, Chat, User as TgUser
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

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

# ── Slack OAuth config ───────────────────────────────────────────────────────
SLACK_CLIENT_ID     = os.environ.get("SLACK_CLIENT_ID", "")
SLACK_CLIENT_SECRET = os.environ.get("SLACK_CLIENT_SECRET", "")
SLACK_REDIRECT_URI  = os.environ.get("SLACK_REDIRECT_URI", "")
SLACK_BOT_SCOPES    = "channels:read,groups:read,chat:write,files:write"

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

# ── Slack per-session state ──────────────────────────────────────────────────
slack_clients:  dict[str, WebClient] = {}   # session_token -> WebClient
slack_sessions: dict[str, dict]      = {}   # session_token -> {team_name, bot_user_id, ...}
_oauth_states:  dict[str, int]       = {}   # state -> app_user_id (for CSRF protection)
tg_session_owners: dict[str, dict]    = {}   # tg session_token -> {"user_id": int, "company_id": int|None}

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
    # Seed default superadmin if table empty
    row = c.execute("SELECT COUNT(*) FROM app_users").fetchone()
    if row[0] == 0:
        default_pw = os.environ.get("ADMIN_PASSWORD", "admin123")
        hashed = hash_password(default_pw)
        c.execute(
            "INSERT INTO app_users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
            ("admin", hashed, "superadmin", datetime.utcnow().isoformat())
        )
        logger.info(f"Created default superadmin — password: {default_pw}")
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
    if "channel_type" not in cols:
        c.execute("ALTER TABLE broadcast_history ADD COLUMN channel_type TEXT DEFAULT 'telegram'")
        logger.info("Migrated broadcast_history: added channel_type")
    # ── migrate chat_lists: add channel_type ──
    cl_cols = {row[1] for row in c.execute("PRAGMA table_info(chat_lists)")}
    if "channel_type" not in cl_cols:
        c.execute("ALTER TABLE chat_lists ADD COLUMN channel_type TEXT DEFAULT 'telegram'")
        logger.info("Migrated chat_lists: added channel_type")
    # ── slack connections ──
    c.execute("""CREATE TABLE IF NOT EXISTS slack_connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_token TEXT NOT NULL UNIQUE,
        bot_token TEXT NOT NULL,
        team_id TEXT,
        team_name TEXT,
        bot_user_id TEXT,
        app_user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL
    )""")
    # ── companies ──
    c.execute("""CREATE TABLE IF NOT EXISTS companies (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        slug       TEXT    NOT NULL UNIQUE,
        name       TEXT    NOT NULL,
        email      TEXT,
        status     TEXT    NOT NULL DEFAULT 'active',
        created_at TEXT    NOT NULL,
        created_by INTEGER
    )""")
    # ── accounts registry ──
    c.execute("""CREATE TABLE IF NOT EXISTS accounts (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        name             TEXT    NOT NULL,
        messenger        TEXT    NOT NULL,
        external_channel TEXT    NOT NULL,
        type             TEXT    NOT NULL,
        owner_id         INTEGER,
        created_at       TEXT    NOT NULL,
        UNIQUE(messenger, external_channel)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS account_tags (
        id   INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT    NOT NULL UNIQUE
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS account_tag_links (
        account_id INTEGER NOT NULL,
        tag_id     INTEGER NOT NULL,
        PRIMARY KEY (account_id, tag_id)
    )""")
    # ── multi-tenant migrations ──
    user_cols = {row[1] for row in c.execute("PRAGMA table_info(app_users)")}
    if "company_id" not in user_cols:
        c.execute("ALTER TABLE app_users ADD COLUMN company_id INTEGER")
        logger.info("Migrated app_users: added company_id")
    if "email" not in user_cols:
        c.execute("ALTER TABLE app_users ADD COLUMN email TEXT")
        logger.info("Migrated app_users: added email")
    if "is_active" not in user_cols:
        c.execute("ALTER TABLE app_users ADD COLUMN is_active INTEGER DEFAULT 1")
        logger.info("Migrated app_users: added is_active")
    # Migrate role='admin' → 'superadmin'
    c.execute("UPDATE app_users SET role='superadmin' WHERE role='admin'")
    # Add company_id to data tables
    for tbl in ("chat_lists", "broadcast_history", "templates", "slack_connections"):
        t_cols = {row[1] for row in c.execute(f"PRAGMA table_info({tbl})")}
        if "company_id" not in t_cols:
            c.execute(f"ALTER TABLE {tbl} ADD COLUMN company_id INTEGER")
            logger.info(f"Migrated {tbl}: added company_id")
    # Clean start: delete old unscoped data
    for tbl in ("chat_lists", "broadcast_history", "templates"):
        c.execute(f"DELETE FROM {tbl} WHERE company_id IS NULL")
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
    # Restore Slack sessions from DB (tokens are stateless, survive restarts)
    try:
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute(
            "SELECT session_token, bot_token, team_id, team_name, bot_user_id, app_user_id, company_id FROM slack_connections"
        ).fetchall()
        conn.close()
        for row in rows:
            s_token, bot_token, team_id, team_name, bot_user_id, app_user_id, company_id = row
            try:
                client = WebClient(token=bot_token)
                client.auth_test()  # validate token still works
                slack_clients[s_token] = client
                slack_sessions[s_token] = {
                    "team_id": team_id, "team_name": team_name,
                    "bot_user_id": bot_user_id, "app_user_id": app_user_id,
                    "company_id": company_id,
                }
                logger.info(f"Restored Slack session: {team_name} ({s_token[:8]}...)")
            except Exception as e:
                logger.warning(f"Failed to restore Slack session {s_token[:8]}...: {e}")
    except Exception as e:
        logger.error(f"Failed to load Slack connections: {e}")
    asyncio.create_task(_cleanup_old_uploads())
    asyncio.create_task(_sqlite_backup_loop())
    yield
    # Graceful shutdown: stop running broadcasts and save to history
    for token, status in list(broadcast_statuses.items()):
        if status.get("running"):
            status["running"] = False
            status["finished"] = True
            status["log"].append("Stopped: server shutdown")
            # Determine channel_type based on whether it's a Slack session
            ch_type = "slack" if token in slack_clients else "telegram"
            try:
                conn = sqlite3.connect(DB_PATH)
                conn.execute(
                    """INSERT INTO broadcast_history
                       (message, total, sent, failed, started_at, finished_at,
                        tg_session_token, log, channel_type)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    ("(shutdown)", status["total"], status["sent"], status["failed"],
                     datetime.utcnow().isoformat(), datetime.utcnow().isoformat(),
                     token, json.dumps(status["log"]), ch_type)
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
def create_jwt(user_id: int, username: str, role: str, company_id: int = None) -> str:
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "company_id": company_id,
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
    """Legacy — kept for backward compat. Accepts superadmin or company_admin."""
    if user.get("role") not in ("superadmin", "company_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    return user

def require_superadmin(user: dict = Depends(get_current_app_user)) -> dict:
    if user.get("role") != "superadmin":
        raise HTTPException(status_code=403, detail="Super Admin only")
    return user

def require_company_admin_or_above(user: dict = Depends(get_current_app_user)) -> dict:
    if user.get("role") not in ("superadmin", "company_admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

def get_company_id(user: dict):
    cid = user.get("company_id")
    return int(cid) if cid is not None else None

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

# ── Slack session helpers ────────────────────────────────────────────────────
def get_slack_session_token(x_slack_session_token: Optional[str] = Header(None)) -> str:
    if not x_slack_session_token:
        raise HTTPException(status_code=400, detail="Missing X-Slack-Session-Token header")
    return x_slack_session_token

def get_slack_client(token: str) -> WebClient:
    c = slack_clients.get(token)
    if not c:
        raise HTTPException(status_code=400, detail="No Slack session. Connect first.")
    return c

# ── Accounts sync helper ─────────────────────────────────────────────────────
def sync_accounts_from_chats(chats: list, messenger: str):
    """Upsert chats into the accounts registry. Preserves owner_id and created_at."""
    conn = sqlite3.connect(DB_PATH)
    now = datetime.utcnow().isoformat()
    for ch in chats:
        conn.execute("""
            INSERT INTO accounts (name, messenger, external_channel, type, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(messenger, external_channel) DO UPDATE SET
                name = excluded.name,
                type = excluded.type
        """, (ch["name"], messenger, str(ch["external_channel"]), ch["type"], now))
    conn.commit()
    conn.close()

# ═════════════════════════════════════════════════════════════════════════════
# ── RBAC: App auth endpoints ──────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════════════════════

class AppLoginRequest(BaseModel):
    username: str
    password: str

class CreateUserRequest(BaseModel):
    username: str
    role: str = "user"         # "user" | "company_admin"
    password: Optional[str] = None  # if None — auto-generate
    company_id: Optional[int] = None  # required for superadmin, auto-set for company_admin
    email: Optional[str] = None

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
        "SELECT id, username, password_hash, role, company_id, is_active FROM app_users WHERE username=?",
        (req.username,)
    ).fetchone()
    if not row or not verify_password(req.password, row[2]):
        conn.close()
        raise HTTPException(status_code=401, detail="Wrong username or password")
    if row[5] is not None and not row[5]:
        conn.close()
        raise HTTPException(status_code=403, detail="Account deactivated")
    company_id = row[4]
    company_name = None
    if company_id is not None:
        comp = conn.execute("SELECT name, status FROM companies WHERE id=?", (company_id,)).fetchone()
        if comp and comp[1] != "active":
            conn.close()
            raise HTTPException(status_code=403, detail="Company is inactive")
        company_name = comp[0] if comp else None
    conn.close()
    token = create_jwt(row[0], row[1], row[3], company_id)
    return {"token": token, "username": row[1], "role": row[3], "id": row[0],
            "company_id": company_id, "company_name": company_name}

@app.get("/api/auth/me")
def app_me(user: dict = Depends(get_current_app_user)):
    result = {"id": user["sub"], "username": user["username"], "role": user["role"],
              "company_id": user.get("company_id")}
    if user.get("company_id"):
        conn = sqlite3.connect(DB_PATH)
        comp = conn.execute("SELECT name FROM companies WHERE id=?", (int(user["company_id"]),)).fetchone()
        conn.close()
        result["company_name"] = comp[0] if comp else None
    return result

@app.get("/api/auth/users")
def list_users(admin: dict = Depends(require_company_admin_or_above),
               company_filter: Optional[int] = Query(None, alias="company_id")):
    conn = sqlite3.connect(DB_PATH)
    if admin["role"] == "superadmin":
        if company_filter:
            rows = conn.execute(
                """SELECT u.id, u.username, u.role, u.created_at, u.created_by, u.company_id,
                          u.email, u.is_active, c.name as company_name
                   FROM app_users u LEFT JOIN companies c ON u.company_id=c.id
                   WHERE u.company_id=? ORDER BY u.id""", (company_filter,)
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT u.id, u.username, u.role, u.created_at, u.created_by, u.company_id,
                          u.email, u.is_active, c.name as company_name
                   FROM app_users u LEFT JOIN companies c ON u.company_id=c.id ORDER BY u.id"""
            ).fetchall()
    else:
        cid = get_company_id(admin)
        rows = conn.execute(
            """SELECT u.id, u.username, u.role, u.created_at, u.created_by, u.company_id,
                      u.email, u.is_active, c.name as company_name
               FROM app_users u LEFT JOIN companies c ON u.company_id=c.id
               WHERE u.company_id=? ORDER BY u.id""", (cid,)
        ).fetchall()
    conn.close()
    return {"users": [
        {"id": r[0], "username": r[1], "role": r[2], "created_at": r[3], "created_by": r[4],
         "company_id": r[5], "email": r[6], "is_active": r[7] if r[7] is not None else 1,
         "company_name": r[8]}
        for r in rows
    ]}

@app.post("/api/auth/users")
def create_user(req: CreateUserRequest, admin: dict = Depends(require_company_admin_or_above)):
    password = req.password or secrets.token_urlsafe(12)
    hashed = hash_password(password)
    if admin["role"] == "superadmin":
        if not req.company_id:
            raise HTTPException(status_code=400, detail="company_id required for superadmin")
        target_company_id = req.company_id
    else:
        target_company_id = get_company_id(admin)
        if req.role not in ("user",):
            raise HTTPException(status_code=403, detail="Company admin can only create users with role 'user'")
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """INSERT INTO app_users (username, password_hash, role, created_at, created_by,
               company_id, email, is_active) VALUES (?,?,?,?,?,?,?,?)""",
            (req.username, hashed, req.role, datetime.utcnow().isoformat(),
             int(admin["sub"]), target_company_id, req.email, 1)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=409, detail="Username already exists")
    conn.close()
    return {"created": True, "username": req.username, "password": password, "role": req.role}

@app.delete("/api/auth/users/{user_id}")
def delete_user(user_id: int, admin: dict = Depends(require_company_admin_or_above)):
    if str(user_id) == str(admin["sub"]):
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    conn = sqlite3.connect(DB_PATH)
    target = conn.execute("SELECT role, company_id FROM app_users WHERE id=?", (user_id,)).fetchone()
    if not target:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    if admin["role"] != "superadmin":
        if target[1] != get_company_id(admin):
            conn.close()
            raise HTTPException(status_code=403, detail="Cannot delete user from another company")
        if target[0] == "company_admin":
            conn.close()
            raise HTTPException(status_code=400, detail="Cannot delete company admin")
    conn.execute("DELETE FROM app_users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return {"deleted": True}

@app.put("/api/auth/users/{user_id}/active")
def toggle_user_active(user_id: int, admin: dict = Depends(require_company_admin_or_above)):
    conn = sqlite3.connect(DB_PATH)
    target = conn.execute("SELECT is_active, company_id FROM app_users WHERE id=?", (user_id,)).fetchone()
    if not target:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    if admin["role"] != "superadmin" and target[1] != get_company_id(admin):
        conn.close()
        raise HTTPException(status_code=403, detail="Cannot modify user from another company")
    new_active = 0 if target[0] else 1
    conn.execute("UPDATE app_users SET is_active=? WHERE id=?", (new_active, user_id))
    conn.commit()
    conn.close()
    return {"is_active": new_active}

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
    return {"ok": True, "password_changed": True}

@app.put("/api/auth/users/{user_id}/password")
def reset_password(user_id: int, admin: dict = Depends(require_company_admin_or_above)):
    conn = sqlite3.connect(DB_PATH)
    target = conn.execute("SELECT company_id FROM app_users WHERE id=?", (user_id,)).fetchone()
    if not target:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    if admin["role"] != "superadmin" and target[0] != get_company_id(admin):
        conn.close()
        raise HTTPException(status_code=403, detail="Cannot reset password for user from another company")
    new_pw = secrets.token_urlsafe(12)
    hashed = hash_password(new_pw)
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
async def connect(req: ConfigRequest, app_user: dict = Depends(get_current_app_user)):
    token = req.session_token or secrets.token_hex(16)
    if token in tg_clients and tg_clients[token].is_connected():
        await tg_clients[token].disconnect()
    session_path = os.path.join(SESSIONS_DIR, token)
    c = TelegramClient(session_path, req.api_id, req.api_hash)
    await c.connect()
    tg_clients[token] = c
    tg_session_owners[token] = {"user_id": int(app_user["sub"]), "company_id": get_company_id(app_user)}
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
    sync_accounts_from_chats([
        {"external_channel": str(ch["id"]), "name": ch["name"],
         "type": "dm" if ch["type"] == "user" else ch["type"]}
        for ch in chats
    ], messenger="telegram")
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
    if req.as_session_token and app_user.get("role") == "superadmin":
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
           (message, total, sent, failed, started_at, finished_at, tg_session_token, app_user_id, app_username, log, company_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (
            (req.message or "")[:200], status["total"], status["sent"], status["failed"],
            started_at, datetime.utcnow().isoformat(),
            token, int(app_user["sub"]), app_user["username"],
            json.dumps(status["log"]), get_company_id(app_user)
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
    cid = get_company_id(app_user)
    if app_user["role"] == "superadmin":
        rows = conn.execute("SELECT id, name, chats, created_at FROM chat_lists ORDER BY id DESC").fetchall()
    elif app_user["role"] == "company_admin":
        rows = conn.execute("SELECT id, name, chats, created_at FROM chat_lists WHERE company_id=? ORDER BY id DESC", (cid,)).fetchall()
    else:
        rows = conn.execute("SELECT id, name, chats, created_at FROM chat_lists WHERE company_id=? AND owner_app_user_id=? ORDER BY id DESC",
                            (cid, int(app_user["sub"]))).fetchall()
    conn.close()
    return {"lists": [{"id": r[0], "name": r[1], "chats": json.loads(r[2]), "created_at": r[3]} for r in rows]}

@app.post("/api/lists")
def save_list(req: SaveListRequest, app_user: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO chat_lists (name, chats, created_at, owner_app_user_id, company_id) VALUES (?,?,?,?,?)",
        (req.name, json.dumps(req.chat_ids), datetime.utcnow().isoformat(), int(app_user["sub"]), get_company_id(app_user))
    )
    conn.commit()
    conn.close()
    return {"saved": True}

@app.delete("/api/lists/{list_id}")
def delete_list(list_id: int, app_user: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    cid = get_company_id(app_user)
    if app_user["role"] == "superadmin":
        conn.execute("DELETE FROM chat_lists WHERE id=?", (list_id,))
    elif app_user["role"] == "company_admin":
        conn.execute("DELETE FROM chat_lists WHERE id=? AND company_id=?", (list_id, cid))
    else:
        conn.execute("DELETE FROM chat_lists WHERE id=? AND company_id=? AND owner_app_user_id=?",
                     (list_id, cid, int(app_user["sub"])))
    conn.commit()
    conn.close()
    return {"deleted": True}

# ── Templates ─────────────────────────────────────────────────────────────────
class SaveTemplateRequest(BaseModel):
    name: str
    text: str

@app.get("/api/templates")
def get_templates(app_user: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    cid = get_company_id(app_user)
    if app_user["role"] == "superadmin":
        rows = conn.execute("SELECT id, name, text, created_at FROM templates ORDER BY id DESC").fetchall()
    else:
        rows = conn.execute("SELECT id, name, text, created_at FROM templates WHERE company_id=? ORDER BY id DESC", (cid,)).fetchall()
    conn.close()
    return {"templates": [{"id": r[0], "name": r[1], "text": r[2], "created_at": r[3]} for r in rows]}

@app.post("/api/templates")
def save_template(req: SaveTemplateRequest, app_user: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO templates (name, text, created_at, company_id) VALUES (?,?,?,?)",
                 (req.name, req.text, datetime.utcnow().isoformat(), get_company_id(app_user)))
    conn.commit()
    conn.close()
    return {"saved": True}

@app.delete("/api/templates/{tid}")
def delete_template(tid: int, app_user: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    cid = get_company_id(app_user)
    if app_user["role"] == "superadmin":
        conn.execute("DELETE FROM templates WHERE id=?", (tid,))
    else:
        conn.execute("DELETE FROM templates WHERE id=? AND company_id=?", (tid, cid))
    conn.commit()
    conn.close()
    return {"deleted": True}

# ── History ───────────────────────────────────────────────────────────────────
@app.get("/api/history")
def get_history(app_user: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    cid = get_company_id(app_user)
    if app_user["role"] == "superadmin":
        rows = conn.execute(
            """SELECT id, message, total, sent, failed, started_at, finished_at, app_username, log, channel_type
               FROM broadcast_history ORDER BY id DESC LIMIT 100"""
        ).fetchall()
    elif app_user["role"] == "company_admin":
        rows = conn.execute(
            """SELECT id, message, total, sent, failed, started_at, finished_at, app_username, log, channel_type
               FROM broadcast_history WHERE company_id=? ORDER BY id DESC LIMIT 100""",
            (cid,)
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT id, message, total, sent, failed, started_at, finished_at, app_username, log, channel_type
               FROM broadcast_history WHERE company_id=? AND app_user_id=? ORDER BY id DESC LIMIT 50""",
            (cid, int(app_user["sub"]))
        ).fetchall()
    result = [
        {"id": r[0], "message": r[1], "total": r[2], "sent": r[3],
         "failed": r[4], "started_at": r[5], "finished_at": r[6],
         "started_by": r[7] or "unknown",
         "log": json.loads(r[8]) if r[8] else [],
         "channel_type": r[9] or "telegram"}
        for r in rows
    ]
    conn.close()
    return {"history": result}

# ── Admin: list active sessions ──────────────────────────────────────────────
@app.get("/api/admin/sessions")
def admin_sessions(admin: dict = Depends(require_admin)):
    result = []
    for token, client in tg_clients.items():
        label = saved_phones.get(token, token[:8] + "...")
        result.append({"token": token, "label": label, "type": "telegram"})
    for token, info in slack_sessions.items():
        label = info.get("team_name", token[:8] + "...")
        result.append({"token": token, "label": label, "type": "slack"})
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

# ═════════════════════════════════════════════════════════════════════════════
# ── Company management (Super Admin) ────────────────────────────────────────
# ═════════════════════════════════════════════════════════════════════════════

class CreateCompanyRequest(BaseModel):
    name: str
    slug: str
    email: Optional[str] = None
    admin_username: str
    admin_password: Optional[str] = None

class UpdateCompanyRequest(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    status: Optional[str] = None

@app.get("/api/admin/companies")
def list_companies(admin: dict = Depends(require_superadmin)):
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id, slug, name, email, status, created_at, created_by FROM companies ORDER BY id"
    ).fetchall()
    result = []
    for r in rows:
        user_count = conn.execute("SELECT COUNT(*) FROM app_users WHERE company_id=?", (r[0],)).fetchone()[0]
        admin_row = conn.execute(
            "SELECT username FROM app_users WHERE company_id=? AND role='company_admin' LIMIT 1", (r[0],)
        ).fetchone()
        result.append({
            "id": r[0], "slug": r[1], "name": r[2], "email": r[3],
            "status": r[4], "created_at": r[5], "created_by": r[6],
            "user_count": user_count,
            "admin_username": admin_row[0] if admin_row else None,
        })
    conn.close()
    return {"companies": result}

@app.post("/api/admin/companies")
def create_company(req: CreateCompanyRequest, admin: dict = Depends(require_superadmin)):
    password = req.admin_password or secrets.token_urlsafe(12)
    hashed = hash_password(password)
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.execute(
            "INSERT INTO companies (slug, name, email, status, created_at, created_by) VALUES (?,?,?,?,?,?)",
            (req.slug, req.name, req.email, "active", datetime.utcnow().isoformat(), int(admin["sub"]))
        )
        company_id = cur.lastrowid
        conn.execute(
            "INSERT INTO app_users (username, password_hash, role, created_at, created_by, company_id, is_active) VALUES (?,?,?,?,?,?,?)",
            (req.admin_username, hashed, "company_admin", datetime.utcnow().isoformat(),
             int(admin["sub"]), company_id, 1)
        )
        conn.commit()
    except sqlite3.IntegrityError as e:
        conn.close()
        detail = "Company slug already exists" if "companies.slug" in str(e) else "Admin username already exists"
        raise HTTPException(status_code=409, detail=detail)
    conn.close()
    return {"created": True, "company_id": company_id, "slug": req.slug, "name": req.name,
            "admin_username": req.admin_username, "admin_password": password}

@app.get("/api/admin/companies/{company_id}")
def get_company(company_id: int, admin: dict = Depends(require_superadmin)):
    conn = sqlite3.connect(DB_PATH)
    comp = conn.execute(
        "SELECT id, slug, name, email, status, created_at FROM companies WHERE id=?", (company_id,)
    ).fetchone()
    if not comp:
        conn.close()
        raise HTTPException(status_code=404, detail="Company not found")
    users = conn.execute(
        "SELECT id, username, role, email, is_active, created_at FROM app_users WHERE company_id=? ORDER BY id",
        (company_id,)
    ).fetchall()
    conn.close()
    return {
        "company": {"id": comp[0], "slug": comp[1], "name": comp[2], "email": comp[3],
                     "status": comp[4], "created_at": comp[5]},
        "users": [{"id": u[0], "username": u[1], "role": u[2], "email": u[3],
                   "is_active": u[4], "created_at": u[5]} for u in users]
    }

@app.put("/api/admin/companies/{company_id}")
def update_company(company_id: int, req: UpdateCompanyRequest,
                   admin: dict = Depends(require_superadmin)):
    conn = sqlite3.connect(DB_PATH)
    comp = conn.execute("SELECT id FROM companies WHERE id=?", (company_id,)).fetchone()
    if not comp:
        conn.close()
        raise HTTPException(status_code=404, detail="Company not found")
    updates = []
    params = []
    if req.name is not None:
        updates.append("name=?"); params.append(req.name)
    if req.email is not None:
        updates.append("email=?"); params.append(req.email)
    if req.status is not None:
        if req.status not in ("active", "inactive"):
            conn.close()
            raise HTTPException(status_code=400, detail="Status must be 'active' or 'inactive'")
        updates.append("status=?"); params.append(req.status)
    if updates:
        params.append(company_id)
        conn.execute(f"UPDATE companies SET {','.join(updates)} WHERE id=?", params)
        conn.commit()
    conn.close()
    return {"updated": True}

@app.delete("/api/admin/companies/{company_id}")
def delete_company(company_id: int, admin: dict = Depends(require_superadmin)):
    conn = sqlite3.connect(DB_PATH)
    comp = conn.execute("SELECT id FROM companies WHERE id=?", (company_id,)).fetchone()
    if not comp:
        conn.close()
        raise HTTPException(status_code=404, detail="Company not found")
    for tbl in ("app_users", "chat_lists", "broadcast_history", "templates", "slack_connections"):
        conn.execute(f"DELETE FROM {tbl} WHERE company_id=?", (company_id,))
    conn.execute("DELETE FROM companies WHERE id=?", (company_id,))
    conn.commit()
    conn.close()
    # Clean up in-memory state for deleted company's sessions
    for token, info in list(tg_session_owners.items()):
        if isinstance(info, dict) and info.get("company_id") == company_id:
            tg_clients.pop(token, None)
            tg_session_owners.pop(token, None)
    for token, info in list(slack_sessions.items()):
        if info.get("company_id") == company_id:
            slack_clients.pop(token, None)
            slack_sessions.pop(token, None)
    return {"deleted": True}

# ═════════════════════════════════════════════════════════════════════════════
# ── Slack: endpoints ─────────────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════════════════════

class SlackConnectRequest(BaseModel):
    bot_token: str

class SlackBroadcastRequest(BaseModel):
    channel_ids: list[str]
    message: Optional[str] = None
    delay: float = 1.0
    random_delay: bool = False
    max_per_minute: int = 30
    file_id: Optional[str] = None

class SlackSaveListRequest(BaseModel):
    name: str
    channel_ids: list[str]

# ── Slack: connect / me / disconnect ─────────────────────────────────────────

@app.post("/api/slack/connect")
async def slack_connect(req: SlackConnectRequest,
                        app_user: dict = Depends(get_current_app_user)):
    try:
        client = WebClient(token=req.bot_token)
        resp = await asyncio.to_thread(client.auth_test)
    except SlackApiError as e:
        raise HTTPException(status_code=400, detail=f"Invalid Slack token: {e.response['error']}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Slack connection failed: {e}")

    session_token = secrets.token_hex(16)
    team_id = resp.get("team_id", "")
    team_name = resp.get("team", "")
    bot_user_id = resp.get("user_id", "")

    slack_clients[session_token] = client
    slack_sessions[session_token] = {
        "team_id": team_id,
        "team_name": team_name,
        "bot_user_id": bot_user_id,
        "app_user_id": int(app_user["sub"]),
        "company_id": get_company_id(app_user),
    }

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO slack_connections
           (session_token, bot_token, team_id, team_name, bot_user_id, app_user_id, created_at, company_id)
           VALUES (?,?,?,?,?,?,?,?)""",
        (session_token, req.bot_token, team_id, team_name, bot_user_id,
         int(app_user["sub"]), datetime.utcnow().isoformat(), get_company_id(app_user))
    )
    conn.commit()
    conn.close()

    return {
        "connected": True,
        "slack_session_token": session_token,
        "team_name": team_name,
        "bot_user_id": bot_user_id,
    }

@app.get("/api/slack/me")
async def slack_me(token: str = Depends(get_slack_session_token),
                   _: dict = Depends(get_current_app_user)):
    client = get_slack_client(token)
    try:
        resp = await asyncio.to_thread(client.auth_test)
    except SlackApiError as e:
        raise HTTPException(status_code=400, detail=f"Slack error: {e.response['error']}")
    return {
        "team": resp.get("team", ""),
        "team_id": resp.get("team_id", ""),
        "user": resp.get("user", ""),
        "user_id": resp.get("user_id", ""),
        "url": resp.get("url", ""),
    }

@app.post("/api/slack/disconnect")
async def slack_disconnect(token: str = Depends(get_slack_session_token),
                           _: dict = Depends(get_current_app_user)):
    slack_clients.pop(token, None)
    slack_sessions.pop(token, None)
    broadcast_statuses.pop(token, None)
    uploaded_files.pop(token, None)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM slack_connections WHERE session_token=?", (token,))
    conn.commit()
    conn.close()
    return {"disconnected": True}

# ── Slack: channels ──────────────────────────────────────────────────────────

@app.get("/api/slack/channels")
async def slack_channels(token: str = Depends(get_slack_session_token),
                         _: dict = Depends(get_current_app_user)):
    client = get_slack_client(token)
    channels = []
    cursor = None
    try:
        while True:
            kwargs = {"types": "public_channel,private_channel", "limit": 200}
            if cursor:
                kwargs["cursor"] = cursor
            resp = await asyncio.to_thread(
                lambda: client.conversations_list(**kwargs)
            )
            for ch in resp.get("channels", []):
                channels.append({
                    "id": ch["id"],
                    "name": ch.get("name", ""),
                    "type": "private_channel" if ch.get("is_private") else "public_channel",
                    "is_member": ch.get("is_member", False),
                    "num_members": ch.get("num_members", 0),
                    "topic": ch.get("topic", {}).get("value", ""),
                })
            cursor = resp.get("response_metadata", {}).get("next_cursor", "")
            if not cursor:
                break
    except SlackApiError as e:
        raise HTTPException(status_code=400, detail=f"Slack error: {e.response['error']}")
    sync_accounts_from_chats([
        {"external_channel": ch["id"], "name": ch["name"],
         "type": "channel" if ch["type"] == "public_channel" else "group"}
        for ch in channels
    ], messenger="slack")
    return {"channels": channels}

# ── Slack: broadcast ─────────────────────────────────────────────────────────

@app.post("/api/slack/broadcast/start")
async def slack_start_broadcast(req: SlackBroadcastRequest,
                                token: str = Depends(get_slack_session_token),
                                app_user: dict = Depends(get_current_app_user)):
    _ = get_slack_client(token)  # ensure connected
    status = get_broadcast_status(token)
    if status["running"]:
        raise HTTPException(status_code=409, detail="Broadcast already running")

    broadcast_statuses[token] = {
        "running": True, "total": len(req.channel_ids), "sent": 0, "failed": 0,
        "current_chat": "", "log": [], "finished": False,
    }
    asyncio.create_task(_run_slack_broadcast(req, token, app_user))
    return {"started": True}

@app.post("/api/slack/broadcast/stop")
async def slack_stop_broadcast(token: str = Depends(get_slack_session_token),
                               _: dict = Depends(get_current_app_user)):
    if token in broadcast_statuses:
        broadcast_statuses[token]["running"] = False
    return {"stopped": True}

@app.get("/api/slack/broadcast/status")
async def slack_broadcast_status(token: str = Depends(get_slack_session_token),
                                 _: dict = Depends(get_current_app_user)):
    return get_broadcast_status(token)

@app.get("/api/slack/broadcast/stream")
async def slack_broadcast_stream(request: Request,
                                 token: str = Depends(get_slack_session_token),
                                 jwt: Optional[str] = None):
    if jwt:
        decode_jwt(jwt)
    else:
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
                    "log": status["log"][-20:],
                })
                yield f"data: {data}\n\n"
            if not status["running"] and status["finished"]:
                yield f"data: {json.dumps({**status, 'log': status['log'][-20:]})}\n\n"
                break
            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

async def _run_slack_broadcast(req: SlackBroadcastRequest, token: str, app_user: dict):
    client = get_slack_client(token)
    uf = uploaded_files.get(token)
    status = broadcast_statuses[token]
    started_at = datetime.utcnow().isoformat()
    sent_times = []

    for i, channel_id in enumerate(req.channel_ids):
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
            info = await asyncio.to_thread(client.conversations_info, channel=channel_id)
            name = info["channel"].get("name", channel_id)
            status["current_chat"] = name

            if uf and os.path.exists(uf["path"]):
                await asyncio.to_thread(
                    client.files_upload_v2,
                    channel=channel_id,
                    file=uf["path"],
                    initial_comment=req.message or "",
                )
            else:
                await asyncio.to_thread(
                    client.chat_postMessage,
                    channel=channel_id,
                    text=req.message,
                )

            status["sent"] += 1
            sent_times.append(time.time())
            status["log"].append(f"OK: {name}")

        except SlackApiError as e:
            err = e.response.get("error", str(e))
            if err == "ratelimited":
                retry_after = int(e.response.headers.get("Retry-After", 5))
                status["log"].append(f"Rate limited by Slack — retrying in {retry_after}s")
                await asyncio.sleep(retry_after)
                try:
                    if uf and os.path.exists(uf["path"]):
                        await asyncio.to_thread(
                            client.files_upload_v2,
                            channel=channel_id,
                            file=uf["path"],
                            initial_comment=req.message or "",
                        )
                    else:
                        await asyncio.to_thread(
                            client.chat_postMessage,
                            channel=channel_id,
                            text=req.message,
                        )
                    status["sent"] += 1
                    status["log"].append(f"OK (retry): {channel_id}")
                except Exception as e2:
                    status["failed"] += 1
                    status["log"].append(f"FAIL [{channel_id}]: {e2}")
            else:
                status["failed"] += 1
                status["log"].append(f"FAIL [{channel_id}]: {err}")
        except Exception as e:
            status["failed"] += 1
            status["log"].append(f"FAIL [{channel_id}]: {e}")

        if i < len(req.channel_ids) - 1 and status["running"]:
            delay = req.delay + (random.uniform(0, 3) if req.random_delay else 0)
            await asyncio.sleep(delay)

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO broadcast_history
           (message, total, sent, failed, started_at, finished_at,
            tg_session_token, app_user_id, app_username, log, channel_type, company_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            (req.message or "")[:200], status["total"], status["sent"], status["failed"],
            started_at, datetime.utcnow().isoformat(),
            token, int(app_user["sub"]), app_user["username"],
            json.dumps(status["log"]), "slack", get_company_id(app_user)
        )
    )
    conn.commit()
    conn.close()

    status["running"] = False
    status["finished"] = True
    status["current_chat"] = ""
    status["log"].append(f"Done. Sent: {status['sent']}, Failed: {status['failed']}")

# ── Slack: lists ─────────────────────────────────────────────────────────────

@app.get("/api/slack/lists")
def get_slack_lists(app_user: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    cid = get_company_id(app_user)
    if app_user["role"] == "superadmin":
        rows = conn.execute("SELECT id, name, chats, created_at FROM chat_lists WHERE channel_type='slack' ORDER BY id DESC").fetchall()
    elif app_user["role"] == "company_admin":
        rows = conn.execute("SELECT id, name, chats, created_at FROM chat_lists WHERE channel_type='slack' AND company_id=? ORDER BY id DESC", (cid,)).fetchall()
    else:
        rows = conn.execute("SELECT id, name, chats, created_at FROM chat_lists WHERE channel_type='slack' AND company_id=? AND owner_app_user_id=? ORDER BY id DESC",
                            (cid, int(app_user["sub"]))).fetchall()
    conn.close()
    return {"lists": [{"id": r[0], "name": r[1], "channels": json.loads(r[2]), "created_at": r[3]} for r in rows]}

@app.post("/api/slack/lists")
def save_slack_list(req: SlackSaveListRequest, app_user: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO chat_lists (name, chats, created_at, owner_app_user_id, channel_type, company_id) VALUES (?,?,?,?,?,?)",
        (req.name, json.dumps(req.channel_ids), datetime.utcnow().isoformat(),
         int(app_user["sub"]), "slack", get_company_id(app_user))
    )
    conn.commit()
    conn.close()
    return {"saved": True}

@app.delete("/api/slack/lists/{list_id}")
def delete_slack_list(list_id: int, app_user: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    cid = get_company_id(app_user)
    if app_user["role"] == "superadmin":
        conn.execute("DELETE FROM chat_lists WHERE id=? AND channel_type='slack'", (list_id,))
    elif app_user["role"] == "company_admin":
        conn.execute("DELETE FROM chat_lists WHERE id=? AND channel_type='slack' AND company_id=?", (list_id, cid))
    else:
        conn.execute("DELETE FROM chat_lists WHERE id=? AND channel_type='slack' AND company_id=? AND owner_app_user_id=?",
                     (list_id, cid, int(app_user["sub"])))
    conn.commit()
    conn.close()
    return {"deleted": True}

# ═════════════════════════════════════════════════════════════════════════════
# ── Slack OAuth flow ─────────────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/slack/oauth/start")
def slack_oauth_start(app_user: dict = Depends(get_current_app_user)):
    if not SLACK_CLIENT_ID or not SLACK_REDIRECT_URI:
        raise HTTPException(status_code=500, detail="Slack OAuth not configured (set SLACK_CLIENT_ID, SLACK_CLIENT_SECRET, SLACK_REDIRECT_URI)")
    state = secrets.token_hex(16)
    _oauth_states[state] = {"user_id": int(app_user["sub"]), "company_id": get_company_id(app_user)}
    url = (
        f"https://slack.com/oauth/v2/authorize"
        f"?client_id={SLACK_CLIENT_ID}"
        f"&scope={SLACK_BOT_SCOPES}"
        f"&redirect_uri={SLACK_REDIRECT_URI}"
        f"&state={state}"
    )
    return {"url": url, "state": state}

@app.get("/api/slack/oauth/callback")
async def slack_oauth_callback(code: str = Query(...), state: str = Query("")):
    oauth_info = _oauth_states.pop(state, None)
    if oauth_info is None:
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state")
    app_user_id = oauth_info["user_id"]
    oauth_company_id = oauth_info.get("company_id")
    try:
        resp = await asyncio.to_thread(
            lambda: WebClient().oauth_v2_access(
                client_id=SLACK_CLIENT_ID,
                client_secret=SLACK_CLIENT_SECRET,
                code=code,
                redirect_uri=SLACK_REDIRECT_URI,
            )
        )
    except SlackApiError as e:
        raise HTTPException(status_code=400, detail=f"Slack OAuth failed: {e.response.get('error', str(e))}")

    access_token = resp.get("access_token", "")
    team_name = resp.get("team", {}).get("name", "")
    team_id = resp.get("team", {}).get("id", "")
    bot_user_id = resp.get("bot_user_id", "")

    session_token = secrets.token_hex(16)
    client = WebClient(token=access_token)
    slack_clients[session_token] = client
    slack_sessions[session_token] = {
        "team_id": team_id, "team_name": team_name,
        "bot_user_id": bot_user_id, "app_user_id": app_user_id,
        "company_id": oauth_company_id,
    }

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO slack_connections
           (session_token, bot_token, team_id, team_name, bot_user_id, app_user_id, created_at, company_id)
           VALUES (?,?,?,?,?,?,?,?)""",
        (session_token, access_token, team_id, team_name, bot_user_id,
         app_user_id, datetime.utcnow().isoformat(), oauth_company_id)
    )
    conn.commit()
    conn.close()
    logger.info(f"Slack OAuth success: {team_name} for user {app_user_id}")

    return RedirectResponse(f"/?slack_connected={session_token}")

# ═════════════════════════════════════════════════════════════════════════════
# ── Unified endpoints ────────────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/integrations/status")
async def integrations_status(app_user: dict = Depends(get_current_app_user)):
    user_id = int(app_user["sub"])
    # TG status
    tg_info = {"connected": False}
    for token, owner_info in tg_session_owners.items():
        if owner_info.get("user_id") == user_id and token in tg_clients:
            c = tg_clients[token]
            try:
                if c.is_connected() and await c.is_user_authorized():
                    me = await c.get_me()
                    tg_info = {
                        "connected": True,
                        "name": f"{me.first_name or ''} {me.last_name or ''}".strip(),
                        "phone": saved_phones.get(token, ""),
                        "session_token": token,
                    }
                    break
            except:
                pass
    # Slack status
    slack_info = {"connected": False}
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT session_token, team_name FROM slack_connections WHERE app_user_id=? ORDER BY id DESC LIMIT 1",
        (user_id,)
    ).fetchone()
    conn.close()
    if row and row[0] in slack_clients:
        slack_info = {
            "connected": True,
            "team": row[1],
            "session_token": row[0],
        }
    return {"telegram": tg_info, "slack": slack_info}

@app.get("/api/unified/chats")
async def get_unified_chats(app_user: dict = Depends(get_current_app_user)):
    user_id = int(app_user["sub"])
    chats = []

    # TG chats
    for token, owner_info in tg_session_owners.items():
        if owner_info.get("user_id") != user_id or token not in tg_clients:
            continue
        c = tg_clients[token]
        try:
            if not c.is_connected() or not await c.is_user_authorized():
                continue
            async for dialog in c.iter_dialogs():
                entity = dialog.entity
                if isinstance(entity, Channel):
                    chat_type = "channel" if entity.broadcast else "group"
                    name = entity.title
                    members = getattr(entity, "participants_count", 0) or 0
                elif isinstance(entity, Chat):
                    chat_type = "group"
                    name = entity.title
                    members = getattr(entity, "participants_count", 0) or 0
                elif isinstance(entity, TgUser) and not entity.bot:
                    chat_type = "dm"
                    name = f"{entity.first_name or ''} {entity.last_name or ''}".strip() or str(entity.id)
                    members = 0
                else:
                    continue
                chats.append({
                    "id": f"tg:{entity.id}",
                    "raw_id": entity.id,
                    "name": name,
                    "platform": "telegram",
                    "type": chat_type,
                    "members": members,
                    "session_token": token,
                })
        except Exception as e:
            logger.warning(f"Failed to load TG chats for token {token[:8]}: {e}")

    # Slack chats
    conn = sqlite3.connect(DB_PATH)
    slack_rows = conn.execute(
        "SELECT session_token FROM slack_connections WHERE app_user_id=?", (user_id,)
    ).fetchall()
    conn.close()
    for (s_token,) in slack_rows:
        client = slack_clients.get(s_token)
        if not client:
            continue
        try:
            cursor = None
            while True:
                kwargs = {"types": "public_channel,private_channel", "limit": 200}
                if cursor:
                    kwargs["cursor"] = cursor
                resp = await asyncio.to_thread(lambda kw=kwargs: client.conversations_list(**kw))
                for ch in resp.get("channels", []):
                    chats.append({
                        "id": f"slack:{ch['id']}",
                        "raw_id": ch["id"],
                        "name": ch.get("name", ""),
                        "platform": "slack",
                        "type": "private_channel" if ch.get("is_private") else "channel",
                        "members": ch.get("num_members", 0),
                        "is_member": ch.get("is_member", False),
                        "session_token": s_token,
                    })
                cursor = resp.get("response_metadata", {}).get("next_cursor", "")
                if not cursor:
                    break
        except Exception as e:
            logger.warning(f"Failed to load Slack channels for token {s_token[:8]}: {e}")

    tg_sync = [{"external_channel": str(c["raw_id"]), "name": c["name"], "type": c["type"]}
               for c in chats if c["platform"] == "telegram"]
    slack_sync = [{"external_channel": str(c["raw_id"]), "name": c["name"], "type": c["type"]}
                  for c in chats if c["platform"] == "slack"]
    if tg_sync:
        sync_accounts_from_chats(tg_sync, messenger="telegram")
    if slack_sync:
        sync_accounts_from_chats(slack_sync, messenger="slack")

    return {"chats": chats}

# ── Unified broadcast ────────────────────────────────────────────────────────

class UnifiedBroadcastRequest(BaseModel):
    chat_ids: list[str]              # ["tg:123", "slack:C01ABC", ...]
    message: Optional[str] = None
    delay: float = 3.0
    random_delay: bool = False
    max_per_minute: int = 15

@app.post("/api/unified/broadcast/start")
async def unified_broadcast_start(req: UnifiedBroadcastRequest,
                                  app_user: dict = Depends(get_current_app_user)):
    if not req.chat_ids:
        raise HTTPException(status_code=400, detail="No chats selected")
    if req.message and len(req.message) > 4096:
        raise HTTPException(status_code=400, detail="Message exceeds 4096 characters")

    user_id = int(app_user["sub"])
    broadcast_id = f"unified_{secrets.token_hex(8)}"

    # Build chat_map: resolve each prefixed ID to platform + client
    chat_map = {}
    for cid in req.chat_ids:
        if cid.startswith("tg:"):
            raw_id = int(cid[3:])
            # Find user's TG session
            session_token = None
            for token, owner_info in tg_session_owners.items():
                if owner_info.get("user_id") == user_id and token in tg_clients:
                    session_token = token
                    break
            if not session_token:
                continue
            chat_map[cid] = {"platform": "telegram", "raw_id": raw_id, "session_token": session_token}
        elif cid.startswith("slack:"):
            raw_id = cid[6:]
            conn = sqlite3.connect(DB_PATH)
            row = conn.execute(
                "SELECT session_token FROM slack_connections WHERE app_user_id=? ORDER BY id DESC LIMIT 1",
                (user_id,)
            ).fetchone()
            conn.close()
            if row and row[0] in slack_clients:
                chat_map[cid] = {"platform": "slack", "raw_id": raw_id, "session_token": row[0]}

    if not chat_map:
        raise HTTPException(status_code=400, detail="No valid chats resolved. Check integrations.")

    status = get_broadcast_status(broadcast_id)
    if status["running"]:
        raise HTTPException(status_code=409, detail="Broadcast already running")

    broadcast_statuses[broadcast_id] = {
        "running": True, "total": len(chat_map), "sent": 0, "failed": 0,
        "current_chat": "", "log": [], "finished": False,
    }
    asyncio.create_task(_run_unified_broadcast(req, broadcast_id, app_user, chat_map))
    return {"started": True, "broadcast_id": broadcast_id}

@app.post("/api/unified/broadcast/stop")
async def unified_broadcast_stop(broadcast_id: str = Query(...),
                                 _: dict = Depends(get_current_app_user)):
    if broadcast_id in broadcast_statuses:
        broadcast_statuses[broadcast_id]["running"] = False
    return {"stopped": True}

@app.get("/api/unified/broadcast/status")
async def unified_broadcast_status_ep(broadcast_id: str = Query(...),
                                      _: dict = Depends(get_current_app_user)):
    return get_broadcast_status(broadcast_id)

@app.get("/api/unified/broadcast/stream")
async def unified_broadcast_stream(request: Request,
                                   broadcast_id: str = Query(...),
                                   jwt: Optional[str] = None):
    if jwt:
        decode_jwt(jwt)
    else:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            decode_jwt(auth[7:])
        else:
            raise HTTPException(status_code=401, detail="Not authenticated")

    async def event_generator():
        last_sent = 0
        last_log_len = 0
        while True:
            status = get_broadcast_status(broadcast_id)
            log_len = len(status.get("log", []))
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
                    "log": status["log"][-20:],
                })
                yield f"data: {data}\n\n"
            if not status["running"] and status["finished"]:
                yield f"data: {json.dumps({**status, 'log': status['log'][-20:]})}\n\n"
                break
            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

async def _run_unified_broadcast(req: UnifiedBroadcastRequest, broadcast_id: str,
                                 app_user: dict, chat_map: dict):
    status = broadcast_statuses[broadcast_id]
    started_at = datetime.utcnow().isoformat()
    sent_times = []
    uf = None  # TODO: unified file upload support

    ordered_ids = list(chat_map.keys())
    for i, chat_id in enumerate(ordered_ids):
        if not status["running"]:
            status["log"].append("Stopped by user")
            break

        now = time.time()
        sent_times = [t for t in sent_times if now - t < 60]
        if len(sent_times) >= req.max_per_minute:
            wait = 60 - (now - sent_times[0])
            status["log"].append(f"Rate limit — waiting {wait:.0f}s")
            await asyncio.sleep(wait)

        info = chat_map[chat_id]
        platform = info["platform"]
        raw_id = info["raw_id"]
        s_token = info["session_token"]

        try:
            if platform == "telegram":
                client = tg_clients.get(s_token)
                if not client:
                    raise Exception("TG session not found")
                entity = await client.get_entity(raw_id)
                name = getattr(entity, "title", str(raw_id))
                status["current_chat"] = f"{name} (TG)"
                if uf and os.path.exists(uf["path"]):
                    await client.send_file(entity, uf["path"], caption=req.message or None)
                else:
                    await client.send_message(entity, req.message)

            elif platform == "slack":
                client = slack_clients.get(s_token)
                if not client:
                    raise Exception("Slack session not found")
                ch_info = await asyncio.to_thread(client.conversations_info, channel=raw_id)
                name = ch_info["channel"].get("name", raw_id)
                status["current_chat"] = f"#{name} (Slack)"
                if uf and os.path.exists(uf["path"]):
                    await asyncio.to_thread(
                        client.files_upload_v2,
                        channel=raw_id, file=uf["path"],
                        initial_comment=req.message or "",
                    )
                else:
                    await asyncio.to_thread(
                        client.chat_postMessage,
                        channel=raw_id, text=req.message,
                    )

            status["sent"] += 1
            sent_times.append(time.time())
            status["log"].append(f"OK: {status['current_chat']}")

        except SlackApiError as e:
            err = e.response.get("error", str(e))
            if err == "ratelimited":
                retry_after = int(e.response.headers.get("Retry-After", 5))
                status["log"].append(f"Rate limited by Slack — retrying in {retry_after}s")
                await asyncio.sleep(retry_after)
                try:
                    await asyncio.to_thread(client.chat_postMessage, channel=raw_id, text=req.message)
                    status["sent"] += 1
                    status["log"].append(f"OK (retry): #{raw_id} (Slack)")
                except Exception as e2:
                    status["failed"] += 1
                    status["log"].append(f"FAIL [{chat_id}]: {e2}")
            else:
                status["failed"] += 1
                status["log"].append(f"FAIL [{chat_id}]: {err}")
        except Exception as e:
            status["failed"] += 1
            status["log"].append(f"FAIL [{chat_id}]: {e}")

        if i < len(ordered_ids) - 1 and status["running"]:
            delay = req.delay + (random.uniform(0, 3) if req.random_delay else 0)
            await asyncio.sleep(delay)

    # Determine channel_type
    platforms_used = set(info["platform"] for info in chat_map.values())
    if len(platforms_used) > 1:
        ch_type = "mixed"
    else:
        ch_type = platforms_used.pop() if platforms_used else "unknown"

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO broadcast_history
           (message, total, sent, failed, started_at, finished_at,
            tg_session_token, app_user_id, app_username, log, channel_type, company_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            (req.message or "")[:200], status["total"], status["sent"], status["failed"],
            started_at, datetime.utcnow().isoformat(),
            broadcast_id, int(app_user["sub"]), app_user["username"],
            json.dumps(status["log"]), ch_type, get_company_id(app_user)
        )
    )
    conn.commit()
    conn.close()

    status["running"] = False
    status["finished"] = True
    status["current_chat"] = ""
    status["log"].append(f"Done. Sent: {status['sent']}, Failed: {status['failed']}")

# ── Unified lists ────────────────────────────────────────────────────────────

class UnifiedSaveListRequest(BaseModel):
    name: str
    chat_ids: list[str]   # ["tg:123", "slack:C01ABC"]

@app.get("/api/unified/lists")
def get_unified_lists(app_user: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    cid = get_company_id(app_user)
    if app_user["role"] == "superadmin":
        rows = conn.execute("SELECT id, name, chats, created_at, channel_type FROM chat_lists ORDER BY id DESC").fetchall()
    elif app_user["role"] == "company_admin":
        rows = conn.execute("SELECT id, name, chats, created_at, channel_type FROM chat_lists WHERE company_id=? ORDER BY id DESC", (cid,)).fetchall()
    else:
        rows = conn.execute("SELECT id, name, chats, created_at, channel_type FROM chat_lists WHERE company_id=? AND owner_app_user_id=? ORDER BY id DESC",
                            (cid, int(app_user["sub"]))).fetchall()
    conn.close()
    return {"lists": [
        {"id": r[0], "name": r[1], "chats": json.loads(r[2]), "created_at": r[3], "channel_type": r[4] or "telegram"}
        for r in rows
    ]}

@app.post("/api/unified/lists")
def save_unified_list(req: UnifiedSaveListRequest, app_user: dict = Depends(get_current_app_user)):
    platforms = set()
    for cid in req.chat_ids:
        if cid.startswith("tg:"): platforms.add("telegram")
        elif cid.startswith("slack:"): platforms.add("slack")
    ch_type = "mixed" if len(platforms) > 1 else (platforms.pop() if platforms else "unknown")
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO chat_lists (name, chats, created_at, owner_app_user_id, channel_type, company_id) VALUES (?,?,?,?,?,?)",
        (req.name, json.dumps(req.chat_ids), datetime.utcnow().isoformat(),
         int(app_user["sub"]), ch_type, get_company_id(app_user))
    )
    conn.commit()
    conn.close()
    return {"saved": True}

@app.delete("/api/unified/lists/{list_id}")
def delete_unified_list(list_id: int, app_user: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    cid = get_company_id(app_user)
    if app_user["role"] == "superadmin":
        conn.execute("DELETE FROM chat_lists WHERE id=?", (list_id,))
    elif app_user["role"] == "company_admin":
        conn.execute("DELETE FROM chat_lists WHERE id=? AND company_id=?", (list_id, cid))
    else:
        conn.execute("DELETE FROM chat_lists WHERE id=? AND company_id=? AND owner_app_user_id=?",
                     (list_id, cid, int(app_user["sub"])))
    conn.commit()
    conn.close()
    return {"deleted": True}

# ═════════════════════════════════════════════════════════════════════════════
# ── Accounts & Dashboard ────────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════════════════════

class BulkAssignOwnerRequest(BaseModel):
    account_ids: list
    owner_id: Optional[int] = None

class BulkAddTagsRequest(BaseModel):
    account_ids: list
    tag_ids: list

class BulkRemoveTagsRequest(BaseModel):
    account_ids: list
    tag_ids: list

class CreateTagRequest(BaseModel):
    name: str


@app.get("/api/accounts")
def list_accounts(
    messenger: Optional[str] = Query(None),
    owner_id: Optional[str] = Query(None),
    type: Optional[str] = Query(None),
    tags: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    app_user: dict = Depends(get_current_app_user),
):
    conn = sqlite3.connect(DB_PATH)
    conditions = []
    params = []

    if messenger:
        conditions.append("a.messenger = ?")
        params.append(messenger)
    if type:
        conditions.append("a.type = ?")
        params.append(type)
    if owner_id is not None:
        if owner_id == "unassigned":
            conditions.append("a.owner_id IS NULL")
        else:
            conditions.append("a.owner_id = ?")
            params.append(int(owner_id))
    if search:
        conditions.append("a.name LIKE ?")
        params.append(f"%{search}%")

    tag_join = ""
    if tags:
        tag_id_list = [int(t) for t in tags.split(",") if t.strip()]
        if tag_id_list:
            placeholders = ",".join("?" * len(tag_id_list))
            tag_join = f" JOIN account_tag_links atl ON a.id = atl.account_id AND atl.tag_id IN ({placeholders})"
            params = list(tag_id_list) + params

    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""

    count_sql = f"SELECT COUNT(DISTINCT a.id) FROM accounts a{tag_join}{where}"
    total = conn.execute(count_sql, params).fetchone()[0]

    offset = (page - 1) * per_page
    data_sql = (
        f"SELECT DISTINCT a.id, a.name, a.messenger, a.external_channel, a.type, "
        f"a.owner_id, u.username AS owner_name, a.created_at "
        f"FROM accounts a{tag_join} LEFT JOIN app_users u ON a.owner_id = u.id"
        f"{where} ORDER BY a.id DESC LIMIT ? OFFSET ?"
    )
    rows = conn.execute(data_sql, params + [per_page, offset]).fetchall()

    account_ids = [r[0] for r in rows]
    tags_map = {}
    if account_ids:
        ph = ",".join("?" * len(account_ids))
        tag_rows = conn.execute(
            f"SELECT atl.account_id, t.id, t.name FROM account_tag_links atl "
            f"JOIN account_tags t ON atl.tag_id = t.id WHERE atl.account_id IN ({ph})",
            account_ids,
        ).fetchall()
        for aid, tid, tname in tag_rows:
            tags_map.setdefault(aid, []).append({"id": tid, "name": tname})

    conn.close()

    accounts = []
    for r in rows:
        accounts.append({
            "id": r[0], "name": r[1], "messenger": r[2],
            "external_channel": r[3], "type": r[4],
            "owner_id": r[5], "owner_name": r[6],
            "created_at": r[7], "tags": tags_map.get(r[0], []),
        })

    return {"accounts": accounts, "total": total, "page": page, "per_page": per_page}


@app.put("/api/accounts/bulk/owner")
def bulk_assign_owner(req: BulkAssignOwnerRequest,
                      _: dict = Depends(get_current_app_user)):
    if not req.account_ids:
        raise HTTPException(status_code=400, detail="account_ids required")
    conn = sqlite3.connect(DB_PATH)
    if req.owner_id is not None:
        owner = conn.execute("SELECT id FROM app_users WHERE id=?", (req.owner_id,)).fetchone()
        if not owner:
            conn.close()
            raise HTTPException(status_code=404, detail="Owner user not found")
    ph = ",".join("?" * len(req.account_ids))
    conn.execute(f"UPDATE accounts SET owner_id = ? WHERE id IN ({ph})",
                 [req.owner_id] + req.account_ids)
    conn.commit()
    updated = conn.total_changes
    conn.close()
    return {"updated": updated}


@app.post("/api/accounts/bulk/tags")
def bulk_add_tags(req: BulkAddTagsRequest,
                  _: dict = Depends(get_current_app_user)):
    if not req.account_ids or not req.tag_ids:
        raise HTTPException(status_code=400, detail="account_ids and tag_ids required")
    conn = sqlite3.connect(DB_PATH)
    for aid in req.account_ids:
        for tid in req.tag_ids:
            conn.execute("INSERT OR IGNORE INTO account_tag_links (account_id, tag_id) VALUES (?, ?)",
                         (aid, tid))
    conn.commit()
    conn.close()
    return {"added": True}


@app.delete("/api/accounts/bulk/tags")
def bulk_remove_tags(req: BulkRemoveTagsRequest,
                     _: dict = Depends(get_current_app_user)):
    if not req.account_ids or not req.tag_ids:
        raise HTTPException(status_code=400, detail="account_ids and tag_ids required")
    conn = sqlite3.connect(DB_PATH)
    ph_accounts = ",".join("?" * len(req.account_ids))
    ph_tags = ",".join("?" * len(req.tag_ids))
    conn.execute(
        f"DELETE FROM account_tag_links WHERE account_id IN ({ph_accounts}) AND tag_id IN ({ph_tags})",
        req.account_ids + req.tag_ids,
    )
    conn.commit()
    conn.close()
    return {"removed": True}


@app.get("/api/accounts/tags")
def list_tags(_: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id, name FROM account_tags ORDER BY name").fetchall()
    conn.close()
    return {"tags": [{"id": r[0], "name": r[1]} for r in rows]}


@app.post("/api/accounts/tags")
def create_tag(req: CreateTagRequest, _: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    try:
        c = conn.execute("INSERT INTO account_tags (name) VALUES (?)", (req.name,))
        conn.commit()
        tag_id = c.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=409, detail="Tag already exists")
    conn.close()
    return {"id": tag_id, "name": req.name}


@app.delete("/api/accounts/tags/{tag_id}")
def delete_tag(tag_id: int, _: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM account_tag_links WHERE tag_id = ?", (tag_id,))
    conn.execute("DELETE FROM account_tags WHERE id = ?", (tag_id,))
    conn.commit()
    conn.close()
    return {"deleted": True}


@app.get("/api/dashboard")
def get_dashboard(_: dict = Depends(get_current_app_user)):
    conn = sqlite3.connect(DB_PATH)
    total = conn.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
    telegram = conn.execute("SELECT COUNT(*) FROM accounts WHERE messenger='telegram'").fetchone()[0]
    slack = conn.execute("SELECT COUNT(*) FROM accounts WHERE messenger='slack'").fetchone()[0]
    channels = conn.execute("SELECT COUNT(*) FROM accounts WHERE type='channel'").fetchone()[0]
    groups = conn.execute("SELECT COUNT(*) FROM accounts WHERE type='group'").fetchone()[0]
    dm = conn.execute("SELECT COUNT(*) FROM accounts WHERE type='dm'").fetchone()[0]

    rows = conn.execute("""
        SELECT u.username, COUNT(a.id)
        FROM accounts a
        LEFT JOIN app_users u ON a.owner_id = u.id
        WHERE a.type != 'dm'
        GROUP BY a.owner_id
        ORDER BY COUNT(a.id) DESC
    """).fetchall()
    conn.close()

    chats_by_manager = [
        {"manager_name": r[0] or "Unassigned", "chats_count": r[1]}
        for r in rows
    ]

    return {
        "total_chats": total,
        "telegram_chats": telegram,
        "slack_chats": slack,
        "channels": channels,
        "groups": groups,
        "dm": dm,
        "chats_by_manager": chats_by_manager,
    }


# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    backup_dir = os.path.join(DATA_DIR, "backups")
    backups = sorted(os.listdir(backup_dir)) if os.path.exists(backup_dir) else []
    return {
        "status": "ok",
        "sessions": len(tg_clients),
        "slack_sessions": len(slack_clients),
        "last_backup": backups[-1] if backups else None,
    }
