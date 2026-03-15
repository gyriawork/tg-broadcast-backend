"""
Comprehensive tests for the TG Broadcast Backend service.
Tests all API endpoints, auth flows, CRUD operations, and edge cases.
"""
import io
import json
import os
import sqlite3
import tempfile
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Use a temp directory for test data to avoid polluting production data
_test_data_dir = tempfile.mkdtemp()
os.environ["DATA_DIR"] = _test_data_dir
os.environ["JWT_SECRET"] = "test-secret-key"
os.environ["ADMIN_PASSWORD"] = "admin123"

import main
from main import app, init_db, hash_password, verify_password, create_jwt, decode_jwt

# Initialize DB before tests (lifespan doesn't run with TestClient by default)
init_db()

client = TestClient(app, raise_server_exceptions=False)

# Cache the admin token to avoid triggering rate limiting
_cached_admin_token = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def admin_token():
    """Get JWT token for the default admin user (cached to avoid rate limits)."""
    global _cached_admin_token
    if _cached_admin_token is not None:
        # Verify it's still valid
        try:
            decode_jwt(_cached_admin_token)
            return _cached_admin_token
        except Exception:
            pass
    # Clear rate limit state for tests
    main._login_attempts.clear()
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert resp.status_code == 200, f"Admin login failed: {resp.text}"
    _cached_admin_token = resp.json()["token"]
    return _cached_admin_token


def auth_header(token=None):
    """Return Authorization header dict."""
    if token is None:
        token = admin_token()
    return {"Authorization": f"Bearer {token}"}


def create_company_and_admin(token=None):
    """Helper to create a company with its admin user."""
    headers = auth_header(token)
    resp = client.post("/api/admin/companies", json={
        "name": "Test Corp",
        "slug": f"test-corp-{int(time.time() * 1000)}",
        "email": "test@corp.com",
        "admin_username": f"testadmin_{int(time.time() * 1000)}",
        "admin_password": "testpass123",
    }, headers=headers)
    return resp


# ═════════════════════════════════════════════════════════════════════════════
# A. Health & Startup
# ═════════════════════════════════════════════════════════════════════════════

class TestHealth:
    def test_health_endpoint(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "sessions" in data
        assert "slack_sessions" in data

    def test_database_initialized(self):
        """Verify all expected tables exist."""
        conn = sqlite3.connect(main.DB_PATH)
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]
        conn.close()
        expected = ["app_users", "chat_lists", "templates", "broadcast_history",
                     "slack_connections", "companies", "accounts",
                     "account_tags", "account_tag_links"]
        for t in expected:
            assert t in tables, f"Table '{t}' missing from database"

    def test_admin_user_seeded(self):
        """Default admin user should exist."""
        conn = sqlite3.connect(main.DB_PATH)
        row = conn.execute("SELECT username, role FROM app_users WHERE username='admin'").fetchone()
        conn.close()
        assert row is not None
        assert row[0] == "admin"
        assert row[1] == "superadmin"


# ═════════════════════════════════════════════════════════════════════════════
# B. Authentication & RBAC
# ═════════════════════════════════════════════════════════════════════════════

class TestAuth:
    def test_login_success(self):
        main._login_attempts.clear()
        resp = client.post("/api/auth/login", json={
            "username": "admin", "password": "admin123"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "token" in data
        assert data["username"] == "admin"
        assert data["role"] == "superadmin"
        assert data["id"] is not None

    def test_login_wrong_password(self):
        main._login_attempts.clear()
        resp = client.post("/api/auth/login", json={
            "username": "admin", "password": "wrongpass"
        })
        assert resp.status_code == 401

    def test_login_nonexistent_user(self):
        main._login_attempts.clear()
        resp = client.post("/api/auth/login", json={
            "username": "nonexistent", "password": "pass"
        })
        assert resp.status_code == 401

    def test_me_with_valid_token(self):
        token = admin_token()
        resp = client.get("/api/auth/me", headers=auth_header(token))
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == "admin"
        assert data["role"] == "superadmin"

    def test_me_without_token(self):
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401 or resp.status_code == 403

    def test_me_with_invalid_token(self):
        resp = client.get("/api/auth/me", headers={"Authorization": "Bearer invalid-token"})
        assert resp.status_code == 401

    def test_create_user(self):
        headers = auth_header()
        # First create a company for the user
        comp_resp = create_company_and_admin()
        assert comp_resp.status_code == 200
        company_id = comp_resp.json()["company_id"]

        resp = client.post("/api/auth/users", json={
            "username": f"testuser_{int(time.time() * 1000)}",
            "role": "user",
            "company_id": company_id,
            "email": "test@example.com",
        }, headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["created"] is True
        assert "password" in data  # auto-generated password

    def test_create_duplicate_user(self):
        headers = auth_header()
        comp_resp = create_company_and_admin()
        company_id = comp_resp.json()["company_id"]
        username = f"dupuser_{int(time.time() * 1000)}"

        client.post("/api/auth/users", json={
            "username": username, "role": "user", "company_id": company_id
        }, headers=headers)
        resp = client.post("/api/auth/users", json={
            "username": username, "role": "user", "company_id": company_id
        }, headers=headers)
        assert resp.status_code == 409

    def test_list_users(self):
        headers = auth_header()
        resp = client.get("/api/auth/users", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "users" in data
        assert len(data["users"]) > 0

    def test_delete_user(self):
        headers = auth_header()
        comp_resp = create_company_and_admin()
        company_id = comp_resp.json()["company_id"]
        username = f"deluser_{int(time.time() * 1000)}"

        client.post("/api/auth/users", json={
            "username": username, "role": "user", "company_id": company_id
        }, headers=headers)

        # Find the user id
        users_resp = client.get("/api/auth/users", headers=headers)
        user_id = None
        for u in users_resp.json()["users"]:
            if u["username"] == username:
                user_id = u["id"]
                break
        assert user_id is not None

        resp = client.delete(f"/api/auth/users/{user_id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True

    def test_cannot_delete_self(self):
        headers = auth_header()
        # Admin user ID is 1
        me_resp = client.get("/api/auth/me", headers=headers)
        my_id = me_resp.json()["id"]
        resp = client.delete(f"/api/auth/users/{my_id}", headers=headers)
        assert resp.status_code == 400

    def test_toggle_user_active(self):
        headers = auth_header()
        comp_resp = create_company_and_admin()
        company_id = comp_resp.json()["company_id"]
        username = f"toggleuser_{int(time.time() * 1000)}"

        client.post("/api/auth/users", json={
            "username": username, "role": "user", "company_id": company_id
        }, headers=headers)

        users_resp = client.get("/api/auth/users", headers=headers)
        user_id = None
        for u in users_resp.json()["users"]:
            if u["username"] == username:
                user_id = u["id"]
                break

        resp = client.put(f"/api/auth/users/{user_id}/active", headers=headers)
        assert resp.status_code == 200
        assert "is_active" in resp.json()

    def test_change_password(self):
        global _cached_admin_token
        headers = auth_header()
        resp = client.put("/api/auth/me/password", json={
            "old_password": "admin123",
            "new_password": "newpass456",
        }, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["password_changed"] is True

        # Login with new password should work
        main._login_attempts.clear()
        resp2 = client.post("/api/auth/login", json={
            "username": "admin", "password": "newpass456"
        })
        assert resp2.status_code == 200

        # Restore original password and update cache
        new_token = resp2.json()["token"]
        client.put("/api/auth/me/password", json={
            "old_password": "newpass456",
            "new_password": "admin123",
        }, headers=auth_header(new_token))
        _cached_admin_token = None  # Force re-login next time

    def test_change_password_wrong_old(self):
        headers = auth_header()
        resp = client.put("/api/auth/me/password", json={
            "old_password": "wrongold",
            "new_password": "newpass",
        }, headers=headers)
        assert resp.status_code == 400

    def test_reset_password(self):
        headers = auth_header()
        comp_resp = create_company_and_admin()
        company_id = comp_resp.json()["company_id"]
        username = f"resetpwuser_{int(time.time() * 1000)}"

        client.post("/api/auth/users", json={
            "username": username, "role": "user", "company_id": company_id
        }, headers=headers)

        users_resp = client.get("/api/auth/users", headers=headers)
        user_id = None
        for u in users_resp.json()["users"]:
            if u["username"] == username:
                user_id = u["id"]
                break

        resp = client.put(f"/api/auth/users/{user_id}/password", headers=headers)
        assert resp.status_code == 200
        assert "password" in resp.json()

    def test_login_deactivated_user(self):
        headers = auth_header()
        comp_resp = create_company_and_admin()
        company_id = comp_resp.json()["company_id"]
        username = f"deactuser_{int(time.time() * 1000)}"
        password = "testpass"

        client.post("/api/auth/users", json={
            "username": username, "role": "user",
            "company_id": company_id, "password": password,
        }, headers=headers)

        users_resp = client.get("/api/auth/users", headers=headers)
        user_id = None
        for u in users_resp.json()["users"]:
            if u["username"] == username:
                user_id = u["id"]
                break

        # Deactivate
        client.put(f"/api/auth/users/{user_id}/active", headers=headers)

        # Try to login
        main._login_attempts.clear()
        resp = client.post("/api/auth/login", json={
            "username": username, "password": password
        })
        assert resp.status_code == 403


# ═════════════════════════════════════════════════════════════════════════════
# C. Company Management
# ═════════════════════════════════════════════════════════════════════════════

class TestCompanies:
    def test_create_company(self):
        resp = create_company_and_admin()
        assert resp.status_code == 200
        data = resp.json()
        assert data["created"] is True
        assert "company_id" in data
        assert "admin_username" in data
        assert "admin_password" in data

    def test_list_companies(self):
        headers = auth_header()
        resp = client.get("/api/admin/companies", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "companies" in data
        assert isinstance(data["companies"], list)

    def test_get_company(self):
        headers = auth_header()
        comp_resp = create_company_and_admin()
        company_id = comp_resp.json()["company_id"]

        resp = client.get(f"/api/admin/companies/{company_id}", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "company" in data
        assert "users" in data
        assert data["company"]["id"] == company_id

    def test_update_company(self):
        headers = auth_header()
        comp_resp = create_company_and_admin()
        company_id = comp_resp.json()["company_id"]

        resp = client.put(f"/api/admin/companies/{company_id}", json={
            "name": "Updated Corp Name",
            "email": "updated@corp.com",
        }, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["updated"] is True

    def test_update_company_status(self):
        headers = auth_header()
        comp_resp = create_company_and_admin()
        company_id = comp_resp.json()["company_id"]

        resp = client.put(f"/api/admin/companies/{company_id}", json={
            "status": "inactive",
        }, headers=headers)
        assert resp.status_code == 200

    def test_update_company_invalid_status(self):
        headers = auth_header()
        comp_resp = create_company_and_admin()
        company_id = comp_resp.json()["company_id"]

        resp = client.put(f"/api/admin/companies/{company_id}", json={
            "status": "invalid_status",
        }, headers=headers)
        assert resp.status_code == 400

    def test_delete_company(self):
        headers = auth_header()
        comp_resp = create_company_and_admin()
        company_id = comp_resp.json()["company_id"]

        resp = client.delete(f"/api/admin/companies/{company_id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True

        # Verify it's gone
        resp2 = client.get(f"/api/admin/companies/{company_id}", headers=headers)
        assert resp2.status_code == 404

    def test_duplicate_slug(self):
        headers = auth_header()
        slug = f"dup-slug-{int(time.time() * 1000)}"
        client.post("/api/admin/companies", json={
            "name": "Corp 1", "slug": slug,
            "admin_username": f"admin1_{int(time.time() * 1000)}",
        }, headers=headers)

        resp = client.post("/api/admin/companies", json={
            "name": "Corp 2", "slug": slug,
            "admin_username": f"admin2_{int(time.time() * 1000)}",
        }, headers=headers)
        assert resp.status_code == 409

    def test_get_nonexistent_company(self):
        headers = auth_header()
        resp = client.get("/api/admin/companies/99999", headers=headers)
        assert resp.status_code == 404

    def test_company_admin_cannot_access_company_management(self):
        """company_admin role cannot manage companies."""
        comp_resp = create_company_and_admin()
        admin_username = comp_resp.json()["admin_username"]
        admin_password = comp_resp.json()["admin_password"]

        main._login_attempts.clear()
        login_resp = client.post("/api/auth/login", json={
            "username": admin_username, "password": admin_password
        })
        token = login_resp.json()["token"]

        resp = client.get("/api/admin/companies", headers=auth_header(token))
        assert resp.status_code == 403


# ═════════════════════════════════════════════════════════════════════════════
# D. Templates CRUD
# ═════════════════════════════════════════════════════════════════════════════

class TestTemplates:
    def test_create_and_list_templates(self):
        headers = auth_header()
        resp = client.post("/api/templates", json={
            "name": "Welcome", "text": "Hello, welcome to our channel!"
        }, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["saved"] is True

        resp2 = client.get("/api/templates", headers=headers)
        assert resp2.status_code == 200
        templates = resp2.json()["templates"]
        assert isinstance(templates, list)

    def test_delete_template(self):
        headers = auth_header()
        client.post("/api/templates", json={
            "name": "ToDelete", "text": "Will be deleted"
        }, headers=headers)

        templates = client.get("/api/templates", headers=headers).json()["templates"]
        tid = templates[0]["id"]

        resp = client.delete(f"/api/templates/{tid}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True

    def test_templates_require_auth(self):
        resp = client.get("/api/templates")
        assert resp.status_code in (401, 403)


# ═════════════════════════════════════════════════════════════════════════════
# E. Chat Lists CRUD
# ═════════════════════════════════════════════════════════════════════════════

class TestChatLists:
    def test_save_and_get_lists(self):
        headers = auth_header()
        resp = client.post("/api/lists", json={
            "name": "Test List", "chat_ids": [123, 456, 789]
        }, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["saved"] is True

        resp2 = client.get("/api/lists", headers=headers)
        assert resp2.status_code == 200
        assert "lists" in resp2.json()

    def test_delete_list(self):
        headers = auth_header()
        client.post("/api/lists", json={
            "name": "ToDelete", "chat_ids": [111]
        }, headers=headers)

        lists = client.get("/api/lists", headers=headers).json()["lists"]
        if lists:
            list_id = lists[0]["id"]
            resp = client.delete(f"/api/lists/{list_id}", headers=headers)
            assert resp.status_code == 200

    def test_lists_require_auth(self):
        resp = client.get("/api/lists")
        assert resp.status_code in (401, 403)


# ═════════════════════════════════════════════════════════════════════════════
# F. Broadcast History
# ═════════════════════════════════════════════════════════════════════════════

class TestHistory:
    def test_get_history(self):
        headers = auth_header()
        resp = client.get("/api/history", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "history" in data
        assert isinstance(data["history"], list)

    def test_history_requires_auth(self):
        resp = client.get("/api/history")
        assert resp.status_code in (401, 403)


# ═════════════════════════════════════════════════════════════════════════════
# G. Accounts & Tags
# ═════════════════════════════════════════════════════════════════════════════

class TestAccounts:
    def _seed_account(self):
        """Insert a test account directly into the DB."""
        conn = sqlite3.connect(main.DB_PATH)
        from datetime import datetime
        conn.execute(
            "INSERT OR IGNORE INTO accounts (name, messenger, external_channel, type, created_at) VALUES (?,?,?,?,?)",
            ("Test Channel", "telegram", f"ext_{int(time.time() * 1000)}", "channel", datetime.utcnow().isoformat())
        )
        conn.commit()
        last_id = conn.execute("SELECT MAX(id) FROM accounts").fetchone()[0]
        conn.close()
        return last_id

    def test_list_accounts(self):
        headers = auth_header()
        self._seed_account()
        resp = client.get("/api/accounts", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "accounts" in data
        assert "total" in data
        assert "page" in data
        assert "per_page" in data

    def test_list_accounts_with_filters(self):
        headers = auth_header()
        self._seed_account()
        resp = client.get("/api/accounts?messenger=telegram&page=1&per_page=10", headers=headers)
        assert resp.status_code == 200
        for acc in resp.json()["accounts"]:
            assert acc["messenger"] == "telegram"

    def test_list_accounts_search(self):
        headers = auth_header()
        self._seed_account()
        resp = client.get("/api/accounts?search=Test", headers=headers)
        assert resp.status_code == 200

    def test_list_accounts_unassigned_filter(self):
        headers = auth_header()
        self._seed_account()
        resp = client.get("/api/accounts?owner_id=unassigned", headers=headers)
        assert resp.status_code == 200

    def test_create_and_list_tags(self):
        headers = auth_header()
        tag_name = f"tag_{int(time.time() * 1000)}"
        resp = client.post("/api/accounts/tags", json={"name": tag_name}, headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == tag_name
        assert "id" in data

        resp2 = client.get("/api/accounts/tags", headers=headers)
        assert resp2.status_code == 200
        tag_names = [t["name"] for t in resp2.json()["tags"]]
        assert tag_name in tag_names

    def test_create_duplicate_tag(self):
        headers = auth_header()
        tag_name = f"duptag_{int(time.time() * 1000)}"
        client.post("/api/accounts/tags", json={"name": tag_name}, headers=headers)
        resp = client.post("/api/accounts/tags", json={"name": tag_name}, headers=headers)
        assert resp.status_code == 409

    def test_delete_tag(self):
        headers = auth_header()
        tag_name = f"deltag_{int(time.time() * 1000)}"
        create_resp = client.post("/api/accounts/tags", json={"name": tag_name}, headers=headers)
        tag_id = create_resp.json()["id"]

        resp = client.delete(f"/api/accounts/tags/{tag_id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True

    def test_bulk_assign_owner(self):
        headers = auth_header()
        account_id = self._seed_account()

        me_resp = client.get("/api/auth/me", headers=headers)
        owner_id = int(me_resp.json()["id"])

        resp = client.put("/api/accounts/bulk/owner", json={
            "account_ids": [account_id],
            "owner_id": owner_id,
        }, headers=headers)
        assert resp.status_code == 200

    def test_bulk_assign_owner_nonexistent_user(self):
        headers = auth_header()
        account_id = self._seed_account()
        resp = client.put("/api/accounts/bulk/owner", json={
            "account_ids": [account_id],
            "owner_id": 99999,
        }, headers=headers)
        assert resp.status_code == 404

    def test_bulk_add_and_remove_tags(self):
        headers = auth_header()
        account_id = self._seed_account()

        tag_name = f"bulktag_{int(time.time() * 1000)}"
        tag_resp = client.post("/api/accounts/tags", json={"name": tag_name}, headers=headers)
        tag_id = tag_resp.json()["id"]

        # Add tags
        resp = client.post("/api/accounts/bulk/tags", json={
            "account_ids": [account_id],
            "tag_ids": [tag_id],
        }, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["added"] is True

        # Verify account has tag
        accs = client.get("/api/accounts", headers=headers).json()["accounts"]
        found = [a for a in accs if a["id"] == account_id]
        if found:
            assert any(t["id"] == tag_id for t in found[0]["tags"])

        # Remove tags (DELETE with body requires client.request)
        resp2 = client.request("DELETE", "/api/accounts/bulk/tags", json={
            "account_ids": [account_id],
            "tag_ids": [tag_id],
        }, headers=headers)
        assert resp2.status_code == 200
        assert resp2.json()["removed"] is True

    def test_bulk_operations_empty_ids(self):
        headers = auth_header()
        resp = client.put("/api/accounts/bulk/owner", json={
            "account_ids": [], "owner_id": 1
        }, headers=headers)
        assert resp.status_code == 400

    def test_accounts_require_auth(self):
        resp = client.get("/api/accounts")
        assert resp.status_code in (401, 403)


# ═════════════════════════════════════════════════════════════════════════════
# H. Dashboard
# ═════════════════════════════════════════════════════════════════════════════

class TestDashboard:
    def test_dashboard(self):
        headers = auth_header()
        resp = client.get("/api/dashboard", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "total_chats" in data
        assert "telegram_chats" in data
        assert "slack_chats" in data
        assert "channels" in data
        assert "groups" in data
        assert "dm" in data
        assert "chats_by_manager" in data

    def test_dashboard_requires_auth(self):
        resp = client.get("/api/dashboard")
        assert resp.status_code in (401, 403)


# ═════════════════════════════════════════════════════════════════════════════
# I. File Upload
# ═════════════════════════════════════════════════════════════════════════════

class TestFileUpload:
    def test_upload_file(self):
        headers = auth_header()
        headers["X-Session-Token"] = "test-upload-token"

        file_content = b"Hello, this is a test file"
        resp = client.post("/api/upload",
                           headers=headers,
                           files={"file": ("test.txt", io.BytesIO(file_content), "text/plain")})
        assert resp.status_code == 200
        data = resp.json()
        assert data["uploaded"] is True
        assert data["name"] == "test.txt"
        assert data["size"] == len(file_content)

    def test_get_upload_status(self):
        headers = auth_header()
        headers["X-Session-Token"] = "test-upload-token-2"

        # No upload yet
        resp = client.get("/api/upload", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["file"] is None

        # Upload a file
        client.post("/api/upload", headers=headers,
                    files={"file": ("test2.txt", io.BytesIO(b"content"), "text/plain")})

        # Check status
        resp2 = client.get("/api/upload", headers=headers)
        assert resp2.status_code == 200
        assert resp2.json()["file"] is not None
        assert resp2.json()["file"]["name"] == "test2.txt"

    def test_clear_upload(self):
        headers = auth_header()
        headers["X-Session-Token"] = "test-upload-token-3"

        client.post("/api/upload", headers=headers,
                    files={"file": ("test3.txt", io.BytesIO(b"content"), "text/plain")})

        resp = client.delete("/api/upload", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["cleared"] is True

        # Verify cleared
        resp2 = client.get("/api/upload", headers=headers)
        assert resp2.json()["file"] is None

    def test_upload_too_large(self):
        headers = auth_header()
        headers["X-Session-Token"] = "test-upload-large"

        # Create a file larger than 50MB
        large_content = b"x" * (main.MAX_UPLOAD_BYTES + 1)
        resp = client.post("/api/upload", headers=headers,
                           files={"file": ("large.bin", io.BytesIO(large_content), "application/octet-stream")})
        assert resp.status_code == 413

    def test_upload_requires_session_token(self):
        headers = auth_header()
        resp = client.post("/api/upload", headers=headers,
                           files={"file": ("test.txt", io.BytesIO(b"content"), "text/plain")})
        assert resp.status_code == 400  # Missing X-Session-Token


# ═════════════════════════════════════════════════════════════════════════════
# J. Telegram Endpoints
# ═════════════════════════════════════════════════════════════════════════════

class TestTelegram:
    def test_connect_requires_auth(self):
        resp = client.post("/api/connect", json={
            "api_id": 12345, "api_hash": "test_hash"
        })
        assert resp.status_code in (401, 403)

    def test_chats_missing_session(self):
        headers = auth_header()
        headers["X-Session-Token"] = "nonexistent-token"
        resp = client.get("/api/chats", headers=headers)
        assert resp.status_code == 400

    def test_chats_missing_session_header(self):
        headers = auth_header()
        resp = client.get("/api/chats", headers=headers)
        assert resp.status_code == 400

    def test_broadcast_start_no_session(self):
        headers = auth_header()
        headers["X-Session-Token"] = "nonexistent-token"
        resp = client.post("/api/broadcast/start", json={
            "chat_ids": [123], "message": "test"
        }, headers=headers)
        assert resp.status_code == 400

    def test_broadcast_status_no_session(self):
        headers = auth_header()
        headers["X-Session-Token"] = "nonexistent-token"
        resp = client.get("/api/broadcast/status", headers=headers)
        assert resp.status_code == 200  # Returns default empty status

    def test_broadcast_stop(self):
        headers = auth_header()
        headers["X-Session-Token"] = "nonexistent-token"
        resp = client.post("/api/broadcast/stop", headers=headers)
        assert resp.status_code == 200

    def test_me_no_session(self):
        headers = auth_header()
        headers["X-Session-Token"] = "nonexistent-token"
        resp = client.get("/api/me", headers=headers)
        assert resp.status_code == 400

    def test_logout_no_session(self):
        headers = auth_header()
        headers["X-Session-Token"] = "nonexistent-token"
        resp = client.post("/api/logout", headers=headers)
        assert resp.status_code == 200  # Should succeed even without a session


# ═════════════════════════════════════════════════════════════════════════════
# K. Slack Endpoints
# ═════════════════════════════════════════════════════════════════════════════

class TestSlack:
    def test_slack_me_no_session(self):
        headers = auth_header()
        headers["X-Slack-Session-Token"] = "nonexistent-token"
        resp = client.get("/api/slack/me", headers=headers)
        assert resp.status_code == 400

    def test_slack_disconnect_no_session(self):
        headers = auth_header()
        headers["X-Slack-Session-Token"] = "nonexistent-token"
        resp = client.post("/api/slack/disconnect", headers=headers)
        assert resp.status_code == 200  # Graceful even without session

    def test_slack_channels_no_session(self):
        headers = auth_header()
        headers["X-Slack-Session-Token"] = "nonexistent-token"
        resp = client.get("/api/slack/channels", headers=headers)
        assert resp.status_code == 400

    def test_slack_broadcast_start_no_session(self):
        headers = auth_header()
        headers["X-Slack-Session-Token"] = "nonexistent-token"
        resp = client.post("/api/slack/broadcast/start", json={
            "channel_ids": ["C123"], "message": "test"
        }, headers=headers)
        assert resp.status_code == 400

    def test_slack_oauth_start_not_configured(self):
        headers = auth_header()
        resp = client.get("/api/slack/oauth/start", headers=headers)
        assert resp.status_code == 500  # Not configured

    def test_slack_lists(self):
        headers = auth_header()
        # Save a slack list
        resp = client.post("/api/slack/lists", json={
            "name": "Test Slack List",
            "channel_ids": ["C123", "C456"],
        }, headers=headers)
        assert resp.status_code == 200

        # Get slack lists
        resp2 = client.get("/api/slack/lists", headers=headers)
        assert resp2.status_code == 200
        assert "lists" in resp2.json()

    def test_slack_delete_list(self):
        headers = auth_header()
        client.post("/api/slack/lists", json={
            "name": "Del Slack List", "channel_ids": ["C789"]
        }, headers=headers)

        lists = client.get("/api/slack/lists", headers=headers).json()["lists"]
        if lists:
            resp = client.delete(f"/api/slack/lists/{lists[0]['id']}", headers=headers)
            assert resp.status_code == 200

    def test_slack_broadcast_stop(self):
        headers = auth_header()
        headers["X-Slack-Session-Token"] = "nonexistent-token"
        resp = client.post("/api/slack/broadcast/stop", headers=headers)
        assert resp.status_code == 200

    def test_slack_broadcast_status(self):
        headers = auth_header()
        headers["X-Slack-Session-Token"] = "nonexistent-token"
        resp = client.get("/api/slack/broadcast/status", headers=headers)
        assert resp.status_code == 200


# ═════════════════════════════════════════════════════════════════════════════
# L. Unified Endpoints
# ═════════════════════════════════════════════════════════════════════════════

class TestUnified:
    def test_integrations_status(self):
        headers = auth_header()
        resp = client.get("/api/integrations/status", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "telegram" in data
        assert "slack" in data
        assert "connected" in data["telegram"]
        assert "connected" in data["slack"]

    def test_unified_broadcast_no_chats(self):
        headers = auth_header()
        resp = client.post("/api/unified/broadcast/start", json={
            "chat_ids": [], "message": "test"
        }, headers=headers)
        assert resp.status_code == 400

    def test_unified_broadcast_message_too_long(self):
        headers = auth_header()
        resp = client.post("/api/unified/broadcast/start", json={
            "chat_ids": ["tg:123"], "message": "x" * 4097
        }, headers=headers)
        assert resp.status_code == 400

    def test_unified_broadcast_invalid_chats(self):
        headers = auth_header()
        resp = client.post("/api/unified/broadcast/start", json={
            "chat_ids": ["tg:123"], "message": "test"
        }, headers=headers)
        # Should fail because no TG session exists for this user
        assert resp.status_code == 400

    def test_unified_lists(self):
        headers = auth_header()
        resp = client.post("/api/unified/lists", json={
            "name": "Mixed List",
            "chat_ids": ["tg:123", "slack:C456"],
        }, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["saved"] is True

        resp2 = client.get("/api/unified/lists", headers=headers)
        assert resp2.status_code == 200
        assert "lists" in resp2.json()

    def test_unified_delete_list(self):
        headers = auth_header()
        client.post("/api/unified/lists", json={
            "name": "Del Unified", "chat_ids": ["tg:111"]
        }, headers=headers)

        lists = client.get("/api/unified/lists", headers=headers).json()["lists"]
        if lists:
            resp = client.delete(f"/api/unified/lists/{lists[0]['id']}", headers=headers)
            assert resp.status_code == 200

    def test_unified_broadcast_stop(self):
        headers = auth_header()
        resp = client.post("/api/unified/broadcast/stop?broadcast_id=nonexistent", headers=headers)
        assert resp.status_code == 200

    def test_unified_broadcast_status(self):
        headers = auth_header()
        resp = client.get("/api/unified/broadcast/status?broadcast_id=nonexistent", headers=headers)
        assert resp.status_code == 200


# ═════════════════════════════════════════════════════════════════════════════
# M. SSE Streams
# ═════════════════════════════════════════════════════════════════════════════

class TestSSEStreams:
    def test_broadcast_stream_no_auth(self):
        resp = client.get("/api/broadcast/stream", headers={"X-Session-Token": "test"})
        assert resp.status_code == 401

    def test_broadcast_stream_with_jwt_query(self):
        token = admin_token()
        # Set up a finished broadcast status so the stream terminates
        stream_token = "test-stream-sse"
        main.broadcast_statuses[stream_token] = {
            "running": False, "total": 1, "sent": 1, "failed": 0,
            "current_chat": "", "log": ["Done"], "finished": True,
        }
        resp = client.get(f"/api/broadcast/stream?jwt={token}",
                          headers={"X-Session-Token": stream_token})
        assert resp.status_code == 200

    def test_slack_stream_no_auth(self):
        resp = client.get("/api/slack/broadcast/stream",
                          headers={"X-Slack-Session-Token": "test"})
        assert resp.status_code == 401

    def test_unified_stream_no_auth(self):
        resp = client.get("/api/unified/broadcast/stream?broadcast_id=test")
        assert resp.status_code == 401

    def test_unified_stream_with_jwt_query(self):
        token = admin_token()
        # Set up a finished broadcast so the stream terminates
        bid = "test-unified-stream"
        main.broadcast_statuses[bid] = {
            "running": False, "total": 1, "sent": 1, "failed": 0,
            "current_chat": "", "log": ["Done"], "finished": True,
        }
        resp = client.get(f"/api/unified/broadcast/stream?broadcast_id={bid}&jwt={token}")
        assert resp.status_code == 200


# ═════════════════════════════════════════════════════════════════════════════
# N. Admin Endpoints
# ═════════════════════════════════════════════════════════════════════════════

class TestAdmin:
    def test_admin_sessions(self):
        headers = auth_header()
        resp = client.get("/api/admin/sessions", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "sessions" in data
        assert isinstance(data["sessions"], list)

    def test_manual_backup(self):
        headers = auth_header()
        resp = client.post("/api/admin/backup", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "backup" in data
        assert "size_bytes" in data

    def test_admin_sessions_requires_admin(self):
        # Create a regular user and try to access admin endpoint
        headers = auth_header()
        comp_resp = create_company_and_admin()
        company_id = comp_resp.json()["company_id"]
        username = f"normaluser_{int(time.time() * 1000)}"

        client.post("/api/auth/users", json={
            "username": username, "role": "user",
            "company_id": company_id, "password": "userpass"
        }, headers=headers)

        main._login_attempts.clear()
        user_login = client.post("/api/auth/login", json={
            "username": username, "password": "userpass"
        })
        user_token = user_login.json()["token"]

        resp = client.get("/api/admin/sessions", headers=auth_header(user_token))
        assert resp.status_code == 403


# ═════════════════════════════════════════════════════════════════════════════
# O. Password Hashing Utilities
# ═════════════════════════════════════════════════════════════════════════════

class TestPasswordUtils:
    def test_hash_and_verify(self):
        pw = "test_password_123"
        hashed = hash_password(pw)
        assert verify_password(pw, hashed) is True
        assert verify_password("wrong_password", hashed) is False

    def test_verify_invalid_hash(self):
        assert verify_password("test", "invalid-hash") is False


# ═════════════════════════════════════════════════════════════════════════════
# P. JWT Utilities
# ═════════════════════════════════════════════════════════════════════════════

class TestJWT:
    def test_create_and_decode_jwt(self):
        token = create_jwt(1, "testuser", "user", company_id=5)
        payload = decode_jwt(token)
        assert payload["sub"] == "1"
        assert payload["username"] == "testuser"
        assert payload["role"] == "user"
        assert payload["company_id"] == 5

    def test_decode_invalid_jwt(self):
        with pytest.raises(Exception):
            decode_jwt("invalid-token")

    def test_jwt_without_company(self):
        token = create_jwt(1, "admin", "superadmin")
        payload = decode_jwt(token)
        assert payload["company_id"] is None


# ═════════════════════════════════════════════════════════════════════════════
# Q. OpenAPI / Docs
# ═════════════════════════════════════════════════════════════════════════════

class TestDocs:
    def test_openapi_schema(self):
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        schema = resp.json()
        assert "paths" in schema
        assert "openapi" in schema

    def test_docs_page(self):
        resp = client.get("/docs")
        assert resp.status_code == 200


# ═════════════════════════════════════════════════════════════════════════════
# R. Edge Cases
# ═════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    def test_delete_nonexistent_user(self):
        headers = auth_header()
        resp = client.delete("/api/auth/users/99999", headers=headers)
        assert resp.status_code == 404

    def test_reset_password_nonexistent_user(self):
        headers = auth_header()
        resp = client.put("/api/auth/users/99999/password", headers=headers)
        assert resp.status_code == 404

    def test_toggle_nonexistent_user(self):
        headers = auth_header()
        resp = client.put("/api/auth/users/99999/active", headers=headers)
        assert resp.status_code == 404

    def test_delete_nonexistent_company(self):
        headers = auth_header()
        resp = client.delete("/api/admin/companies/99999", headers=headers)
        assert resp.status_code == 404

    def test_update_nonexistent_company(self):
        headers = auth_header()
        resp = client.put("/api/admin/companies/99999", json={"name": "X"}, headers=headers)
        assert resp.status_code == 404

    def test_company_admin_scoped_user_creation(self):
        """Company admin can only create users with role 'user'."""
        comp_resp = create_company_and_admin()
        admin_username = comp_resp.json()["admin_username"]
        admin_password = comp_resp.json()["admin_password"]

        main._login_attempts.clear()
        login_resp = client.post("/api/auth/login", json={
            "username": admin_username, "password": admin_password
        })
        token = login_resp.json()["token"]
        headers = auth_header(token)

        # Try to create company_admin — should fail
        resp = client.post("/api/auth/users", json={
            "username": f"elevateduser_{int(time.time() * 1000)}",
            "role": "company_admin",
        }, headers=headers)
        assert resp.status_code == 403

    def test_superadmin_needs_company_id_for_user(self):
        """Superadmin must provide company_id when creating users."""
        headers = auth_header()
        resp = client.post("/api/auth/users", json={
            "username": f"nocompany_{int(time.time() * 1000)}",
            "role": "user",
        }, headers=headers)
        assert resp.status_code == 400

    def test_inactive_company_login_blocked(self):
        """Users from inactive companies cannot login."""
        headers = auth_header()
        comp_resp = create_company_and_admin()
        company_id = comp_resp.json()["company_id"]
        admin_username = comp_resp.json()["admin_username"]
        admin_password = comp_resp.json()["admin_password"]

        # Deactivate the company
        client.put(f"/api/admin/companies/{company_id}", json={
            "status": "inactive"
        }, headers=headers)

        # Try to login as company admin
        main._login_attempts.clear()
        resp = client.post("/api/auth/login", json={
            "username": admin_username, "password": admin_password
        })
        assert resp.status_code == 403
