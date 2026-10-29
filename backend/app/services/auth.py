import hashlib
import hmac
import os
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import HTTPException, Request


SESSION_COOKIE = "kesihba_session"
SESSION_LIFETIME = timedelta(days=7)
DEFAULT_AUTH_DB_PATH = Path(__file__).resolve().parents[2] / "kesihba_auth.db"


class DuplicateAccountError(Exception):
    pass


def _db_path() -> Path:
    return Path(os.getenv("KESIHBA_AUTH_DB", DEFAULT_AUTH_DB_PATH))


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions(expires_at);
        """
    )
    return connection


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32, maxmem=32 * 1024 * 1024)
    return f"scrypt$16384$8$1${salt.hex()}${derived.hex()}"


def _verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, n, r, p, salt_hex, digest_hex = stored_hash.split("$")
        if algorithm != "scrypt":
            return False
        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(bytes.fromhex(digest_hex)),
            maxmem=32 * 1024 * 1024,
        )
        return hmac.compare_digest(candidate.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def _public_user(row: sqlite3.Row) -> dict[str, Any]:
    return {"id": row["id"], "name": row["name"], "email": row["email"]}


def _new_session(connection: sqlite3.Connection, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    now = _utc_now()
    connection.execute(
        "INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
        (
            hashlib.sha256(token.encode("utf-8")).hexdigest(),
            user_id,
            (now + SESSION_LIFETIME).isoformat(),
            now.isoformat(),
        ),
    )
    connection.execute("DELETE FROM sessions WHERE expires_at < ?", (now.isoformat(),))
    return token


def create_account(name: str, email: str, password: str) -> dict[str, Any]:
    clean_email = email.strip().lower()
    password_hash = _password_hash(password)
    with closing(_connect()) as connection, connection:
        try:
            cursor = connection.execute(
                "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (name.strip(), clean_email, password_hash, _utc_now().isoformat()),
            )
        except sqlite3.IntegrityError as error:
            raise DuplicateAccountError from error
        user_id = int(cursor.lastrowid)
        row = connection.execute("SELECT id, name, email FROM users WHERE id = ?", (user_id,)).fetchone()
    return _public_user(row)


def authenticate(email: str, password: str) -> tuple[dict[str, Any], str] | None:
    clean_email = email.strip().lower()
    with closing(_connect()) as connection, connection:
        row = connection.execute(
            "SELECT id, name, email, password_hash FROM users WHERE email = ?",
            (clean_email,),
        ).fetchone()
        password_hash = row["password_hash"] if row else _password_hash(password)
        if not _verify_password(password, password_hash) or row is None:
            return None
        token = _new_session(connection, row["id"])
    return _public_user(row), token


def user_for_session(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = _utc_now().isoformat()
    with closing(_connect()) as connection, connection:
        row = connection.execute(
            """
            SELECT users.id, users.name, users.email
            FROM sessions JOIN users ON users.id = sessions.user_id
            WHERE sessions.token_hash = ? AND sessions.expires_at > ?
            """,
            (token_hash, now),
        ).fetchone()
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
    return _public_user(row) if row else None


def revoke_session(token: str | None) -> None:
    if not token:
        return
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with closing(_connect()) as connection, connection:
        connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))


def current_user(request: Request, required: bool = False) -> dict[str, Any] | None:
    user = user_for_session(request.cookies.get(SESSION_COOKIE))
    if user is None and required:
        raise HTTPException(status_code=401, detail="Sign in to access this account feature.")
    return user


def allowed_origins() -> set[str]:
    configured = os.getenv("KESIHBA_ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
    return {origin.strip().rstrip("/") for origin in configured.split(",") if origin.strip()}


def require_csrf(request: Request) -> None:
    origin = request.headers.get("origin", "").rstrip("/")
    if request.headers.get("x-kesihba-csrf") != "1" or origin not in allowed_origins():
        raise HTTPException(status_code=403, detail="Request could not be verified. Refresh the page and try again.")


def set_session_cookie(response: Any, token: str) -> None:
    secure = os.getenv("KESIHBA_COOKIE_SECURE", "false").strip().lower() in {"1", "true", "yes"}
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        secure=secure,
        samesite="lax",
        max_age=int(SESSION_LIFETIME.total_seconds()),
        path="/",
    )


def clear_session_cookie(response: Any) -> None:
    secure = os.getenv("KESIHBA_COOKIE_SECURE", "false").strip().lower() in {"1", "true", "yes"}
    response.delete_cookie(key=SESSION_COOKIE, path="/", httponly=True, secure=secure, samesite="lax")
