"""SQLite user store with hashed passwords for dashboard login/signup."""
import os
import sqlite3

from werkzeug.security import check_password_hash, generate_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")


def _conn():
    return sqlite3.connect(DB_PATH)


def init_db():
    with _conn() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            )
            """
        )


def register_user(username: str, password: str, password_confirm: str) -> tuple[bool, str]:
    u = (username or "").strip()
    if len(u) < 3 or len(u) > 64:
        return False, "Operator ID must be 3–64 characters."
    if password != password_confirm:
        return False, "Passwords do not match."
    if len(password) < 6:
        return False, "Access key must be at least 6 characters."
    ph = generate_password_hash(password)
    try:
        with _conn() as c:
            c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (u, ph))
        return True, ""
    except sqlite3.IntegrityError:
        return False, "That operator ID is already registered."


def verify_login(username: str, password: str) -> bool:
    u = (username or "").strip()
    with _conn() as c:
        row = c.execute(
            "SELECT password_hash FROM users WHERE lower(username) = lower(?)",
            (u,),
        ).fetchone()
    if not row:
        return False
    return check_password_hash(row[0], password)
