import aiosqlite
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from backend.app.config import settings

async def get_db() -> AsyncGenerator[aiosqlite.Connection, None]:
    """Provide an asynchronous SQLite database connection for FastAPI Depends."""
    conn = await aiosqlite.connect(settings.DATABASE_PATH)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
    finally:
        await conn.close()

@asynccontextmanager
async def get_db_context() -> AsyncGenerator[aiosqlite.Connection, None]:
    """Provide an asynchronous SQLite connection as a context manager for non-FastAPI tasks."""
    conn = await aiosqlite.connect(settings.DATABASE_PATH)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
    finally:
        await conn.close()

async def init_db() -> None:
    """Initialize database tables and indexes."""
    async with get_db_context() as conn:
        # Users table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                identity_pubkey TEXT NOT NULL,
                prekey_pubkey TEXT NOT NULL,
                signed_prekey_pubkey TEXT,
                signed_prekey_signature TEXT,
                signature_algorithm TEXT DEFAULT 'ECDSA-P-256-SHA256',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        for column_name, column_sql in {
            'signed_prekey_pubkey': 'TEXT',
            'signed_prekey_signature': 'TEXT',
            'signature_algorithm': "TEXT DEFAULT 'ECDSA-P-256-SHA256'"
        }.items():
            try:
                await conn.execute(f"ALTER TABLE users ADD COLUMN {column_name} {column_sql};")
            except aiosqlite.DatabaseError:
                pass

        # Offline messages queue for store-and-forward delivery of encrypted payloads
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS offline_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT UNIQUE NOT NULL,
                sender_username TEXT NOT NULL COLLATE NOCASE,
                recipient_username TEXT NOT NULL COLLATE NOCASE,
                payload TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (recipient_username) REFERENCES users(username) ON DELETE CASCADE
            );
        """)

        # Login attempts tracking for brute-force protection
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                username TEXT NOT NULL COLLATE NOCASE,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN NOT NULL
            );
        """)

        # Indexes for fast lookup
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_offline_recipient ON offline_messages(recipient_username);")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts(username, attempt_time);")

        await conn.commit()

