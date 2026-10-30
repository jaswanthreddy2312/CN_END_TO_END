from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
import aiosqlite

from backend.app.config import settings

# Initialize Argon2id hasher with secure parameters
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MB
    parallelism=4,
    hash_len=32,
    salt_len=16
)

def hash_password(password: str) -> str:
    """Hash a password securely using Argon2id."""
    return ph.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against an Argon2id hash."""
    try:
        return ph.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate a JWT access token."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

async def is_account_locked(conn: aiosqlite.Connection, username: str, ip_address: str) -> bool:
    """
    Check if an account or IP is temporarily locked out due to excessive failed attempts.
    Protection against brute-force attacks.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=settings.LOCKOUT_DURATION_MINUTES)
    cutoff_iso = cutoff.strftime("%Y-%m-%d %H:%M:%S")

    cursor = await conn.execute(
        """
        SELECT COUNT(*) as failed_count
        FROM login_attempts
        WHERE (username = ? OR ip_address = ?)
          AND success = 0
          AND attempt_time > ?
        """,
        (username, ip_address, cutoff_iso)
    )
    row = await cursor.fetchone()
    if row and row["failed_count"] >= settings.MAX_LOGIN_ATTEMPTS:
        return True
    return False

async def record_login_attempt(conn: aiosqlite.Connection, username: str, ip_address: str, success: bool) -> None:
    """Record a login attempt in the database."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    await conn.execute(
        """
        INSERT INTO login_attempts (ip_address, username, attempt_time, success)
        VALUES (?, ?, ?, ?)
        """,
        (ip_address, username, now_iso, 1 if success else 0)
    )
    if success:
        # Clear recent failed attempts upon successful login for this user
        await conn.execute(
            "DELETE FROM login_attempts WHERE username = ? AND success = 0",
            (username,)
        )
    await conn.commit()
