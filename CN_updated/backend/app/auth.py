from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
import aiosqlite
from datetime import datetime, timezone

from backend.app.database import get_db
from backend.app.models import UserRegisterRequest, UserLoginRequest, TokenResponse, UserProfile
from backend.app.security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    is_account_locked,
    record_login_attempt
)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])
security = HTTPBearer(auto_error=False)

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: aiosqlite.Connection = Depends(get_db)
) -> dict:
    """Dependency to retrieve and validate the authenticated user from the Bearer token."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    payload = decode_access_token(credentials.credentials)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username = payload["sub"]
    cursor = await db.execute("SELECT id, username, identity_pubkey, prekey_pubkey, signed_prekey_pubkey, signed_prekey_signature, signature_algorithm, created_at, last_seen FROM users WHERE username = ?", (username,))
    user = await cursor.fetchone()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return dict(user)

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(req: UserRegisterRequest, db: aiosqlite.Connection = Depends(get_db)):
    """Register a new user with Argon2id password hashing and client public keys."""
    # Check if username is already taken
    cursor = await db.execute("SELECT id FROM users WHERE username = ?", (req.username,))
    existing = await cursor.fetchone()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already registered. Please choose a different username."
        )

    # Securely hash password with Argon2id
    pwd_hash = hash_password(req.password)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # Insert new user with their public keys (Private keys NEVER leave user's device!)
    await db.execute(
        """
        INSERT INTO users (username, password_hash, identity_pubkey, prekey_pubkey, signed_prekey_pubkey, signed_prekey_signature, signature_algorithm, created_at, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            req.username,
            pwd_hash,
            req.identity_pubkey,
            req.prekey_pubkey,
            req.signed_prekey_pubkey,
            req.signed_prekey_signature,
            req.signature_algorithm or 'ECDSA-P-256-SHA256',
            now_iso,
            now_iso
        )
    )
    await db.commit()

    # Generate JWT
    token = create_access_token({"sub": req.username})
    return TokenResponse(access_token=token, token_type="bearer", username=req.username)

@router.post("/login", response_model=TokenResponse)
async def login(req: UserLoginRequest, request: Request, db: aiosqlite.Connection = Depends(get_db)):
    """Authenticate a user and return an access token with brute-force protection."""
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Check for brute-force lockout
    if await is_account_locked(db, req.username, client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account temporarily locked due to multiple failed login attempts. Please try again after 5 minutes."
        )

    cursor = await db.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (req.username,))
    user = await cursor.fetchone()

    if not user or not verify_password(req.password, user["password_hash"]):
        await record_login_attempt(db, req.username, client_ip, success=False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    # Successful login
    await record_login_attempt(db, req.username, client_ip, success=True)
    
    # Update last_seen
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    await db.execute("UPDATE users SET last_seen = ? WHERE id = ?", (now_iso, user["id"]))
    await db.commit()

    token = create_access_token({"sub": user["username"]})
    return TokenResponse(access_token=token, token_type="bearer", username=user["username"])

@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    """Retrieve the currently authenticated user's profile and public keys."""
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "identity_pubkey": current_user["identity_pubkey"],
        "prekey_pubkey": current_user["prekey_pubkey"],
        "signed_prekey_pubkey": current_user.get("signed_prekey_pubkey"),
        "signed_prekey_signature": current_user.get("signed_prekey_signature"),
        "signature_algorithm": current_user.get("signature_algorithm"),
        "created_at": current_user["created_at"],
        "last_seen": current_user["last_seen"]
    }

@router.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    """Logout endpoint. Client will discard token."""
    return {"message": f"User {current_user['username']} logged out successfully"}

