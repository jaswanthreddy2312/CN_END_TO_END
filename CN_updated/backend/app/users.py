from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
import aiosqlite

from backend.app.database import get_db
from backend.app.auth import get_current_user
from backend.app.models import UserProfile, KeyBundleResponse, PrekeyUpdateRequest
from backend.app.websocket_manager import connection_manager

router = APIRouter(prefix="/api/users", tags=["Users"])

@router.get("", response_model=List[UserProfile])
async def list_users(
    current_user: dict = Depends(get_current_user),
    db: aiosqlite.Connection = Depends(get_db)
):
    """
    List all registered users in the network with their public identity/prekeys
    and live connection status.
    """
    cursor = await db.execute(
        """
        SELECT id, username, identity_pubkey, prekey_pubkey, signed_prekey_pubkey, signed_prekey_signature, signature_algorithm, last_seen
        FROM users
        ORDER BY username ASC
        """
    )
    rows = await cursor.fetchall()
    
    users = []
    for row in rows:
        uname = row["username"]
        is_online = connection_manager.is_online(uname)
        users.append(UserProfile(
            id=row["id"],
            username=uname,
            identity_pubkey=row["identity_pubkey"],
            prekey_pubkey=row["prekey_pubkey"],
            signed_prekey_pubkey=row["signed_prekey_pubkey"],
            signed_prekey_signature=row["signed_prekey_signature"],
            signature_algorithm=row["signature_algorithm"],
            is_online=is_online,
            last_seen=row["last_seen"]
        ))
    return users

@router.get("/{username}/keys", response_model=KeyBundleResponse)
async def get_user_keys(
    username: str,
    current_user: dict = Depends(get_current_user),
    db: aiosqlite.Connection = Depends(get_db)
):
    """
    Fetch public cryptographic keys for a conversation partner to initialize E2EE handshake.
    Never exposes private keys (server has no knowledge of private keys).
    """
    cursor = await db.execute(
        """
        SELECT username, identity_pubkey, prekey_pubkey, signed_prekey_pubkey, signed_prekey_signature, signature_algorithm
        FROM users
        WHERE username = ?
        """,
        (username,)
    )
    row = await cursor.fetchone()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{username}' not found in key directory."
        )
    return KeyBundleResponse(
        username=row["username"],
        identity_pubkey=row["identity_pubkey"],
        prekey_pubkey=row["prekey_pubkey"],
        signed_prekey_pubkey=row["signed_prekey_pubkey"],
        signed_prekey_signature=row["signed_prekey_signature"],
        signature_algorithm=row["signature_algorithm"]
    )

@router.put("/prekey")
async def update_prekey(
    req: PrekeyUpdateRequest,
    current_user: dict = Depends(get_current_user),
    db: aiosqlite.Connection = Depends(get_db)
):
    """Rotate prekey public key for the current user."""
    await db.execute(
        "UPDATE users SET prekey_pubkey = ?, signed_prekey_pubkey = COALESCE(?, signed_prekey_pubkey), signed_prekey_signature = COALESCE(?, signed_prekey_signature), signature_algorithm = COALESCE(?, signature_algorithm) WHERE id = ?",
        (req.prekey_pubkey, req.signed_prekey_pubkey, req.signed_prekey_signature, req.signature_algorithm, current_user["id"])
    )
    await db.commit()
    return {"message": "Prekey updated successfully"}

