import json
import logging
from typing import List, Dict, Any
import aiosqlite
from backend.app.database import get_db

logger = logging.getLogger("message_relay")

async def store_offline_message(
    db: aiosqlite.Connection,
    message_id: str,
    sender: str,
    recipient: str,
    payload: Dict[str, Any]
) -> None:
    """
    Store an encrypted message payload until the recipient acknowledges receipt.
    SECURITY AUDIT NOTE:
    - Only the opaque encrypted payload (ciphertext, IV, ratchet pubkey) is stored.
    - Plaintext messages and private keys NEVER enter the backend database or memory.
    """
    payload_json = json.dumps(payload)
    await db.execute(
        """
        INSERT OR IGNORE INTO offline_messages (message_id, sender_username, recipient_username, payload)
        VALUES (?, ?, ?, ?)
        """,
        (message_id, sender, recipient, payload_json)
    )
    await db.commit()
    logger.info(f"[STORE-AND-FORWARD] Queued encrypted message {message_id} from '{sender}' to '{recipient}'. (Payload size: {len(payload_json)} bytes)")

async def get_offline_messages(db: aiosqlite.Connection, recipient: str) -> List[Dict[str, Any]]:
    """Retrieve all pending offline encrypted messages for a user in chronological order."""
    cursor = await db.execute(
        """
        SELECT id, message_id, sender_username, recipient_username, payload, timestamp
        FROM offline_messages
        WHERE recipient_username = ?
        ORDER BY id ASC
        """,
        (recipient,)
    )
    rows = await cursor.fetchall()
    messages = []
    for r in rows:
        try:
            parsed_payload = json.loads(r["payload"])
            messages.append(parsed_payload)
        except Exception as e:
            logger.error(f"Failed to parse stored payload for msg {r['message_id']}: {e}")
    return messages

async def clear_offline_messages(db: aiosqlite.Connection, recipient: str, message_ids: List[str]) -> None:
    """Remove delivered offline messages from storage once recipient confirms receipt."""
    if not message_ids:
        return
    placeholders = ",".join("?" for _ in message_ids)
    await db.execute(
        f"DELETE FROM offline_messages WHERE recipient_username = ? AND message_id IN ({placeholders})",
        [recipient] + message_ids
    )
    await db.commit()
    logger.info(f"[STORE-AND-FORWARD] Cleared {len(message_ids)} delivered offline messages for user '{recipient}'.")
