import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from pydantic import ValidationError
from backend.app.database import get_db_context
from backend.app.security import decode_access_token
from backend.app.models import EncryptedMessageEnvelope
from backend.app.websocket_manager import connection_manager
from backend.app.message_relay import store_offline_message, get_offline_messages, clear_offline_messages

logger = logging.getLogger("websocket_router")
router = APIRouter(tags=["WebSocket"])

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    Authenticated WebSocket endpoint for real-time E2EE message relay.
    Security controls:
    1. Token-based authentication on handshake.
    2. Enforced sender identity: client cannot spoof message sender.
    3. Pure ciphertext relay: backend never inspects or logs plaintext.
    4. Store-and-forward queueing for offline recipients.
    """
    # 1. Authenticate token
    protocols = [
        protocol.strip()
        for protocol in websocket.headers.get("sec-websocket-protocol", "").split(",")
    ]
    token_protocols = [protocol for protocol in protocols if protocol.startswith("bearer.")]
    payload = (
        decode_access_token(token_protocols[0][7:])
        if "cypherchat" in protocols and len(token_protocols) == 1
        else None
    )
    if not payload or "sub" not in payload:
        logger.warning("WebSocket connection rejected: Invalid or expired token.")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    username = payload["sub"]

    # 2. Register connection
    await connection_manager.connect(username, websocket)

    try:
        async with get_db_context() as db:
            # 3. Deliver pending offline messages
            offline_msgs = await get_offline_messages(db, username)
            if offline_msgs:
                logger.info(f"Delivering {len(offline_msgs)} pending offline messages to '{username}'.")
                for msg in offline_msgs:
                    await websocket.send_json({
                        "type": "encrypted_message",
                        "payload": msg
                    })

            # Send initial presence synchronization
            await websocket.send_json({
                "type": "initial_sync",
                "online_users": connection_manager.get_online_users()
            })

            # 4. Process incoming WebSocket events
            while True:
                data = await websocket.receive_json()
                if not isinstance(data, dict):
                    await websocket.send_json({"type": "error", "message": "Expected a JSON object."})
                    continue
                msg_type = data.get("type")

                if msg_type == "ping":
                    await websocket.send_json({"type": "pong"})
                    continue

                elif msg_type == "message_received":
                    message_id = data.get("message_id")
                    if isinstance(message_id, str) and 1 <= len(message_id) <= 80:
                        await clear_offline_messages(db, username, [message_id])
                        await websocket.send_json({
                            "type": "receipt_ack",
                            "message_id": message_id
                        })
                    else:
                        await websocket.send_json({
                            "type": "error",
                            "message": "Invalid receipt acknowledgement."
                        })
                    continue

                elif msg_type == "send_encrypted_message":
                    payload_data = data.get("payload", {})
                    if not isinstance(payload_data, dict):
                        await websocket.send_json({
                            "type": "error",
                            "message": "Invalid encrypted message envelope."
                        })
                        continue

                    try:
                        envelope = EncryptedMessageEnvelope.model_validate(payload_data)
                    except ValidationError:
                        await websocket.send_json({
                            "type": "error",
                            "message": "Invalid encrypted message envelope.",
                            "message_id": payload_data.get("message_id")
                            if isinstance(payload_data.get("message_id"), str)
                            else None
                        })
                        continue

                    payload_data = envelope.model_dump(exclude_none=True)
                    recipient = envelope.recipient.strip()
                    message_id = envelope.message_id

                    # The authenticated connection, never client input, identifies the sender.
                    payload_data["sender"] = username

                    # Check recipient existence in database
                    cursor = await db.execute("SELECT id FROM users WHERE username = ?", (recipient,))
                    recipient_exists = await cursor.fetchone()
                    if not recipient_exists:
                        await websocket.send_json({
                            "type": "message_ack",
                            "message_id": message_id,
                            "status": "failed",
                            "recipient": recipient,
                            "error": f"Recipient '{recipient}' does not exist."
                        })
                        continue

                    # Keep a retry copy until the authenticated recipient acknowledges receipt.
                    await store_offline_message(db, message_id, username, recipient, payload_data)

                    # Check if recipient is online
                    if connection_manager.is_online(recipient):
                        # Relay directly over active WebSocket
                        delivered = await connection_manager.send_to_user(recipient, {
                            "type": "encrypted_message",
                            "payload": payload_data
                        })
                        if delivered:
                            await websocket.send_json({
                                "type": "message_ack",
                                "message_id": message_id,
                                "status": "delivered",
                                "recipient": recipient
                            })
                            logger.info(f"[RELAY] Transmitted encrypted message {message_id} directly: {username} -> {recipient}")
                        else:
                            await websocket.send_json({
                                "type": "message_ack",
                                "message_id": message_id,
                                "status": "sent",
                                "recipient": recipient,
                                "info": "queued_offline"
                            })
                    else:
                        await websocket.send_json({
                            "type": "message_ack",
                            "message_id": message_id,
                            "status": "sent",
                            "recipient": recipient,
                            "info": "queued_offline"
                        })

                elif msg_type == "typing":
                    recipient = data.get("recipient")
                    is_typing = data.get("is_typing", False)
                    if not isinstance(recipient, str) or len(recipient) > 30 or not isinstance(is_typing, bool):
                        await websocket.send_json({
                            "type": "error",
                            "message": "Invalid typing event."
                        })
                        continue
                    if recipient and connection_manager.is_online(recipient):
                        await connection_manager.send_to_user(recipient, {
                            "type": "typing",
                            "sender": username,
                            "is_typing": is_typing
                        })
                else:
                    await websocket.send_json({
                        "type": "error",
                        "message": "Unsupported WebSocket event."
                    })

    except WebSocketDisconnect:
        await connection_manager.disconnect(username)
    except Exception as e:
        logger.error(f"WebSocket error for user '{username}': {e}")
        await connection_manager.disconnect(username)
