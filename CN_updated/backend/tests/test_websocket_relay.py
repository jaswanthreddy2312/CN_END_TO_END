import pytest
from starlette.testclient import TestClient
from pathlib import Path
import os
import json

from backend.app.main import app
from backend.app.config import settings
from backend.app.database import init_db

from backend.app.websocket_manager import connection_manager

TEST_DB_PATH = Path(__file__).resolve().parent / "test_ws.db"
PUBLIC_JWK = json.dumps({
    "kty": "EC",
    "crv": "P-256",
    "x": "A" * 43,
    "y": "B" * 43
})

@pytest.fixture(autouse=True)
def setup_ws_db():
    connection_manager.active_connections.clear()
    settings.DATABASE_PATH = TEST_DB_PATH
    if TEST_DB_PATH.exists():
        try:
            os.remove(TEST_DB_PATH)
        except PermissionError:
            pass

    import asyncio
    asyncio.run(init_db())
    yield
    connection_manager.active_connections.clear()
    if TEST_DB_PATH.exists():
        try:
            os.remove(TEST_DB_PATH)
        except PermissionError:
            pass

def test_websocket_rejects_unauthorized():
    client = TestClient(app)
    # A token in the URL query string is not accepted.
    registration = client.post("/api/auth/register", json={
        "username": "query_user",
        "password": "Password123!",
        "identity_pubkey": "query_identity_public_key",
        "prekey_pubkey": "query_prekey_public_key"
    })
    assert registration.status_code == 201
    token = registration.json()["access_token"]
    with pytest.raises(Exception):
        with client.websocket_connect(f"/ws?token={token}") as ws:
            pass

def test_websocket_direct_relay_between_two_users():
    client = TestClient(app)

    # 1. Register Alice and Bob via API
    res_a = client.post("/api/auth/register", json={
        "username": "alice",
        "password": "Password123!",
        "identity_pubkey": "alice_identity_public_key_base64",
        "prekey_pubkey": "alice_prekey_public_key_base64"
    })
    assert res_a.status_code == 201, res_a.text
    token_alice = res_a.json()["access_token"]

    res_b = client.post("/api/auth/register", json={
        "username": "bob",
        "password": "Password123!",
        "identity_pubkey": "bob_identity_public_key_base64",
        "prekey_pubkey": "bob_prekey_public_key_base64"
    })
    assert res_b.status_code == 201, res_b.text
    token_bob = res_b.json()["access_token"]

    # 2. Open WebSockets for both Alice and Bob
    with client.websocket_connect("/ws", subprotocols=["cypherchat", f"bearer.{token_alice}"]) as ws_alice:
        sync_alice = ws_alice.receive_json()
        assert sync_alice["type"] == "initial_sync"

        with client.websocket_connect("/ws", subprotocols=["cypherchat", f"bearer.{token_bob}"]) as ws_bob:
            # Alice receives notification that Bob is online
            user_status_event = ws_alice.receive_json()
            assert user_status_event["type"] == "user_status"
            assert user_status_event["username"] == "bob"
            assert user_status_event["status"] == "online"

            sync_bob = ws_bob.receive_json()
            assert sync_bob["type"] == "initial_sync"

            # 3. Alice sends encrypted message to Bob
            # Notice: The payload contains only ciphertext, nonce, and ratchet keys.
            msg_payload = {
                "message_id": "msg_001",
                "recipient": "bob",
                "sender": "spoofed_sender",
                "ciphertext": "aGVsbG9fd29ybGRfY2lwaGVydGV4dF9iYXNlNjQ=",
                "iv": "MTIzNDU2Nzg5MDEy",
                "dh_ratchet_pubkey": PUBLIC_JWK,
                "msg_counter": 0,
                "prev_chain_len": 0,
                "timestamp": 1718000000000,
                "is_initial": True,
                "ephemeral_pubkey": PUBLIC_JWK
            }

            ws_alice.send_json({
                "type": "send_encrypted_message",
                "payload": msg_payload
            })

            # Alice receives delivery acknowledgment
            ack = ws_alice.receive_json()
            assert ack["type"] == "message_ack"
            assert ack["message_id"] == "msg_001"
            assert ack["status"] == "delivered"
            assert ack["recipient"] == "bob"

            # Bob receives the relayed encrypted message
            incoming = ws_bob.receive_json()
            assert incoming["type"] == "encrypted_message"
            assert incoming["payload"]["message_id"] == "msg_001"
            assert incoming["payload"]["sender"] == "alice"
            assert incoming["payload"]["ciphertext"] == msg_payload["ciphertext"]
            assert incoming["payload"]["iv"] == msg_payload["iv"]
            ws_bob.send_json({
                "type": "message_received",
                "message_id": "msg_001"
            })
            receipt_ack = ws_bob.receive_json()
            assert receipt_ack["type"] == "receipt_ack"
            assert receipt_ack["message_id"] == "msg_001"

            ws_alice.send_json({
                "type": "send_encrypted_message",
                "payload": {"recipient": "bob", "message_id": "invalid"}
            })
            invalid = ws_alice.receive_json()
            assert invalid["type"] == "error"
            assert invalid["message_id"] == "invalid"

            private_jwk_payload = {
                **msg_payload,
                "message_id": "msg_private_key_rejected",
                "dh_ratchet_pubkey": json.dumps({
                    **json.loads(PUBLIC_JWK),
                    "d": "C" * 43
                })
            }
            ws_alice.send_json({
                "type": "send_encrypted_message",
                "payload": private_jwk_payload
            })
            rejected_key = ws_alice.receive_json()
            assert rejected_key["type"] == "error"
            assert rejected_key["message_id"] == "msg_private_key_rejected"

            plaintext_payload = {
                **msg_payload,
                "message_id": "msg_plaintext_rejected",
                "plaintext": "must never reach the relay"
            }
            ws_alice.send_json({
                "type": "send_encrypted_message",
                "payload": plaintext_payload
            })
            rejected_plaintext = ws_alice.receive_json()
            assert rejected_plaintext["type"] == "error"
            assert rejected_plaintext["message_id"] == "msg_plaintext_rejected"

def test_offline_store_and_forward_delivery():
    client = TestClient(app)

    # Register Alice and Charlie
    res_a = client.post("/api/auth/register", json={
        "username": "alice",
        "password": "Password123!",
        "identity_pubkey": "alice_identity_public_key_base64",
        "prekey_pubkey": "alice_prekey_public_key_base64"
    })
    assert res_a.status_code == 201, res_a.text
    token_alice = res_a.json()["access_token"]

    res_c = client.post("/api/auth/register", json={
        "username": "charlie",
        "password": "Password123!",
        "identity_pubkey": "charlie_identity_public_key_base64",
        "prekey_pubkey": "charlie_prekey_public_key_base64"
    })
    assert res_c.status_code == 201, res_c.text
    token_charlie = res_c.json()["access_token"]

    # Charlie is currently OFFLINE
    with client.websocket_connect("/ws", subprotocols=["cypherchat", f"bearer.{token_alice}"]) as ws_alice:
        ws_alice.receive_json() # initial_sync

        offline_payload = {
            "message_id": "msg_offline_001",
            "recipient": "charlie",
            "ciphertext": "c3RvcmVkX29mZmxpbmVfY2lwaGVydGV4dA==",
            "iv": "MTIzNDU2Nzg5MDEy",
            "dh_ratchet_pubkey": PUBLIC_JWK,
            "msg_counter": 1,
            "prev_chain_len": 0,
            "timestamp": 1718000005000
        }

        # Alice sends to Charlie
        ws_alice.send_json({
            "type": "send_encrypted_message",
            "payload": offline_payload
        })

        # Alice receives sent (queued_offline) ACK
        ack = ws_alice.receive_json()
        assert ack["type"] == "message_ack"
        assert ack["status"] == "sent"
        assert ack["info"] == "queued_offline"

    # Charlie comes ONLINE later
    with client.websocket_connect("/ws", subprotocols=["cypherchat", f"bearer.{token_charlie}"]) as ws_charlie:
        # Charlie immediately receives the queued offline encrypted message
        queued_msg = ws_charlie.receive_json()
        assert queued_msg["type"] == "encrypted_message"
        assert queued_msg["payload"]["message_id"] == "msg_offline_001"
        assert queued_msg["payload"]["sender"] == "alice"
        assert queued_msg["payload"]["ciphertext"] == offline_payload["ciphertext"]

        # Followed by presence sync
        sync = ws_charlie.receive_json()
        assert sync["type"] == "initial_sync"
        ws_charlie.send_json({
            "type": "message_received",
            "message_id": "msg_offline_001"
        })
        receipt_ack = ws_charlie.receive_json()
        assert receipt_ack["type"] == "receipt_ack"
        assert receipt_ack["message_id"] == "msg_offline_001"

    # Acknowledged offline messages are not replayed on reconnection.
    with client.websocket_connect("/ws", subprotocols=["cypherchat", f"bearer.{token_charlie}"]) as ws_charlie:
        sync = ws_charlie.receive_json()
        assert sync["type"] == "initial_sync"
