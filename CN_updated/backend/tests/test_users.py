import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from pathlib import Path
import os

from backend.app.main import app
from backend.app.config import settings
from backend.app.database import init_db

TEST_DB_PATH = Path(__file__).resolve().parent / "test_users.db"

@pytest_asyncio.fixture(autouse=True)
async def setup_test_db():
    settings.DATABASE_PATH = TEST_DB_PATH
    if TEST_DB_PATH.exists():
        os.remove(TEST_DB_PATH)
    await init_db()
    yield
    if TEST_DB_PATH.exists():
        try:
            os.remove(TEST_DB_PATH)
        except PermissionError:
            pass

@pytest.mark.asyncio
async def test_users_list_and_key_bundle():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register Alice
        res_a = await client.post("/api/auth/register", json={
            "username": "alice",
            "password": "PasswordAlice123!",
            "identity_pubkey": "alice_ik_public_base64",
            "prekey_pubkey": "alice_spk_public_base64"
        })
        token_a = res_a.json()["access_token"]

        # Register Bob
        await client.post("/api/auth/register", json={
            "username": "bob",
            "password": "PasswordBob123!",
            "identity_pubkey": "bob_ik_public_base64",
            "prekey_pubkey": "bob_spk_public_base64"
        })

        # Alice lists users
        headers = {"Authorization": f"Bearer {token_a}"}
        list_res = await client.get("/api/users", headers=headers)
        assert list_res.status_code == 200
        users = list_res.json()
        assert len(users) == 2
        usernames = [u["username"] for u in users]
        assert "alice" in usernames and "bob" in usernames

        # Alice fetches Bob's key bundle to initiate E2EE
        keys_res = await client.get("/api/users/bob/keys", headers=headers)
        assert keys_res.status_code == 200
        bundle = keys_res.json()
        assert bundle["username"] == "bob"
        assert bundle["identity_pubkey"] == "bob_ik_public_base64"
        assert bundle["prekey_pubkey"] == "bob_spk_public_base64"

        # Lookup of nonexistent user
        notFound = await client.get("/api/users/nonexistent/keys", headers=headers)
        assert notFound.status_code == 404

@pytest.mark.asyncio
async def test_prekey_rotation():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        reg = await client.post("/api/auth/register", json={
            "username": "rotate_user",
            "password": "Password123!",
            "identity_pubkey": "initial_ik",
            "prekey_pubkey": "initial_spk"
        })
        token = reg.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Update prekey
        put_res = await client.put("/api/users/prekey", json={"prekey_pubkey": "new_rotated_spk"}, headers=headers)
        assert put_res.status_code == 200

        # Verify updated key in bundle
        keys_res = await client.get("/api/users/rotate_user/keys", headers=headers)
        assert keys_res.json()["prekey_pubkey"] == "new_rotated_spk"

