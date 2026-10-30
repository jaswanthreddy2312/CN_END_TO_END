import pytest
import pytest_asyncio
import aiosqlite
from httpx import AsyncClient, ASGITransport
from pathlib import Path
import os

from backend.app.main import app
from backend.app.config import Settings, settings
from backend.app.database import init_db

# Use an isolated test database
TEST_DB_PATH = Path(__file__).resolve().parent / "test_auth.db"

def test_default_jwt_secret_is_random_and_strong():
    first = Settings(_env_file=None).JWT_SECRET_KEY
    second = Settings(_env_file=None).JWT_SECRET_KEY

    assert len(first) >= 32
    assert first != second

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
async def test_user_registration_success():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/auth/register", json={
            "username": "alice",
            "password": "Password123!",
            "identity_pubkey": "test_identity_pubkey_alice",
            "prekey_pubkey": "test_prekey_pubkey_alice"
        })
        assert res.status_code == 201
        data = res.json()
        assert data["username"] == "alice"
        assert "access_token" in data

@pytest.mark.asyncio
async def test_duplicate_username_rejection():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "username": "bob",
            "password": "SecurePassword123!",
            "identity_pubkey": "test_identity_pubkey_bob",
            "prekey_pubkey": "test_prekey_pubkey_bob"
        }
        res1 = await client.post("/api/auth/register", json=payload)
        assert res1.status_code == 201

        # Attempt to register with the same username
        res2 = await client.post("/api/auth/register", json=payload)
        assert res2.status_code == 409
        assert "already registered" in res2.json()["detail"].lower()

@pytest.mark.asyncio
async def test_login_success_and_failure():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register user
        await client.post("/api/auth/register", json={
            "username": "charlie",
            "password": "CorrectPassword123!",
            "identity_pubkey": "pub_charlie_ik",
            "prekey_pubkey": "pub_charlie_spk"
        })

        # Correct password login
        login_res = await client.post("/api/auth/login", json={
            "username": "charlie",
            "password": "CorrectPassword123!"
        })
        assert login_res.status_code == 200
        token = login_res.json()["access_token"]
        assert token

        # Verify /me endpoint
        me_res = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me_res.status_code == 200
        assert me_res.json()["username"] == "charlie"

        # Incorrect password login
        bad_login = await client.post("/api/auth/login", json={
            "username": "charlie",
            "password": "WrongPassword!"
        })
        assert bad_login.status_code == 401
        assert "Invalid username or password" in bad_login.json()["detail"]

@pytest.mark.asyncio
async def test_brute_force_lockout():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/auth/register", json={
            "username": "target_user",
            "password": "RealPassword123!",
            "identity_pubkey": "pub_target_ik",
            "prekey_pubkey": "pub_target_spk"
        })

        # Send MAX_LOGIN_ATTEMPTS (5) consecutive bad passwords
        for _ in range(5):
            res = await client.post("/api/auth/login", json={
                "username": "target_user",
                "password": "BadPassword123!"
            })
            assert res.status_code == 401

        # 6th attempt should be locked out with HTTP 429
        locked_res = await client.post("/api/auth/login", json={
            "username": "target_user",
            "password": "RealPassword123!"
        })
        assert locked_res.status_code == 429
        assert "locked" in locked_res.json()["detail"].lower()
