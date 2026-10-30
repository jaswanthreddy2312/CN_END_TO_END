import pytest
from httpx import AsyncClient, ASGITransport
from pathlib import Path
import os

from backend.app.main import app
from backend.app.config import settings
from backend.app.database import init_db

TEST_DB_PATH = Path(__file__).resolve().parent / "test_api.db"

@pytest.fixture(autouse=True)
def setup_api_db():
    settings.DATABASE_PATH = TEST_DB_PATH
    if TEST_DB_PATH.exists():
        try:
            os.remove(TEST_DB_PATH)
        except PermissionError:
            pass

    import asyncio
    asyncio.run(init_db())
    yield
    if TEST_DB_PATH.exists():
        try:
            os.remove(TEST_DB_PATH)
        except PermissionError:
            pass

@pytest.mark.asyncio
async def test_frontend_serving():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Root route serves index.html
        res_index = await client.get("/")
        assert res_index.status_code == 200
        assert "CypherChat" in res_index.text
        assert "E2EE Ratchet Prototype" in res_index.text

        # 2. Static CSS is served
        res_css = await client.get("/static/css/styles.css")
        assert res_css.status_code == 200
        assert "--bg-primary" in res_css.text

        # 3. Static Crypto JS is served
        res_crypto = await client.get("/static/js/crypto.js")
        assert res_crypto.status_code == 200
        assert "E2EECrypto" in res_crypto.text

        # 4. Static Auth JS is served
        res_auth = await client.get("/static/js/auth.js")
        assert res_auth.status_code == 200
        assert "Auth" in res_auth.text

        # 5. Static Chat JS is served
        res_chat = await client.get("/static/js/chat.js")
        assert res_chat.status_code == 200
        assert "Chat" in res_chat.text

        # 6. Static App JS is served
        res_app = await client.get("/static/js/app.js")
        assert res_app.status_code == 200
        assert "App" in res_app.text
