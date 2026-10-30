from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn
import logging

from backend.app.config import settings
from backend.app.database import init_db
from backend.app.auth import router as auth_router
from backend.app.users import router as users_router
from backend.app.websocket_router import router as ws_router

# Configure clean logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("main")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize resources on application startup."""
    logger.info("Initializing SQLite database tables...")
    await init_db()
    logger.info("Database initialized successfully.")
    yield
    logger.info("Application shutting down.")

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    lifespan=lifespan,
    description="End-to-End Encrypted Chat Backend with Double Ratchet, ECDH Key Exchange, and WebSockets."
)

# Register API routers
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(ws_router)

# Serve static frontend files
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    async def serve_index():
        """Serve the single-page application frontend."""
        return FileResponse(FRONTEND_DIR / "index.html")

if __name__ == "__main__":
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=True)
