from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.utils.logging import setup_logging, get_logger
from app.routers import github, pypi_npm, ws
from app.routers.ai import router as ai_router

setup_logging()
log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("app_starting")
    yield
    log.info("app_stopped")


app = FastAPI(
    title="OSSGuard API",
    version="2.0.0",
    description="Open Source Supply Chain Security Platform",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(github.router)
app.include_router(pypi_npm.router)
app.include_router(ws.router)
app.include_router(ai_router)


@app.get("/health")
async def health():
    from app.utils.redis_client import redis_client
    redis_ok = False
    try:
        redis_ok = redis_client.ping()
    except Exception:
        pass
    return {"status": "ok", "redis": redis_ok}
