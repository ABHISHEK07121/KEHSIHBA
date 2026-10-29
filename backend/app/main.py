import asyncio
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

from app.routes.analyze import router as analyze_router
from app.routes.auth import router as auth_router
from app.routes.health import router as health_router
from app.routes.tools import router as tools_router
from app.services.threat_intelligence import threat_intelligence
from app.services.auth import allowed_origins

@asynccontextmanager
async def lifespan(_app: FastAPI):
    stop_event = threading.Event()
    refresh_thread = threading.Thread(
        target=threat_intelligence.refresh_loop,
        args=(stop_event,),
        daemon=True,
    )
    refresh_thread.start()
    try:
        yield
    finally:
        stop_event.set()
        await asyncio.to_thread(refresh_thread.join, 1)


app = FastAPI(
    title="KESHIHBA Phishing Threat Intelligence API",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(allowed_origins()),
    allow_origin_regex=r"chrome-extension://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(analyze_router)
app.include_router(tools_router)
app.include_router(auth_router)
