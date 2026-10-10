"""DevPulse - uptime & latency monitor (FastAPI)."""
import asyncio
import os
import socket
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import core

BASE_DIR = Path(__file__).resolve().parent.parent
INTERVAL_SEC = float(os.environ.get("CHECK_INTERVAL_SEC", "30"))   # 0 disables the scheduler
MAX_MONITORS = int(os.environ.get("MAX_MONITORS", "20"))
DATA_FILE = os.environ.get("DATA_FILE", str(BASE_DIR / "data" / "monitors.json"))
STARTED_AT = time.time()

store = core.MonitorStore(DATA_FILE, max_monitors=MAX_MONITORS)


# ----------------------------- rate limiting ------------------------------ #
class RateLimiter:
    """Sliding-window limiter, per client IP. Used as a FastAPI dependency."""

    def __init__(self, limit: int = 30, window: int = 60):
        self.limit, self.window = limit, window
        self.hits: dict = {}
        self.lock = threading.Lock()

    def __call__(self, request: Request):
        ip = (request.headers.get("x-forwarded-for") or (request.client.host if request.client else "")).split(",")[0].strip()
        now = time.monotonic()
        with self.lock:
            recent = [t for t in self.hits.get(ip, []) if now - t < self.window]
            recent.append(now)
            self.hits[ip] = recent
            if len(self.hits) > 10_000:                      # keep memory bounded
                self.hits = {k: v for k, v in self.hits.items() if now - v[-1] < self.window}
        if len(recent) > self.limit:
            raise HTTPException(status_code=429, detail="Too many requests, slow down")


limiter = RateLimiter()


# ------------------------------- scheduler -------------------------------- #
async def check_one(m: dict) -> dict:
    """Probe in a worker thread (probe() is blocking) and save the result."""
    try:
        result = await asyncio.to_thread(core.probe, core.parse_target(m["url"]))
    except core.ValidationError as e:
        result = core.failure(str(e))
    store.record(m["id"], result)
    return result


async def scheduler():
    while True:
        await asyncio.sleep(INTERVAL_SEC)
        await asyncio.gather(*(check_one(m) for m in store.all()), return_exceptions=True)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    task = asyncio.create_task(scheduler()) if INTERVAL_SEC > 0 else None
    yield
    if task:
        task.cancel()
    store.flush()                                            # graceful shutdown


app = FastAPI(title="DevPulse", version="1.0.0", description="Uptime & latency monitoring API", lifespan=lifespan)


# --------------------------- errors & middleware --------------------------- #
@app.exception_handler(core.ValidationError)
async def _validation_error(_req, exc):
    return JSONResponse({"error": str(exc)}, status_code=400)


@app.exception_handler(StarletteHTTPException)
async def _http_error(_req, exc):
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code)


@app.exception_handler(RequestValidationError)
async def _bad_body(_req, _exc):
    return JSONResponse({"error": "Invalid request: a valid 'url' is required"}, status_code=422)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    if not request.url.path.startswith(("/docs", "/redoc", "/openapi.json")):   # Swagger UI needs its CDN
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    return response


# --------------------------------- routes ---------------------------------- #
class MonitorIn(BaseModel):
    name: str | None = Field(default=None, max_length=60)
    url: str = Field(min_length=1, max_length=2048)


def _get_or_404(mid: str) -> dict:
    m = store.get(mid)
    if m is None:
        raise HTTPException(status_code=404, detail="Monitor not found")
    return m


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/api/info")
def info():
    return {"version": app.version, "uptimeSec": round(time.time() - STARTED_AT),
            "monitors": len(store.all()), "intervalSec": INTERVAL_SEC}


@app.get("/api/monitors")
def list_monitors():
    return [core.view(m) for m in store.all()]


@app.post("/api/monitors", status_code=201, dependencies=[Depends(limiter)])
async def create_monitor(body: MonitorIn):
    target = core.parse_target(body.url)
    try:                                                     # reject hostnames that resolve to internal IPs
        await asyncio.to_thread(core.resolve_public, target.host, target.port)
    except socket.gaierror:
        raise core.ValidationError("Could not resolve hostname")
    name = (body.name or "").strip() or target.host
    m = store.add(name[:60], target.url)
    await check_one(m)                                       # first result immediately
    return core.view(store.get(m["id"]))


@app.get("/api/monitors/{mid}")
def get_monitor(mid: str):
    return core.view(_get_or_404(mid))


@app.post("/api/monitors/{mid}/check", dependencies=[Depends(limiter)])
async def check_now(mid: str):
    m = _get_or_404(mid)
    await check_one(m)
    return core.view(store.get(mid) or m)


@app.delete("/api/monitors/{mid}", dependencies=[Depends(limiter)])
def delete_monitor(mid: str):
    _get_or_404(mid)
    store.remove(mid)
    return {"deleted": True}


# Dashboard (must be mounted last so it doesn't shadow the API routes)
app.mount("/", StaticFiles(directory=BASE_DIR / "static", html=True), name="static")
