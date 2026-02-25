"""
main.py — FastAPI Webhook Receiver: Primary Application Entrypoint
"""

import os
import asyncio
import logging
import threading
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, BackgroundTasks, Depends, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from models import WebhookPayload
from processor import process_status_update
from security import verify_hmac_signature

_log_level_str: str = os.environ.get("LOG_LEVEL", "INFO").upper()
_log_level: int = getattr(logging, _log_level_str, logging.INFO)

logging.basicConfig(level=_log_level, format="%(message)s")
logger = logging.getLogger(__name__)

SERVICE_VERSION = "1.0.1"
SERVICE_NAME = "status-tracker"

_active_tasks_count: int = 0
_active_tasks_lock: threading.Lock = threading.Lock()

def _increment_active_tasks() -> None:
    global _active_tasks_count
    with _active_tasks_lock:
        _active_tasks_count += 1

def _decrement_active_tasks() -> None:
    global _active_tasks_count
    with _active_tasks_lock:
        _active_tasks_count -= 1

def _get_active_tasks() -> int:
    with _active_tasks_lock:
        return _active_tasks_count

def _tracked_process_status_update(payload: WebhookPayload) -> None:
    _increment_active_tasks()
    try:
        process_status_update(payload)
    except Exception:
        logger.error(
            "Unhandled exception in process_status_update(). "
            "Event was acknowledged (202) but processing failed.",
            exc_info=True,
        )
    finally:
        _decrement_active_tasks()

MAX_BODY_BYTES: int = 1_048_576

class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method == "POST":
            content_length_header: str = request.headers.get("content-length", "")
            if content_length_header:
                try:
                    content_length = int(content_length_header)
                    if content_length > MAX_BODY_BYTES:
                        logger.error(f"Request rejected: Content-Length {content_length} bytes exceeds limit.")
                        return Response(content="Request entity too large. Maximum body size is 1MB.", status_code=413)
                except ValueError:
                    return Response(content="Invalid Content-Length header.", status_code=400)
        return await call_next(request)

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    production_mode: bool = os.environ.get("PRODUCTION_MODE", "").lower() == "true"
    secret_configured: bool = bool(os.environ.get("WEBHOOK_SECRET"))

    if production_mode and not secret_configured:
        raise RuntimeError("FATAL: PRODUCTION_MODE is set but WEBHOOK_SECRET is not configured.")

    if not secret_configured:
        logger.warning(
            "=" * 70 + chr(10) +
            "SECURITY WARNING: WEBHOOK_SECRET is not set." + chr(10) +
            "All incoming webhook requests are processed WITHOUT authentication." + chr(10) +
            "This is acceptable for local development only." + chr(10) +
            "Set PRODUCTION_MODE=true to enforce the secret requirement." + chr(10) +
            "=" * 70
        )
    else:
        logger.info(f"Service '{SERVICE_NAME}' v{SERVICE_VERSION} starting. HMAC-SHA256 verification: ACTIVE.")

    logger.info(f"Log level: {_log_level_str}. Body size limit: {MAX_BODY_BYTES // 1024}KB. Production mode: {production_mode}.")

    yield

    logger.info(f"Service '{SERVICE_NAME}' received shutdown signal. Draining tasks...")
    _SHUTDOWN_POLL_INTERVAL: float = 0.5
    _SHUTDOWN_MAX_WAIT: float = 10.0
    elapsed: float = 0.0

    while _get_active_tasks() > 0 and elapsed < _SHUTDOWN_MAX_WAIT:
        remaining = _get_active_tasks()
        logger.info(f"Shutdown waiting: {remaining} background task(s) in-flight. Elapsed: {elapsed:.1f}s / {_SHUTDOWN_MAX_WAIT}s max.")
        await asyncio.sleep(_SHUTDOWN_POLL_INTERVAL)
        elapsed += _SHUTDOWN_POLL_INTERVAL

    remaining_at_exit = _get_active_tasks()
    if remaining_at_exit > 0:
        logger.warning(f"Shutdown forced with {remaining_at_exit} background task(s) still running.")
    else:
        logger.info("All background tasks completed. Shutdown clean.")

    logger.info(f"Service '{SERVICE_NAME}' v{SERVICE_VERSION} stopped.")

app = FastAPI(
    title="Event-Driven Service Status Tracker",
    description="Webhook receiver for Atlassian Statuspage events.",
    version=SERVICE_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(BodySizeLimitMiddleware)

@app.post("/webhook", status_code=202, dependencies=[Depends(verify_hmac_signature)])
async def webhook_receiver(payload: WebhookPayload, background_tasks: BackgroundTasks) -> JSONResponse:
    background_tasks.add_task(_tracked_process_status_update, payload)
    return JSONResponse(status_code=202, content={"status": "accepted", "message": "Webhook payload queued for processing."})

@app.get("/health", status_code=200)
def health_check() -> dict:
    return {
        "status": "healthy",
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "secret_configured": bool(os.environ.get("WEBHOOK_SECRET")),
        "production_mode": os.environ.get("PRODUCTION_MODE", "false").lower() == "true",
        "active_background_tasks": _get_active_tasks(),
        "log_level": _log_level_str,
    }

@app.get("/", status_code=200)
def root() -> dict:
    return {
        "service": "Event-Driven Service Status Tracker",
        "status": "online",
        "version": SERVICE_VERSION,
        "endpoints": {"webhook": "/webhook", "health": "/health", "docs": "/docs", "redoc": "/redoc"},
    }
