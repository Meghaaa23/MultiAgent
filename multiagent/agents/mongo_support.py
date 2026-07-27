# agents/mongo_support.py
"""Shared MongoDB Atlas client helpers — fail-fast TLS, optional KB."""

from __future__ import annotations

import logging
import os
from typing import Any, Optional, Tuple

logger = logging.getLogger(__name__)

# Keep selection short so web/AI scan is not blocked for 30s×N on dead Atlas TLS.
DEFAULT_SERVER_SELECTION_MS = int(os.getenv("MONGO_SERVER_SELECTION_MS", "5000"))
DEFAULT_CONNECT_MS = int(os.getenv("MONGO_CONNECT_MS", "5000"))
DEFAULT_SOCKET_MS = int(os.getenv("MONGO_SOCKET_MS", "10000"))


def mongo_client_kwargs(
    server_selection_ms: int = DEFAULT_SERVER_SELECTION_MS,
    connect_ms: int = DEFAULT_CONNECT_MS,
    socket_ms: int = DEFAULT_SOCKET_MS,
) -> dict:
    """TLS kwargs shared by all Atlas clients on this app."""
    try:
        import certifi
        ca_file = certifi.where()
    except Exception:
        ca_file = None

    kwargs: dict = {
        "tls": True,
        # Default matches prior app behavior; set MONGO_TLS_ALLOW_INVALID=false to enforce CA checks.
        "tlsAllowInvalidCertificates": os.getenv(
            "MONGO_TLS_ALLOW_INVALID", "true"
        ).strip().lower() in ("1", "true", "yes"),
        "serverSelectionTimeoutMS": server_selection_ms,
        "connectTimeoutMS": connect_ms,
        "socketTimeoutMS": socket_ms,
        "retryWrites": True,
    }
    if ca_file:
        kwargs["tlsCAFile"] = ca_file
    return kwargs


def create_mongo_client(uri: Optional[str] = None) -> Any:
    """Build a client from MONGODB_ATLAS_URI (or MONGODB_URI). Does not ping."""
    from pymongo import MongoClient

    uri = uri or os.getenv("MONGODB_ATLAS_URI") or os.getenv("MONGODB_URI")
    if not uri:
        logger.error("MONGODB_ATLAS_URI / MONGODB_URI not set")
        return None
    try:
        return MongoClient(uri, **mongo_client_kwargs())
    except Exception as e:
        logger.error("MongoClient init failed: %s", e)
        return None


def ping_mongo(client: Any) -> Tuple[bool, str]:
    """Return (ok, detail). Safe when client is None."""
    if client is None:
        return False, "client not initialized"
    try:
        client.admin.command("ping")
        return True, "connected"
    except Exception as e:
        return False, str(e)


def sanitize_retrieval_error(exc: BaseException | str) -> str:
    """Keep Autogen prompts free of raw TLS/Atlas stack dumps."""
    text = str(exc)
    low = text.lower()
    if "tls" in low or "ssl" in low or "handshake" in low:
        return (
            "Knowledge base unavailable (MongoDB Atlas TLS/SSL handshake failed). "
            "Continuing without KB context. Fix Atlas Network Access / cluster "
            "status, then retry. Detail: "
            + text.split("(configured timeouts")[0].strip()[:180]
        )
    if "server selection" in low or "timeout" in low:
        return (
            "Knowledge base unavailable (MongoDB connection timeout). "
            "Continuing without KB context."
        )
    return f"Knowledge base retrieval error: {text[:240]}"
