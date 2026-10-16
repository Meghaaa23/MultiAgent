"""
scan_limits.py  —  resource-exhaustion controls for expensive scans (audit F5).

Provides three central, configuration-driven controls that every scan entry
point shares:

  * Concurrency  — a global asyncio semaphore (MAX_CONCURRENT_SCANS) so only a
    bounded number of scans run at once. The default is 1 because the scanner
    uses shared singletons (one BrowserController) and a process-global SSRF
    egress policy (F1); serializing scans keeps both correct — one scan can
    never observe another scan's internal allowlist, and two scans can never
    fight over the same browser. Acquisition is bounded (no indefinite wait).

  * Rate limiting — a per-caller sliding window (SCAN_RATE_LIMIT per
    SCAN_RATE_WINDOW_SECONDS) keyed by a salted hash of the auth token, so
    repeated scan initiation is rejected with 429 without the raw token ever
    being stored or logged. Expired state is pruned and the key table is
    bounded.

  * Timeout — a maximum scan duration (SCAN_TIMEOUT_SECONDS) enforced with
    asyncio.wait_for so a scan cannot run indefinitely.

None of this changes F1/F2: it sits around the scan, never inside the auth or
SSRF decision.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import secrets
import threading
import time
from collections import deque
from contextlib import asynccontextmanager
from typing import Deque, Dict, Optional

logger = logging.getLogger(__name__)

# Cap the rate-limit key table so a flood of distinct callers cannot grow it
# without bound.
_MAX_RATE_KEYS = 10_000

# Per-process random salt so stored keys are not a plain hash of the token
# (prevents trivial reversal / correlation). Never logged.
_KEY_SALT = secrets.token_bytes(16)


# ---------------------------------------------------------------------------
# Configuration helpers (read from env each call so tests can reconfigure)
# ---------------------------------------------------------------------------
def _env_int(name: str, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float, minimum: float = 0.0) -> float:
    try:
        return max(minimum, float(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


def max_concurrent_scans() -> int:
    return _env_int("MAX_CONCURRENT_SCANS", 1, minimum=1)


def scan_timeout_seconds() -> Optional[float]:
    """Maximum scan duration in seconds, or None to disable the time cap.

    Default is None: a scan runs to natural completion (YuraScanner-style
    run-to-completion), with no wall-clock budget. Set SCAN_TIMEOUT_SECONDS to a
    positive number to impose a budget (enforced, clamped to a 1s floor); 0,
    "none" or "off" also mean no cap.
    """
    raw = os.getenv("SCAN_TIMEOUT_SECONDS")
    if raw is None:
        return None
    token = raw.strip().lower()
    if token in ("", "0", "none", "off", "disabled"):
        return None
    try:
        value = float(token)
    except ValueError:
        return None
    if value <= 0:
        return None
    return max(1.0, value)


def slot_acquire_timeout_seconds() -> float:
    return _env_float("SCAN_SLOT_ACQUIRE_TIMEOUT_SECONDS", 30.0, minimum=0.0)


# --- Coverage / depth knobs ------------------------------------------------
# These bound how much of an app a single scan explores. Larger values mean
# deeper coverage but more LLM calls (cost) and longer runs.
def scan_max_tasks() -> Optional[int]:
    """Max exploration tasks (goals) a deep scan pursues; None = unbounded.

    Default is None (unbounded, YuraScanner-style): the scan pursues every task
    the planner generates with no artificial ceiling. Set SCAN_MAX_TASKS to a
    positive integer to cap it; 0, "none" or "off" also mean unbounded.
    """
    raw = os.getenv("SCAN_MAX_TASKS")
    if raw is None:
        return None
    token = raw.strip().lower()
    if token in ("", "0", "none", "off", "unbounded"):
        return None
    try:
        value = int(token)
    except ValueError:
        return None
    return value if value >= 1 else None


def scan_max_steps_per_task() -> int:
    """Max browser actions per task before moving on. Default 18."""
    return _env_int("SCAN_MAX_STEPS_PER_TASK", 18, minimum=1)


def scan_max_input_chunks() -> int:
    """Max 50-element chunks of a page fed to the task planner. Default 8."""
    return _env_int("SCAN_MAX_INPUT_CHUNKS", 8, minimum=1)


def scan_taint_revisit_pages() -> int:
    """Max pages re-visited after the crawl for taint/XSS checks. Default 10."""
    return _env_int("SCAN_TAINT_REVISIT_PAGES", 10, minimum=0)


def scan_rate_limit() -> int:
    return _env_int("SCAN_RATE_LIMIT", 10, minimum=1)


def scan_rate_window_seconds() -> float:
    return _env_float("SCAN_RATE_WINDOW_SECONDS", 60.0, minimum=1.0)


# ---------------------------------------------------------------------------
# Exceptions (mapped to HTTP status codes by the API layer)
# ---------------------------------------------------------------------------
class ScanBusy(Exception):
    """All scan concurrency slots are in use (-> 503)."""

    def __init__(self, retry_after: int = 30):
        super().__init__("Scanner is at capacity; try again shortly.")
        self.retry_after = retry_after


class ScanTimeout(Exception):
    """A scan exceeded its configured maximum duration (-> 504)."""


class RateLimited(Exception):
    """Too many scan requests from this caller (-> 429)."""

    def __init__(self, retry_after: int = 60):
        super().__init__("Scan rate limit exceeded.")
        self.retry_after = retry_after


# ---------------------------------------------------------------------------
# Concurrency slot
# ---------------------------------------------------------------------------
_sem_lock = threading.Lock()
_semaphore: asyncio.Semaphore | None = None
_sem_limit: int = 0


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore, _sem_limit
    limit = max_concurrent_scans()
    with _sem_lock:
        if _semaphore is None or _sem_limit != limit:
            _semaphore = asyncio.Semaphore(limit)
            _sem_limit = limit
        return _semaphore


@asynccontextmanager
async def scan_slot():
    """Acquire one scan concurrency slot, then always release it.

    Waiting for a slot does no scan work and creates no browsers. The wait is
    bounded by SCAN_SLOT_ACQUIRE_TIMEOUT_SECONDS; on expiry ScanBusy is raised
    before any scan work begins. The slot is released in ``finally`` on success,
    failure, timeout, or cancellation.
    """
    sem = _get_semaphore()
    wait = slot_acquire_timeout_seconds()
    try:
        if wait > 0:
            await asyncio.wait_for(sem.acquire(), timeout=wait)
        else:
            await sem.acquire()
    except asyncio.TimeoutError:
        raise ScanBusy(retry_after=int(wait) or 30)
    try:
        yield
    finally:
        sem.release()


# ---------------------------------------------------------------------------
# Rate limiting (per-caller sliding window)
# ---------------------------------------------------------------------------
_rate_lock = threading.Lock()
_rate_state: Dict[str, Deque[float]] = {}


def caller_key(authorization_header: str | None) -> str:
    """Derive a stable, non-reversible identifier for the authenticated caller.

    Uses a salted hash of the bearer token so the raw token is never stored or
    logged. Falls back to a single shared key when no token is present (should
    not happen behind F2 auth, but keeps the limiter safe either way).
    """
    token = ""
    if authorization_header:
        scheme, _, value = authorization_header.partition(" ")
        if scheme.lower() == "bearer":
            token = value.strip()
    if not token:
        return "anon"
    return hashlib.sha256(_KEY_SALT + token.encode("utf-8")).hexdigest()[:16]


def check_rate_limit(key: str) -> None:
    """Record one scan initiation for ``key``; raise RateLimited if over budget.

    Sliding window: timestamps older than the window are discarded on each
    call, empty entries are removed, and the key table is capped.
    """
    limit = scan_rate_limit()
    window = scan_rate_window_seconds()
    now = time.monotonic()
    cutoff = now - window
    with _rate_lock:
        bucket = _rate_state.get(key)
        if bucket is None:
            if len(_rate_state) >= _MAX_RATE_KEYS:
                _evict_locked(cutoff)
            bucket = _rate_state.setdefault(key, deque())
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if len(bucket) >= limit:
            retry_after = int(bucket[0] + window - now) + 1
            raise RateLimited(retry_after=max(1, retry_after))
        bucket.append(now)


def _evict_locked(cutoff: float) -> None:
    """Drop fully-expired buckets; must hold _rate_lock."""
    for k in [k for k, b in _rate_state.items() if not b or b[-1] <= cutoff]:
        _rate_state.pop(k, None)


# ---------------------------------------------------------------------------
# Test support
# ---------------------------------------------------------------------------
def reset_for_tests() -> None:
    """Re-read configuration and clear all limiter state. Tests only."""
    global _semaphore, _sem_limit
    with _sem_lock:
        _semaphore = None
        _sem_limit = 0
    with _rate_lock:
        _rate_state.clear()
