"""Shared auth credential helpers for authenticated scans.

Credentials are supplied up front (UI / API / CLI), not mid-scan.
- Cookie string: ``session=abc; token=xyz`` → Cookie header
- Bearer token:  ``Bearer eyJ...`` → Authorization header
"""
from __future__ import annotations

from typing import Dict, List
from urllib.parse import urlparse


def request_auth_headers(auth_cookie: str = "") -> Dict[str, str]:
    """Build HTTP auth headers from a user-supplied credential string."""
    cred = (auth_cookie or "").strip()
    if not cred:
        return {}
    low = cred.lower()
    if low.startswith("bearer "):
        return {"Authorization": cred}
    if low.startswith("authorization:"):
        return {"Authorization": cred.split(":", 1)[1].strip()}
    return {"Cookie": cred}


def playwright_cookies_from_header(auth_cookie: str, url: str) -> List[Dict]:
    """Convert a Cookie header string into Playwright add_cookies() entries.

    Bearer tokens are ignored here (Playwright uses request headers instead).
    """
    cred = (auth_cookie or "").strip()
    if not cred:
        return []
    low = cred.lower()
    if low.startswith("bearer ") or low.startswith("authorization:"):
        return []

    host = urlparse(url).hostname
    if not host:
        return []

    skip = {
        "path", "domain", "secure", "httponly", "samesite",
        "max-age", "expires",
    }
    out: List[Dict] = []
    for part in cred.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, _, value = part.partition("=")
        name = name.strip()
        if not name or name.lower() in skip:
            continue
        out.append({
            "name": name,
            "value": value.strip(),
            "domain": host,
            "path": "/",
        })
    return out
