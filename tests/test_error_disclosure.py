"""
Security tests for raw exception / error disclosure (audit finding F6).

Forces representative internal failures and verifies clients receive safe,
generic messages (never Python exception text, tracebacks, filesystem paths,
connection strings, or token-like values), while intentional 4xx/5xx security
and validation errors keep their authored behavior.
"""
import os
import sys

import pytest

_MULTIAGENT_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "multiagent")
)
if _MULTIAGENT_DIR not in sys.path:
    sys.path.insert(0, _MULTIAGENT_DIR)

os.environ["API_AUTH_TOKEN"] = "tokA-value"
os.environ["API_AUTH_TOKENS"] = "tokB-value"

from fastapi.testclient import TestClient  # noqa: E402
import main  # noqa: E402
from agents.webappscanner import scan_limits  # noqa: E402

A = {"Authorization": "Bearer tokA-value"}
B = {"Authorization": "Bearer tokB-value"}

# Sensitive-looking strings embedded in forced exceptions. None are real.
SECRET_PATH = "/home/testuser/project/secret.py"
SECRET_DSN = "postgresql://dbuser:dbpass@10.1.2.3:5432/scanner"
SECRET_KEYISH = "sk-FAKEKEY1234567890"
SENSITIVE = [SECRET_PATH, SECRET_DSN, SECRET_KEYISH, "Traceback (most recent call last)"]

client = TestClient(main.app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.setenv("API_AUTH_TOKEN", "tokA-value")
    monkeypatch.setenv("API_AUTH_TOKENS", "tokB-value")
    monkeypatch.delenv("SSRF_INTERNAL_ALLOWLIST", raising=False)
    main.session_owners.clear()
    main.session_histories.clear()
    main.session_teams.clear()
    scan_limits.reset_for_tests()
    yield


def _raising_coro(exc):
    async def _boom(*a, **k):
        raise exc
    return _boom


def _assert_no_leak(resp_text):
    for s in SENSITIVE:
        assert s not in resp_text, f"leaked sensitive fragment: {s!r}"


# ---------------------------------------------------------------------------
# Unexpected exception -> generic 500, no leak
# ---------------------------------------------------------------------------
def test_scan_internal_exception_is_sanitized(monkeypatch):
    exc = RuntimeError(f"{SECRET_PATH}: connect {SECRET_DSN} key={SECRET_KEYISH}")
    monkeypatch.setattr(main.threat_modeling_agent, "analyze", _raising_coro(exc))
    r = client.post("/scan/", json={"target_url": "http://example.com/"}, headers=A)
    assert r.status_code == 500
    assert r.json() == {"detail": "Internal server error"}
    _assert_no_leak(r.text)


def test_query_internal_exception_is_sanitized(monkeypatch):
    exc = RuntimeError(f"boom {SECRET_PATH} {SECRET_DSN} {SECRET_KEYISH}")
    # Force an unexpected (non-HTTPException) failure early in the /query path.
    monkeypatch.setattr(main, "_authorize_session", _raise_sync(exc))
    r = client.post("/query/", json={"question": "hi", "session_id": "s1"}, headers=A)
    assert r.status_code == 500
    assert r.json()["detail"] == "Internal server error"
    _assert_no_leak(r.text)


def test_threat_modeling_internal_exception_is_sanitized(monkeypatch):
    exc = RuntimeError(f"kaboom {SECRET_PATH} {SECRET_KEYISH}")
    monkeypatch.setattr(main.threat_modeling_agent, "is_security_query",
                        lambda q, use_llm=True: True)
    monkeypatch.setattr(main.threat_modeling_agent, "analyze", _raising_coro(exc))
    r = client.post("/threat-modeling/", json={"question": "model a threat"}, headers=A)
    assert r.status_code == 500
    assert r.json()["detail"] == "Internal server error"
    _assert_no_leak(r.text)


# ---------------------------------------------------------------------------
# Streaming: SSE error event must not carry raw exception text
# ---------------------------------------------------------------------------
def test_stream_error_is_sanitized(monkeypatch):
    exc = RuntimeError(f"stream-boom {SECRET_PATH} {SECRET_DSN} {SECRET_KEYISH}")
    # Raise outside the inner answer try so the generator's outer handler runs.
    monkeypatch.setattr(main.threat_modeling_agent, "is_security_query",
                        _raise_sync(exc))
    r = client.post("/query/stream", json={"question": "hi", "session_id": "s1"},
                    headers=A)
    assert r.status_code == 200          # SSE already started; body carries error
    assert "Internal server error" in r.text
    _assert_no_leak(r.text)


def test_stream_answer_failure_is_sanitized(monkeypatch):
    exc = RuntimeError(f"llm-boom {SECRET_PATH} {SECRET_KEYISH}")
    monkeypatch.setattr(main.threat_modeling_agent, "is_security_query",
                        lambda q, use_llm=True: False)
    monkeypatch.setattr(main.threat_modeling_agent, "is_web_scan_request",
                        lambda q: False)
    monkeypatch.setattr(main, "answer_with_llm", _raising_coro(exc))
    r = client.post("/query/stream", json={"question": "hi", "session_id": "s1"},
                    headers=A)
    _assert_no_leak(r.text)              # generic fallback answer, no raw text


# ---------------------------------------------------------------------------
# Intentional errors keep their authored behavior (not turned into 500)
# ---------------------------------------------------------------------------
def test_intentional_errors_preserved(monkeypatch):
    # Validation
    assert client.post("/scan/", json={}, headers=A).status_code == 400
    # F2 auth
    assert client.post("/scan/", json={"target_url": "http://x/"}).status_code == 401
    assert client.post("/scan/", json={"target_url": "http://x/"},
                       headers={"Authorization": "Bearer nope"}).status_code == 403
    # F1 SSRF (safe 403, not generic 500)
    r = client.post("/scan/", json={"target_url": "http://169.254.169.254/"}, headers=A)
    assert r.status_code == 403
    assert "SSRF" in r.json()["detail"]
    # F3 session ownership (404)
    assert client.get("/session/does-not-exist/history", headers=A).status_code == 404
    # F4 admin-only model mutation (403)
    monkeypatch.setenv("API_ADMIN_TOKEN", "admintok")
    assert client.post("/settings/model", json={"provider": "local"},
                       headers=A).status_code == 403
    # /health public
    assert client.get("/health").status_code == 200


def test_safe_scan_exceptions_not_turned_into_500(monkeypatch):
    # ScanBusy -> 503, ScanTimeout -> 504, both with safe messages, no leak.
    monkeypatch.setattr(main.threat_modeling_agent, "analyze",
                        _raising_coro(scan_limits.ScanBusy()))
    r = client.post("/scan/", json={"target_url": "http://example.com/"}, headers=A)
    assert r.status_code == 503 and "capacity" in r.json()["detail"].lower()

    monkeypatch.setattr(main.threat_modeling_agent, "analyze",
                        _raising_coro(scan_limits.ScanTimeout("exceeded 600s")))
    r = client.post("/scan/", json={"target_url": "http://example.com/"}, headers=A)
    assert r.status_code == 504
    assert r.json()["detail"] == "Scan exceeded its time budget."


def test_rate_limit_still_429(monkeypatch):
    monkeypatch.setenv("SCAN_RATE_LIMIT", "1")
    monkeypatch.setenv("SCAN_RATE_WINDOW_SECONDS", "60")
    scan_limits.reset_for_tests()
    meta = {"target_url": "http://169.254.169.254/"}
    assert client.post("/scan/", json=meta, headers=A).status_code == 403   # SSRF
    assert client.post("/scan/", json=meta, headers=A).status_code == 429   # rate


def _raise_sync(exc):
    def _boom(*a, **k):
        raise exc
    return _boom
