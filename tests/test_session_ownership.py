"""
Security tests for session ownership / IDOR (audit finding F3).

Two distinct authenticated callers (two tokens via API_AUTH_TOKENS) exercise the
real FastAPI app through TestClient. The LLM and classifier are faked so the
ownership logic is tested without network/LLM calls; the scanner/SSRF/rate-limit
paths are exercised for real (F1/F5 regression).
"""
import os
import sys

import pytest

# The app is written to run with the multiagent/ directory on sys.path
# (top-level ``agents`` / ``utils`` packages), i.e. the same context as
# ``python main.py``. Mirror that so we import the real app and its modules.
_MULTIAGENT_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "multiagent")
)
if _MULTIAGENT_DIR not in sys.path:
    sys.path.insert(0, _MULTIAGENT_DIR)

# Tokens must be configured before importing the app module.
os.environ["API_AUTH_TOKEN"] = "tokenA-secret-value"
os.environ["API_AUTH_TOKENS"] = "tokenB-secret-value"
os.environ.pop("SSRF_INTERNAL_ALLOWLIST", None)

from fastapi.testclient import TestClient  # noqa: E402
import main  # noqa: E402
from agents.webappscanner import scan_limits  # noqa: E402

A = {"Authorization": "Bearer tokenA-secret-value"}
B = {"Authorization": "Bearer tokenB-secret-value"}

client = TestClient(main.app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def clean_state(monkeypatch):
    main.session_owners.clear()
    main.session_histories.clear()
    main.session_teams.clear()
    scan_limits.reset_for_tests()
    monkeypatch.setenv("API_AUTH_TOKEN", "tokenA-secret-value")
    monkeypatch.setenv("API_AUTH_TOKENS", "tokenB-secret-value")
    monkeypatch.delenv("SSRF_INTERNAL_ALLOWLIST", raising=False)

    # Fake the general-answer LLM path: record history like the real one does.
    async def fake_answer(question, session_id):
        h = main.session_histories.setdefault(session_id, [])
        h.append({"role": "user", "content": question})
        h.append({"role": "assistant", "content": "ANSWER"})
        main.session_histories[session_id] = h
        return "ANSWER"

    monkeypatch.setattr(main, "answer_with_llm", fake_answer)
    # Force the non-scan general path (no classifier LLM calls).
    if main.threat_modeling_agent is not None:
        monkeypatch.setattr(main.threat_modeling_agent, "is_security_query",
                            lambda q, use_llm=True: False)
        monkeypatch.setattr(main.threat_modeling_agent, "is_web_scan_request",
                            lambda q: False)
    yield


def _query(headers, session_id, question="hello", **extra):
    body = {"question": question, "session_id": session_id, **extra}
    return client.post("/query/", json=body, headers=headers)


# ---------------------------------------------------------------------------
# Ownership: create / read / cross-caller deny
# ---------------------------------------------------------------------------
def test_owner_can_create_and_read_history():
    assert _query(A, "sessA").status_code == 200
    r = client.get("/session/sessA/history", headers=A)
    assert r.status_code == 200
    assert r.json()["total_messages"] == 2


def test_other_caller_cannot_read_history():
    assert _query(A, "sessA").status_code == 200
    r = client.get("/session/sessA/history", headers=B)
    assert r.status_code == 404
    assert r.json()["detail"] == "Session not found."   # no existence disclosure


# ---------------------------------------------------------------------------
# Enumeration isolation
# ---------------------------------------------------------------------------
def test_sessions_listing_is_per_caller():
    _query(A, "sessA")
    _query(B, "sessB")
    a_ids = {s["session_id"] for s in client.get("/sessions", headers=A).json()["sessions"]}
    b_ids = {s["session_id"] for s in client.get("/sessions", headers=B).json()["sessions"]}
    assert "sessA" in a_ids and "sessA" not in b_ids
    assert "sessB" in b_ids and "sessB" not in a_ids


# ---------------------------------------------------------------------------
# Write paths cannot cross ownership
# ---------------------------------------------------------------------------
def test_other_caller_cannot_write_via_query():
    _query(A, "sessA")
    before = list(main.session_histories["sessA"])
    r = _query(B, "sessA", question="inject")
    assert r.status_code == 404
    assert main.session_histories["sessA"] == before     # unchanged


def test_other_caller_cannot_write_via_stream():
    _query(A, "sessA")
    before = list(main.session_histories["sessA"])
    r = client.post("/query/stream",
                    json={"question": "inject", "session_id": "sessA"},
                    headers=B)
    assert "Session not found." in r.text                # SSE error, denied
    assert main.session_histories["sessA"] == before


def test_owner_can_write_via_stream():
    _query(A, "sessA")
    r = client.post("/query/stream",
                    json={"question": "hi again", "session_id": "sessA"},
                    headers=A)
    assert r.status_code == 200
    assert "ANSWER" in r.text


# ---------------------------------------------------------------------------
# Scan/session interaction
# ---------------------------------------------------------------------------
def test_scan_cannot_target_another_callers_session():
    _query(A, "sessA")
    before = list(main.session_histories["sessA"])
    r = client.post("/scan/",
                    json={"target_url": "http://example.com/", "session_id": "sessA"},
                    headers=B)
    assert r.status_code == 404                          # ownership denied first
    assert main.session_histories["sessA"] == before     # A's session untouched


# ---------------------------------------------------------------------------
# Ownership spoofing via client-supplied fields is ignored
# ---------------------------------------------------------------------------
def test_client_supplied_owner_fields_are_ignored():
    _query(A, "sessA")
    # B supplies A-ish owner/username hints; must still be denied.
    r = _query(B, "sessA", owner_id="whatever", caller_id="whatever", username="A")
    assert r.status_code == 404


def test_cannot_hijack_default_session_of_another_caller():
    # A uses the default (no session_id) -> caller-scoped; B's default differs.
    assert client.post("/query/", json={"question": "x"}, headers=A).status_code == 200
    assert client.post("/query/", json={"question": "y"}, headers=B).status_code == 200
    a_ids = {s["session_id"] for s in client.get("/sessions", headers=A).json()["sessions"]}
    b_ids = {s["session_id"] for s in client.get("/sessions", headers=B).json()["sessions"]}
    assert a_ids.isdisjoint(b_ids)                       # defaults do not collide


# ---------------------------------------------------------------------------
# Legacy / ownerless sessions fail closed
# ---------------------------------------------------------------------------
def test_ownerless_session_is_inaccessible():
    # Simulate a pre-existing session with no owner metadata.
    main.session_histories["legacy"] = [
        {"role": "user", "content": "old"},
        {"role": "assistant", "content": "old-ans"},
    ]
    assert client.get("/session/legacy/history", headers=A).status_code == 404
    # A query attempting to use it must not silently claim it either.
    assert _query(A, "legacy").status_code == 404
    assert "legacy" not in main.session_owners


# ---------------------------------------------------------------------------
# Authentication regression (F2)
# ---------------------------------------------------------------------------
def test_auth_regression():
    assert client.get("/health").status_code == 200
    assert client.get("/session/sessA/history").status_code == 401          # no auth
    assert client.get("/session/sessA/history",
                      headers={"Authorization": "Bearer nope"}).status_code == 403
    _query(A, "sessA")
    assert client.get("/session/sessA/history", headers=A).status_code == 200
    assert client.get("/session/sessA/history", headers=B).status_code == 404


# ---------------------------------------------------------------------------
# F1 + F5 regression still active alongside F3
# ---------------------------------------------------------------------------
def test_f1_ssrf_still_blocks_through_scan():
    r = client.post("/scan/",
                    json={"target_url": "http://169.254.169.254/latest/meta-data/",
                          "session_id": "sessA"},
                    headers=A)
    assert r.status_code == 403                          # SSRF egress policy


def test_f5_rate_limit_still_enforced(monkeypatch):
    monkeypatch.setenv("SCAN_RATE_LIMIT", "2")
    monkeypatch.setenv("SCAN_RATE_WINDOW_SECONDS", "60")
    scan_limits.reset_for_tests()
    meta = {"target_url": "http://169.254.169.254/", "session_id": "sessA"}
    # First two are SSRF-blocked (403) but consume rate budget; third -> 429.
    assert client.post("/scan/", json=meta, headers=A).status_code == 403
    assert client.post("/scan/", json=meta, headers=A).status_code == 403
    assert client.post("/scan/", json=meta, headers=A).status_code == 429
