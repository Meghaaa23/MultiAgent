"""
Security tests for unauthorized global model-config / global state changes
(audit finding F4).

Verifies that an ordinary authenticated caller cannot change the deployment-wide
model provider or cause a global session wipe; that mutation requires a separate
admin credential (X-Admin-Token / API_ADMIN_TOKEN), fails closed when unset, and
never leaks the token; and that F2/F3 behavior is preserved.
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

A = {"Authorization": "Bearer tokA-value"}
B = {"Authorization": "Bearer tokB-value"}
ADMIN_SECRET = "admin-secret-value"

client = TestClient(main.app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.setenv("API_AUTH_TOKEN", "tokA-value")
    monkeypatch.setenv("API_AUTH_TOKENS", "tokB-value")
    # Snapshot + restore the process-global provider so tests are hermetic.
    saved_provider = main.active_provider
    main.session_owners.clear()
    main.session_histories.clear()
    main.session_teams.clear()

    async def fake_answer(question, session_id):
        h = main.session_histories.setdefault(session_id, [])
        h += [{"role": "user", "content": question},
              {"role": "assistant", "content": "ANSWER"}]
        return "ANSWER"

    monkeypatch.setattr(main, "answer_with_llm", fake_answer)
    if main.threat_modeling_agent is not None:
        monkeypatch.setattr(main.threat_modeling_agent, "is_security_query",
                            lambda q, use_llm=True: False)
        monkeypatch.setattr(main.threat_modeling_agent, "is_web_scan_request",
                            lambda q: False)
    yield
    main.active_provider = saved_provider


def _admin(extra_bearer=A):
    h = dict(extra_bearer)
    h["X-Admin-Token"] = ADMIN_SECRET
    return h


# ---------------------------------------------------------------------------
# Model-setting mutation is admin-only
# ---------------------------------------------------------------------------
def test_unauthenticated_cannot_change_provider():
    r = client.post("/settings/model", json={"provider": "local"})
    assert r.status_code == 401                       # F2: no auth


def test_ordinary_caller_cannot_change_provider(monkeypatch):
    monkeypatch.setenv("API_ADMIN_TOKEN", ADMIN_SECRET)
    before = main.active_provider
    r = client.post("/settings/model", json={"provider": "local"}, headers=A)
    assert r.status_code == 403
    assert main.active_provider == before             # unchanged


def test_wrong_admin_token_rejected(monkeypatch):
    monkeypatch.setenv("API_ADMIN_TOKEN", ADMIN_SECRET)
    before = main.active_provider
    h = dict(A); h["X-Admin-Token"] = "wrong-admin"
    r = client.post("/settings/model", json={"provider": "local"}, headers=h)
    assert r.status_code == 403
    assert main.active_provider == before


def test_fails_closed_when_admin_token_unset(monkeypatch):
    monkeypatch.delenv("API_ADMIN_TOKEN", raising=False)
    before = main.active_provider
    # Even presenting an X-Admin-Token must be refused when none is configured.
    h = dict(A); h["X-Admin-Token"] = "anything"
    r = client.post("/settings/model", json={"provider": "local"}, headers=h)
    assert r.status_code == 403
    assert main.active_provider == before


def test_valid_admin_can_switch_provider(monkeypatch):
    monkeypatch.setenv("API_ADMIN_TOKEN", ADMIN_SECRET)
    r = client.post("/settings/model", json={"provider": "local"}, headers=_admin())
    assert r.status_code == 200
    assert r.json()["active_provider"] == "local"
    assert main.active_provider == "local"


def test_admin_token_never_returned(monkeypatch):
    monkeypatch.setenv("API_ADMIN_TOKEN", ADMIN_SECRET)
    r = client.post("/settings/model", json={"provider": "local"}, headers=_admin())
    assert ADMIN_SECRET not in r.text
    g = client.get("/settings/model", headers=A)
    assert ADMIN_SECRET not in g.text


def test_get_settings_is_readonly_and_has_no_secrets(monkeypatch):
    r = client.get("/settings/model", headers=A)
    assert r.status_code == 200
    text = r.text.lower()
    # No credentials / connection details leaked.
    for leaked in (str(main.azure_api_key or "ZZnoneZZ").lower(),
                   str(main.azure_endpoint or "ZZnoneZZ").lower()):
        if leaked and leaked != "none":
            assert leaked not in text
    assert "api_key" not in text and "authorization" not in text


# ---------------------------------------------------------------------------
# Global session state is not manipulated by a config change
# ---------------------------------------------------------------------------
def test_provider_switch_does_not_wipe_sessions(monkeypatch):
    monkeypatch.setenv("API_ADMIN_TOKEN", ADMIN_SECRET)
    client.post("/query/", json={"question": "hi", "session_id": "sA"}, headers=A)
    client.post("/query/", json={"question": "hi", "session_id": "sB"}, headers=B)
    assert set(main.session_owners) == {"sA", "sB"}

    r = client.post("/settings/model", json={"provider": "local"}, headers=_admin())
    assert r.status_code == 200
    # Other callers' sessions survive the config change.
    assert set(main.session_owners) == {"sA", "sB"}
    assert "sessions_cleared" not in r.json()
    assert client.get("/session/sA/history", headers=A).status_code == 200
    assert client.get("/session/sB/history", headers=B).status_code == 200


def test_no_global_session_clear_endpoint_for_ordinary_caller():
    # The only clear endpoint is per-caller and ownership-checked (F3).
    client.post("/query/", json={"question": "hi", "session_id": "sA"}, headers=A)
    # B cannot clear A's session.
    assert client.post("/clear-session/sA", headers=B).status_code == 404
    assert "sA" in main.session_owners
    # A can clear its own session.
    assert client.post("/clear-session/sA", headers=A).status_code == 200
    assert "sA" not in main.session_owners


# ---------------------------------------------------------------------------
# Concurrency / state-integrity of runtime switching
# ---------------------------------------------------------------------------
def test_provider_state_stays_consistent_across_switches(monkeypatch):
    monkeypatch.setenv("API_ADMIN_TOKEN", ADMIN_SECRET)
    for prov in ("local", "local", "local"):
        r = client.post("/settings/model", json={"provider": prov}, headers=_admin())
        assert r.status_code == 200
        # Active provider is always a complete, valid value (never partial).
        assert main.active_provider in ("local", "azure")
        assert client.get("/settings/model", headers=A).json()["active_provider"] \
            == main.active_provider


# ---------------------------------------------------------------------------
# F2/F3 regression
# ---------------------------------------------------------------------------
def test_health_public_and_auth_regression(monkeypatch):
    monkeypatch.setenv("API_ADMIN_TOKEN", ADMIN_SECRET)
    assert client.get("/health").status_code == 200
    assert client.post("/settings/model", json={"provider": "local"}).status_code == 401
    bad = {"Authorization": "Bearer nope"}
    assert client.post("/settings/model", json={"provider": "local"},
                       headers=bad).status_code == 403
    # Admin flow still requires valid F2 auth too: admin header without a valid
    # bearer is unauthenticated.
    assert client.post("/settings/model", json={"provider": "local"},
                       headers={"X-Admin-Token": ADMIN_SECRET}).status_code == 401
