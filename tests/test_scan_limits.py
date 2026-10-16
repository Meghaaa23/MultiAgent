"""
Security tests for scan resource-exhaustion controls (audit finding F5):
concurrency limit, per-caller rate limiting, scan timeout, resource cleanup,
and the F1 SSRF-policy-isolation invariant under the new concurrency control.

Async tests use asyncio.run() so no pytest-asyncio plugin is required. The
expensive inner scan is replaced with a controllable fake so the real
scan_application() wrapper (slot acquire -> guarded_egress -> wait_for ->
browser cleanup) is exercised without a browser or network.
"""
import asyncio
import types

import pytest

from multiagent.agents.webappscanner import scan_limits, ssrf_guard
from multiagent.agents.webappscanner.scan_limits import (
    ScanBusy, ScanTimeout, RateLimited, caller_key, check_rate_limit,
)
from multiagent.agents.webappscanner.web_scanner_agent import WebScannerAgent


@pytest.fixture(autouse=True)
def clean_limits(monkeypatch):
    # Fresh semaphore/rate state bound to each test's event loop.
    for var in ("MAX_CONCURRENT_SCANS", "SCAN_TIMEOUT_SECONDS",
                "SCAN_SLOT_ACQUIRE_TIMEOUT_SECONDS", "SCAN_RATE_LIMIT",
                "SCAN_RATE_WINDOW_SECONDS", "SSRF_INTERNAL_ALLOWLIST",
                "ACTIVE_MODEL_PROVIDER"):
        monkeypatch.delenv(var, raising=False)
    scan_limits.reset_for_tests()
    yield
    scan_limits.reset_for_tests()


def _make_agent(on_scan, on_close=None):
    """A minimal WebScannerAgent exercising only the F5 wrapper."""
    agent = WebScannerAgent.__new__(WebScannerAgent)
    closed = {"n": 0}

    async def _close():
        closed["n"] += 1
        if on_close:
            await on_close()

    agent.browser = types.SimpleNamespace(close_deep_session=_close)
    agent._closed_counter = closed
    agent._fake_scan = on_scan
    return agent


def _bind_scan(monkeypatch, agent):
    async def _guarded(self, target_url, verbose=False, ai_auth_token=None, auth=None):
        return await agent._fake_scan()
    monkeypatch.setattr(WebScannerAgent, "_scan_application_guarded", _guarded)


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------
def test_single_scan_runs_and_releases_slot(monkeypatch):
    monkeypatch.setenv("SSRF_INTERNAL_ALLOWLIST", "127.0.0.1")
    scan_limits.reset_for_tests()

    async def ok():
        return {"ok": True}

    agent = _make_agent(ok)
    _bind_scan(monkeypatch, agent)

    async def run():
        res = await WebScannerAgent.scan_application(agent, "http://127.0.0.1/")
        # Slot free again afterwards.
        async with scan_limits.scan_slot():
            pass
        return res

    assert asyncio.run(run()) == {"ok": True}
    assert agent._closed_counter["n"] == 1            # browser cleaned up


def test_concurrency_limit_serializes(monkeypatch):
    monkeypatch.setenv("MAX_CONCURRENT_SCANS", "1")
    monkeypatch.setenv("SSRF_INTERNAL_ALLOWLIST", "127.0.0.1")
    scan_limits.reset_for_tests()

    state = {"concurrent": 0, "max": 0}

    async def busy():
        state["concurrent"] += 1
        state["max"] = max(state["max"], state["concurrent"])
        await asyncio.sleep(0.2)
        state["concurrent"] -= 1
        return {"ok": True}

    agent = _make_agent(busy)
    _bind_scan(monkeypatch, agent)

    async def run():
        await asyncio.gather(
            WebScannerAgent.scan_application(agent, "http://127.0.0.1/"),
            WebScannerAgent.scan_application(agent, "http://127.0.0.1/"),
        )

    asyncio.run(run())
    assert state["max"] == 1          # never two scans at once
    assert agent._closed_counter["n"] == 2


def test_slot_busy_returns_scanbusy(monkeypatch):
    monkeypatch.setenv("MAX_CONCURRENT_SCANS", "1")
    monkeypatch.setenv("SCAN_SLOT_ACQUIRE_TIMEOUT_SECONDS", "0.1")
    scan_limits.reset_for_tests()

    async def run():
        async with scan_limits.scan_slot():          # occupy the only slot
            with pytest.raises(ScanBusy):
                async with scan_limits.scan_slot():
                    pass
        # released now: acquiring again succeeds
        async with scan_limits.scan_slot():
            pass

    asyncio.run(run())


def test_slot_released_after_exception(monkeypatch):
    monkeypatch.setenv("MAX_CONCURRENT_SCANS", "1")
    monkeypatch.setenv("SSRF_INTERNAL_ALLOWLIST", "127.0.0.1")
    scan_limits.reset_for_tests()

    async def boom():
        raise ValueError("scan failed")

    agent = _make_agent(boom)
    _bind_scan(monkeypatch, agent)

    async def run():
        with pytest.raises(ValueError):
            await WebScannerAgent.scan_application(agent, "http://127.0.0.1/")
        async with scan_limits.scan_slot():          # slot was released
            pass

    asyncio.run(run())
    assert agent._closed_counter["n"] == 1           # cleanup still happened


# ---------------------------------------------------------------------------
# Timeout
# ---------------------------------------------------------------------------
def test_scan_timeout_raises_and_releases(monkeypatch):
    monkeypatch.setenv("MAX_CONCURRENT_SCANS", "1")
    monkeypatch.setenv("SCAN_TIMEOUT_SECONDS", "0.2")
    monkeypatch.setenv("SSRF_INTERNAL_ALLOWLIST", "127.0.0.1")
    scan_limits.reset_for_tests()

    async def slow():
        await asyncio.sleep(5)
        return {"ok": True}

    agent = _make_agent(slow)
    _bind_scan(monkeypatch, agent)

    async def run():
        with pytest.raises(ScanTimeout):
            await WebScannerAgent.scan_application(agent, "http://127.0.0.1/")
        async with scan_limits.scan_slot():          # slot free after timeout
            pass

    asyncio.run(run())
    assert agent._closed_counter["n"] == 1           # browser cleaned up on timeout


def test_cancellation_releases_slot_and_cleans_up(monkeypatch):
    monkeypatch.setenv("MAX_CONCURRENT_SCANS", "1")
    monkeypatch.setenv("SSRF_INTERNAL_ALLOWLIST", "127.0.0.1")
    scan_limits.reset_for_tests()

    async def slow():
        await asyncio.sleep(5)

    agent = _make_agent(slow)
    _bind_scan(monkeypatch, agent)

    async def run():
        task = asyncio.create_task(
            WebScannerAgent.scan_application(agent, "http://127.0.0.1/")
        )
        await asyncio.sleep(0.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        async with scan_limits.scan_slot():          # slot released on cancel
            pass

    asyncio.run(run())
    assert agent._closed_counter["n"] == 1


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
def test_rate_limit_allows_then_rejects(monkeypatch):
    monkeypatch.setenv("SCAN_RATE_LIMIT", "3")
    monkeypatch.setenv("SCAN_RATE_WINDOW_SECONDS", "60")
    scan_limits.reset_for_tests()
    key = "callerA"
    for _ in range(3):
        check_rate_limit(key)                        # under the limit: OK
    with pytest.raises(RateLimited):
        check_rate_limit(key)                        # 4th exceeds


def test_rate_limit_per_caller_independent(monkeypatch):
    monkeypatch.setenv("SCAN_RATE_LIMIT", "2")
    monkeypatch.setenv("SCAN_RATE_WINDOW_SECONDS", "60")
    scan_limits.reset_for_tests()
    check_rate_limit("A"); check_rate_limit("A")
    with pytest.raises(RateLimited):
        check_rate_limit("A")
    # Different caller unaffected.
    check_rate_limit("B"); check_rate_limit("B")


def test_rate_limit_window_expires(monkeypatch):
    monkeypatch.setenv("SCAN_RATE_LIMIT", "1")
    monkeypatch.setenv("SCAN_RATE_WINDOW_SECONDS", "10")
    scan_limits.reset_for_tests()

    clock = {"t": 1000.0}
    fake_time = types.SimpleNamespace(monotonic=lambda: clock["t"])
    monkeypatch.setattr(scan_limits, "time", fake_time)

    check_rate_limit("A")
    with pytest.raises(RateLimited):
        check_rate_limit("A")
    clock["t"] += 11                                  # window elapsed
    check_rate_limit("A")                             # allowed again


def test_caller_key_never_contains_raw_token():
    token = "super-secret-token-value"
    key = caller_key(f"Bearer {token}")
    assert token not in key
    assert key != "anon" and len(key) == 16
    assert caller_key(None) == "anon"
    assert caller_key("Basic xyz") == "anon"          # only Bearer is a caller
    # Deterministic within a process run.
    assert caller_key(f"Bearer {token}") == key


# ---------------------------------------------------------------------------
# F1 SSRF regression + policy isolation under the F5 concurrency control
# ---------------------------------------------------------------------------
def test_ssrf_still_blocks_during_scan_entry(monkeypatch):
    # No allowlist -> public-only. scan_application preflight must reject.
    scan_limits.reset_for_tests()

    async def ok():
        return {"ok": True}

    agent = _make_agent(ok)
    _bind_scan(monkeypatch, agent)

    async def run(url):
        return await WebScannerAgent.scan_application(agent, url)

    for blocked in ("http://127.0.0.1/", "http://localhost/",
                    "http://169.254.169.254/", "http://10.0.0.1/",
                    "http://192.168.1.1/"):
        with pytest.raises(ssrf_guard.SSRFBlocked):
            asyncio.run(run(blocked))
    # Blocked targets never consumed a slot or touched the browser.
    assert agent._closed_counter["n"] == 0


def test_allowlisted_internal_target_passes_entry(monkeypatch):
    monkeypatch.setenv("SSRF_INTERNAL_ALLOWLIST", "127.0.0.1")
    scan_limits.reset_for_tests()

    async def ok():
        return {"ok": True}

    agent = _make_agent(ok)
    _bind_scan(monkeypatch, agent)
    assert asyncio.run(
        WebScannerAgent.scan_application(agent, "http://127.0.0.1/")
    ) == {"ok": True}


def test_no_policy_leak_between_scans(monkeypatch):
    """One scan's internal allowlist must not affect another scan."""
    scan_limits.reset_for_tests()

    seen = {}

    async def observe():
        pol = ssrf_guard.current_policy()
        seen["allow_internal"] = pol.allow_internal
        seen["loopback_ok"] = pol.ip_allowed("127.0.0.1", "127.0.0.1")
        return {"ok": True}

    agent = _make_agent(observe)
    _bind_scan(monkeypatch, agent)

    # Scan A: 127.0.0.1 explicitly allowlisted.
    monkeypatch.setenv("SSRF_INTERNAL_ALLOWLIST", "127.0.0.1")
    scan_limits.reset_for_tests()
    asyncio.run(WebScannerAgent.scan_application(agent, "http://127.0.0.1/"))
    assert seen["allow_internal"] is True and seen["loopback_ok"] is True
    # Policy fully cleared after the scan (no leak to the next one).
    assert ssrf_guard.current_policy() is None

    # Scan B: no allowlist -> loopback must now be blocked at entry.
    monkeypatch.delenv("SSRF_INTERNAL_ALLOWLIST", raising=False)
    scan_limits.reset_for_tests()
    with pytest.raises(ssrf_guard.SSRFBlocked):
        asyncio.run(WebScannerAgent.scan_application(agent, "http://127.0.0.1/"))
