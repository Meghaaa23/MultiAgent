"""The browser layer must work regardless of how the server is launched.

On Windows, `uvicorn --reload` runs on a SelectorEventLoop that cannot spawn
the Playwright browser subprocess. The controller bridges its Playwright
coroutines onto a dedicated ProactorEventLoop thread. These tests exercise the
bridge without launching a real browser.
"""
import asyncio
import sys
import pytest

from multiagent.agents.webappscanner import browser_controller as bc


def test_run_browser_coro_returns_result_inline():
    async def coro():
        return 42

    async def driver():
        return await bc._run_browser_coro(coro())

    loop = asyncio.new_event_loop()
    try:
        assert loop.run_until_complete(driver()) == 42
    finally:
        loop.close()


def test_run_browser_coro_propagates_exceptions():
    async def boom():
        raise ValueError("kaboom")

    async def driver():
        return await bc._run_browser_coro(boom())

    loop = asyncio.new_event_loop()
    try:
        with pytest.raises(ValueError, match="kaboom"):
            loop.run_until_complete(driver())
    finally:
        loop.close()


@pytest.mark.skipif(sys.platform != "win32",
                    reason="Selector-loop subprocess limitation is Windows-only")
def test_bridges_off_selector_loop_to_proactor():
    """From a SelectorEventLoop (what --reload gives), the coroutine must be
    routed onto a subprocess-capable Proactor loop."""
    async def report_loop():
        return type(asyncio.get_event_loop()).__name__

    async def driver():
        assert bc._loop_supports_subprocess() is False
        return await bc._run_browser_coro(report_loop())

    # Build a Selector loop directly, without touching the global policy.
    loop = asyncio.SelectorEventLoop()
    try:
        landed_on = loop.run_until_complete(driver())
    finally:
        loop.close()
    assert "Selector" not in landed_on
    assert "Proactor" in landed_on
