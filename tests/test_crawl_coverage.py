"""The deep crawl is coverage-based (Black Widow / YuraScanner style): it runs
every extracted task and drains the navigation frontier to saturation, with no
time budget. These tests pin that contract."""
import asyncio
import inspect

from multiagent.agents.webappscanner.browser_controller import BrowserController


def _make_controller():
    bc = BrowserController(openai_client=None, llm_model="test-model")
    bc._visited_urls = set()
    bc._network_apis = set()
    bc.nav_graph.frontier = []
    bc.taint.sources = {}
    return bc


def test_no_time_budget_params_exist():
    for fn in (BrowserController.deep_crawl, BrowserController._deep_crawl_impl,
               BrowserController.execute_task, BrowserController._execute_task_impl):
        params = set(inspect.signature(fn).parameters)
        assert "time_budget_seconds" not in params
        assert "deadline" not in params


def test_all_tasks_run_to_coverage(monkeypatch):
    bc = _make_controller()
    ran = []

    async def fake_start(base_url):
        bc._page = object(); return True

    async def fake_exec(task, base_url, max_steps=15, reuse_session=False):
        ran.append(task.get("name"))
        return {"task": task.get("name"), "urls": [], "forms": [], "api_urls": []}

    async def _zero(*a, **k):
        return 0

    monkeypatch.setattr(bc, "start_deep_session", fake_start)
    monkeypatch.setattr(bc, "execute_task", fake_exec)
    monkeypatch.setattr(bc, "_drain_frontier", _zero)
    monkeypatch.setattr(bc, "_replay_probe_forms", _zero)
    monkeypatch.setattr(bc, "_revisit_for_taint", _zero)

    tasks = [{"name": f"t{i}"} for i in range(12)]
    res = asyncio.run(
        bc._deep_crawl_impl(tasks, "http://t.local", max_tasks=len(tasks),
                            max_steps_per_task=5)
    )
    # every task executed — nothing stopped the crawl early on a clock
    assert ran == [f"t{i}" for i in range(12)]
    assert res["tasks_executed"] == 12


def test_frontier_drains_until_empty(monkeypatch):
    bc = _make_controller()
    drained = {"called": False}

    async def fake_start(base_url):
        bc._page = object(); return True

    async def fake_exec(task, base_url, max_steps=15, reuse_session=False):
        return {"task": task.get("name"), "urls": [], "forms": [], "api_urls": []}

    async def fake_drain(page, forms_out, urls_out, max_edges=1500):
        # the crawl must call the frontier drain with a large safety bound,
        # not a tiny fixed cap, so coverage can saturate.
        drained["called"] = True
        drained["max_edges"] = max_edges
        return 0

    async def _zero(*a, **k):
        return 0

    bc.nav_graph.frontier = [object()]   # non-empty -> drain is invoked
    monkeypatch.setattr(bc, "start_deep_session", fake_start)
    monkeypatch.setattr(bc, "execute_task", fake_exec)
    monkeypatch.setattr(bc, "_drain_frontier", fake_drain)
    monkeypatch.setattr(bc, "_replay_probe_forms", _zero)
    monkeypatch.setattr(bc, "_revisit_for_taint", _zero)

    asyncio.run(
        bc._deep_crawl_impl([{"name": "t0"}], "http://t.local", max_tasks=1,
                            max_steps_per_task=5)
    )
    assert drained["called"] is True
    assert drained["max_edges"] >= 1000
