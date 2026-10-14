"""Navigation graph + inter-state taint + XSS/SQLi/CSRF surface ranking."""
import sys
import os
import asyncio

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "multiagent"))

from multiagent.agents.webappscanner.navigation_model import (
    NavigationGraph, normalize_state_url, form_signature, replay_script,
    pack_replay_step, paper_coverage_row,
)
from multiagent.agents.webappscanner.interstate_tracker import (
    InterstateTracker, TaintFlow, rank_forms, rank_urls,
    stored_reflection_findings, class_coverage_metrics, CANARY_PREFIX,
    stored_xss_payload, stored_xss_executed, stored_xss_breakout,
    iter_xss_fields, xss_oracle_payload,
)
from multiagent.agents.webappscanner.browser_controller import BrowserController
from multiagent.agents.webappscanner.vulnerability_tester import (
    VulnerabilityTester,
)


class TestNavigationGraph:
    def test_dedupes_same_state(self):
        g = NavigationGraph()
        a = g.add_state("http://x/search?q=1", forms=[{"action": "/s", "method": "get",
                         "fields": [{"name": "q"}]}], cookie_names=["sid"])
        b = g.add_state("http://x/search?q=2", forms=[{"action": "/s", "method": "get",
                         "fields": [{"name": "q"}]}], cookie_names=["sid"])
        assert a.key == b.key
        assert len(g.states) == 1

    def test_edge_between_distinct_urls(self):
        g = NavigationGraph()
        src = g.add_state("http://x/login")
        dst = g.add_state("http://x/search")
        g.add_edge(src, dst, command="CLICK", task="Explore search")
        g.add_edge(src, dst, command="CLICK", task="Explore search")
        assert len(g.edges) == 1
        summary = g.summary()
        assert summary["states"] == 2
        assert summary["edges"] == 1
        assert summary["commands"]["CLICK"] == 1

    def test_normalize_strips_query(self):
        assert normalize_state_url("HTTP://X/a/?q=1#h") == "http://x/a"

    def test_form_signature_stable(self):
        a = form_signature([{"action": "/u", "method": "POST",
                             "inputs": [{"name": "b"}, {"name": "a"}]}])
        b = form_signature([{"action": "/u", "method": "post",
                             "fields": [{"name": "a"}, {"name": "b"}]}])
        assert a == b


class TestInterstateTracker:
    def test_plant_and_observe_other_page(self):
        t = InterstateTracker()
        token = t.plant("comment", "text", "http://x/post", "http://x/post", "Leave comment")
        assert token and token.startswith(CANARY_PREFIX)
        hits = t.observe(f"<p>hello {token} world</p>", "http://x/guestbook")
        assert len(hits) == 1
        assert hits[0].source_field == "comment"
        assert hits[0].sink_url == "http://x/guestbook"
        assert t.summary()["flows"] == 1

    def test_same_page_is_not_stored_flow(self):
        t = InterstateTracker()
        token = t.plant("q", "search", "http://x/search", "http://x/search")
        hits = t.observe(f"results for {token}", "http://x/search?q=1")
        assert hits == []

    def test_skips_password_and_csrf_fields(self):
        t = InterstateTracker()
        assert t.plant("password", "password", "http://x/l", "http://x/l") is None
        assert t.plant("csrfmiddlewaretoken", "hidden", "http://x/l", "http://x/l") is None

    def test_rank_forms_prefers_flow_sources(self):
        forms = [
            {"action": "http://x/about", "method": "get", "inputs": [{"name": "x"}]},
            {"action": "http://x/comment", "method": "post",
             "inputs": [{"name": "body"}]},
            {"action": "http://x/search", "method": "get",
             "inputs": [{"name": "q"}]},
        ]
        flows = [TaintFlow(
            token="bwistabc", source_url="http://x/comment",
            source_action="http://x/comment", source_field="body",
            sink_url="http://x/guestbook", escaped=False,
        )]
        ranked = rank_forms(forms, flows)
        assert ranked[0]["action"] == "http://x/comment"

    def test_rank_urls_prefers_sinks(self):
        urls = ["http://x/about", "http://x/guestbook?id=1", "http://x/"]
        flows = [TaintFlow(
            token="t", source_url="http://x/c", source_action="http://x/c",
            source_field="body", sink_url="http://x/guestbook", escaped=False,
        )]
        ranked = rank_urls(urls, flows)
        assert "guestbook" in ranked[0]

    def test_stored_reflection_findings_only_unescaped(self):
        flows = [
            TaintFlow(token="bwist1", source_url="http://x/c",
                      source_action="http://x/c", source_field="body",
                      sink_url="http://x/g", escaped=True, snippet="&lt;"),
            TaintFlow(token="bwist2", source_url="http://x/c",
                      source_action="http://x/c", source_field="body",
                      sink_url="http://x/g", escaped=False, snippet="hello bwist2"),
        ]
        findings = stored_reflection_findings(flows)
        assert len(findings) == 1
        assert findings[0]["type"] == "Stored Reflection Surface"
        assert findings[0]["status"] == "Potential"


class TestCsrfHiddenToken:
    def test_hidden_token_suppresses_missing_csrf(self):
        tester = VulnerabilityTester(timeout=2)

        async def run():
            return await tester.test_csrf_missing(
                [{
                    "action": "http://localhost/account/profile/update",
                    "method": "post",
                    "inputs": [
                        {"name": "displayname", "type": "text"},
                        {"name": "csrfmiddlewaretoken", "type": "hidden"},
                    ],
                }],
                target_url="http://localhost/",
                page_html="",
            )

        findings = asyncio.run(run())
        assert findings == []

    def test_state_changing_post_without_token_is_potential(self):
        tester = VulnerabilityTester(timeout=2)

        async def run():
            tester._fetch_full = lambda url: (200, {}, "<html>no token</html>")
            return await tester.test_csrf_missing(
                [{
                    "action": "http://localhost/account/profile/update",
                    "method": "post",
                    "inputs": [{"name": "displayname", "type": "text"}],
                }],
                target_url="http://localhost/",
                page_html="",
            )

        findings = asyncio.run(run())
        assert findings
        assert findings[0]["type"] == "Missing CSRF Protection"
        assert findings[0]["status"] == "Potential"

    def test_samesite_strict_lowers_confidence(self):
        tester = VulnerabilityTester(timeout=2)

        async def run():
            tester._fetch_full = lambda url: (200, {}, "<html>no token</html>")
            return await tester.test_csrf_missing(
                [{
                    "action": "http://localhost/account/profile/update",
                    "method": "post",
                    "inputs": [{"name": "bio", "type": "text"}],
                }],
                target_url="http://localhost/",
                page_html="",
                shared_headers={"Set-Cookie": "sid=abc; SameSite=Strict"},
            )

        findings = asyncio.run(run())
        assert findings
        assert findings[0]["confidence"] == "Low"
        assert findings[0]["evidence"]["cookie_samesite"] == "strict"


class TestClassCoverage:
    def test_counts_xss_sqli_csrf(self):
        findings = [
            {"type": "Reflected XSS", "status": "Confirmed"},
            {"type": "SQL Injection", "status": "Confirmed"},
            {"type": "Missing CSRF Protection", "status": "Potential"},
        ]
        exercised = [
            {"tests_run": ["reflected_xss", "sqli"]},
            {"tests_run": ["csrf"]},
        ]
        m = class_coverage_metrics(
            findings, exercised,
            {"states": 4, "edges": 3, "unique_urls": 3},
            {"tokens_planted": 2, "flows": 1, "unescaped_flows": 0},
        )
        assert m["xss_confirmed"] == 1
        assert m["sqli_confirmed"] == 1
        assert m["csrf_potential"] == 1
        assert m["xss_attempted"] == 1
        assert m["sqli_attempted"] == 1
        assert m["csrf_attempted"] == 1
        assert m["nav_states"] == 4
        assert m["interstate_flows"] == 1


class TestTaskGenerationClassCoverage:
    def test_deterministic_tasks_name_sqli_and_csrf_shapes(self):
        bc = BrowserController(openai_client=None, llm_model="test")
        tasks = bc._deterministic_tasks(
            [
                {"type": "form", "action": "http://x/search", "method": "get",
                 "inputs": [{"name": "q", "type": "text"}]},
                {"type": "form", "action": "http://x/account/update", "method": "post",
                 "inputs": [{"name": "bio", "type": "text"}]},
                {"type": "form", "action": "http://x/guestbook", "method": "post",
                 "inputs": [{"name": "comment", "type": "text"}]},
            ],
            "http://x/",
        )
        descs = " ".join(t["description"] for t in tasks).lower()
        assert "sqli" in descs
        assert "csrf" in descs
        assert "stored" in descs or "inter-page" in descs


class TestDeepCrawlArtifacts:
    def test_empty_crawl_exports_graph_and_taint(self):
        bc = BrowserController(openai_client=None, llm_model="test")

        async def run():
            return await bc.deep_crawl(
                tasks=[{"name": "noop", "url": "http://localhost/"}],
                base_url="http://localhost/",
                max_tasks=0,
            )

        result = asyncio.run(run())
        assert "nav_graph" in result
        assert "interstate" in result
        assert result["nav_graph"]["summary"]["states"] == 0
        assert result["interstate"]["summary"]["tokens_planted"] == 0
        assert result["crawl_findings"] == []


class TestGraphDrivenCrawl:
    def test_click_to_visited_is_not_useful(self):
        bc = BrowserController(openai_client=None, llm_model="test")
        bc._visited_urls = {"http://localhost/about"}
        state = {
            "clickables": [{"href": "http://localhost/about", "text": "About"}],
            "forms": [],
        }
        assert bc._action_is_useful(
            {"command": "CLICK", "target_id": 0}, state, []
        ) is False

    def test_graph_picks_unvisited_edge(self):
        bc = BrowserController(openai_client=None, llm_model="test")
        bc._session_base = "http://localhost"
        bc._visited_urls = {"http://localhost/"}
        state = {
            "url": "http://localhost/",
            "forms": [],
            "clickables": [
                {"text": "Home", "href": "http://localhost/"},
                {"text": "Guestbook", "href": "http://localhost/guestbook"},
            ],
        }
        action = bc._graph_next_action("Explore", state, [])
        assert action["command"] == "CLICK"
        assert action["target_id"] == 1

    def test_revisit_skips_current_and_ranks_sinks(self):
        bc = BrowserController(openai_client=None, llm_model="test")
        bc._session_base = "http://localhost"
        bc._visited_urls = {
            "http://localhost/",
            "http://localhost/guestbook",
            "http://localhost/about",
        }
        picks = bc._revisit_candidates(
            ["http://localhost/search?q=1"],
            "http://localhost/",
            max_pages=5,
        )
        assert "http://localhost/" not in picks
        assert any("guestbook" in u or "search" in u for u in picks)


class TestStoredXssConfirm:
    def test_payload_sets_title_marker(self):
        payload = stored_xss_payload("bwistabc123")
        assert "bwistabc123" in payload
        assert "document.title" in payload
        assert "<svg" in payload

    def test_title_is_execution(self):
        assert stored_xss_executed("bwistabc123", "bwistabc123") is True
        assert stored_xss_executed("Guestbook", "bwistabc123") is False

    def test_live_markup_is_breakout(self):
        html = '<div><svg/onload=document.title="bwistabc123"></div>'
        assert stored_xss_breakout(html, "bwistabc123") is True

    def test_escaped_markup_is_not_breakout(self):
        html = "<div>&lt;svg/onload=document.title=&quot;bwistabc123&quot;&gt;</div>"
        assert stored_xss_breakout(html, "bwistabc123") is False


class TestReplayAndFrontier:
    def test_replay_script_is_seed_then_clicks(self):
        steps = replay_script(
            "http://x/",
            ["http://x/shop", "http://x/item"],
            "http://x/review",
        )
        assert [s["op"] for s in steps] == ["goto", "click", "click", "click"]
        assert steps[-1]["href"] == "http://x/review"

    def test_frontier_skips_visited_and_replays_path(self):
        g = NavigationGraph()
        g.add_state("http://x/")
        added = g.enqueue_unexplored(
            "http://x/",
            ["http://x/shop"],
            ["http://x/review", "http://x/", "javascript:void(0)"],
            visited=["http://x/"],
        )
        assert added == 1
        edge = g.pop_frontier(["http://x/"])
        assert edge is not None
        assert edge.href == "http://x/review"
        assert edge.trace == ("http://x/shop",)
        assert g.pop_frontier([]) is None
        assert g.summary()["frontier_taken"] == 1

    def test_rank_prefers_traced_form(self):
        forms = [
            {"action": "http://x/about", "method": "get",
             "inputs": [{"name": "q"}]},
            {"action": "http://x/review", "method": "post",
             "inputs": [{"name": "body"}],
             "reach_trace": ["http://x/shop", "http://x/item"],
             "seed_url": "http://x/"},
        ]
        ranked = rank_forms(forms, [])
        assert ranked[0]["action"] == "http://x/review"

    def test_coverage_includes_replay_counters(self):
        m = class_coverage_metrics(
            [], [],
            {"states": 3, "edges": 2, "unique_urls": 3,
             "traces_recorded": 4, "frontier_taken": 2, "replay_probes": 1},
            {},
        )
        assert m["traces_recorded"] == 4
        assert m["frontier_taken"] == 2
        assert m["replay_probes"] == 1

    def test_packed_click_keeps_text_and_frame(self):
        packed = pack_replay_step("http://x/item", "Buy", "http://x/frame")
        steps = replay_script("http://x/", [packed])
        assert steps[1]["op"] == "click"
        assert steps[1]["text"] == "Buy"
        assert steps[1]["frame"] == "http://x/frame"

    def test_event_edge_is_not_dropped(self):
        g = NavigationGraph()
        added = g.enqueue_unexplored(
            "http://x/", [], ["event:Open modal"], visited=["http://x/"],
        )
        assert added == 1
        edge = g.pop_frontier(["http://x/"])
        assert edge.href == "event:Open modal"
        steps = replay_script("http://x/", [], edge.href)
        assert steps[-1]["op"] == "event"
        assert steps[-1]["text"] == "Open modal"

    def test_xss_plan_is_safe_then_aggressive(self):
        plan = iter_xss_fields([
            {"name": "csrf_token", "type": "hidden"},
            {"name": "body", "type": "text"},
            {"name": "go", "type": "submit"},
            {"name": "note", "type": "file"},
            {"name": "role", "type": "select"},
            {"name": "extra", "type": "hidden"},
            {"name": "_token", "type": "hidden"},
        ])
        assert plan[0] == ("safe", "body", "text")
        assert [item[0] for item in plan].index("aggressive") > 0
        names = [item[1] for item in plan]
        assert names == ["body", "note", "role", "extra"]
        payload = xss_oracle_payload("bwistabc123")
        assert 'xss("bwistabc123")' in payload

    def test_coverage_row_counts_in_page_xss(self):
        row = paper_coverage_row(
            {"states": 4, "edges": 3, "replay_probes": 2, "frontier_taken": 6},
            [{
                "status": "Confirmed",
                "evidence": {
                    "confirmation_method": "js_execution_after_replay",
                    "field_phase": "aggressive",
                },
            }],
        )
        assert row["states"] == 4
        assert row["xss_confirmed_in_page"] == 1
        assert row["xss_aggressive_phase"] == 1
        assert row["xss_safe_phase"] == 0


class TestWorkflowChoice:
    def test_checkout_keeps_the_model_step(self):
        bc = BrowserController(openai_client=None, llm_model="test")
        bc._visited_urls = set()
        state = {
            "clickables": [{"text": "Other", "href": "http://x/other"}],
            "forms": [{"action": "http://x/checkout", "fields": [{"name": "card"}]}],
        }
        graph = {"command": "CLICK", "target_id": 0}
        llm = {"command": "FILL_FORM", "target_id": 0}
        chosen = bc._choose_crawl_action("Complete checkout", graph, llm, state, [])
        assert chosen["command"] == "FILL_FORM"

    def test_explore_follows_the_unvisited_edge(self):
        bc = BrowserController(openai_client=None, llm_model="test")
        bc._visited_urls = set()
        state = {
            "clickables": [{"text": "Other", "href": "http://x/other"}],
            "forms": [{"action": "http://x/checkout", "fields": [{"name": "card"}]}],
        }
        graph = {"command": "CLICK", "target_id": 0}
        llm = {"command": "FILL_FORM", "target_id": 0}
        chosen = bc._choose_crawl_action("Explore", graph, llm, state, [])
        assert chosen["command"] == "CLICK"


class TestGraphFirst:
    def test_single_unvisited_edge_is_decisive(self):
        bc = BrowserController(openai_client=None, llm_model="test")
        bc._visited_urls = {"http://localhost/"}
        state = {
            "forms": [],
            "clickables": [
                {"text": "Home", "href": "http://localhost/"},
                {"text": "Guestbook", "href": "http://localhost/guestbook"},
            ],
        }
        assert bc._graph_is_decisive("Explore", state, []) is True
        action = bc._graph_next_action("Explore", state, [])
        assert action["target_id"] == 1

    def test_tied_edges_are_not_decisive(self):
        bc = BrowserController(openai_client=None, llm_model="test")
        bc._visited_urls = {"http://localhost/"}
        state = {
            "forms": [],
            "clickables": [
                {"text": "Alpha", "href": "http://localhost/alpha"},
                {"text": "Beta", "href": "http://localhost/beta"},
            ],
        }
        assert bc._graph_is_decisive("Explore", state, []) is False


class TestDummyStillStable:
    def test_identity_fields_not_canaries(self):
        bc = BrowserController(openai_client=None, llm_model="test")
        assert bc._dummy_value("username", "text") == "testuser"
        assert bc._dummy_value("password", "password") == "TestPassword123!"
        token = bc._dummy_value("comment", "text", url="http://x/c", form_action="http://x/c")
        assert token.startswith(CANARY_PREFIX)
