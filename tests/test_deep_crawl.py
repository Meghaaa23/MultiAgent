"""Unit tests for Yura-style deep crawl session helpers."""
import sys
import os
import asyncio

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "multiagent"))

from multiagent.agents.webappscanner.browser_controller import BrowserController

def _bc() -> BrowserController:
    return BrowserController(openai_client=None, llm_model="test")

class TestCookieParse:
    def test_parses_cookie_header(self):
        bc = _bc()
        cookies = bc._parse_cookie_header(
            "PHPSESSID=abc123; security=low",
            "http://localhost:3142/login.php",
        )
        assert len(cookies) == 2
        assert cookies[0]["name"] == "PHPSESSID"
        assert cookies[0]["value"] == "abc123"
        assert cookies[0]["domain"] == "localhost"

class TestDummyFill:
    def test_benign_dummy_values(self):
        bc = _bc()
        assert bc._dummy_value("username", "text") == "testuser"
        assert bc._dummy_value("password", "password") == "TestPassword123!"
        assert bc._dummy_value("email", "email") == "test@example.com"

class TestFormNormalize:
    def test_fields_and_inputs_aligned(self):
        bc = _bc()
        form = bc._normalize_form({
            "action": "http://x/login.php",
            "method": "post",
            "fields": [{"name": "username", "type": "text"}],
        })
        assert form["inputs"] == form["fields"]
        assert form["action"].endswith("login.php")

class TestHeuristicDeepActions:
    def test_prefers_login_form_when_task_mentions_login(self):
        bc = _bc()
        state = {
            "url": "http://localhost/login.php",
            "forms": [{
                "fields": [
                    {"name": "username", "type": "text"},
                    {"name": "password", "type": "password"},
                ]
            }],
            "clickables": [],
        }
        action = bc._heuristic_next_action("Login to app", state, [])
        assert action["command"] == "FILL_FORM"

    def test_explores_unvisited_link(self):
        bc = _bc()
        bc._session_base = "http://localhost:3142"
        bc._visited_urls = {"http://localhost:3142/login.php"}
        state = {
            "url": "http://localhost:3142/",
            "forms": [],
            "clickables": [
                {"text": "SQL Injection", "href": "http://localhost:3142/vulnerabilities/sqli/"},
            ],
        }
        action = bc._heuristic_next_action("Explore vulns", state, [])
        assert action["command"] == "CLICK"
        assert action["target_id"] == 0

class TestBlackBoxDeepCrawl:
    def test_deep_crawl_return_has_no_auth_fields(self):
        """Black-box mode must not export auth_cookie / authenticated flags."""
        bc = _bc()

        async def run():
            return await bc.deep_crawl(
                tasks=[{"name": "noop", "url": "http://localhost/"}],
                base_url="http://localhost/",
                max_tasks=0,
            )

        result = asyncio.run(run())
        assert "auth_cookie" not in result
        assert "authenticated" not in result
        assert "api_urls" in result
        assert result["tasks_executed"] == 0

class TestApiHarvestAndTaskHeuristics:
    def test_harvestable_api_urls(self):
        bc = _bc()
        bc._session_base = "http://localhost:3141"
        assert bc._is_harvestable_api_url(
            "http://localhost:3141/rest/products/search?q=apple"
        )
        assert bc._is_harvestable_api_url(
            "http://localhost:3141/api/users"
        )
        assert not bc._is_harvestable_api_url(
            "http://localhost:3141/main.js"
        )
        assert not bc._is_harvestable_api_url(
            "https://evil.example.com/api/users"
        )

    def test_clickable_score_prefers_search_and_spa_hash(self):
        bc = _bc()
        low = bc._clickable_score("Home", "http://localhost/#/", "")
        high = bc._clickable_score(
            "Search", "http://localhost/#/search", "explore search"
        )
        assert high > low

    def test_heuristic_ranks_security_links_first(self):
        bc = _bc()
        bc._session_base = "http://localhost:3141"
        bc._visited_urls = set()
        state = {
            "url": "http://localhost:3141/",
            "forms": [],
            "clickables": [
                {"text": "About", "href": "http://localhost:3141/#/about"},
                {"text": "Search", "href": "http://localhost:3141/#/search"},
            ],
        }
        action = bc._heuristic_next_action("Explore search products", state, [])
        assert action["command"] == "CLICK"
        assert action["target_id"] == 1

class TestTaskGenerationUnauthenticated:
    def test_no_credentials_login_task_prepended(self):
        bc = _bc()

        class Completions:
            def create(self, **kwargs):
                raise RuntimeError("no llm")

        class Chat:
            completions = Completions()

        class Boom:
            chat = Chat()

        async def run():
            return await bc.generate_tasks(
                elements=[
                    {"type": "form", "action": "http://localhost/login.php",
                     "method": "post", "inputs": [{"name": "username"}]},
                    {"type": "link", "href": "http://localhost/setup.php", "text": "Setup"},
                ],
                page_description="login page",
                openai_client=Boom(),
                llm_model="x",
                target_url="http://localhost/",
                deep=True,
            )

        tasks = asyncio.run(run())
        assert tasks
        assert "authenticate with provided" not in (tasks[0].get("name") or "").lower()
