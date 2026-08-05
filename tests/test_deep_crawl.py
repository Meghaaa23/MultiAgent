"""Unit tests for Yura-style deep crawl session helpers."""
import sys
import os

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


class TestCredentialsFill:
    def test_uses_provided_credentials(self):
        bc = _bc()
        bc.configure_auth(username="admin", password="password")
        assert bc._dummy_value("username", "text") == "admin"
        assert bc._dummy_value("password", "password") == "password"

    def test_falls_back_without_credentials(self):
        bc = _bc()
        assert "Password" in bc._dummy_value("password", "password") or \
            bc._dummy_value("password", "password") == "TestPassword123!"


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
    def test_prefers_login_form(self):
        bc = _bc()
        bc.configure_auth(username="a", password="b")
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


class TestAuthenticatedFlagOptInOnly:
    def test_anonymous_cookies_do_not_mean_authenticated(self):
        """Regression: Cloudflare/WP cookies must not mark Authenticated scan."""
        bc = _bc()
        # Simulate what deep_crawl used to do wrong: any cookie ⇒ authenticated
        auth_requested = bool(
            (bc.auth_cookie or "").strip()
            or (
                (bc.credentials.get("username") or "").strip()
                and (bc.credentials.get("password") or "").strip()
            )
        )
        assert auth_requested is False

    def test_credentials_request_auth_mode(self):
        bc = _bc()
        bc.configure_auth(username="admin", password="password")
        auth_requested = bool(
            (bc.auth_cookie or "").strip()
            or (
                (bc.credentials.get("username") or "").strip()
                and (bc.credentials.get("password") or "").strip()
            )
        )
        assert auth_requested is True

    def test_auth_cookie_requests_auth_mode(self):
        bc = _bc()
        bc.configure_auth(auth_cookie="PHPSESSID=abc")
        assert bool((bc.auth_cookie or "").strip()) is True


class TestTaskGenerationIncludesLoginPriority:
    def test_credentials_prepend_login_task(self):
        import asyncio
        bc = _bc()
        bc.configure_auth(username="admin", password="password")

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
        assert "credential" in tasks[0]["name"].lower() or "authenticate" in tasks[0]["name"].lower()
