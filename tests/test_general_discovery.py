"""
Product-agnostic discovery / injectable seeding — no app-brand hardcoding.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from multiagent.agents.webappscanner.endpoint_discovery_agent import (
    EndpointDiscoveryAgent,
    SSR_COMMON_PATHS,
    API_COMMON_PATHS,
)
from multiagent.agents.webappscanner.vulnerability_tester import (
    synthesize_injectable_urls,
    GENERIC_INJECTABLE_TEMPLATES,
)
from multiagent.agents.webappscanner.browser_controller import BrowserController


class TestProbePathSelection:
    def test_php_signal_prefers_ssr_paths(self):
        agent = EndpointDiscoveryAgent(max_probe_paths=40)
        html = '<html><form action="login.php"><input name="username"><input name="password" type="password"></form></html>'
        paths = agent._select_probe_paths(html)
        assert "/login.php" in paths
        # SSR family should appear before deep API-only brand paths
        assert paths.index("/login.php") < paths.index("/api/v3") if "/api/v3" in paths else True
        assert any(p.endswith(".php") for p in paths[:20])

    def test_api_signal_prefers_api_paths(self):
        agent = EndpointDiscoveryAgent(max_probe_paths=40)
        html = '<script>fetch("/api/users"); axios.get("/rest/search");</script>'
        paths = agent._select_probe_paths(html)
        assert "/api/login" in paths or "/api/users" in paths
        assert "/api/search" in paths or "/rest/search" in paths

    def test_html_referenced_paths_are_prioritized(self):
        agent = EndpointDiscoveryAgent(max_probe_paths=40)
        html = '<a href="/custom-setup.php">setup</a><form action="/my-login">'
        paths = agent._select_probe_paths(html)
        assert paths[0] in ("/custom-setup.php", "/my-login") or \
            "/custom-setup.php" in paths[:5]

    def test_no_juice_shop_brand_paths_in_defaults(self):
        brand = (
            "/rest/products/search",
            "/rest/user/login",
            "/rest/admin/application-configuration",
            "/api/Products",
            "/api/Challenges",
        )
        for p in brand:
            assert p not in SSR_COMMON_PATHS
            assert p not in API_COMMON_PATHS


class TestInjectableUrlSeedingGeneral:
    def test_empty_discovery_uses_generic_templates_only(self):
        urls = synthesize_injectable_urls("http://localhost:3000", [])
        assert urls
        for u in urls:
            assert "/rest/products/" not in u
            assert "/api/Products" not in u
        assert any("/search?q=" in u or "/api/search?q=" in u for u in urls)

    def test_ssr_php_path_gets_generic_params(self):
        urls = synthesize_injectable_urls(
            "http://localhost/dvwa",
            ["http://localhost/dvwa/vulnerabilities/sqli/"],
        )
        assert any("id=test" in u or "page=test" in u or "q=test" in u for u in urls)

    def test_html_query_links_seeded(self):
        html = '<a href="/index.php?page=home">Home</a>'
        urls = synthesize_injectable_urls("http://localhost", [], page_html=html)
        assert any("page=home" in u for u in urls)

    def test_html_get_form_seeds_named_input(self):
        html = '''
        <form method="GET" action="vulnerabilities/sqli/">
          <input type="text" name="id" />
          <input type="submit" name="Submit" />
        </form>
        '''
        urls = synthesize_injectable_urls("http://localhost/dvwa/", [], page_html=html)
        assert any("id=test" in u and "sqli" in u for u in urls)

    def test_discovered_api_path_gets_q_param(self):
        urls = synthesize_injectable_urls(
            "http://localhost:3141",
            ["http://localhost:3141/rest/products/search"],
        )
        assert any(u.endswith("/rest/products/search?q=test") for u in urls)

    def test_generic_templates_constant_has_no_brand_paths(self):
        for path, _ in GENERIC_INJECTABLE_TEMPLATES:
            assert "product" not in path.lower()
            assert "challenge" not in path.lower()
            assert "juice" not in path.lower()


class TestBrowserCrawlGeneral:
    def test_parse_keeps_links_without_query(self):
        bc = BrowserController(openai_client=None, llm_model="x")
        html = '<a href="/vulnerabilities/xss_r/">XSS</a><a href="/login.php">Login</a>'
        els = bc._extract_elements_from_html(html, "http://localhost/dvwa/")
        hrefs = [e["href"] for e in els if e.get("type") == "link"]
        assert any("xss_r" in h for h in hrefs)
        assert any("login.php" in h for h in hrefs)

    def test_empty_form_action_resolves_to_page(self):
        bc = BrowserController(openai_client=None, llm_model="x")
        html = '<form method="post"><input name="username"><input name="password" type="password"></form>'
        els = bc._extract_elements_from_html(html, "http://localhost/dvwa/login.php")
        forms = [e for e in els if e.get("type") == "form"]
        assert forms
        assert "login.php" in forms[0]["action"]

    def test_deterministic_tasks_from_forms(self):
        bc = BrowserController(openai_client=None, llm_model="x")
        elements = [
            {"type": "form", "action": "http://localhost/login.php",
             "method": "post", "inputs": [{"name": "username"}]},
            {"type": "link", "href": "http://localhost/setup.php", "text": "Setup"},
        ]
        tasks = bc._deterministic_tasks(elements, "http://localhost/")
        assert len(tasks) >= 2
        assert any("login" in (t.get("url") or "") for t in tasks)
