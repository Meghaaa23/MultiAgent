"""
Unit tests for XSS confirmation gates and injectable URL seeding.
No live Juice Shop required — simulates the failure modes from the multiagent report.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from multiagent.agents.webappscanner.vulnerability_tester import (
    _XSS_MARKER,
    _xss_reflection_is_executable,
    synthesize_injectable_urls,
    _json_result_count,
    _sqli_error_match,
)

class TestXssConfirmationGate:
    def test_rejects_406_redirect_error_echo(self):
        body = (
            f'Unrecognized target URL for redirect: '
            f'<script>document.title="{_XSS_MARKER}"</script>'
        )
        ok, reason = _xss_reflection_is_executable(
            406, body, _XSS_MARKER,
            {"Content-Type": "text/html; charset=utf-8"},
            param_name="to",
        )
        assert ok is False
        assert reason in ("non_success_status_406", "error_page_reflection")

    def test_rejects_json_string_reflection(self):
        body = f'{{"q":"<script>document.title=\\"{_XSS_MARKER}\\"</script>"}}'
        ok, reason = _xss_reflection_is_executable(
            200, body, _XSS_MARKER,
            {"Content-Type": "application/json"},
            param_name="q",
        )
        assert ok is False
        assert reason == "json_string_reflection"

    def test_rejects_html_escaped_reflection(self):
        body = f"Result: &lt;script&gt;document.title=&quot;{_XSS_MARKER}&quot;&lt;/script&gt;"
        ok, reason = _xss_reflection_is_executable(
            200, body, _XSS_MARKER,
            {"Content-Type": "text/html"},
            param_name="q",
        )
        assert ok is False

    def test_accepts_unescaped_script_in_html(self):
        body = (
            f'<html><body><div>Search: '
            f'<script>document.title="{_XSS_MARKER}"</script>'
            f'</div></body></html>'
        )
        ok, reason = _xss_reflection_is_executable(
            200, body, _XSS_MARKER,
            {"Content-Type": "text/html; charset=utf-8"},
            param_name="q",
        )
        assert ok is True, reason
        assert reason == "ok"

class TestInjectableUrlSeeding:
    def test_seeds_generic_search_when_empty(self):
        urls = synthesize_injectable_urls("http://localhost:3141", [])
        assert any("/search?q=" in u or "/api/search?q=" in u for u in urls)
        assert not any("/rest/products/" in u for u in urls)

    def test_adds_query_to_bare_rest_path(self):
        urls = synthesize_injectable_urls(
            "http://localhost:3141",
            ["http://localhost:3141/rest/products/search"],
        )
        assert any(u.endswith("/rest/products/search?q=test") for u in urls)

    def test_keeps_existing_query(self):
        urls = synthesize_injectable_urls(
            "http://localhost:3141",
            ["http://localhost:3141/rest/products/search?q=apple"],
        )
        assert any("q=apple" in u for u in urls)

class TestSqliOracles:
    def test_sqlite_error_pattern(self):
        body = 'SQLITE_ERROR: near "OR": syntax error'
        assert _sqli_error_match(body)

    def test_sequelize_error_pattern(self):
        body = '{"error":"SequelizeDatabaseError: SQLITE_ERROR"}'
        assert _sqli_error_match(body)

    def test_json_result_count_juice_shop_shape(self):
        body = '{"status":"success","data":[{"id":1},{"id":2},{"id":3}]}'
        assert _json_result_count(body) == 3

    def test_json_result_count_plain_list(self):
        assert _json_result_count('[{"a":1},{"a":2}]') == 2
