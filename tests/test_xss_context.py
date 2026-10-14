"""Context-aware XSS breakout selection: detect where a marker reflects and try
the matching breakout first (Black Widow-style), which raises confirmation
recall within a fixed probe budget."""
from multiagent.agents.webappscanner.vulnerability_tester import (
    _detect_reflection_context, _rank_payloads_for_context,
    XSS_PAYLOADS, XSS_ALERT_PAYLOADS,
)

M = "yuraxss"


class TestContextDetection:
    def test_js_block(self):
        body = f'<html><script>var q="{M}";</script></html>'
        assert _detect_reflection_context(body, M) == "js_block"

    def test_comment(self):
        assert _detect_reflection_context(f"<div><!-- {M} --></div>", M) == "comment"

    def test_attribute_double(self):
        assert _detect_reflection_context(f'<input value="{M}">', M) == "attribute_double"

    def test_attribute_single(self):
        assert _detect_reflection_context(f"<input value='{M}'>", M) == "attribute_single"

    def test_attribute_unquoted(self):
        assert _detect_reflection_context(f"<input value={M}>", M) == "attribute_unquoted"

    def test_tag_body(self):
        assert _detect_reflection_context(f"<div>{M}</div>", M) == "tag_body"

    def test_absent_is_unknown(self):
        assert _detect_reflection_context("<div>nothing</div>", M) == "unknown"


class TestPayloadRanking:
    def test_ranking_preserves_all_payloads(self):
        ranked = _rank_payloads_for_context(XSS_PAYLOADS, "attribute_double")
        assert sorted(ranked) == sorted(XSS_PAYLOADS)

    def test_js_block_puts_script_close_first(self):
        ranked = _rank_payloads_for_context(XSS_PAYLOADS, "js_block")
        first = ranked[0].lstrip().lower()
        assert first.startswith(("</script>", "'-", '";', "';"))

    def test_attribute_double_puts_quote_breakout_first(self):
        ranked = _rank_payloads_for_context(XSS_ALERT_PAYLOADS, "attribute_double")
        assert ranked[0].lstrip().startswith('">')

    def test_comment_puts_comment_close_first(self):
        ranked = _rank_payloads_for_context(XSS_PAYLOADS, "comment")
        assert ranked[0].lstrip().startswith(("-->", "<"))

    def test_unknown_context_keeps_order(self):
        assert _rank_payloads_for_context(XSS_PAYLOADS, "unknown") == list(XSS_PAYLOADS)


class TestFormPathThreadsContext:
    """The form XSS path must return the reflection context alongside the
    finding, so the browser confirmer can order breakouts by context too."""

    def _agent(self, body, ctype="text/html"):
        import asyncio
        from multiagent.agents.webappscanner.vulnerability_tester import VulnerabilityTester
        t = VulnerabilityTester()
        async def fake(url, method="get", data=None, follow_redirects=True,
                       timeout=None, json_body=False):
            return 200, {"Content-Type": ctype}, body
        t._http_request = fake
        return t, asyncio.new_event_loop()

    def test_reflection_returns_finding_and_context(self):
        t, loop = self._agent(f"<html><body><div><svg/onload=x>{M}</div></body></html>")
        finding, ctx = loop.run_until_complete(
            t._test_xss_reflection_http(
                "http://h/f", "get", [{"name": "q", "type": "text"}],
                XSS_PAYLOADS[1], False))
        assert finding is not None
        assert ctx in ("tag_body", "attribute_double", "attribute_single",
                       "js_block", "comment", "attribute_unquoted")

    def test_no_reflection_returns_none_and_unknown(self):
        t, loop = self._agent("<html><body><div>clean output</div></body></html>")
        finding, ctx = loop.run_until_complete(
            t._test_xss_reflection_http(
                "http://h/f", "get", [{"name": "q", "type": "text"}],
                XSS_PAYLOADS[1], False))
        assert finding is None and ctx == "unknown"
