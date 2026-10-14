"""XSS engine upgrades that push past Black Widow / YuraScanner:

  * per-injection unique markers (attribution, concurrency safety)
  * a single multi-context polyglot (more contexts per probe)
  * a context-targeted breakout *generator* (not just ranking a fixed list)
  * one unified in-browser execution oracle (dialog + title + JS beacon)

These are pure functions, verifiable without a live browser.
"""
import re

from multiagent.agents.webappscanner.vulnerability_tester import (
    _XSS_MARKER,
    _new_xss_marker,
    XSS_ALERT_POLYGLOT,
    _xss_polyglot_with_marker,
    _context_breakout_payloads,
    _beacon_marker_hit,
    _detect_reflection_context,
    XSS_EXEC_BEACON,
)

_CONTEXTS = (
    "attribute_double", "attribute_single", "attribute_unquoted",
    "js_block", "comment", "tag_body", "unknown",
)


class TestUniqueMarker:
    def test_prefix_and_shape(self):
        m = _new_xss_marker()
        assert m.startswith(_XSS_MARKER)
        assert re.fullmatch(_XSS_MARKER + r"[0-9a-f]{6}", m)

    def test_markers_are_unique(self):
        markers = {_new_xss_marker() for _ in range(200)}
        assert len(markers) == 200


class TestPolyglot:
    def test_alert_polyglot_covers_multiple_contexts(self):
        p = XSS_ALERT_POLYGLOT.lower()
        # closes script/title/textarea/style, opens svg, has an onload handler,
        # a js: scheme and an onclick handler — several contexts at once.
        assert "</script" in p
        assert "<svg" in p
        assert "onload=" in p
        assert "javascript:" in p or "javascript" in p
        assert "alert(1)" in p

    def test_marker_polyglot_carries_marker_and_sets_title(self):
        m = _new_xss_marker()
        p = _xss_polyglot_with_marker(m)
        assert m in p
        assert "document.title" in p
        assert "<svg" in p.lower() and "onload=" in p.lower()

    def test_marker_polyglot_marker_is_quote_safe(self):
        # a marker is hex only, but the sanitiser must never leave a stray quote
        p = _xss_polyglot_with_marker("ab'c\"d\\e")
        inner = p.split("document.title='", 1)[1].split("'", 1)[0]
        assert "'" not in inner and '"' not in inner and "\\" not in inner


class TestContextBreakoutGenerator:
    def test_every_context_yields_marker_firing_payloads(self):
        m = _new_xss_marker()
        for ctx in _CONTEXTS:
            payloads = _context_breakout_payloads(ctx, m)
            assert payloads, f"no payloads generated for {ctx}"
            for pl in payloads:
                assert m in pl, f"{ctx}: marker missing in {pl!r}"
                low = pl.lower()
                # each payload must fire an oracle: title mutation and/or beacon
                assert "document.title" in low or "__xssbeacon" in low

    def test_double_quote_context_opens_with_quote_gt(self):
        m = _new_xss_marker()
        first = _context_breakout_payloads("attribute_double", m)[0]
        assert first.startswith('">')

    def test_single_quote_context_opens_with_quote_gt(self):
        m = _new_xss_marker()
        first = _context_breakout_payloads("attribute_single", m)[0]
        assert first.startswith("'>")

    def test_js_block_context_closes_string_or_script(self):
        m = _new_xss_marker()
        first = _context_breakout_payloads("js_block", m)[0].lstrip()
        assert first.startswith(('"', "'", "</script>"))

    def test_comment_context_closes_comment(self):
        m = _new_xss_marker()
        first = _context_breakout_payloads("comment", m)[0]
        assert first.startswith("-->")

    def test_generator_matches_detected_context(self):
        # round-trip: detect the context of a reflected marker, then the
        # generated breakout for that context should escape it.
        m = _new_xss_marker()
        body = f'<input value="{m}">'
        ctx = _detect_reflection_context(body, m)
        assert ctx == "attribute_double"
        assert _context_breakout_payloads(ctx, m)[0].startswith('">')


class TestBeaconOracle:
    def test_beacon_source_defines_hook_without_clobbering_alert(self):
        # it must ADD window.xss/__xssbeacon but NOT replace window.alert,
        # so Playwright's native dialog oracle keeps working.
        assert "__xssbeacon" in XSS_EXEC_BEACON
        assert "window.xss" in XSS_EXEC_BEACON
        assert "window.alert" not in XSS_EXEC_BEACON

    def test_beacon_hit_matches_marker_case_insensitively(self):
        m = _new_xss_marker()
        assert _beacon_marker_hit([f"fired:{m.upper()}"], m) is True
        assert _beacon_marker_hit([m], m) is True

    def test_beacon_hit_ignores_unrelated(self):
        m = _new_xss_marker()
        assert _beacon_marker_hit(["something else", "1"], m) is False
        assert _beacon_marker_hit([], m) is False
        assert _beacon_marker_hit(None, m) is False
