"""
General XSS oracle fixtures — not app-specific.
Encoded href reflection must NOT pass; live HTML breakout may.
Confirmed XSS requires js_execution at the publisher.
"""
import sys
import os

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "multiagent"))

from multiagent.agents.webappscanner.vulnerability_tester import (
    _XSS_MARKER,
    _xss_reflection_is_executable,
    _xss_marker_only_url_encoded,
    _dedupe_findings,
    _is_bogus_param_name,
)
from multiagent.agents.threat_modeling_agent import (
    _is_publishable_confirmed,
    _is_manual_queue_finding,
)

class TestUrlEncodedHrefIsNotXss:
    def test_canonical_link_percent_encoded_payload(self):
        body = (
            '<html><head><title>Search</title>'
            f'<link href="https://example.com/search?q=%22%3E%3Cimg+src%3Dx+'
            f'onerror%3D%22document.title%3D%27{_XSS_MARKER}%27%22%3E" '
            'rel="canonical">'
            '</head><body>results</body></html>'
        )
        ok, reason = _xss_reflection_is_executable(
            200, body, _XSS_MARKER,
            {"Content-Type": "text/html"},
            param_name="q",
        )
        assert ok is False
        assert reason in (
            "url_encoded_attribute_reflection",
            "no_html_breakout",
            "no_tag_context",
        )

    def test_helper_detects_encoded_only(self):
        window = (
            f'href="https://x/search?q=%22%3E%3Cimg+src%3Dx+onerror%3D%22'
            f'document.title%3D%27{_XSS_MARKER}%27%22%3E"'
        )
        assert _xss_marker_only_url_encoded(window, _XSS_MARKER) is True

class TestLiveHtmlBreakout:
    def test_raw_img_onerror_passes_gate(self):
        body = (
            f'<html><body><div>q=\'"><img src=x onerror="document.title='
            f"'{_XSS_MARKER}'\"></div></body></html>"
        )
        ok, reason = _xss_reflection_is_executable(
            200, body, _XSS_MARKER,
            {"Content-Type": "text/html"},
            param_name="q",
        )
        assert ok is True, reason

    def test_raw_script_passes_gate(self):
        body = (
            f'<html><body><script>document.title="{_XSS_MARKER}"</script>'
            f'</body></html>'
        )
        ok, reason = _xss_reflection_is_executable(
            200, body, _XSS_MARKER,
            {"Content-Type": "text/html"},
            param_name="q",
        )
        assert ok is True, reason

class TestPublisherXssTier:
    def test_http_body_xss_not_publishable_confirmed(self):
        v = {
            "type": "Reflected XSS",
            "status": "Confirmed",
            "confidence": "High",
            "location": "https://example.com/search?q=",
            "evidence": {
                "confirmation_method": "http_body",
                "verified": True,
                "confidence": "High",
                "response_body_snippet": f"<img onerror=...{_XSS_MARKER}",
                "request": "GET https://example.com/search",
                "response_status": 200,
            },
        }
        assert _is_publishable_confirmed(v) is False

    def test_js_execution_xss_is_publishable(self):
        v = {
            "type": "Reflected XSS",
            "status": "Confirmed",
            "confidence": "High",
            "location": "https://example.com/search",
            "evidence": {
                "confirmation_method": "js_execution",
                "verified": True,
                "confidence": "High",
                "response_body_snippet": "title='yuraxss'",
                "request": "POST https://example.com/search",
                "response_status": 200,
            },
        }
        assert _is_publishable_confirmed(v) is True

    def test_potential_medium_reflection_is_queued(self):
        v = {
            "type": "Reflected XSS",
            "status": "Potential",
            "confidence": "Medium",
            "evidence": {"confidence": "Medium", "confirmation_method": "http_body"},
        }
        assert _is_manual_queue_finding(v) is True

class TestXssDedupAndBogusParams:
    def test_dedupe_collapses_same_path_params(self):
        findings = [
            {
                "type": "Reflected XSS",
                "status": "Potential",
                "severity": "High",
                "location": "https://ex.com/search?q=",
            },
            {
                "type": "Reflected XSS",
                "status": "Potential",
                "severity": "High",
                "location": "https://ex.com/search?message=",
            },
            {
                "type": "Reflected XSS",
                "status": "Confirmed",
                "severity": "High",
                "location": "https://ex.com/search?title=",
            },
        ]
        out = _dedupe_findings(findings)
        assert len(out) == 1
        assert out[0]["status"] == "Confirmed"

    def test_bogus_amp_param(self):
        assert _is_bogus_param_name("amp;title") is True
        assert _is_bogus_param_name("q") is False
