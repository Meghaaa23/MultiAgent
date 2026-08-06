"""
Tests for SPA soft-404 probe gating, evidence substance publishing,
and localhost fingerprint honesty — the review failure modes.

Run with: PYTHONPATH=/workspace:/workspace/multiagent python3 tests/test_report_evidence_gates.py
"""
import sys
import os

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "multiagent"))

from multiagent.agents.webappscanner.endpoint_discovery_agent import EndpointDiscoveryAgent
from multiagent.agents.webappscanner.action_agent import ActionAgent
from multiagent.agents.threat_modeling_agent import (
    _is_publishable_confirmed,
    _evidence_has_substance,
    _is_private_or_local_host,
    _build_section_2,
)


SPA_SHELL = (
    "<!doctype html><html><head><title>OWASP Juice Shop</title></head>"
    "<body><app-root></app-root><script src=\"main.js\"></script>"
    "<script src=\"runtime.js\"></script><script src=\"polyfills.js\"></script>"
    "<div id=\"app\">Juice Shop SPA shell content for soft-404 baseline matching tests.</div>"
    "</body></html>"
)


class TestSpaShellGate:
    def test_matches_baseline_shell(self):
        disco = EndpointDiscoveryAgent()
        disco._soft_mode = True
        disco._soft404_bodies = [SPA_SHELL]
        assert disco._matches_spa_shell(SPA_SHELL, "text/html") is True

    def test_json_api_not_treated_as_shell(self):
        disco = EndpointDiscoveryAgent()
        disco._soft_mode = True
        disco._soft404_bodies = [SPA_SHELL]
        body = '{"status":"success","data":{"version":"1.0"}}'
        assert disco._matches_spa_shell(body, "application/json") is False

    def test_disabled_when_not_soft_mode(self):
        disco = EndpointDiscoveryAgent()
        disco._soft_mode = False
        disco._soft404_bodies = [SPA_SHELL]
        assert disco._matches_spa_shell(SPA_SHELL, "text/html") is False


class TestEvidenceSubstanceGate:
    def test_rejects_empty_evidence(self):
        assert _evidence_has_substance({}) is False
        assert _is_publishable_confirmed({
            "status": "Confirmed", "confidence": "High",
            "location": "http://x", "evidence": {},
        }) is False

    def test_accepts_header_evidence(self):
        ev = {
            "confirmation_method": "header",
            "verified": True,
            "confidence": "High",
            "request": "GET http://x",
            "response_status": 200,
            "response_headers": {"Access-Control-Allow-Origin": "*"},
        }
        assert _evidence_has_substance(ev) is True
        assert _is_publishable_confirmed({
            "status": "Confirmed", "confidence": "High",
            "location": "http://x", "evidence": ev,
        }) is True

    def test_accepts_pattern_with_body(self):
        ev = {
            "confirmation_method": "pattern",
            "verified": True,
            "confidence": "High",
            "response_body_snippet": "SQLITE_ERROR: near OR",
            "request": "GET http://x/rest/products/search?q=%27",
            "response_status": 500,
        }
        assert _evidence_has_substance(ev) is True

    def test_rejects_pattern_without_body(self):
        ev = {
            "confirmation_method": "pattern",
            "verified": True,
            "confidence": "High",
            "request": "GET http://x",
            "response_status": 500,
        }
        assert _evidence_has_substance(ev) is False
        assert _is_publishable_confirmed({
            "status": "Confirmed", "confidence": "High",
            "location": "http://x/q=", "evidence": ev,
        }) is False


class TestLocalhostFingerprint:
    def test_private_hosts(self):
        assert _is_private_or_local_host("http://localhost:3141") is True
        assert _is_private_or_local_host("http://127.0.0.1:3000") is True
        assert _is_private_or_local_host("http://192.168.1.10/") is True
        assert _is_private_or_local_host("https://example.com") is False

    def test_section2_no_cdn_waf_on_localhost(self):
        text = _build_section_2(
            {"technologies": [], "stack_summary": "Unknown"},
            [],
            [],
            target_url="http://localhost:3141",
        )
        assert "CDN/WAF" not in text
        assert "Unidentified" in text or "local/private" in text


class TestActionAgentEvidenceKeys:
    def test_cors_uses_response_headers(self):
        agent = ActionAgent()
        action = agent._action_cors(
            "http://localhost:3141",
            [],
            evidence={
                "request": "GET http://localhost:3141 (Origin: https://evil-cors-test.example.com)",
                "response_headers": {
                    "Access-Control-Allow-Origin": "https://evil-cors-test.example.com",
                },
                "confirmation_method": "header",
            },
        )
        assert action["evidence_captured"] is True
        assert "NO EVIDENCE CAPTURED" not in action["attack_poc"]
        assert "Access-Control-Allow-Origin" in action["attack_poc"]

    def test_sqli_uses_response_body_snippet(self):
        agent = ActionAgent()
        action = agent._action_sqli(
            "SQL Injection",
            "http://localhost:3141/rest/products/search?q=",
            "q",
            {
                "confirmation_method": "pattern",
                "response_body_snippet": "SequelizeDatabaseError: SQLITE_ERROR",
            },
            [],
        )
        assert action["evidence_captured"] is True
        assert "SQLITE_ERROR" in action["attack_poc"]
        assert "NO EVIDENCE CAPTURED" not in action["attack_poc"]

    def test_process_all_skips_empty_evidence(self):
        agent = ActionAgent()
        actions = agent.process_all(
            findings=[{
                "type": "SQL Injection",
                "status": "Confirmed",
                "severity": "Critical",
                "location": "http://x/q=",
                "parameter": "q",
                "evidence": {
                    "confirmation_method": "pattern",
                    "confidence": "High",
                    "verified": True,
                },
            }],
            target_url="http://x",
            stack={},
        )
        assert actions == []


if __name__ == "__main__":
    fails = 0
    for cls in [
        TestSpaShellGate, TestEvidenceSubstanceGate,
        TestLocalhostFingerprint, TestActionAgentEvidenceKeys,
    ]:
        o = cls()
        for name in sorted(n for n in dir(o) if n.startswith("test_")):
            try:
                getattr(o, name)()
                print("PASS", f"{cls.__name__}.{name}")
            except Exception as e:
                fails += 1
                print("FAIL", f"{cls.__name__}.{name}", ":", type(e).__name__, e)
    raise SystemExit(fails)
