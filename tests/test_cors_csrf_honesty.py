"""CORS/CSRF severity honesty + Section 4 confidence display."""
import asyncio
import sys
import os

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "multiagent"))

from multiagent.agents.webappscanner.vulnerability_tester import (
    VulnerabilityTester,
    _csrf_finding_should_skip,
    _page_looks_like_spa_jwt,
)
from multiagent.agents.webappscanner.web_scanner_agent import (
    _build_evidence_gated_stride,
)
from multiagent.agents.webappscanner.action_agent import ActionAgent
from multiagent.agents.threat_modeling_agent import _build_section_4


class TestCorsSeverityTiers:
    def test_wildcard_without_credentials_is_low(self):
        vt = VulnerabilityTester(timeout=2)

        def fake_headers(url, extra=None):
            return {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "false",
            }

        vt._sync_headers = fake_headers  # type: ignore
        findings = asyncio.run(vt.test_cors("http://localhost:3141"))
        assert findings
        assert findings[0]["severity"] == "Low"
        assert "credentials" not in findings[0]["impact"].lower() or \
            "not enabled" in findings[0]["impact"].lower()

    def test_reflected_origin_without_credentials_is_medium(self):
        vt = VulnerabilityTester(timeout=2)

        def fake_headers(url, extra=None):
            return {
                "Access-Control-Allow-Origin": "https://evil-cors-test.example.com",
            }

        vt._sync_headers = fake_headers  # type: ignore
        findings = asyncio.run(vt.test_cors("http://localhost:3141"))
        assert findings[0]["severity"] == "Medium"

    def test_credentialed_reflection_is_high(self):
        vt = VulnerabilityTester(timeout=2)

        def fake_headers(url, extra=None):
            return {
                "Access-Control-Allow-Origin": "https://evil-cors-test.example.com",
                "Access-Control-Allow-Credentials": "true",
            }

        vt._sync_headers = fake_headers  # type: ignore
        findings = asyncio.run(vt.test_cors("http://localhost:3141"))
        assert findings[0]["severity"] == "High"


class TestCorsStrideHonesty:
    def test_wildcard_omitted_from_stride(self):
        threats = _build_evidence_gated_stride(
            "http://x", {}, set(), [], "wildcard", {},
        )
        assert not any(t.get("threat") == "CORS Misconfiguration" for t in threats)

    def test_reflected_is_medium_impact(self):
        threats = _build_evidence_gated_stride(
            "http://x", {}, set(), [], "reflected", {},
        )
        cors = [t for t in threats if t.get("threat") == "CORS Misconfiguration"]
        assert cors and cors[0]["impact"] == "Medium"

    def test_credentialed_is_high_impact(self):
        threats = _build_evidence_gated_stride(
            "http://x", {}, set(), [], "credentialed", {},
        )
        cors = [t for t in threats if t.get("threat") == "CORS Misconfiguration"]
        assert cors and cors[0]["impact"] == "High"


class TestCorsActionPoc:
    def test_wildcard_poc_no_credential_theft(self):
        agent = ActionAgent()
        action = agent._action_cors(
            "http://localhost:3141",
            [],
            evidence={
                "access_control_allow_origin": "*",
                "access_control_allow_credentials": "",
                "response_headers": {"Access-Control-Allow-Origin": "*"},
            },
        )
        assert action["severity"] == "Low"
        assert "credentials: \"include\"" not in action["attack_poc"]
        assert "not enabled" in action["attack_poc"].lower() or \
            "reject credentialed" in action["attack_poc"].lower()


class TestCsrfSkipGates:
    def test_skips_spa_login(self):
        html = '<html ng-version="15"><script>localStorage.setItem("token", jwt)</script>'
        assert _page_looks_like_spa_jwt(html) is True
        form = {"action": "http://localhost:3141/login", "method": "post"}
        inputs = [
            {"name": "email", "type": "email"},
            {"name": "password", "type": "password"},
        ]
        assert _csrf_finding_should_skip(form, inputs, page_html=html) is True

    def test_skips_numeric_public_action(self):
        form = {"action": "https://www.limesurvey.org/989347", "method": "post"}
        inputs = [{"name": "email", "type": "email"}]
        assert _csrf_finding_should_skip(form, inputs, page_html="") is True

    def test_keeps_state_changing_profile_form(self):
        form = {"action": "http://x/account/profile/update", "method": "post"}
        inputs = [
            {"name": "displayname", "type": "text"},
            {"name": "bio", "type": "text"},
        ]
        assert _csrf_finding_should_skip(form, inputs, page_html="") is False


class TestSection4Confidence:
    def test_uses_stored_medium_not_hardcoded_low(self):
        text = _build_section_4([{
            "type": "Missing CSRF Protection",
            "severity": "Medium",
            "confidence": "Medium",
            "location": "http://x/account/update",
            "details": "POST form has no CSRF token",
            "cwe": "CWE-352",
            "evidence": {
                "confidence": "Medium",
                "confirmation_method": "code analysis",
            },
        }])
        assert "Confidence: LOW" not in text
        assert "Confidence: MEDIUM" in text
