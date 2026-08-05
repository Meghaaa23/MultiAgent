"""
General SSR/login oracles: auth-bypass SQLi, CSRF publishability, phpinfo HTML.
"""
import sys
import os
import asyncio

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "multiagent"))

from multiagent.agents.webappscanner.vulnerability_tester import (
    _looks_like_login_form,
    _auth_bypass_confirmed,
    VulnerabilityTester,
)
from multiagent.agents.threat_modeling_agent import _is_manual_queue_finding


class TestLoginFormDetection:
    def test_password_plus_username(self):
        inputs = [
            {"name": "username", "type": "text"},
            {"name": "password", "type": "password"},
        ]
        assert _looks_like_login_form(inputs, "/login.php") is True

    def test_search_form_not_login(self):
        inputs = [{"name": "q", "type": "text"}]
        assert _looks_like_login_form(inputs, "/search") is False


class TestAuthBypassOracle:
    def test_redirect_away_from_login(self):
        ok, reason = _auth_bypass_confirmed(
            baseline_status=200,
            baseline_headers={},
            baseline_body='<form>login failed<input type="password">',
            status=302,
            headers={"Location": "/index.php"},
            body="",
            action="http://localhost/login.php",
        )
        assert ok is True
        assert "redirect" in reason

    def test_baseline_also_redirecting_is_not_bypass(self):
        ok, _ = _auth_bypass_confirmed(
            baseline_status=302,
            baseline_headers={"Location": "/index.php"},
            baseline_body="",
            status=302,
            headers={"Location": "/index.php"},
            body="",
            action="http://localhost/login.php",
        )
        assert ok is False

    def test_redirect_back_to_login_not_bypass(self):
        ok, _ = _auth_bypass_confirmed(
            baseline_status=200,
            baseline_headers={},
            baseline_body="login failed",
            status=302,
            headers={"Location": "/login.php"},
            body="",
            action="http://localhost/login.php",
        )
        assert ok is False


class TestCsrfPublishable:
    def test_medium_potential_is_queued(self):
        assert _is_manual_queue_finding({
            "status": "Potential",
            "confidence": "Medium",
            "type": "Missing CSRF Protection",
            "evidence": {"confidence": "Medium"},
        }) is True

    def test_low_potential_still_dropped(self):
        assert _is_manual_queue_finding({
            "status": "Potential",
            "confidence": "Low",
            "evidence": {"confidence": "Low"},
        }) is False


class TestPhpinfoHtmlDisclosure:
    def test_phpinfo_html_confirmed(self):
        tester = VulnerabilityTester(timeout=2)
        findings = []

        async def run():
            # Monkeypatch fetch to return phpinfo HTML
            def fake_fetch(url):
                body = (
                    "<html><title>phpinfo()</title><body>"
                    "PHP Version 7.4.3<br>phpinfo()</body></html>"
                )
                return 200, {"Content-Type": "text/html"}, body

            tester._fetch_full = fake_fetch
            return await tester.test_sensitive_paths(
                "http://localhost:3142",
                {"/phpinfo.php"},
                verbose=False,
                baseline_html="<html><body>DVWA login</body></html>",
            )

        findings = asyncio.run(run())
        assert findings
        assert any("phpinfo" in f.get("type", "").lower() for f in findings)
        assert findings[0]["status"] == "Confirmed"
