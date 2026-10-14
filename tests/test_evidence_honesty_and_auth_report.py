"""Reporting-layer evidence honesty + authenticated-scan surfacing.

A finding must never read "Confirmed" beside a "no evidence captured" note:
  * a disclosure finding needs the actual disclosed value (not just req+status);
  * the action layer must recover a value the detector already recorded.
The executive summary must state whether authenticated surfaces were tested,
and never print the password.
"""
import os
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "multiagent"))

from multiagent.agents.webappscanner.action_agent import ActionAgent
from multiagent.agents.threat_modeling_agent import (
    _is_publishable_confirmed,
    _auth_and_surface_block,
)


def _disclosure(details="", headers=None):
    return {
        "type": "Information Disclosure: server header",
        "status": "Confirmed", "confidence": "High", "location": "http://h",
        "details": details,
        "evidence": {
            "confirmation_method": "header", "verified": True, "confidence": "High",
            "request": "GET http://h", "response_status": 200,
            "response_headers": headers or {},
        },
    }


class TestDisclosureNeedsValue:
    def test_valueless_disclosure_not_confirmed(self):
        assert _is_publishable_confirmed(_disclosure()) is False

    def test_disclosure_with_header_value_is_confirmed(self):
        assert _is_publishable_confirmed(
            _disclosure(headers={"server": "Apache/2.4.25"})) is True

    def test_disclosure_with_value_in_details_is_confirmed(self):
        assert _is_publishable_confirmed(
            _disclosure(details="server: Apache/2.4.25")) is True

    def test_missing_header_still_confirmed_without_a_value(self):
        # Absence IS the evidence for a *missing* header; req+status suffices.
        missing = {
            "type": "Missing Security Header: Content-Security-Policy",
            "status": "Confirmed", "confidence": "High", "location": "http://h",
            "evidence": {"confirmation_method": "header", "verified": True,
                         "confidence": "High", "request": "GET http://h",
                         "response_status": 200, "response_headers": {}},
        }
        assert _is_publishable_confirmed(missing) is True


class TestActionLayerRecoversValue:
    def _agent(self):
        return ActionAgent()

    def test_recovers_value_from_finding_evidence(self):
        ev = {"response_headers": {"Server": "Apache/2.4.25 (Debian)"}}
        r = self._agent()._action_info_disclosure_header(
            "Information Disclosure: server header", "http://h", [], {}, ev)
        assert r["evidence_captured"] is True
        assert "Apache/2.4.25" in str(r)

    def test_no_value_anywhere_marks_uncaptured(self):
        r = self._agent()._action_info_disclosure_header(
            "Information Disclosure: server header", "http://h", [], {}, {})
        assert r["evidence_captured"] is False


class TestAuthSurfaceBlock:
    EPS = [{"url": "/a"}, {"url": "/b", "auth_required": True},
           {"url": "/c", "category": "discovered_protected"}]

    def _block(self, auth):
        return _auth_and_surface_block({"auth": auth, "endpoints_discovered": self.EPS})

    def test_success_reports_enabled_and_counts(self):
        out = self._block({"enabled": True, "logged_in": True, "username": "admin"})
        assert "Authentication status: SUCCESS" in out
        assert "Authenticated crawling: ENABLED" in out
        assert "Post-login surfaces tested: YES" in out
        assert "Public pages: 1" in out
        assert "Authenticated pages: 2" in out
        assert "Total discovered routes: 3" in out

    def test_failure_states_not_tested(self):
        out = self._block({"enabled": True, "logged_in": False, "error": "bad creds"})
        assert "Status: FAILED" in out
        assert "Post-login surfaces tested: NO" in out
        assert "bad creds" in out

    def test_not_attempted_when_no_credentials(self):
        out = self._block({"enabled": False})
        assert "NOT PROVIDED" in out
        assert "Post-login surfaces tested: NO" in out

    def test_password_never_printed(self):
        out = self._block({"enabled": True, "logged_in": True,
                           "username": "admin", "password": "s3cr3t"})
        assert "s3cr3t" not in out
