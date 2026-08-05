"""
Time-based SQLi oracle: reject client timeouts (HTTP 0) as Confirmed SLEEP hits.
"""
import asyncio
import sys
import os

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "multiagent"))

from multiagent.agents.webappscanner.vulnerability_tester import VulnerabilityTester
from multiagent.agents.threat_modeling_agent import (
    _evidence_has_substance,
    _is_publishable_confirmed,
)


class TestTimingEvidenceGate:
    def test_rejects_http_0_even_with_delta(self):
        ev = {
            "confirmation_method": "timing",
            "verified": True,
            "confidence": "High",
            "request": "GET http://x/template/search-template",
            "response_status": 0,
            "timing_delta_seconds": 3.1,
            "response_body_snippet": "timeout",
        }
        assert _evidence_has_substance(ev) is False
        assert _is_publishable_confirmed({
            "status": "Confirmed",
            "confidence": "High",
            "type": "SQL Injection (Time-Based Blind)",
            "location": "http://x/template/search-template",
            "evidence": ev,
        }) is False

    def test_accepts_real_status_with_delta(self):
        ev = {
            "confirmation_method": "timing",
            "verified": True,
            "confidence": "High",
            "request": "GET http://x/search",
            "response_status": 200,
            "timing_delta_seconds": 2.9,
            "response_body_snippet": "baseline=0.05s probes=[3.1, 3.0]",
        }
        assert _evidence_has_substance(ev) is True


class TestConfirmTimeBasedSqli:
    def test_unreachable_baseline_returns_none(self):
        vt = VulnerabilityTester()

        async def boom(*args, **kwargs):
            return 0, "", {}

        vt._http_request = boom  # type: ignore

        async def run():
            return await vt._confirm_time_based_sqli(
                "http://example.test/search",
                "get",
                {"q": "test"},
            )

        assert asyncio.run(run()) is None

    def test_timeout_on_delay_probe_returns_none(self):
        vt = VulnerabilityTester()
        calls = {"n": 0}

        async def flaky(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return 200, "ok", {}  # fast baseline
            return 0, "", {}  # client timeout on SLEEP probe

        vt._http_request = flaky  # type: ignore

        async def run():
            return await vt._confirm_time_based_sqli(
                "http://example.test/search",
                "get",
                {"q": "test"},
            )

        assert asyncio.run(run()) is None
