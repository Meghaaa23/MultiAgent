"""
Regression tests for:
- detect_app_identity NameError / for-else wipe / preferred CMS
- Caching category remap
- Yoast Premium collapse
- sse_chunked_transfer weight
"""
import sys
import os
import asyncio

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "multiagent"))

from multiagent.agents.webappscanner.app_identity import (
    detect_app_identity,
    _pick_preferred_wappalyzer_app,
)
from multiagent.agents.webappscanner.fingerprint_agent import (
    _normalise_category,
    _collapse_premium_duplicates,
)
from multiagent.agents.ai_agents.ai_fingerprint import EVIDENCE_WEIGHTS


class TestDetectAppIdentityCrashFix:
    def test_accepts_wappalyzer_technologies_kwarg(self):
        async def run():
            return await detect_app_identity(
                base_url="https://example.com",
                html='<meta name="generator" content="WordPress 6.4.2">',
                response_headers={"server": "cloudflare"},
                wappalyzer_technologies=[
                    {"name": "WordPress", "version": "", "category": "CMS", "confidence": 0.75},
                    {"name": "WP Rocket", "version": "3.19.4", "category": "Other", "confidence": 0.9},
                ],
                verbose=False,
            )
        identity = asyncio.run(run())
        assert identity.name == "WordPress"
        assert identity.version == "6.4.2" or identity.version  # from generator

    def test_cms_preferred_does_not_wipe_best(self):
        preferred = _pick_preferred_wappalyzer_app([
            {"name": "HTTP/3", "category": "Other"},
            {"name": "WordPress", "category": "CMS", "version": "6.4"},
            {"name": "Yoast SEO", "category": "Other", "version": "25.9"},
        ])
        assert preferred is not None
        assert preferred["name"] == "WordPress"

    def test_empty_wappalyzer_list_no_nameerror(self):
        async def run():
            return await detect_app_identity(
                base_url="https://example.com",
                html="<html><title>Hello</title></html>",
                response_headers={},
                wappalyzer_technologies=[],
            )
        identity = asyncio.run(run())
        # May be low-confidence / None name, but must not raise
        assert identity is not None


class TestCachingCategory:
    def test_caching_is_not_server(self):
        assert _normalise_category("Caching") != "Server"
        assert _normalise_category("Caching") == "Other"
        assert _normalise_category("Web servers") == "Server"


class TestPremiumCollapse:
    def test_yoast_premium_collapsed(self):
        techs = [
            {"name": "Yoast SEO", "version": "25.9", "category": "Other", "confidence": 0.6},
            {"name": "Yoast SEO Premium", "version": "25.9", "category": "Other", "confidence": 0.6},
            {"name": "WordPress", "version": "", "category": "CMS", "confidence": 0.75},
        ]
        out = _collapse_premium_duplicates(techs)
        names = [t["name"] for t in out]
        assert "Yoast SEO" in names
        assert "Yoast SEO Premium" not in names
        assert "WordPress" in names

    def test_keeps_premium_when_base_absent(self):
        techs = [
            {"name": "Yoast SEO Premium", "version": "25.9", "category": "Other"},
        ]
        out = _collapse_premium_duplicates(techs)
        assert len(out) == 1
        assert out[0]["name"] == "Yoast SEO Premium"


class TestSseChunkedWeight:
    def test_weight_is_low(self):
        assert EVIDENCE_WEIGHTS["sse_chunked_transfer"] <= 3
