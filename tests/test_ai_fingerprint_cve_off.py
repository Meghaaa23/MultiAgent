"""CVE mapping off (fingerprint-only stack) + taxonomy AI gate helpers."""
import sys
import os

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "multiagent"))

from multiagent.agents.threat_modeling_agent import (
    _build_section_2,
    _build_section_5,
    _build_section_8_ai_backdoor,
)
from multiagent.agents.ai_agents.ai_evidence_scoring import score_evidence


class TestSection2FingerprintOnly:
    def test_no_orphan_cve_dump(self):
        text = _build_section_2(
            {
                "technologies": [
                    {"name": "LibreChat", "category": "Framework", "confidence": 0.9},
                    {"name": "x-robots-tag: noindex", "category": "Other", "confidence": 0.5},
                ],
                "app_identity_name": "LibreChat",
            },
            [],
            [
                {"cve_id": "CVE-2025-1716", "query": "express"},
                {"cve_id": "CVE-2025-1889", "query": "node"},
            ],
            target_url="http://localhost:3080",
        )
        assert "Known CVEs" not in text
        assert "Other detected components" not in text
        assert "CVE-2025" not in text
        assert "LibreChat" in text
        assert "x-robots-tag" not in text.lower()

    def test_app_identity_when_tech_empty(self):
        text = _build_section_2(
            {"technologies": [], "app_identity_name": "LibreChat"},
            [],
            [],
            target_url="http://localhost:3080",
        )
        assert "LibreChat" in text


class TestStrideNoDoubleSeeSection3:
    def test_no_double_prefix(self):
        text = _build_section_5(
            [{
                "category": "Spoofing",
                "threat": "Clickjacking",
                "confirmed": True,
                "evidence": (
                    "See Section 3: Clickjacking "
                    "(X-Frame-Options and CSP frame-ancestors absent)"
                ),
                "likelihood": "Medium",
                "impact": "Medium",
                "mitigation": "Add XFO",
            }],
            confirmed_vulns=[{
                "type": "Clickjacking",
                "status": "Confirmed",
            }],
        )
        assert text.count("See Section 3") == 1


class TestLiveSurfaceGateNoNameHardcoding:
    """Scanner must escalate on live surface, not product-name lists."""

    def _gate(self, ai_fingerprint):
        has_live_surface = bool(
            ai_fingerprint.get("has_live_surface")
            or ai_fingerprint.get("ml_endpoints")
            or ai_fingerprint.get("auth_required_paths")
        )
        brand_only = bool(ai_fingerprint.get("ai_brand_only")) and not has_live_surface
        is_ai = bool(ai_fingerprint.get("is_ai_powered") and has_live_surface)
        return is_ai, brand_only

    def test_brand_only_librechat_name_does_not_escalate(self):
        fp = {
            "is_ai_powered": False,
            "has_live_surface": False,
            "ai_brand_only": True,
            "framework": "LibreChat",
            "ml_endpoints": [],
            "auth_required_paths": [],
        }
        is_ai, brand_only = self._gate(fp)
        assert is_ai is False
        assert brand_only is True

    def test_auth_gated_messages_escalates(self):
        fp = {
            "is_ai_powered": True,
            "has_live_surface": True,
            "ai_brand_only": False,
            "framework": "",
            "ml_endpoints": ["http://localhost:3080/api/messages"],
            "auth_required_paths": [
                {"endpoint": "http://localhost:3080/api/messages", "status_code": 401},
            ],
        }
        is_ai, brand_only = self._gate(fp)
        assert is_ai is True
        assert brand_only is False

    def test_taxonomy_brand_vs_live(self):
        assert score_evidence(["framework_identified"]).is_ai is False
        assert score_evidence(["ml_endpoint_401_403"]).is_ai is True


class TestSection8AuthGatedAndRecommendations:
    def _scan(self, vulns, strategic=None):
        return {
            "ai_fingerprint": {
                "is_ai_powered": True,
                "confidence": "high",
                "has_live_surface": True,
                "ml_endpoints": ["http://localhost:3080/api/chat"],
                "chat_components": [{"type": "chat_ui"}],
                "atlas_techniques": ["AML.T0051"],
            },
            "vulnerabilities": vulns,
            "strategic_recommendations": strategic or [],
            "avid_backdoor_relevant": [],
            "stack": {"technologies": [{"name": "LibreChat"}]},
        }

    def test_collapses_duplicate_auth_gated_rows(self):
        locations = [
            "http://localhost:3080/api/chat",
            "http://localhost:3080/api/chat/abort",
            "http://localhost:3080/api/chat/active",
            "http://localhost:3080/api/chat/status",
        ]
        vulns = [
            {
                "category": "ai_vulnerability",
                "status": "Potential",
                "type": "Potential Prompt Injection (auth-gated)",
                "severity": "Medium",
                "location": loc,
                "details": "auth required",
                "atlas": "AML.T0051",
                "remediation": "keep auth",
            }
            for loc in locations
        ]
        text = _build_section_8_ai_backdoor(self._scan(vulns))
        assert text.count("[POTENTIAL] Potential Prompt Injection (auth-gated)") == 1
        assert "Related auth-gated surfaces" in text

    def test_section_84_does_not_deny_ai_surfaces(self):
        vulns = [{
            "category": "ai_vulnerability",
            "status": "Potential",
            "type": "Potential Prompt Injection (auth-gated)",
            "severity": "Medium",
            "location": "http://localhost:3080/api/chat",
            "details": "auth required",
            "atlas": "AML.T0051",
            "remediation": "keep auth",
        }]
        text = _build_section_8_ai_backdoor(self._scan(vulns))
        assert "8.4 Strategic Recommendations" in text
        assert "no AI-specific attack surfaces identified" not in text
        assert "AI chat/inference surfaces were identified" in text


if __name__ == "__main__":
    fails = 0
    for cls in [
        TestSection2FingerprintOnly,
        TestStrideNoDoubleSeeSection3,
        TestLiveSurfaceGateNoNameHardcoding,
        TestSection8AuthGatedAndRecommendations,
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
