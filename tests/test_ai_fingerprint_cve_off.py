"""AI fingerprint honesty + CVE mapping off (fingerprint-only stack)."""
import sys
import os

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "multiagent"))

from multiagent.agents.threat_modeling_agent import _build_section_2, _build_section_5
from multiagent.agents.ai_agents.ai_fingerprint import (
    FRAMEWORK_SIGNATURES,
    score_to_confidence,
    EVIDENCE_WEIGHTS,
)


class TestLibreChatAiGateReason:
    """Document why LibreChat was missed and the score/confidence math."""

    def test_framework_alone_is_low_confidence_band(self):
        # framework_identified weight=30 → score>=26 (is_ai) but confidence "low"
        score = EVIDENCE_WEIGHTS["framework_identified"]
        assert score >= 26
        assert score_to_confidence(score) == "low"

    def test_librechat_in_framework_signatures(self):
        assert "LibreChat" in FRAMEWORK_SIGNATURES
        paths = FRAMEWORK_SIGNATURES["LibreChat"]["paths"]
        assert "/api/config" in paths
        assert "/api/user" in paths


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


class TestKnownAiAppEscalationLogic:
    """Mirror the web_scanner gate without spinning up the full agent."""

    def _gate(self, ai_fingerprint, app_identity_name=""):
        raw_is_ai = ai_fingerprint.get("is_ai_powered", False)
        confidence = ai_fingerprint.get("confidence", "low")
        has_concrete = bool(
            ai_fingerprint.get("ml_endpoints") or ai_fingerprint.get("ai_headers")
        )
        known = (
            "librechat", "open webui", "open-webui", "flowise", "dify",
            "anythingllm", "lobechat", "lobe-chat", "langflow", "openhands",
        )
        fw = (
            (ai_fingerprint.get("framework") or "")
            + " "
            + (ai_fingerprint.get("app_layer") or "")
            + " "
            + (app_identity_name or "")
        ).lower()
        known_ai_app = any(k in fw for k in known)
        named_framework = bool(ai_fingerprint.get("framework"))
        return (
            (raw_is_ai and (
                confidence in ("high", "very_high", "medium")
                or has_concrete
                or named_framework
            ))
            or known_ai_app
        )

    def test_old_gate_would_miss_librechat_low_conf(self):
        # Previous gate: raw_is_ai and (confidence == "high" or has_concrete)
        fp = {
            "is_ai_powered": True,
            "confidence": "low",
            "framework": "LibreChat",
            "ml_endpoints": [],
            "ai_headers": [],
        }
        old = fp["is_ai_powered"] and (
            fp["confidence"] == "high" or bool(fp["ml_endpoints"] or fp["ai_headers"])
        )
        assert old is False
        assert self._gate(fp) is True

    def test_stack_identity_alone(self):
        fp = {
            "is_ai_powered": False,
            "confidence": "none",
            "framework": "",
            "ml_endpoints": [],
            "ai_headers": [],
        }
        assert self._gate(fp, app_identity_name="LibreChat") is True


if __name__ == "__main__":
    fails = 0
    for cls in [
        TestLibreChatAiGateReason,
        TestSection2FingerprintOnly,
        TestStrideNoDoubleSeeSection3,
        TestKnownAiAppEscalationLogic,
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
