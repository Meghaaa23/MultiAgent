"""
Zero-finding sections must report a coverage denominator.
Also: clickjacking stack-correct CSP alt, OpenAPI listing, AI-negative note.
"""
import sys
import os

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "multiagent"))

from multiagent.agents.threat_modeling_agent import (
    _build_section_2,
    _build_section_4,
    _build_section_8_ai_backdoor,
    _build_section_8_ai_negative,
    _coverage_denominator_text,
)
from multiagent.agents.webappscanner.action_agent import ActionAgent
from multiagent.agents.webappscanner.app_identity import (
    _is_infra_or_framework_name,
    _looks_like_app_name,
    _from_powered_by,
    _from_page_title,
)
from multiagent.agents.webappscanner.endpoint_discovery_agent import (
    EndpointDiscoveryAgent,
)


def _scan(**kwargs):
    base = {
        "endpoints_discovered": [
            {
                "url": "http://localhost:3101/api/docs",
                "method": "GET",
                "status": 200,
                "source": "probe",
                "interesting": True,
            },
            {
                "url": "http://localhost:3101/manifest.json",
                "method": "GET",
                "status": 200,
                "source": "probe",
                "interesting": True,
            },
            {
                "url": "http://localhost:3101/api/openapi.json",
                "method": "GET",
                "status": 200,
                "source": "probe",
                "interesting": False,
                "spa_catch_all": True,
                "excluded": True,
                "exclude_reason": "SPA/soft-404 shell — not a real endpoint",
            },
        ],
        "forms_discovered": 1,
        "forms_testing": {
            "discovered": 1,
            "tested": 1,
            "with_findings": 0,
            "errored": 0,
        },
        "not_assessed_endpoints": [],
        "is_ai_powered": False,
        "ai_brand_only": False,
        "has_live_surface": False,
    }
    base.update(kwargs)
    return base


class TestSection4Denominator:
    def test_zero_potentials_includes_coverage(self):
        text = _build_section_4([], _scan())
        assert "All tested surfaces returned clean results" not in text
        assert "No potential vulnerabilities identified" in text
        assert "Coverage:" in text
        assert "functional endpoint" in text
        assert "form" in text
        assert "soft-404" in text

    def test_denominator_helper_counts(self):
        t = _coverage_denominator_text(_scan())
        assert "2 functional" in t or "2 functional endpoint" in t
        assert "1 form" in t
        assert "1 candidate" in t or "excluded" in t


class TestSection2IdentityAndForms:
    def test_identity_not_determined(self):
        text = _build_section_2(
            {"technologies": [{"name": "Express", "category": "Framework", "confidence": 0.95}]},
            [],
            [],
            target_url="http://localhost:3101",
            forms_discovered=0,
            scan_results=_scan(forms_discovered=0, forms_testing={
                "discovered": 0, "tested": 0, "with_findings": 0, "errored": 0,
            }),
        )
        assert "App identity: not determined" in text

    def test_form_outcome_line(self):
        text = _build_section_2(
            {
                "technologies": [
                    {"name": "Node", "category": "Language", "confidence": 0.6},
                    {"name": "Express", "category": "Framework", "confidence": 0.95},
                ],
                "app_identity_name": "",
            },
            _scan()["endpoints_discovered"],
            [],
            target_url="http://localhost:3101",
            forms_discovered=1,
            forms_testing=_scan()["forms_testing"],
            scan_results=_scan(),
        )
        assert "Forms discovered: 1" in text
        assert "tested: 1" in text
        assert "no injection/CSRF findings" in text

    def test_openapi_enumerated_listed(self):
        eps = _scan()["endpoints_discovered"] + [
            {
                "url": "http://localhost:3101/api/v1/workspaces",
                "method": "GET",
                "status": None,
                "source": "swagger",
                "interesting": True,
                "openapi_spec": "http://localhost:3101/api/openapi.json",
            }
        ]
        text = _build_section_2(
            {"technologies": [{"name": "Express", "category": "Framework", "confidence": 0.9}]},
            eps,
            [],
            forms_discovered=0,
            scan_results=_scan(),
        )
        assert "OpenAPI-enumerated endpoints" in text
        assert "/api/v1/workspaces" in text


class TestAiNegativeSection:
    def test_negative_ai_note_has_denominator(self):
        text = _build_section_8_ai_negative(_scan())
        assert "8. AI/ML BACKDOOR VULNERABILITY ANALYSIS" in text
        assert "No AI/ML attack surface" in text
        assert "Coverage:" in text
        # Full §8 builder still returns empty when not is_ai_powered
        assert _build_section_8_ai_backdoor(_scan()) == ""

    def test_brand_only_top_level_still_gets_negative_note(self):
        """is_ai_powered True from brand-only must not blank §8."""
        sr = _scan(
            is_ai_powered=True,
            ai_brand_only=True,
            has_live_surface=False,
            ai_fingerprint={
                "is_ai_powered": False,
                "ai_brand_only": True,
                "has_live_surface": False,
            },
        )
        full = _build_section_8_ai_backdoor(sr)
        assert full == ""
        neg = _build_section_8_ai_negative(sr)
        assert "not applicable" in neg.lower() or "branding" in neg.lower()


class TestAppIdentityNotStack:
    def test_express_is_infra(self):
        assert _is_infra_or_framework_name("Express") is True
        assert _looks_like_app_name("Express") is False
        assert _from_powered_by("", {"x-powered-by": "Express"}) == (None, None, "")

    def test_anythingllm_is_product(self):
        assert _looks_like_app_name("AnythingLLM") is True
        assert _is_infra_or_framework_name("AnythingLLM") is False

    def test_page_title_prefers_brand_over_slogan(self):
        html = (
            "<title>AnythingLLM | Your personal LLM trained on anything</title>"
        )
        name, version, evidence = _from_page_title(html)
        assert name == "AnythingLLM"
        assert "page title" in evidence
        assert _looks_like_app_name(
            "Your personal LLM trained on anything"
        ) is False

    def test_section2_rejects_express_identity(self):
        text = _build_section_2(
            {
                "technologies": [
                    {"name": "Node", "category": "Language", "confidence": 0.95},
                    {"name": "Express", "category": "Framework", "confidence": 0.95},
                ],
                "app_identity_name": "Express",
            },
            [],
            [],
            target_url="http://localhost:3101",
            scan_results=_scan(forms_discovered=0),
        )
        assert "App identity: not determined" in text
        assert "App identity: Express" not in text

    def test_docs_ui_without_spec_is_stated(self):
        text = _build_section_2(
            {"technologies": [{"name": "Express", "category": "Framework", "confidence": 0.9}]},
            [
                {
                    "url": "http://localhost:3101/api/docs",
                    "method": "GET",
                    "status": 200,
                    "source": "probe",
                    "interesting": True,
                }
            ],
            [],
            scan_results=_scan(),
        )
        assert "OpenAPI/Swagger: docs UI found" in text
        assert "no machine-readable" in text


class TestClickjackingFixDialect:
    def test_express_csp_alt_is_javascript(self):
        agent = ActionAgent()
        out = agent._action_clickjacking(
            "http://localhost:3101",
            ["express"],
            evidence={
                "confirmation_method": "header",
                "response_headers": {
                    "X-Frame-Options": "(missing)",
                    "Content-Security-Policy": "(missing)",
                },
            },
        )
        snip = out["fix_snippet"]
        assert "helmet.frameguard" in snip
        assert "frameAncestors" in snip or "frame-ancestors" in snip
        # Must not splice a raw HTTP header into the JS fence
        assert "\nContent-Security-Policy: frame-ancestors" not in snip
        assert "# OR use CSP" not in snip


class TestOpenApiHelpers:
    def test_extract_refs_from_swagger_ui_html(self):
        html = '''
        <html><script>
        SwaggerUIBundle({ url: "/api/openapi.json", dom_id: "#swagger" })
        </script></html>
        '''
        refs = EndpointDiscoveryAgent._extract_openapi_refs_from_html(
            html, "http://localhost:3101"
        )
        assert "/api/openapi.json" in refs

    def test_spa_shell_never_matches_json(self):
        disco = EndpointDiscoveryAgent()
        disco._soft_mode = True
        disco._soft404_bodies = ["<!doctype html><html><body><div id='app'></div></body></html>"]
        assert disco._matches_spa_shell('{"openapi":"3.0.0","paths":{}}', "application/json") is False


if __name__ == "__main__":
    fails = 0
    for cls in [
        TestSection4Denominator,
        TestSection2IdentityAndForms,
        TestAiNegativeSection,
        TestAppIdentityNotStack,
        TestClickjackingFixDialect,
        TestOpenApiHelpers,
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
