"""SPA catch-all + header false-positive cleanup (LibreChat-style reports)."""
import sys
import os
import asyncio

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "multiagent"))

from multiagent.agents.webappscanner.endpoint_discovery_agent import (
    looks_like_spa_shell,
    has_strong_admin_content,
    _is_api_surface_path,
)
from multiagent.agents.webappscanner.vulnerability_tester import (
    VulnerabilityTester,
    _hsts_applicable,
    _should_report_missing_header,
    DEPRECATED_SECURITY_HEADERS,
)
from multiagent.agents.webappscanner.action_agent import ActionAgent
from multiagent.agents.webappscanner.web_scanner_agent import (
    _build_evidence_gated_stride,
)
from multiagent.agents.threat_modeling_agent import _build_section_2


SPA_SHELL = (
    '<!DOCTYPE html><html><head><title>LibreChat</title></head>'
    '<body><div id="root"></div><script src="/assets/index.js"></script>'
    '<nav>admin dashboard manage</nav></body></html>'
)


class TestSpaShellDetection:
    def test_spa_shell_detection(self):
        assert looks_like_spa_shell(SPA_SHELL) is True
        assert looks_like_spa_shell("plain text admin") is False

    def test_admin_requires_strong_markers(self):
        assert has_strong_admin_content("Welcome to the admin panel") is True
        assert has_strong_admin_content("<html>nav: admin</html>") is False
        assert has_strong_admin_content("management console login") is True


class TestHstsAndDeprecatedHeaders:
    def test_hsts_skipped_on_http_localhost(self):
        assert _hsts_applicable("http://localhost:3080") is False
        assert _hsts_applicable("https://localhost:3080") is False
        assert _hsts_applicable("https://app.example.com") is True
        assert _should_report_missing_header(
            "Strict-Transport-Security", "http://localhost:3080"
        ) is False
        assert _should_report_missing_header(
            "X-XSS-Protection", "https://app.example.com"
        ) is False
        assert _should_report_missing_header(
            "Content-Security-Policy", "http://localhost:3080"
        ) is True
        assert "X-XSS-Protection" in DEPRECATED_SECURITY_HEADERS


class TestGraphqlPathHelper:
    def test_graphql_is_api_surface(self):
        assert _is_api_surface_path("/graphql") is True
        assert _is_api_surface_path("http://localhost:3080/graphql") is True
        assert _is_api_surface_path("/api/user") is True
        assert _is_api_surface_path("/admin") is False


class TestCorsWildcardPotential:
    def test_wildcard_is_potential_low_not_confirmed(self):
        vt = VulnerabilityTester(timeout=2)

        def fake_headers(url, extra=None):
            return {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "false",
            }

        vt._sync_headers = fake_headers  # type: ignore
        findings = asyncio.run(vt.test_cors("http://localhost:3080"))
        assert findings
        assert findings[0]["severity"] == "Low"
        assert findings[0]["status"] == "Potential"


class TestCorsStrideNoSeverityFallback:
    def test_wildcard_omitted(self):
        threats = _build_evidence_gated_stride(
            "http://x", {}, set(), [], "wildcard", {},
        )
        assert not any(t.get("threat") == "CORS Misconfiguration" for t in threats)


class TestEvidencePocs:
    def test_clickjacking_uses_response_headers(self):
        agent = ActionAgent()
        out = agent._action_clickjacking(
            "http://localhost:3080",
            ["express"],
            evidence={
                "confirmation_method": "header",
                "response_headers": {
                    "X-Frame-Options": "(missing)",
                    "Content-Security-Policy": "(missing)",
                },
            },
        )
        assert out["evidence_captured"] is True
        assert "NO EVIDENCE CAPTURED" not in out["attack_poc"]
        assert "no X-Frame-Options" in out["attack_poc"]

    def test_cors_uses_response_headers(self):
        agent = ActionAgent()
        out = agent._action_cors(
            "http://localhost:3080",
            ["express"],
            evidence={
                "request": "GET http://localhost:3080 (Origin: https://evil-cors-test.example.com)",
                "response_headers": {
                    "Access-Control-Allow-Origin": "https://evil-cors-test.example.com",
                },
                "reflected_origin": "https://evil-cors-test.example.com",
                "access_control_allow_origin": "https://evil-cors-test.example.com",
            },
        )
        assert out["evidence_captured"] is True
        assert "NO EVIDENCE CAPTURED" not in out["attack_poc"]


class TestSection2SpaExclusion:
    def test_spa_admin_not_in_administrative(self):
        text = _build_section_2(
            {"unverified_hints": ["LibreChat"]},
            [
                {
                    "url": "http://localhost:3080/api/user",
                    "method": "GET",
                    "status": 401,
                    "source": "probe",
                    "interesting": True,
                    "auth_required": True,
                },
                {
                    "url": "http://localhost:3080/admin",
                    "method": "GET",
                    "status": 200,
                    "source": "probe",
                    "interesting": False,
                    "spa_catch_all": True,
                    "excluded": True,
                    "exclude_reason": "SPA catch-all — not a real admin endpoint",
                },
                {
                    "url": "http://localhost:3080/dashboard",
                    "method": "GET",
                    "status": 200,
                    "source": "probe",
                    "interesting": True,
                    "admin_panel": True,
                    "verification": "SPA/soft-404 shell — not a real endpoint",
                },
            ],
            [],
            target_url="http://localhost:3080",
        )
        assert "Administrative Endpoints" not in text
        assert "Excluded endpoints" in text
        assert "/admin" in text
        assert "/api/user" in text


if __name__ == "__main__":
    fails = 0
    for cls in [
        TestSpaShellDetection,
        TestHstsAndDeprecatedHeaders,
        TestGraphqlPathHelper,
        TestCorsWildcardPotential,
        TestCorsStrideNoSeverityFallback,
        TestEvidencePocs,
        TestSection2SpaExclusion,
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
