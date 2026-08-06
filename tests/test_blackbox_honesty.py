"""
Black-box unauth honesty: auth-wall coverage, static-asset filtering,
auth-redirect status rendering, .mvc fingerprint, STRIDE↔Section 3 clickjacking.

Run:
  PYTHONPATH=/workspace:/workspace/multiagent python3 tests/test_blackbox_honesty.py
"""
import sys
import os

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "multiagent"))

from multiagent.agents.webappscanner.endpoint_discovery_agent import (
    is_static_asset,
)
from multiagent.agents.webappscanner.fingerprint_agent import _rule_detect
from multiagent.agents.threat_modeling_agent import (
    _build_section_1,
    _build_section_2,
    _build_section_5,
    _coverage_from_scan,
)
from multiagent.agents.webappscanner.web_scanner_agent import (
    _build_evidence_gated_stride,
)


class TestStaticAssetFilter:
    def test_css_extension(self):
        assert is_static_asset(
            "http://localhost:3143/WebGoat/plugin/Bootstrap/css/bootstrap.min.css"
        )

    def test_font_awesome_css(self):
        assert is_static_asset(
            "/WebGoat/plugins/font-awesome/css/font-awesome.min.css"
        )

    def test_content_type_css(self):
        assert is_static_asset("/unknown", "text/css; charset=utf-8")

    def test_mvc_not_static(self):
        assert not is_static_asset("http://localhost:3143/WebGoat/start.mvc")

    def test_login_not_static(self):
        assert not is_static_asset("/login", "text/html")


class TestAdminClassifierIgnoresStaticPlugins:
    def test_bootstrap_under_plugins_not_admin(self):
        text = _build_section_2(
            {"technologies": []},
            [{
                "url": "http://x/WebGoat/plugin/Bootstrap/css/bootstrap.min.css",
                "method": "GET",
                "status": 200,
                "interesting": True,
                "admin_panel": True,  # bad label from body heuristic
                "content_type": "text/css",
                "source": "probe",
            }],
            [],
            target_url="http://x/WebGoat/",
        )
        assert "Administrative Endpoints" not in text
        assert "bootstrap.min.css" not in text


class TestAuthRedirectStatusHonesty:
    def test_no_landing_200_beside_redirects_to_auth(self):
        text = _build_section_2(
            {"technologies": []},
            [{
                "url": "http://x/WebGoat/start.mvc",
                "method": "GET",
                "status": 200,
                "interesting": True,
                "redirects_to_auth": True,
                "final_url": "http://x/WebGoat/login.mvc",
                "source": "probe",
            }],
            [],
            target_url="http://x/WebGoat/",
        )
        assert "[REDIR→AUTH]" in text
        assert "[200]" not in text
        assert "REDIRECTS TO AUTH" in text


class TestAuthWallCoverageDisclosure:
    def test_dominated_surface_qualifies_risk(self):
        scan = {
            "scan_duration": 120,
            "not_assessed_endpoints": [
                {"url": "http://x/a", "reason": "auth_required"},
                {"url": "http://x/b", "reason": "auth_required"},
                {"url": "http://x/c", "reason": "auth_required"},
            ],
            "endpoints_discovered": [
                {"url": "http://x/login", "interesting": True, "status": 200},
                {"url": "http://x/a", "redirects_to_auth": True,
                 "category": "discovered_protected"},
                {"url": "http://x/b", "redirects_to_auth": True,
                 "category": "discovered_protected"},
                {"url": "http://x/c", "redirects_to_auth": True,
                 "category": "discovered_protected"},
            ],
        }
        cov = _coverage_from_scan(scan)
        assert cov["auth_wall_dominated"] is True
        assert cov["auth_gated_count"] == 3

        summary = _build_section_1(
            confirmed_vulns=[{
                "type": "Missing Security Header: X-Content-Type-Options",
                "severity": "Low",
                "remediation": "Add XCTO",
                "evidence": {"confirmation_method": "header"},
            }],
            potential_vulns=[],
            target_url="http://x/WebGoat/",
            scan_results=scan,
        )
        assert "pre-authentication" in summary.lower()
        assert "auth-gated and not tested" in summary.lower()
        assert "3 functional" in summary
        # Must not present as unqualified app-wide risk
        assert "Overall risk level: Low-Medium" not in summary
        assert "assessed pre-authentication surface" in summary.lower()

    def test_no_auth_gate_keeps_plain_risk(self):
        summary = _build_section_1(
            confirmed_vulns=[],
            potential_vulns=[],
            target_url="http://x/",
            scan_results={
                "scan_duration": 10,
                "not_assessed_endpoints": [],
                "endpoints_discovered": [
                    {"url": "http://x/", "interesting": True},
                ],
            },
        )
        assert "Overall risk level: Low" in summary
        assert "auth-gated" not in summary.lower()


class TestMvcFingerprint:
    def test_mvc_promotes_spring_java_tomcat(self):
        hits = _rule_detect(
            {},
            [],
            url="http://localhost:3143/WebGoat/start.mvc",
        )
        names = {h["name"] for h in hits}
        assert "Spring" in names
        assert "Java" in names
        assert "Tomcat" in names
        for h in hits:
            if h["name"] in ("Spring", "Java", "Tomcat"):
                assert h["confidence"] >= 0.50
                assert h["confidence"] <= 0.60


class TestStrideClickjackingCorroboration:
    def test_stride_cites_section3_finding(self):
        threats = _build_evidence_gated_stride(
            "http://x", {}, set(), [], None, {},
        )
        cj = [t for t in threats if t.get("threat") == "Clickjacking"]
        assert cj
        assert "Missing Clickjacking Protection" in cj[0]["evidence"]

        section5 = _build_section_5(
            cj,
            confirmed_vulns=[{
                "type": "Missing Clickjacking Protection",
                "status": "Confirmed",
            }],
        )
        assert "See Section 3: Missing Clickjacking Protection" in section5


if __name__ == "__main__":
    fails = 0
    for cls in [
        TestStaticAssetFilter,
        TestAdminClassifierIgnoresStaticPlugins,
        TestAuthRedirectStatusHonesty,
        TestAuthWallCoverageDisclosure,
        TestMvcFingerprint,
        TestStrideClickjackingCorroboration,
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
