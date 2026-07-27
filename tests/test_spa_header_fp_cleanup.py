# tests/test_spa_header_fp_cleanup.py
"""SPA catch-all + header false-positive cleanup."""
from multiagent.agents.webappscanner.endpoint_discovery_agent import (
    looks_like_spa_shell,
    has_strong_admin_content,
    _is_api_surface_path,
)
from multiagent.agents.webappscanner.vulnerability_tester import (
    _hsts_applicable,
    _should_report_missing_header,
    DEPRECATED_SECURITY_HEADERS,
)
from multiagent.agents.webappscanner.action_agent import ActionAgent
from multiagent.agents.threat_modeling_agent import _build_section_2, _build_section_5


def test_spa_shell_detection():
    spa = "<!DOCTYPE html><html><div id=\"root\"></div><script src=\"/app.js\"></script>"
    assert looks_like_spa_shell(spa) is True
    assert looks_like_spa_shell("plain text admin") is False


def test_admin_requires_strong_markers():
    assert has_strong_admin_content("Welcome to the admin panel") is True
    assert has_strong_admin_content("<html>nav: admin</html>") is False
    assert has_strong_admin_content("management console login") is True


def test_hsts_skipped_on_http_localhost():
    assert _hsts_applicable("http://localhost:3080") is False
    assert _hsts_applicable("https://localhost:3080") is False
    assert _hsts_applicable("https://app.example.com") is True
    assert _should_report_missing_header("Strict-Transport-Security", "http://localhost:3080") is False
    assert _should_report_missing_header("X-XSS-Protection", "https://app.example.com") is False
    assert _should_report_missing_header("Content-Security-Policy", "http://localhost:3080") is True
    assert "X-XSS-Protection" in DEPRECATED_SECURITY_HEADERS


def test_graphql_not_treated_as_spa_admin_path():
    assert _is_api_surface_path("/graphql") is True
    assert _is_api_surface_path("http://localhost:3080/graphql") is True
    assert _is_api_surface_path("/api/user") is True
    assert _is_api_surface_path("/admin") is False


def test_cors_action_uses_response_headers_evidence():
    agent = ActionAgent.__new__(ActionAgent)
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
    assert "evil-cors-test.example.com" in out["attack_poc"]


def test_clickjacking_action_uses_response_headers_evidence():
    agent = ActionAgent.__new__(ActionAgent)
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


def test_stride_section_matches_potential_cors():
    """§5 must not say Evidence-confirmed when CORS is Potential."""
    threats = [{
        "category": "Information Disclosure",
        "threat": "CORS Misconfiguration",
        "evidence": "ACAO: * — unconfirmed / manual verification required",
        "likelihood": "Low",
        "impact": "Low",
        "mitigation": "Restrict ACAO to trusted origins; remove wildcard",
        "confirmed": False,
    }]
    section = _build_section_5(threats)
    assert "Evidence-based (potential)" in section
    cors_block = section.split("CORS Misconfiguration")[1].split("\n\n")[0]
    assert "Evidence-confirmed" not in cors_block
    assert "Low" in cors_block


def test_excluded_spa_endpoints_visible_in_section_2():
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
        ],
        [],
    )
    assert "Functional Endpoints" in text
    assert "/api/user" in text
    assert "Excluded endpoints" in text
    assert "/admin" in text
    assert "SPA catch-all" in text
    assert "Administrative Endpoints" not in text


def test_stride_builder_aligns_cors_with_finding():
    # Import lazily — avoid sqlalchemy if pipeline import fails in some envs.
    from multiagent.agents.webappscanner import web_scanner_agent as wsa
    threats = wsa._build_evidence_gated_stride(
        "http://localhost:3080",
        {},
        [],
        [],
        cors_misconfigured=False,
        stack={},
        cors_finding={
            "type": "CORS Misconfiguration",
            "status": "Potential",
            "details": "ACAO: *",
        },
    )
    cors = next(t for t in threats if t["threat"] == "CORS Misconfiguration")
    assert cors["confirmed"] is False
    assert cors["likelihood"] == "Low"
