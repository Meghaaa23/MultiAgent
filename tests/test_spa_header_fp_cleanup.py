# tests/test_spa_header_fp_cleanup.py
"""SPA catch-all + header false-positive cleanup."""
from multiagent.agents.webappscanner.endpoint_discovery_agent import (
    looks_like_spa_shell,
    has_strong_admin_content,
)
from multiagent.agents.webappscanner.vulnerability_tester import (
    _hsts_applicable,
    _should_report_missing_header,
)
from multiagent.agents.webappscanner.action_agent import ActionAgent


def test_spa_shell_detection():
    spa = "<!DOCTYPE html><html><div id=\"root\"></div><script src=\"/app.js\"></script>"
    assert looks_like_spa_shell(spa) is True
    assert looks_like_spa_shell("plain text admin") is False


def test_admin_requires_strong_markers():
    assert has_strong_admin_content("Welcome to the admin panel") is True
    assert has_strong_admin_content("<html>admin dashboard link</html>") is False
    assert has_strong_admin_content("management console login") is True


def test_hsts_skipped_on_http_localhost():
    assert _hsts_applicable("http://localhost:3080") is False
    assert _hsts_applicable("https://localhost:3080") is False
    assert _hsts_applicable("https://app.example.com") is True
    assert _should_report_missing_header("Strict-Transport-Security", "http://localhost:3080") is False
    assert _should_report_missing_header("X-XSS-Protection", "https://app.example.com") is False
    assert _should_report_missing_header("Content-Security-Policy", "http://localhost:3080") is True


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
