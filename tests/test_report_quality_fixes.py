"""
Report-quality fixes: SPA endpoint filtering, HSTS/XSS header noise,
evidence key normalization, AI framework in stack, ATLAS strategic recs.
"""
import asyncio

from multiagent.agents.webappscanner.endpoint_discovery_agent import (
    EndpointDiscoveryAgent,
    _looks_html_body,
)
from multiagent.agents.webappscanner.vulnerability_tester import (
    VulnerabilityTester,
    SECURITY_HEADERS,
)
from multiagent.agents.webappscanner.attack_verification_agent import (
    AttackVerificationAgent,
    SECURITY_HEADERS as AV_SECURITY_HEADERS,
)
from multiagent.agents.webappscanner.action_agent import ActionAgent
from multiagent.agents.ai_agents.ai_vulnerability_test import AIVulnerabilityTester


def test_looks_html_body_endpoint_discovery():
    assert _looks_html_body("text/html", "<html></html>")
    assert _looks_html_body("", "<!DOCTYPE html><html>")
    assert not _looks_html_body("application/json", '{"ok":true}')


def test_security_headers_drop_xss_protection():
    assert "X-XSS-Protection" not in SECURITY_HEADERS
    assert "X-XSS-Protection" not in AV_SECURITY_HEADERS
    assert "Strict-Transport-Security" in SECURITY_HEADERS


def test_hsts_skipped_on_localhost_http():
    async def _run():
        vt = VulnerabilityTester(timeout=2)
        findings = await vt.test_security_headers(
            "http://localhost:3001/",
            shared_headers={
                "server": "uvicorn",
                "content-type": "text/html",
            },
        )
        types = [f["type"] for f in findings]
        assert not any("Strict-Transport-Security" in t for t in types)
        assert not any("X-XSS-Protection" in t for t in types)
        assert any("Content-Security-Policy" in t for t in types)
        return findings

    asyncio.run(_run())


def test_hsts_flagged_on_https_remote():
    async def _run():
        vt = VulnerabilityTester(timeout=2)
        findings = await vt.test_security_headers(
            "https://example.com/",
            shared_headers={"content-type": "text/html"},
        )
        assert any("Strict-Transport-Security" in f["type"] for f in findings)

    asyncio.run(_run())


def test_av_header_check_case_insensitive_and_skip_hsts():
    async def _run():
        av = AttackVerificationAgent(openai_client=None, llm_model="x", timeout=2)
        findings = await av._check_security_headers(
            "http://127.0.0.1:8080/",
            shared_headers={
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'self'",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "geolocation=()",
            },
        )
        # All required non-HSTS headers present (mixed case) → no missing-header findings
        missing = [f for f in findings if "Missing Security Header" in f.vuln_type]
        assert missing == []

    asyncio.run(_run())


def test_action_evidence_normalizes_vt_keys():
    agent = ActionAgent()
    block = agent._evidence_block(
        {
            "request": "GET http://x/",
            "response_status": 200,
            "response_body_snippet": "<html>ok</html>",
            "response_headers": {"Server": "uvicorn"},
        },
        "fallback",
    )
    assert "NO EVIDENCE CAPTURED" not in block
    assert "GET http://x/" in block
    assert "200" in block


def test_action_cors_uses_response_headers():
    agent = ActionAgent()
    action = agent._action_cors(
        "http://localhost:3001/",
        ["uvicorn"],
        evidence={
            "request": "GET http://localhost:3001/ (Origin: https://evil-cors-test.example.com)",
            "response_status": 200,
            "response_headers": {
                "Access-Control-Allow-Origin": "*",
            },
        },
    )
    assert action["evidence_captured"] is True
    assert "NO EVIDENCE CAPTURED" not in action["attack_poc"]
    assert "Access-Control-Allow-Origin: *" in action["attack_poc"]


def test_strategic_recommendations_for_auth_gated():
    fp = {
        "framework": "Open WebUI",
        "is_ai_powered": True,
        "auth_required_paths": [
            {"endpoint": "http://localhost:3001/api/chat", "status_code": 401},
        ],
        "ml_endpoints": [],
        "chat_components": True,
    }
    potential = [{
        "type": "Potential Prompt Injection (auth-gated)",
        "location": "http://localhost:3001/api/chat",
        "evidence": {"outcome": "auth_required"},
    }]
    recs = AIVulnerabilityTester._build_strategic_recommendations(fp, [], potential)
    assert recs
    assert any(r["atlas_id"] == "AML.T0051" for r in recs)


def test_section_4_dedupes_by_type_and_location():
    # Mirror threat_modeling_agent._build_section_4 keying without importing
    # the heavy ThreatModelingAgent module (openai + mongo deps).
    vulns = [
        {"type": "Potential Prompt Injection (auth-gated)", "location": "http://a/api/chat",
         "severity": "Medium", "details": "a", "evidence": {}},
        {"type": "Potential Prompt Injection (auth-gated)", "location": "http://a/api/v1/chat",
         "severity": "Medium", "details": "b", "evidence": {}},
        {"type": "Potential Prompt Injection (auth-gated)", "location": "http://a/api/chat",
         "severity": "Medium", "details": "dup", "evidence": {}},
    ]
    seen = set()
    kept = []
    for v in vulns:
        key = (v.get("type", ""), v.get("location", ""))
        if key in seen:
            continue
        seen.add(key)
        kept.append(v)
    assert len(kept) == 2
    assert kept[0]["location"] == "http://a/api/chat"
    assert kept[1]["location"] == "http://a/api/v1/chat"


def test_probe_path_drops_html_api_shell():
    async def _run():
        agent = EndpointDiscoveryAgent(timeout=2)

        def fake_head(url):
            return 200, {"Content-Type": "text/html"}, url

        agent._sync_head = fake_head  # type: ignore
        result = await agent._probe_path("http://spa.local", "/api")
        assert result is None
        result_admin = await agent._probe_path("http://spa.local", "/admin")
        assert result_admin is None

    asyncio.run(_run())
