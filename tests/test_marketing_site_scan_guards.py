"""
Regression tests for marketing-site / SPA scan blowups
(openwebui.com: 2111 interesting endpoints, invented /api/agents/*).
"""
from multiagent.agents.ai_agents.ai_fingerprint import expand_semantic_candidates
from multiagent.agents.ai_agents.ai_vulnerability_test import AIVulnerabilityTester
from multiagent.agents.webappscanner.endpoint_discovery_agent import EndpointDiscoveryAgent


def test_expand_semantic_ignores_marketing_agents_path():
    # /o/agents on openwebui.com must NOT invent /api/agents/ask
    out = expand_semantic_candidates(["/o/agents", "/u/dannyl1b", "/c/prompts"])
    assert not any(p.startswith("/api/agents/") for p in out)
    assert "/api/agents/ask" not in out


def test_expand_semantic_from_api_agents_path():
    out = expand_semantic_candidates(["/api/agents", "/api/v1/agents/list"])
    assert any(p.startswith("/api/agents/") for p in out)
    # Real app path /assistant still expands.
    out2 = expand_semantic_candidates(["/assistant"])
    assert "/assistant/query" in out2


def test_build_endpoint_list_skips_unverified_discovered_paths():
    tester = AIVulnerabilityTester(timeout=2, max_requests=10)
    fp = {
        "framework": "Open WebUI",
        "ml_endpoints": [],
        "discovered_paths": [
            "/api/agents/ask",
            "/api/agents/chat",
            "/api/chat/completions",
            "/o/ask",
        ],
        "spa_catch_all": True,  # marketing SPA — no active spray
        "chat_components": [],
    }
    eps = tester._build_endpoint_list([], [], "https://openwebui.com/", fp)
    assert eps == []
    # Without spa_catch_all, framework fallback is OK but not invented agents paths.
    fp2 = dict(fp)
    fp2["spa_catch_all"] = False
    eps2 = tester._build_endpoint_list([], [], "https://openwebui.com/", fp2)
    assert eps2  # Open WebUI framework fallbacks
    assert not any("/api/agents/" in e for e in eps2)


def test_build_endpoint_list_uses_verified_ml_endpoints():
    tester = AIVulnerabilityTester(timeout=2, max_requests=10)
    fp = {
        "framework": "Open WebUI",
        "ml_endpoints": ["https://localhost:3001/api/chat/completions"],
        "discovered_paths": ["/api/agents/ask"],
    }
    eps = tester._build_endpoint_list(
        ["https://localhost:3001/api/chat/completions"],
        [],
        "https://localhost:3001/",
        fp,
    )
    assert eps == ["https://localhost:3001/api/chat/completions"]


def test_verify_unprobed_passive_not_interesting():
    agent = EndpointDiscoveryAgent(timeout=2)
    ep = {
        "url": "https://openwebui.com/o/agents",
        "source": "sitemap",
        "status": None,
        "interesting": True,
    }
    out = __import__("asyncio").run(agent._verify_endpoint(ep))
    assert out["interesting"] is False


def test_strategic_recs_for_framework_only():
    fp = {
        "framework": "Open WebUI",
        "is_ai_powered": True,
        "ml_endpoints": [],
        "auth_required_paths": [],
        "atlas_techniques": ["AML.T0051 - LLM Prompt Injection"],
    }
    recs = AIVulnerabilityTester._build_strategic_recommendations(fp, [], [])
    assert any(r["atlas_id"] == "AML.T0051" for r in recs)
