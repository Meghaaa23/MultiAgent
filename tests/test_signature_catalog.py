"""Discovery-first detection — no endpoint path catalogs."""
from multiagent.agents.ai_agents.ai_evidence_scoring import Detection, score_evidence
from multiagent.agents.ai_agents.ai_fingerprint import (
    AIFingerprintAgent,
    GRAPHQL_BOOTSTRAP_PATHS,
    PROTOCOL_SIGNATURES,
    SPEC_BOOTSTRAP_PATHS,
)
from multiagent.agents.ai_agents.signature_loader import load_signature_catalog


def test_catalog_body_patterns_only_for_protocol_labels():
    cat = load_signature_catalog()
    assert len(cat.universal) >= 4
    assert "OpenAI-compatible" in PROTOCOL_SIGNATURES


def test_no_product_brand_labels():
    labels = set(PROTOCOL_SIGNATURES)
    for banned in (
        "Open WebUI", "LibreChat", "Flowise", "Langflow",
        "Gradio", "Ollama", "Dify", "AnythingLLM",
    ):
        assert banned not in labels


def test_spec_bootstrap_is_meta_only():
    """Bootstrap finds API maps — not AI chat endpoints."""
    assert "/openapi.json" in SPEC_BOOTSTRAP_PATHS
    assert "/v1/chat/completions" not in SPEC_BOOTSTRAP_PATHS
    assert "/api/chat" not in SPEC_BOOTSTRAP_PATHS
    assert "/graphql" in GRAPHQL_BOOTSTRAP_PATHS


def test_js_path_extraction_finds_app_routes():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    paths = agent._extract_api_paths_from_js(
        'fetch("/api/chat"); axios.get("/internal/llm/query"); '
        'const x = "/assets/app.js";'
    )
    assert "/api/chat" in paths
    assert "/internal/llm/query" in paths
    assert "/assets/app.js" not in paths


def test_normalize_candidates_dedupes_and_caps():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    out = agent._normalize_candidate_paths([
        "/api/chat", "http://x/api/chat", "/api/chat?x=1",
        "/v1/chat/completions", "/logo.png",
    ])
    assert out.count("/api/chat") == 1
    assert "/logo.png" not in out
    assert "/v1/chat/completions" in out


def test_unknown_openai_surface_confirmed_without_product_name():
    result = score_evidence(["chat_endpoint_200", "error_openai_format"])
    assert result.detection == Detection.CONFIRMED
    assert result.is_ai is True
    assert result.has_live_surface is True


def test_brand_only_does_not_escalate():
    result = score_evidence([
        "html_brand_signal",
        "page_title_ai",
        "framework_header",
    ])
    assert result.detection == Detection.POSSIBLE
    assert result.is_ai is False
    assert result.has_live_surface is False
    assert result.brand_only is True
