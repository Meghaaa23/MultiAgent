"""Discovery-first evidence helpers — no signature packs or bootstrap catalogs."""
from multiagent.agents.ai_agents.ai_evidence_scoring import Detection, score_evidence
from multiagent.agents.ai_agents.ai_fingerprint import (
    AIFingerprintAgent,
    _body_from_openapi,
    _probe_post_body,
)


def test_no_signature_loader_module():
    import importlib.util
    spec = importlib.util.find_spec("multiagent.agents.ai_agents.signature_loader")
    assert spec is None


def test_extract_spec_refs_from_app_surface_only():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    refs = agent._extract_spec_refs(
        'fetch("/openapi.json"); const docs = "/swagger.yaml";'
    )
    assert "/openapi.json" in refs
    assert "/swagger.yaml" in refs
    # Must not invent catalog paths that were never referenced.
    assert agent._extract_spec_refs("<html></html>") == []


def test_extract_graphql_refs_from_app_surface_only():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    refs = agent._extract_graphql_refs('axios.post("/api/graphql", body)')
    assert "/api/graphql" in refs
    assert agent._extract_graphql_refs("no api map here") == []


def test_js_path_extraction_finds_app_routes():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    paths = agent._extract_api_paths_from_js(
        'fetch("/api/chat"); axios.get("/internal/llm/query"); '
        'const x = "/assets/app.js";'
    )
    assert "/api/chat" in paths
    assert "/internal/llm/query" in paths
    assert "/assets/app.js" not in paths


def test_js_path_extraction_template_literal_base_url():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    paths = agent._extract_api_paths_from_js(
        'export const getMessages = (id) => '
        'request.get(`${BASE_URL}/api/messages/${id}`);'
    )
    assert "/api/messages" in paths
    assert "/assets/app.js" not in paths


def test_openapi_derived_probe_body():
    schema = {
        "paths": {
            "/api/ask": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "properties": {
                                        "question": {"type": "string"},
                                        "stream": {"type": "boolean"},
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    body = _body_from_openapi("/api/ask", schema)
    assert body is not None
    import json
    parsed = json.loads(body)
    assert parsed["question"] == "Hi"
    assert parsed["stream"] is False


def test_generic_probe_fallback_without_schema():
    body = _probe_post_body("/api/chat", "chat", None)
    assert b"messages" in body


def test_unknown_openai_surface_confirmed_without_product_name():
    result = score_evidence(["chat_endpoint_200", "error_openai_format"])
    assert result.detection == Detection.CONFIRMED
    assert result.is_ai is True


def test_brand_only_does_not_escalate():
    result = score_evidence(["html_brand_signal", "page_title_ai", "framework_header"])
    assert result.detection == Detection.POSSIBLE
    assert result.is_ai is False
    assert result.brand_only is True
