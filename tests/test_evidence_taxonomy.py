from multiagent.agents.ai_agents.ai_evidence_scoring import (
    Detection,
    EvidenceClass,
    classify_evidence,
    evidence_weight,
    group_evidence,
    has_behavioral_evidence,
    has_brand_only_evidence,
    has_live_surface_evidence,
    score_evidence,
)
from multiagent.agents.ai_agents.ai_fingerprint import (
    AIFingerprintAgent,
    EvidenceItem,
    _looks_ai_api_json,
)
from multiagent.agents.ai_agents.ai_vulnerability_test import AIVulnerabilityTester


# Classification

def test_behavior_is_behavioral():
    assert classify_evidence("behavior_llm_response") == EvidenceClass.BEHAVIORAL
    assert classify_evidence("behavior_nondeterministic") == EvidenceClass.BEHAVIORAL
    assert evidence_weight("behavior_llm_response") == 4


def test_endpoint_and_error_are_live_surface():
    assert classify_evidence("chat_endpoint_200") == EvidenceClass.LIVE_SURFACE
    assert classify_evidence("ml_endpoint_401_403") == EvidenceClass.LIVE_SURFACE
    assert classify_evidence("openapi_ai_endpoint") == EvidenceClass.LIVE_SURFACE
    assert classify_evidence("error_openai_format") == EvidenceClass.LIVE_SURFACE
    assert classify_evidence("ai_response_header") == EvidenceClass.LIVE_SURFACE


def test_passive_and_brand_defaults():
    assert classify_evidence("openapi_schema") == EvidenceClass.PASSIVE
    assert classify_evidence("js_ai_sdk") == EvidenceClass.PASSIVE
    assert classify_evidence("framework_cookie") == EvidenceClass.PASSIVE
    assert classify_evidence("framework_header") == EvidenceClass.BRAND
    assert classify_evidence("page_title_ai") == EvidenceClass.BRAND
    assert classify_evidence("html_brand_signal") == EvidenceClass.BRAND
    assert classify_evidence("unknown_new_detector") == EvidenceClass.BRAND


def test_group_evidence_buckets():
    group = group_evidence([
        "behavior_streaming",
        "chat_endpoint_200",
        "js_ai_sdk",
        "page_title_ai",
        "page_title_ai",
    ])
    assert group.behavioral == ["behavior_streaming"]
    assert group.live_surface == ["chat_endpoint_200"]
    assert group.passive == ["js_ai_sdk"]
    assert group.brand == ["page_title_ai"]


# Detection tiers

def test_confirmed_on_live_surface():
    result = score_evidence(["ml_endpoint_401_403", "page_title_ai"])
    assert result.detection == Detection.CONFIRMED
    assert result.confidence == "high"
    assert result.is_ai is True
    assert result.has_live_surface is True
    assert result.brand_only is False


def test_confirmed_on_behavioral():
    result = score_evidence(["behavior_nondeterministic"])
    assert result.detection == Detection.CONFIRMED
    assert result.has_behavioral is True
    assert result.is_ai is True


def test_probable_needs_two_passive():
    one = score_evidence(["js_ai_sdk"])
    two = score_evidence(["js_ai_sdk", "openapi_schema"])
    assert one.detection == Detection.POSSIBLE
    assert two.detection == Detection.PROBABLE
    assert two.is_ai is False


def test_possible_brand_only():
    result = score_evidence(["html_brand_signal", "page_title_ai"])
    assert result.detection == Detection.POSSIBLE
    assert result.confidence == "low"
    assert result.is_ai is False
    assert result.brand_only is True


def test_not_detected_empty():
    result = score_evidence([])
    assert result.detection == Detection.NOT_DETECTED
    assert result.confidence == "none"
    assert result.is_ai is False


def test_helper_predicates():
    assert has_live_surface_evidence(["page_title_ai", "ml_endpoint_401_403"])
    assert not has_live_surface_evidence(["page_title_ai", "html_brand_signal"])
    assert has_behavioral_evidence(["behavior_llm_response"])
    assert has_brand_only_evidence(["html_brand_signal", "page_title_ai"])
    assert not has_brand_only_evidence(["html_brand_signal", "js_ai_sdk"])


# Evidence item

def test_evidence_item_uses_class_weight():
    item = EvidenceItem.make("framework_identified", "Open WebUI", "html")
    assert item.evidence_class == "brand"
    assert item.weight == 1
    live = EvidenceItem.make("chat_endpoint_200", "chat ok", "probe")
    assert live.evidence_class == "live_surface"
    assert live.weight == 3


# Non-determinism helpers

def test_token_divergence_identical():
    assert AIFingerprintAgent._token_divergence("hello world", "hello world") == 0.0


def test_token_divergence_disjoint():
    assert AIFingerprintAgent._token_divergence("alpha beta", "gamma delta") == 1.0


def test_extract_text_openai_shape():
    body = '{"choices":[{"message":{"content":"The ocean is vast."}}]}'
    assert AIFingerprintAgent._extract_text(body) == "The ocean is vast."


def test_extract_text_ollama_shape():
    body = '{"response":"Blue water everywhere."}'
    assert AIFingerprintAgent._extract_text(body) == "Blue water everywhere."


# OpenAI passthrough acceptance

def test_looks_ai_api_json_openai_shapes():
    assert _looks_ai_api_json('{"choices":[{"message":{"content":"hi"}}]}')
    assert _looks_ai_api_json('{"object":"list","data":[{"id":"gpt"}]}')
    assert _looks_ai_api_json('{"model":"gpt-4","usage":{"total_tokens":1}}')
    assert _looks_ai_api_json('{"error":{"message":"missing messages","type":"invalid_request"}}')
    assert not _looks_ai_api_json("{}")
    assert not _looks_ai_api_json("<html></html>")


def test_evaluate_probe_records_openai_passthrough_200():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    auth = []
    body = '{"id":"chatcmpl-1","object":"chat.completion","choices":[{"message":{"content":"ok"}}]}'
    r = agent._evaluate_probe_response(
        "http://x/v1/chat/completions", "/v1/chat/completions", "chat",
        200, {"Content-Type": "application/json"}, body, auth, spa_catch_all=True,
    )
    assert "http://x/v1/chat/completions" in r["endpoints"]
    assert any(e.key == "chat_endpoint_200" for e in r["evidence"])


def test_evaluate_probe_records_models_list_200():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    auth = []
    body = '{"object":"list","data":[{"id":"gpt-3.5-turbo","object":"model"}]}'
    r = agent._evaluate_probe_response(
        "http://x/v1/models", "/v1/models", "schema",
        200, {"Content-Type": "application/json"}, body, auth, spa_catch_all=True,
    )
    assert "http://x/v1/models" in r["endpoints"]


def test_merge_exposed_endpoints_backstop():
    fp = {
        "is_ai_powered": True,
        "has_live_surface": True,
        "ml_endpoints": ["http://localhost:3080/api/messages"],
        "auth_required_paths": [
            {"endpoint": "http://localhost:3080/api/messages",
             "auth_type": "unknown", "status_code": 401, "detail": "auth"},
        ],
    }
    merged = AIVulnerabilityTester.merge_exposed_endpoints(
        fp, ["http://localhost:3080/v1/chat/completions"])
    assert "http://localhost:3080/v1/chat/completions" in merged["ml_endpoints"]
    assert merged["has_live_surface"] is True


def test_inference_path_200_json_without_ai_keys():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    auth = []
    # Opaque JSON 200 on the OpenAI passthrough (no choices/model/object keys)
    body = '{"status":"ready","detail":"accepted"}'
    r = agent._evaluate_probe_response(
        "http://x/v1/chat/completions", "/v1/chat/completions", "chat",
        200, {"Content-Type": "application/json"}, body, auth, spa_catch_all=True,
    )
    assert "http://x/v1/chat/completions" in r["endpoints"]
    assert any(e.key == "chat_endpoint_200" for e in r["evidence"])


def test_inference_path_ignores_soft_404_json():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    auth = []
    r = agent._evaluate_probe_response(
        "http://x/v1/chat/completions", "/v1/chat/completions", "chat",
        200, {"Content-Type": "application/json"}, "{}", auth, spa_catch_all=True,
    )
    assert r.get("endpoints", []) == []


def test_infra_classify_inference_passthrough():
    from multiagent.agents.ai_agents.Ai_Infra_agent import AIInfraAgent
    agent = AIInfraAgent(timeout=3)
    verdict = agent._classify(
        200, '{"message":"ok"}', "application/json",
        "/v1/chat/completions", True, catch_all=True,
    )
    assert verdict == "exposed"
