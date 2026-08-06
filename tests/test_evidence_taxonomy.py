from multiagent.agents.ai_agents.ai_evidence_scoring import (
    Detection,
    EvidenceClass,
    PROBABLE_MIN_HINT,
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
    assert evidence_weight("behavior_llm_response") == 5


def test_endpoint_and_error_are_live_surface():
    assert classify_evidence("chat_endpoint_200") == EvidenceClass.LIVE_SURFACE
    assert classify_evidence("ml_endpoint_401_403") == EvidenceClass.LIVE_SURFACE
    assert classify_evidence("openapi_ai_endpoint") == EvidenceClass.LIVE_SURFACE
    assert classify_evidence("error_openai_format") == EvidenceClass.LIVE_SURFACE
    assert classify_evidence("ai_response_header") == EvidenceClass.LIVE_SURFACE
    assert evidence_weight("chat_endpoint_200") == 4


def test_passive_structural_vs_hint_and_brand():
    assert classify_evidence("openapi_schema") == EvidenceClass.PASSIVE_STRUCTURAL
    assert classify_evidence("graphql_schema") == EvidenceClass.PASSIVE_STRUCTURAL
    assert classify_evidence("js_ai_sdk") == EvidenceClass.PASSIVE_HINT
    assert classify_evidence("robots_ai_path") == EvidenceClass.PASSIVE_HINT
    assert classify_evidence("sitemap_ai_path") == EvidenceClass.PASSIVE_HINT
    assert classify_evidence("framework_cookie") == EvidenceClass.PASSIVE_HINT
    # Chatbot UI channel shares the same ordinal taxonomy.
    assert classify_evidence("chatbot_ui_live_surface") == EvidenceClass.LIVE_SURFACE
    assert classify_evidence("chatbot_ui_structural") == EvidenceClass.PASSIVE_STRUCTURAL
    assert classify_evidence("chatbot_ui_hint") == EvidenceClass.PASSIVE_HINT
    assert classify_evidence("behavior_chatbot_ui_confirmed") == EvidenceClass.BEHAVIORAL
    # Alias maps to the same enum member as PASSIVE_HINT.
    assert EvidenceClass.PASSIVE is EvidenceClass.PASSIVE_HINT
    assert classify_evidence("framework_header") == EvidenceClass.BRAND
    assert classify_evidence("framework_identified") == EvidenceClass.BRAND
    assert classify_evidence("page_title_ai") == EvidenceClass.BRAND
    assert classify_evidence("meta_ai_tag") == EvidenceClass.BRAND
    assert classify_evidence("html_brand_signal") == EvidenceClass.BRAND
    assert classify_evidence("unknown_new_detector") == EvidenceClass.BRAND


def test_group_evidence_buckets():
    group = group_evidence([
        "behavior_streaming",
        "chat_endpoint_200",
        "openapi_schema",
        "js_ai_sdk",
        "page_title_ai",
        "page_title_ai",
    ])
    assert group.behavioral == ["behavior_streaming"]
    assert group.live_surface == ["chat_endpoint_200"]
    assert group.passive_structural == ["openapi_schema"]
    assert group.passive_hint == ["js_ai_sdk"]
    assert group.passive == ["js_ai_sdk"]  # compat alias
    assert group.brand == ["page_title_ai"]
    d = group.as_dict()
    assert "passive_structural" in d and "passive_hint" in d and "passive" in d


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


def test_probable_structural_or_many_hints():
    hint_one = score_evidence(["js_ai_sdk"])
    structural = score_evidence(["openapi_schema"])
    two_hints = score_evidence(["robots_ai_path", "sitemap_ai_path"])
    many_hints = score_evidence([
        "robots_ai_path", "sitemap_ai_path", "js_ai_sdk", "csp_ai",
    ])
    assert hint_one.detection == Detection.POSSIBLE
    assert structural.detection == Detection.PROBABLE
    assert structural.is_ai is False
    assert two_hints.detection == Detection.POSSIBLE  # bar raised past 2
    assert many_hints.detection == Detection.PROBABLE
    assert len(many_hints.classes["passive_hint"]) >= PROBABLE_MIN_HINT
    assert many_hints.is_ai is False


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
    assert live.weight == 4
    structural = EvidenceItem.make("openapi_schema", "spec", "openapi")
    assert structural.evidence_class == "passive_structural"
    assert structural.weight == 3


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


def test_inference_path_200_requires_ai_shaped_body():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    auth = []
    # Opaque JSON 200 on an inference path is not enough without AI body shape.
    body = '{"status":"ready","detail":"accepted"}'
    r = agent._evaluate_probe_response(
        "http://x/v1/chat/completions", "/v1/chat/completions", "chat",
        200, {"Content-Type": "application/json"}, body, auth, spa_catch_all=True,
    )
    assert r.get("endpoints", []) == []


def test_inference_path_ignores_soft_404_json():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    auth = []
    r = agent._evaluate_probe_response(
        "http://x/v1/chat/completions", "/v1/chat/completions", "chat",
        200, {"Content-Type": "application/json"}, "{}", auth, spa_catch_all=True,
    )
    assert r.get("endpoints", []) == []


def test_non_inference_401_is_auth_only():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    auth = []
    r = agent._evaluate_probe_response(
        "http://x/admin", "/admin", "schema",
        401, {"Content-Type": "application/json"},
        '{"detail":"Unauthorized"}', auth,
    )
    assert r.get("endpoints", []) == []
    assert not any(e.key == "ml_endpoint_401_403" for e in r.get("evidence", []))
    assert len(auth) == 1


def test_related_host_sso_logout_400_is_not_live_surface():
    """Booking.com FP: account.booking.com/sso/logout/v3 JSON 400 ≠ AI."""
    from multiagent.agents.ai_agents.ai_fingerprint import AIFingerprintAgent

    agent = AIFingerprintAgent(run_behavioral_probes=False)
    assert agent._looks_absolute_api_url(
        "https://account.booking.com/sso/logout/v3",
    ) is False
    assert agent._looks_auth_account_path("/sso/logout/v3") is True

    auth = []
    url = "https://account.booking.com/sso/logout/v3"
    body = (
        '{"detail":[{"type":"missing","loc":["body"],'
        '"msg":"Field required","input":null}]}'
    )
    r = agent._evaluate_probe_response(
        url,
        "/sso/logout/v3",
        "schema",
        400,
        {"Content-Type": "application/json"},
        body,
        auth,
        related_api_hosts={"account.booking.com"},
        page_host="www.booking.com",
    )
    assert r.get("endpoints", []) == []
    assert not any(e.key == "error_generic_validation" for e in r.get("evidence", []))


def test_related_host_api_v1_still_looks_like_api():
    from multiagent.agents.ai_agents.ai_fingerprint import AIFingerprintAgent
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    assert agent._looks_absolute_api_url(
        "https://capi.example.com/api/configuration/product/v1/settings",
    ) is True
    # Bare /v3 alone must not qualify.
    assert agent._looks_absolute_api_url(
        "https://account.example.com/sso/logout/v3",
    ) is False


def test_related_host_api_401_html_does_not_confirm():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    auth = []
    url = "https://capi.example.com/api/configuration/v1/settings"
    r = agent._evaluate_probe_response(
        url,
        "/api/configuration/v1/settings",
        "schema",
        401,
        {"Content-Type": "text/html"},
        "<!DOCTYPE html><html><body>login</body></html>",
        auth,
        related_api_hosts={"capi.example.com"},
        page_host="www.example.com",
    )
    assert r.get("endpoints", []) == []
    assert not any(e.key == "ml_endpoint_401_403" for e in r.get("evidence", []))


def test_page_origin_non_inference_api_401_still_auth_only():
    """Same-origin /api/settings without inference segments must not auto-confirm."""
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    auth = []
    r = agent._evaluate_probe_response(
        "https://www.example.com/api/configuration/v1/settings",
        "/api/configuration/v1/settings",
        "schema",
        401,
        {"Content-Type": "application/json"},
        '{"detail":"Unauthorized"}',
        auth,
        related_api_hosts={"capi.example.com"},
        page_host="www.example.com",
    )
    assert r.get("endpoints", []) == []
    assert len(auth) == 1


def test_non_inference_405_emits_nothing():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    r = agent._evaluate_probe_response(
        "http://x/create/", "/create/", "schema",
        405, {"Content-Type": "text/plain"}, "", [],
        spa_catch_all=False,
    )
    assert r.get("endpoints", []) == []
    assert not any(e.key == "ml_endpoint_405" for e in r.get("evidence", []))


def test_oss_405_not_live_surface():
    """qwencloud /try-ai/chat regression: Aliyun OSS 405 must not confirm AI."""
    from multiagent.agents.ai_agents.ai_fingerprint import (
        _looks_api_method_rejection,
        _looks_static_storage_error,
    )

    oss_body = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<Error>\n"
        "  <Code>MethodNotAllowed</Code>\n"
        "  <Message>The specified method is not allowed against this resource.</Message>\n"
        "  <HostId>www-qwencloud-com.oss-accelerate.aliyuncs.com</HostId>\n"
        "  <Method>POST</Method>\n"
        "</Error>"
    )
    assert _looks_static_storage_error("application/xml", oss_body) is True
    assert _looks_api_method_rejection("application/xml", oss_body, {}) is False

    agent = AIFingerprintAgent(run_behavioral_probes=False)
    r = agent._evaluate_probe_response(
        "https://www.qwencloud.com/try-ai/chat",
        "/try-ai/chat",
        "chat",
        405,
        {"Content-Type": "application/xml"},
        oss_body,
        [],
        spa_catch_all=False,
    )
    assert r.get("endpoints", []) == []
    assert not any(e.key == "ml_endpoint_405" for e in r.get("evidence", []))


def test_json_api_405_still_counts():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    r = agent._evaluate_probe_response(
        "http://x/api/chat",
        "/api/chat",
        "chat",
        405,
        {"Content-Type": "application/json", "Allow": "GET, POST"},
        '{"detail":"Method Not Allowed"}',
        [],
        spa_catch_all=False,
    )
    assert "http://x/api/chat" in (r.get("endpoints") or [])
    assert any(e.key == "ml_endpoint_405" for e in r.get("evidence", []))


def test_guess_probe_category_fallthrough_is_schema():
    assert AIFingerprintAgent._guess_probe_category("/features/") == "schema"
    assert AIFingerprintAgent._guess_probe_category("/create/") == "schema"
    assert AIFingerprintAgent._guess_probe_category("/api/chat") == "chat"


def test_infra_classify_inference_passthrough():
    from multiagent.agents.ai_agents.Ai_Infra_agent import AIInfraAgent
    agent = AIInfraAgent(timeout=3)
    verdict = agent._classify(
        200, '{"message":"ok"}', "application/json",
        "/v1/chat/completions", True, catch_all=True,
    )
    assert verdict == "exposed"
