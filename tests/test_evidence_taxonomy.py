"""Evidence-class taxonomy for AI fingerprint (live surface vs brand)."""
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
    _is_inference_path,
)


def test_behavior_is_behavioral():
    assert classify_evidence("behavior_llm_response") == EvidenceClass.BEHAVIORAL
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
    assert classify_evidence("framework_cookie") == EvidenceClass.PASSIVE_HINT
    assert classify_evidence("framework_header") == EvidenceClass.BRAND
    assert classify_evidence("framework_identified") == EvidenceClass.BRAND
    assert classify_evidence("page_title_ai") == EvidenceClass.BRAND
    assert classify_evidence("meta_ai_tag") == EvidenceClass.BRAND


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
    assert group.brand == ["page_title_ai"]


def test_confirmed_on_live_surface():
    result = score_evidence(["ml_endpoint_401_403", "page_title_ai"])
    assert result.detection == Detection.CONFIRMED
    assert result.confidence == "high"
    assert result.is_ai is True
    assert result.has_live_surface is True
    assert result.brand_only is False


def test_confirmed_on_behavioral():
    result = score_evidence(["behavior_llm_response"])
    assert result.detection == Detection.CONFIRMED
    assert result.has_behavioral is True
    assert result.is_ai is True


def test_probable_structural_or_many_hints():
    hint_one = score_evidence(["js_ai_sdk"])
    structural = score_evidence(["openapi_schema"])
    two_hints = score_evidence(["robots_ai_path", "sitemap_ai_path"])
    many_hints = score_evidence([
        "robots_ai_path", "sitemap_ai_path", "js_ai_sdk", "csp_ai_domain",
    ])
    assert hint_one.detection == Detection.POSSIBLE
    assert structural.detection == Detection.PROBABLE
    assert structural.is_ai is False
    assert two_hints.detection == Detection.POSSIBLE
    assert many_hints.detection == Detection.PROBABLE
    assert len(many_hints.classes["passive_hint"]) >= PROBABLE_MIN_HINT
    assert many_hints.is_ai is False


def test_possible_brand_only():
    result = score_evidence(["framework_identified", "page_title_ai"])
    assert result.detection == Detection.POSSIBLE
    assert result.confidence == "low"
    assert result.is_ai is False
    assert result.brand_only is True


def test_not_detected_empty():
    result = score_evidence([])
    assert result.detection == Detection.NOT_DETECTED
    assert result.is_ai is False


def test_helper_predicates():
    assert has_live_surface_evidence(["page_title_ai", "ml_endpoint_401_403"])
    assert not has_live_surface_evidence(["page_title_ai", "html_brand_signal"])
    assert has_behavioral_evidence(["behavior_llm_response"])
    assert has_brand_only_evidence(["html_brand_signal", "page_title_ai"])
    assert not has_brand_only_evidence(["html_brand_signal", "js_ai_sdk"])


def test_evidence_item_uses_class_weight():
    item = EvidenceItem.make("framework_identified", "LibreChat", "html")
    assert item.evidence_class == "brand"
    assert item.weight == 1
    live = EvidenceItem.make("chat_endpoint_200", "chat ok", "probe")
    assert live.evidence_class == "live_surface"
    assert live.weight == 4


def test_inference_path_segments():
    assert _is_inference_path("/api/messages") is True
    assert _is_inference_path("/api/ask") is True
    assert _is_inference_path("/v1/chat/completions") is True
    assert _is_inference_path("/api/user") is False
    assert _is_inference_path("/api/config") is False
    assert _is_inference_path("/admin") is False
    assert _is_inference_path("/assets/index.js") is False


def test_probe_401_inference_is_live_surface():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    auth = []
    r = agent._evaluate_probe_response(
        "http://x/api/messages", "/api/messages", "chat",
        401, {"WWW-Authenticate": "Bearer"}, '{"message":"Unauthorized"}', auth,
    )
    assert any(e.key == "ml_endpoint_401_403" for e in r["evidence"])
    assert "http://x/api/messages" in r["endpoints"]
    keys = [e.key for e in r["evidence"]]
    scored = score_evidence(keys)
    assert scored.is_ai is True
    assert scored.has_live_surface is True


def test_probe_401_non_inference_not_live():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    auth = []
    r = agent._evaluate_probe_response(
        "http://x/admin", "/admin", "ml",
        401, {}, "login required", auth,
    )
    assert not any(e.key == "ml_endpoint_401_403" for e in r["evidence"])
    assert auth  # still recorded as AuthSignal
    assert score_evidence([e.key for e in r["evidence"]]).is_ai is False


def test_librechat_style_auth_gated_messages():
    """LibreChat: brand alone is not AI; /api/messages 401 is."""
    brand = score_evidence(["framework_identified", "meta_ai_tag"])
    assert brand.is_ai is False
    assert brand.brand_only is True

    live = score_evidence(["ml_endpoint_401_403", "framework_identified"])
    assert live.is_ai is True
    assert live.detection == Detection.CONFIRMED
