"""External signature packs: universal detection vs naming labels."""
from multiagent.agents.ai_agents.ai_evidence_scoring import Detection, score_evidence
from multiagent.agents.ai_agents.ai_fingerprint import (
    FRAMEWORK_SIGNATURES,
    SEED_ENDPOINT_RANKING,
    UNIVERSAL_OPENAI_PATHS,
)
from multiagent.agents.ai_agents.signature_loader import (
    get_signature_catalog,
    load_signature_catalog,
)


def test_catalog_loads_universal_and_naming():
    cat = load_signature_catalog()
    assert len(cat.universal) >= 4
    assert len(cat.naming) >= 10
    ids = {s.id for s in cat.universal}
    assert "openai_compatible" in ids
    assert "chat_inference" in ids


def test_naming_packs_require_live_surface():
    cat = get_signature_catalog()
    for sig in cat.naming:
        assert sig.requires_live_surface is True, sig.id
        assert sig.kind == "naming"
        fw = FRAMEWORK_SIGNATURES[sig.name or sig.id]
        assert fw.get("requires_live_surface") is True


def test_openai_compatible_always_probe_paths():
    paths = {p for p, _ in UNIVERSAL_OPENAI_PATHS}
    assert "/v1/chat/completions" in paths
    assert "/v1/models" in paths
    assert "/api/chat/completions" in paths
    # Must not pull generic /api/v1/* from other universal packs.
    assert "/api/v1/prediction" not in paths
    assert "/api/v1/run" not in paths


def test_seed_ranking_prefers_openai_compatible():
    ranked = [p for p, _ in SEED_ENDPOINT_RANKING]
    assert ranked.index("/v1/chat/completions") < ranked.index("/api/chat")


def test_unknown_openai_surface_confirmed_without_product_name():
    """Capability evidence alone is enough; product naming is optional."""
    result = score_evidence([
        "chat_endpoint_200",
        "error_openai_format",
    ])
    assert result.detection == Detection.CONFIRMED
    assert result.is_ai is True
    assert result.has_live_surface is True


def test_brand_only_naming_does_not_escalate():
    """Naming signals (title/header/brand) never set is_ai without live surface."""
    result = score_evidence([
        "html_brand_signal",
        "page_title_ai",
        "framework_header",
    ])
    assert result.detection == Detection.POSSIBLE
    assert result.is_ai is False
    assert result.has_live_surface is False
    assert result.brand_only is True

    # Cookies are passive naming aids — still not enough to confirm AI.
    with_cookie = score_evidence([
        "html_brand_signal",
        "framework_header",
        "framework_cookie",
    ])
    assert with_cookie.is_ai is False
    assert with_cookie.has_live_surface is False
    assert with_cookie.detection in (Detection.POSSIBLE, Detection.PROBABLE)


def test_framework_signatures_include_known_products():
    for name in (
        "Open WebUI", "LibreChat", "Flowise", "Langflow",
        "Gradio", "Ollama", "OpenAI-compatible",
    ):
        assert name in FRAMEWORK_SIGNATURES
        assert FRAMEWORK_SIGNATURES[name].get("paths")
