"""Universal signature packs — no product naming catalogs."""
from multiagent.agents.ai_agents.ai_evidence_scoring import Detection, score_evidence
from multiagent.agents.ai_agents.ai_fingerprint import (
    PROTOCOL_SIGNATURES,
    SEED_ENDPOINT_RANKING,
    UNIVERSAL_INJECTION_PATHS,
    UNIVERSAL_OPENAI_PATHS,
)
from multiagent.agents.ai_agents.signature_loader import (
    get_signature_catalog,
    load_signature_catalog,
)


def test_catalog_loads_universal_only():
    cat = load_signature_catalog()
    assert len(cat.universal) >= 4
    assert not hasattr(cat, "naming") or not getattr(cat, "naming", None)
    ids = {s.id for s in cat.universal}
    assert "openai_compatible" in ids
    assert "chat_inference" in ids
    assert not (cat.__dict__.get("naming"))


def test_no_naming_directory_required():
    cat = get_signature_catalog()
    labels = set(PROTOCOL_SIGNATURES)
    # Protocol labels only — never product brands.
    for banned in (
        "Open WebUI", "LibreChat", "Flowise", "Langflow",
        "Gradio", "Ollama", "Dify", "AnythingLLM",
    ):
        assert banned not in labels


def test_openai_compatible_always_probe_paths():
    paths = {p for p, _ in UNIVERSAL_OPENAI_PATHS}
    assert "/v1/chat/completions" in paths
    assert "/v1/models" in paths
    assert "/api/chat/completions" in paths
    assert "/api/v1/prediction" not in paths


def test_seed_ranking_covers_chat_and_schema_surfaces():
    ranked = {p for p, _ in SEED_ENDPOINT_RANKING}
    for path in (
        "/v1/chat/completions", "/api/chat", "/api/v1/prediction",
        "/api/v1/run", "/api/v1/flows", "/config", "/api/ask",
    ):
        assert path in ranked
    ranked_list = [p for p, _ in SEED_ENDPOINT_RANKING]
    assert ranked_list.index("/v1/chat/completions") < ranked_list.index("/api/chat")


def test_injection_paths_from_universal():
    assert "/v1/chat/completions" in UNIVERSAL_INJECTION_PATHS
    assert "/api/v1/prediction" in UNIVERSAL_INJECTION_PATHS


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
