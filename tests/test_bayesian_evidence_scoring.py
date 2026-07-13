import math
import tempfile
from pathlib import Path

from multiagent.agents.ai_agents.ai_evidence_scoring import (
    FEATURE_RATES,
    LIVE_SURFACE_KEYS,
    LabeledScan,
    LogisticCalibrator,
    combine_scores,
    estimate_rates_from_corpus,
    export_rates_table,
    feature_log_lr,
    fit_logistic_calibrator,
    has_brand_only_evidence,
    has_live_surface_evidence,
    likelihood_ratio,
    load_rates,
    merge_rates,
    posterior_to_confidence,
    resolve_prior,
    save_rates,
    score_evidence_keys,
    select_independent_keys,
    sensitivity_analysis,
)
from multiagent.agents.ai_agents.ai_fingerprint import EvidenceItem


# Bayesian scoring

def test_framework_stronger_than_title():
    fw = likelihood_ratio("framework_identified")
    title = likelihood_ratio("page_title_ai")
    assert fw > title
    assert fw > 10
    assert title < 3


def test_live_surface_keys_are_strong():
    for key in (
        "behavior_llm_response",
        "chat_endpoint_200",
        "ml_endpoint_401_403",
        "openapi_ai_endpoint",
    ):
        assert key in LIVE_SURFACE_KEYS
        assert likelihood_ratio(key) > 5


def test_posterior_rises_with_strong_evidence():
    weak = score_evidence_keys(["page_title_ai"])
    strong = score_evidence_keys([
        "framework_identified",
        "behavior_llm_response",
        "chat_endpoint_200",
    ])
    assert strong.posterior > weak.posterior
    assert strong.posterior > 0.9
    assert weak.posterior < 0.5
    assert strong.confidence in ("high", "very_high")


def test_unique_keys_avoid_double_count():
    once = score_evidence_keys(["html_brand_signal"])
    twice = score_evidence_keys(["html_brand_signal", "html_brand_signal"])
    assert abs(once.posterior - twice.posterior) < 1e-9


def test_correlated_features_deduped():
    raw = ["framework_identified", "framework_header", "html_brand_signal"]
    selected = select_independent_keys(raw)
    assert len(selected) == 1
    naive = score_evidence_keys(raw, enforce_independence=False)
    indep = score_evidence_keys(raw, enforce_independence=True)
    assert indep.posterior < naive.posterior


def test_live_and_brand_helpers():
    assert has_live_surface_evidence(["page_title_ai", "ml_endpoint_401_403"])
    assert not has_live_surface_evidence(["page_title_ai", "html_brand_signal"])
    assert has_brand_only_evidence(["html_brand_signal", "page_title_ai"])
    assert not has_brand_only_evidence(["html_brand_signal", "behavior_streaming"])


def test_evidence_item_uses_log_lr():
    item = EvidenceItem.make("framework_identified", "Open WebUI", "html")
    assert item.log_lr == feature_log_lr("framework_identified")
    assert item.weight == int(round(item.log_lr * 10))
    assert item.likelihood_ratio > 1


def test_confidence_bands():
    assert posterior_to_confidence(0.97) == "very_high"
    assert posterior_to_confidence(0.85) == "high"
    assert posterior_to_confidence(0.55) == "medium"
    assert posterior_to_confidence(0.25) == "low"
    assert posterior_to_confidence(0.05) == "none"


def test_rate_provenance_marked():
    assert FEATURE_RATES["behavior_llm_response"].source == "literature"
    assert FEATURE_RATES["page_title_ai"].source == "expert_elicited"
    assert all(r.source in ("expert_elicited", "literature", "empirical")
               for r in FEATURE_RATES.values())


def test_resolve_prior_contexts():
    assert resolve_prior("general") == 0.08
    assert resolve_prior("ai_deployment") > resolve_prior("general")


# Corpus estimation

def test_estimate_rates_from_corpus():
    scans = [
        LabeledScan("ai", ["behavior_llm_response", "chat_endpoint_200"]),
        LabeledScan("ai", ["behavior_llm_response", "framework_identified"]),
        LabeledScan("ai", ["chat_endpoint_200"]),
        LabeledScan("non_ai", ["page_title_ai"]),
        LabeledScan("non_ai", ["spa_catch_all"]),
        LabeledScan("non_ai", []),
    ]
    rates = estimate_rates_from_corpus(scans, feature_keys=[
        "behavior_llm_response", "chat_endpoint_200", "page_title_ai",
    ])
    assert rates["behavior_llm_response"].source == "empirical"
    assert rates["behavior_llm_response"].ai_pos == 2
    assert rates["behavior_llm_response"].ai_total == 3
    assert rates["behavior_llm_response"].non_ai_pos == 0
    assert rates["page_title_ai"].non_ai_pos == 1


def test_merge_keeps_prior_until_min_n():
    empirical = estimate_rates_from_corpus([
        LabeledScan("ai", ["page_title_ai"]),
        LabeledScan("non_ai", ["page_title_ai"]),
    ], feature_keys=["page_title_ai"])
    merged = merge_rates(FEATURE_RATES, empirical, min_ai=30, min_non=30)
    assert merged["page_title_ai"].source == "expert_elicited"


def test_rates_roundtrip_json():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "rates.json"
        save_rates(path)
        loaded = load_rates(path)
        assert loaded["framework_identified"].ai_pos == FEATURE_RATES["framework_identified"].ai_pos
    table = export_rates_table()
    assert any(r["feature"] == "framework_identified" for r in table)


# Sensitivity analysis

def test_sensitivity_high_confidence_stable():
    keys = ["behavior_llm_response", "chat_endpoint_200", "framework_identified"]
    report = sensitivity_analysis(keys)
    assert report["baseline"]["confidence"] in ("high", "very_high")
    assert report["high_confidence_stable"] is True


# Learned calibrator

def test_logistic_calibrator_adaptive_blend():
    bayes = score_evidence_keys(["page_title_ai"])
    weak = LogisticCalibrator(
        bias=-2.0,
        coefficients={"page_title_ai": 4.0},
        n_train=10,
    )
    blended_weak = combine_scores(bayes, weak, ["page_title_ai"])
    assert 0.0 < blended_weak.blend_weight_learned < 0.3

    strong = LogisticCalibrator(
        bias=-2.0,
        coefficients={"page_title_ai": 4.0},
        n_train=120,
    )
    blended_strong = combine_scores(bayes, strong, ["page_title_ai"])
    assert blended_strong.blend_weight_learned == 1.0
    assert abs(blended_strong.posterior - strong.predict_proba(["page_title_ai"])) < 1e-9


def test_fit_logistic_calibrator():
    scans = [
        LabeledScan("ai", ["behavior_llm_response", "chat_endpoint_200"]) for _ in range(20)
    ] + [
        LabeledScan("non_ai", ["page_title_ai"]) for _ in range(20)
    ]
    model = fit_logistic_calibrator(scans, feature_keys=[
        "behavior_llm_response", "chat_endpoint_200", "page_title_ai",
    ])
    assert model.n_train == 40
    p_ai = model.predict_proba(["behavior_llm_response", "chat_endpoint_200"])
    p_non = model.predict_proba(["page_title_ai"])
    assert p_ai > p_non


def test_feature_rates_cover_weights():
    assert "framework_identified" in FEATURE_RATES
    assert all(math.isfinite(feature_log_lr(k)) for k in FEATURE_RATES)
