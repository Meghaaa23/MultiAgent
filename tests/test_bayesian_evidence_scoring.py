import math

from multiagent.agents.ai_agents.ai_evidence_scoring import (
    FEATURE_RATES,
    LIVE_SURFACE_KEYS,
    LogisticCalibrator,
    combine_scores,
    feature_log_lr,
    has_brand_only_evidence,
    has_live_surface_evidence,
    likelihood_ratio,
    posterior_to_confidence,
    score_evidence_keys,
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


# Learned calibrator

def test_logistic_calibrator_blend():
    bayes = score_evidence_keys(["page_title_ai"])
    calibrator = LogisticCalibrator(
        bias=-2.0,
        coefficients={"page_title_ai": 4.0},
    )
    blended = combine_scores(bayes, calibrator, ["page_title_ai"])
    learned = calibrator.predict_proba(["page_title_ai"])
    assert 0.0 < learned < 1.0
    assert abs(blended.posterior - 0.5 * (bayes.posterior + learned)) < 1e-9


def test_feature_rates_cover_weights():
    assert "framework_identified" in FEATURE_RATES
    assert all(math.isfinite(feature_log_lr(k)) for k in FEATURE_RATES)
