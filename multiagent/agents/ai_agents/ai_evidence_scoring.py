from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


# Feature rates
@dataclass(frozen=True)
class FeatureRate:
    ai_pos: int
    ai_total: int
    non_ai_pos: int
    non_ai_total: int


FEATURE_RATES: Dict[str, FeatureRate] = {
    "openapi_schema":           FeatureRate(40, 100, 8, 100),
    "openapi_ai_endpoint":      FeatureRate(70, 100, 2, 100),
    "graphql_schema":           FeatureRate(25, 100, 10, 100),
    "graphql_ai_field":         FeatureRate(55, 100, 2, 100),

    "framework_identified":     FeatureRate(95, 100, 3, 100),
    "framework_header":         FeatureRate(60, 100, 1, 100),
    "framework_cookie":         FeatureRate(45, 100, 2, 100),

    "behavior_llm_response":    FeatureRate(80, 100, 1, 100),
    "behavior_model_reported":  FeatureRate(75, 100, 1, 100),
    "behavior_streaming":       FeatureRate(65, 100, 2, 100),

    "chat_endpoint_200":        FeatureRate(85, 100, 2, 100),
    "embedding_endpoint_200":   FeatureRate(50, 100, 1, 100),
    "tool_endpoint_200":        FeatureRate(45, 100, 2, 100),
    "ml_endpoint_200":          FeatureRate(70, 100, 4, 100),
    "ml_endpoint_401_403":      FeatureRate(80, 100, 5, 100),
    "ml_endpoint_405":          FeatureRate(55, 100, 6, 100),

    "error_openai_format":      FeatureRate(60, 100, 1, 100),
    "error_missing_messages":   FeatureRate(55, 100, 1, 100),
    "error_missing_model":      FeatureRate(50, 100, 1, 100),
    "error_triton_format":      FeatureRate(30, 100, 0, 100),
    "error_huggingface_format": FeatureRate(30, 100, 0, 100),
    "error_generic_validation": FeatureRate(35, 100, 15, 100),

    "sse_streaming_header":     FeatureRate(50, 100, 3, 100),
    "sse_chunked_transfer":     FeatureRate(40, 100, 8, 100),
    "sse_in_js":                FeatureRate(45, 100, 10, 100),
    "websocket_ai_path":        FeatureRate(35, 100, 4, 100),

    "ai_response_header":       FeatureRate(40, 100, 1, 100),

    "js_ai_sdk":                FeatureRate(55, 100, 8, 100),
    "js_api_path_extracted":    FeatureRate(60, 100, 12, 100),

    "robots_ai_path":           FeatureRate(30, 100, 5, 100),
    "sitemap_ai_path":          FeatureRate(25, 100, 6, 100),
    "csp_ai_domain":            FeatureRate(35, 100, 4, 100),
    "meta_ai_tag":              FeatureRate(40, 100, 15, 100),
    "favicon_known_framework":  FeatureRate(25, 100, 2, 100),
    "page_title_ai":            FeatureRate(60, 100, 42, 100),
    "html_brand_signal":        FeatureRate(70, 100, 12, 100),
    "spa_catch_all":            FeatureRate(55, 100, 35, 100),

    "dom_assistant_role":       FeatureRate(30, 100, 8, 100),
    "html_ai_form":             FeatureRate(35, 100, 10, 100),
}


# Live surface
LIVE_SURFACE_KEYS = frozenset({
    "behavior_llm_response",
    "behavior_model_reported",
    "behavior_streaming",
    "chat_endpoint_200",
    "embedding_endpoint_200",
    "tool_endpoint_200",
    "ml_endpoint_200",
    "ml_endpoint_401_403",
    "ml_endpoint_405",
    "openapi_ai_endpoint",
    "graphql_ai_field",
    "error_openai_format",
    "error_missing_messages",
    "error_missing_model",
    "error_triton_format",
    "error_huggingface_format",
    "sse_streaming_header",
    "framework_header",
    "ai_response_header",
})


# Soft brand
SOFT_BRAND_KEYS = frozenset({
    "html_brand_signal",
    "page_title_ai",
    "favicon_known_framework",
    "meta_ai_tag",
    "framework_identified",
    "js_ai_sdk",
})


# Posterior bands
POSTERIOR_BANDS: List[Tuple[float, str]] = [
    (0.95, "very_high"),
    (0.80, "high"),
    (0.50, "medium"),
    (0.20, "low"),
    (0.00, "none"),
]

DEFAULT_PRIOR = 0.08
SMOOTHING_ALPHA = 1.0


@dataclass
class EvidenceContribution:
    key: str
    likelihood_ratio: float
    log_lr: float


@dataclass
class BayesianScore:
    prior: float
    posterior: float
    log_odds: float
    evidence_score: int
    confidence: str
    contributions: List[EvidenceContribution] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "prior": self.prior,
            "posterior": round(self.posterior, 6),
            "log_odds": round(self.log_odds, 6),
            "evidence_score": self.evidence_score,
            "confidence": self.confidence,
            "contributions": [
                {
                    "key": c.key,
                    "likelihood_ratio": round(c.likelihood_ratio, 4),
                    "log_lr": round(c.log_lr, 4),
                }
                for c in self.contributions
            ],
        }


def likelihood_ratio(key: str, alpha: float = SMOOTHING_ALPHA) -> float:
    rate = FEATURE_RATES.get(key)
    if rate is None:
        return 1.0
    p_ai = (rate.ai_pos + alpha) / (rate.ai_total + 2.0 * alpha)
    p_non = (rate.non_ai_pos + alpha) / (rate.non_ai_total + 2.0 * alpha)
    if p_non <= 0:
        return float("inf")
    return p_ai / p_non


def feature_log_lr(key: str, alpha: float = SMOOTHING_ALPHA) -> float:
    lr = likelihood_ratio(key, alpha=alpha)
    if lr <= 0:
        return 0.0
    if math.isinf(lr):
        return 20.0
    return math.log(lr)


def posterior_to_confidence(posterior: float) -> str:
    for threshold, label in POSTERIOR_BANDS:
        if posterior >= threshold:
            return label
    return "none"


def score_evidence_keys(
    keys: Iterable[str],
    prior: float = DEFAULT_PRIOR,
    alpha: float = SMOOTHING_ALPHA,
) -> BayesianScore:
    unique: List[str] = list(dict.fromkeys(k for k in keys if k))
    prior = min(max(prior, 1e-6), 1.0 - 1e-6)
    log_odds = math.log(prior / (1.0 - prior))
    contributions: List[EvidenceContribution] = []

    for key in unique:
        lr = likelihood_ratio(key, alpha=alpha)
        log_lr = feature_log_lr(key, alpha=alpha)
        log_odds += log_lr
        contributions.append(
            EvidenceContribution(key=key, likelihood_ratio=lr, log_lr=log_lr)
        )

    posterior = 1.0 / (1.0 + math.exp(-log_odds))
    return BayesianScore(
        prior=prior,
        posterior=posterior,
        log_odds=log_odds,
        evidence_score=int(round(posterior * 100)),
        confidence=posterior_to_confidence(posterior),
        contributions=contributions,
    )


def has_live_surface_evidence(keys: Iterable[str]) -> bool:
    return any(k in LIVE_SURFACE_KEYS for k in keys)


def has_brand_only_evidence(keys: Iterable[str]) -> bool:
    key_set = set(keys)
    return bool(key_set & SOFT_BRAND_KEYS) and not bool(key_set & LIVE_SURFACE_KEYS)


# Learned calibrator
@dataclass
class LogisticCalibrator:
    bias: float = 0.0
    coefficients: Dict[str, float] = field(default_factory=dict)
    feature_order: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict) -> "LogisticCalibrator":
        return cls(
            bias=float(data.get("bias", 0.0)),
            coefficients={str(k): float(v) for k, v in (data.get("coefficients") or {}).items()},
            feature_order=[str(x) for x in (data.get("feature_order") or [])],
        )

    @classmethod
    def load(cls, path: str | Path) -> "LogisticCalibrator":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    def predict_proba(self, features: Dict[str, int] | Sequence[str]) -> float:
        if isinstance(features, dict):
            active = features
        else:
            active = {k: 1 for k in features}
        z = self.bias
        for key, coef in self.coefficients.items():
            z += coef * float(active.get(key, 0))
        return 1.0 / (1.0 + math.exp(-z))


def combine_scores(
    bayesian: BayesianScore,
    calibrator: Optional[LogisticCalibrator],
    feature_keys: Sequence[str],
) -> BayesianScore:
    if calibrator is None or not calibrator.coefficients:
        return bayesian
    learned = calibrator.predict_proba(feature_keys)
    blended = 0.5 * bayesian.posterior + 0.5 * learned
    return BayesianScore(
        prior=bayesian.prior,
        posterior=blended,
        log_odds=math.log(blended / max(1.0 - blended, 1e-12)),
        evidence_score=int(round(blended * 100)),
        confidence=posterior_to_confidence(blended),
        contributions=bayesian.contributions,
    )
