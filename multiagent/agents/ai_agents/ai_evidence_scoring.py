from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


# Feature rates
@dataclass(frozen=True)
class FeatureRate:
    ai_pos: int
    ai_total: int
    non_ai_pos: int
    non_ai_total: int
    source: str = "expert_elicited"
    note: str = ""

    def p_ai(self, alpha: float = 1.0) -> float:
        return (self.ai_pos + alpha) / (self.ai_total + 2.0 * alpha)

    def p_non(self, alpha: float = 1.0) -> float:
        return (self.non_ai_pos + alpha) / (self.non_ai_total + 2.0 * alpha)

    def with_perturbation(self, delta: float) -> "FeatureRate":
        def _clip_count(pos: int, total: int) -> int:
            rate = pos / max(total, 1)
            rate = min(max(rate * (1.0 + delta), 0.0), 1.0)
            return int(round(rate * total))

        return FeatureRate(
            ai_pos=_clip_count(self.ai_pos, self.ai_total),
            ai_total=self.ai_total,
            non_ai_pos=_clip_count(self.non_ai_pos, self.non_ai_total),
            non_ai_total=self.non_ai_total,
            source=self.source,
            note=self.note,
        )


def _r(
    ai_pos: int,
    ai_total: int,
    non_ai_pos: int,
    non_ai_total: int,
    source: str = "expert_elicited",
    note: str = "",
) -> FeatureRate:
    return FeatureRate(ai_pos, ai_total, non_ai_pos, non_ai_total, source, note)


FEATURE_RATES: Dict[str, FeatureRate] = {
    "openapi_schema": _r(40, 100, 8, 100, note="common on documented APIs"),
    "openapi_ai_endpoint": _r(70, 100, 2, 100, source="literature", note="OpenAI-style paths"),
    "graphql_schema": _r(25, 100, 10, 100),
    "graphql_ai_field": _r(55, 100, 2, 100),

    "framework_identified": _r(95, 100, 3, 100, note="known AI framework fingerprint"),
    "framework_header": _r(60, 100, 1, 100, source="literature", note="vendor headers"),
    "framework_cookie": _r(45, 100, 2, 100),

    "behavior_llm_response": _r(80, 100, 1, 100, source="literature", note="LLM reply patterns"),
    "behavior_model_reported": _r(75, 100, 1, 100, source="literature"),
    "behavior_streaming": _r(65, 100, 2, 100, source="literature", note="SSE token streams"),

    "chat_endpoint_200": _r(85, 100, 2, 100),
    "embedding_endpoint_200": _r(50, 100, 1, 100),
    "tool_endpoint_200": _r(45, 100, 2, 100),
    "ml_endpoint_200": _r(70, 100, 4, 100),
    "ml_endpoint_401_403": _r(80, 100, 5, 100, source="literature", note="auth-gated AI APIs"),
    "ml_endpoint_405": _r(55, 100, 6, 100),

    "error_openai_format": _r(60, 100, 1, 100, source="literature", note="OpenAI error schema"),
    "error_missing_messages": _r(55, 100, 1, 100, source="literature"),
    "error_missing_model": _r(50, 100, 1, 100, source="literature"),
    "error_triton_format": _r(30, 100, 0, 100, source="literature"),
    "error_huggingface_format": _r(30, 100, 0, 100, source="literature"),
    "error_generic_validation": _r(35, 100, 15, 100),

    "sse_streaming_header": _r(50, 100, 3, 100, source="literature", note="SSE default in LLM APIs"),
    "sse_chunked_transfer": _r(40, 100, 8, 100),
    "sse_in_js": _r(45, 100, 10, 100),
    "websocket_ai_path": _r(35, 100, 4, 100),

    "ai_response_header": _r(40, 100, 1, 100, source="literature"),

    "js_ai_sdk": _r(55, 100, 8, 100),
    "js_api_path_extracted": _r(60, 100, 12, 100),

    "robots_ai_path": _r(30, 100, 5, 100),
    "sitemap_ai_path": _r(25, 100, 6, 100),
    "csp_ai_domain": _r(35, 100, 4, 100),
    "meta_ai_tag": _r(40, 100, 15, 100),
    "favicon_known_framework": _r(25, 100, 2, 100),
    "page_title_ai": _r(60, 100, 42, 100, note="weak; high non-AI base rate"),
    "html_brand_signal": _r(70, 100, 12, 100, note="marketing FP risk"),
    "spa_catch_all": _r(55, 100, 35, 100, note="weak; common on SPAs"),

    "dom_assistant_role": _r(30, 100, 8, 100),
    "html_ai_form": _r(35, 100, 10, 100),
}


# Correlated groups
CORRELATED_GROUPS: Tuple[Tuple[str, ...], ...] = (
    ("framework_identified", "framework_header", "framework_cookie", "html_brand_signal"),
    ("behavior_llm_response", "behavior_model_reported", "behavior_streaming"),
    ("chat_endpoint_200", "ml_endpoint_200", "ml_endpoint_401_403", "ml_endpoint_405"),
    ("error_openai_format", "error_missing_messages", "error_missing_model"),
    ("sse_streaming_header", "sse_chunked_transfer", "sse_in_js", "behavior_streaming"),
    ("page_title_ai", "meta_ai_tag", "html_brand_signal"),
)


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
AI_DEPLOYMENT_PRIOR = 0.55
SMOOTHING_ALPHA = 1.0
MIN_CORPUS_FOR_LEARNED_DOMINANCE = 60


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
    blend_weight_learned: float = 0.0
    rate_source_summary: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "prior": self.prior,
            "posterior": round(self.posterior, 6),
            "log_odds": round(self.log_odds, 6),
            "evidence_score": self.evidence_score,
            "confidence": self.confidence,
            "blend_weight_learned": round(self.blend_weight_learned, 4),
            "rate_source_summary": self.rate_source_summary,
            "contributions": [
                {
                    "key": c.key,
                    "likelihood_ratio": round(c.likelihood_ratio, 4),
                    "log_lr": round(c.log_lr, 4),
                }
                for c in self.contributions
            ],
        }


@dataclass
class LabeledScan:
    label: str
    features: List[str]
    target: str = ""


def resolve_prior(scan_context: str = "general") -> float:
    if scan_context in ("ai_deployment", "known_ai", "ai_focused"):
        return AI_DEPLOYMENT_PRIOR
    return DEFAULT_PRIOR


def select_independent_keys(
    keys: Iterable[str],
    rates: Optional[Dict[str, FeatureRate]] = None,
    alpha: float = SMOOTHING_ALPHA,
) -> List[str]:
    rates = rates or FEATURE_RATES
    unique = list(dict.fromkeys(k for k in keys if k))
    claimed: set = set()
    selected: List[str] = []

    for group in CORRELATED_GROUPS:
        present = [k for k in unique if k in group and k not in claimed]
        if not present:
            continue
        best = max(present, key=lambda k: abs(_log_lr_for_rate(rates.get(k), alpha)))
        selected.append(best)
        claimed.update(present)

    for key in unique:
        if key not in claimed:
            selected.append(key)
            claimed.add(key)
    return selected


def _log_lr_for_rate(rate: Optional[FeatureRate], alpha: float) -> float:
    if rate is None:
        return 0.0
    p_ai = rate.p_ai(alpha)
    p_non = rate.p_non(alpha)
    if p_non <= 0:
        return 20.0
    lr = p_ai / p_non
    if lr <= 0:
        return 0.0
    return math.log(lr)


def likelihood_ratio(
    key: str,
    alpha: float = SMOOTHING_ALPHA,
    rates: Optional[Dict[str, FeatureRate]] = None,
) -> float:
    rate = (rates or FEATURE_RATES).get(key)
    if rate is None:
        return 1.0
    p_non = rate.p_non(alpha)
    if p_non <= 0:
        return float("inf")
    return rate.p_ai(alpha) / p_non


def feature_log_lr(
    key: str,
    alpha: float = SMOOTHING_ALPHA,
    rates: Optional[Dict[str, FeatureRate]] = None,
) -> float:
    lr = likelihood_ratio(key, alpha=alpha, rates=rates)
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


def rate_source_summary(rates: Dict[str, FeatureRate]) -> Dict[str, int]:
    summary: Dict[str, int] = {}
    for rate in rates.values():
        summary[rate.source] = summary.get(rate.source, 0) + 1
    return summary


def score_evidence_keys(
    keys: Iterable[str],
    prior: float = DEFAULT_PRIOR,
    alpha: float = SMOOTHING_ALPHA,
    rates: Optional[Dict[str, FeatureRate]] = None,
    enforce_independence: bool = True,
) -> BayesianScore:
    rates = rates or FEATURE_RATES
    unique = (
        select_independent_keys(keys, rates=rates, alpha=alpha)
        if enforce_independence
        else list(dict.fromkeys(k for k in keys if k))
    )
    prior = min(max(prior, 1e-6), 1.0 - 1e-6)
    log_odds = math.log(prior / (1.0 - prior))
    contributions: List[EvidenceContribution] = []

    for key in unique:
        lr = likelihood_ratio(key, alpha=alpha, rates=rates)
        log_lr = feature_log_lr(key, alpha=alpha, rates=rates)
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
        rate_source_summary=rate_source_summary(rates),
    )


def has_live_surface_evidence(keys: Iterable[str]) -> bool:
    return any(k in LIVE_SURFACE_KEYS for k in keys)


def has_brand_only_evidence(keys: Iterable[str]) -> bool:
    key_set = set(keys)
    return bool(key_set & SOFT_BRAND_KEYS) and not bool(key_set & LIVE_SURFACE_KEYS)


# Corpus estimation
def estimate_rates_from_corpus(
    scans: Sequence[LabeledScan],
    feature_keys: Optional[Sequence[str]] = None,
    alpha_totals: bool = False,
) -> Dict[str, FeatureRate]:
    keys = list(feature_keys) if feature_keys else sorted({
        *FEATURE_RATES.keys(),
        *(f for s in scans for f in s.features),
    })
    ai = [s for s in scans if s.label in ("ai", "AI", "positive", 1, True)]
    non = [s for s in scans if s.label in ("non_ai", "non-ai", "negative", 0, False)]
    n_ai = len(ai)
    n_non = len(non)
    if n_ai == 0 or n_non == 0:
        raise ValueError("corpus needs both AI and non-AI labeled scans")

    out: Dict[str, FeatureRate] = {}
    for key in keys:
        ai_pos = sum(1 for s in ai if key in s.features)
        non_pos = sum(1 for s in non if key in s.features)
        out[key] = FeatureRate(
            ai_pos=ai_pos,
            ai_total=n_ai,
            non_ai_pos=non_pos,
            non_ai_total=n_non,
            source="empirical",
            note=f"measured on {n_ai} AI / {n_non} non-AI scans",
        )
    return out


def merge_rates(
    base: Dict[str, FeatureRate],
    empirical: Dict[str, FeatureRate],
    min_ai: int = 30,
    min_non: int = 30,
) -> Dict[str, FeatureRate]:
    merged = dict(base)
    for key, rate in empirical.items():
        if rate.ai_total >= min_ai and rate.non_ai_total >= min_non:
            merged[key] = rate
        elif key in merged:
            keep = merged[key]
            merged[key] = FeatureRate(
                ai_pos=keep.ai_pos,
                ai_total=keep.ai_total,
                non_ai_pos=keep.non_ai_pos,
                non_ai_total=keep.non_ai_total,
                source="expert_elicited",
                note=f"kept prior; empirical n={rate.ai_total}/{rate.non_ai_total}",
            )
    return merged


def export_rates_table(rates: Optional[Dict[str, FeatureRate]] = None) -> List[Dict]:
    rates = rates or FEATURE_RATES
    rows = []
    for key, rate in sorted(rates.items()):
        rows.append({
            "feature": key,
            "p_ai": round(rate.p_ai(), 4),
            "p_non_ai": round(rate.p_non(), 4),
            "lr": round(likelihood_ratio(key, rates=rates), 4),
            "ai_pos": rate.ai_pos,
            "ai_total": rate.ai_total,
            "non_ai_pos": rate.non_ai_pos,
            "non_ai_total": rate.non_ai_total,
            "source": rate.source,
            "note": rate.note,
        })
    return rows


def save_rates(path: str | Path, rates: Optional[Dict[str, FeatureRate]] = None) -> None:
    rates = rates or FEATURE_RATES
    payload = {k: asdict(v) for k, v in rates.items()}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def load_rates(path: str | Path) -> Dict[str, FeatureRate]:
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    return {k: FeatureRate(**v) for k, v in raw.items()}


# Sensitivity analysis
@dataclass
class SensitivityResult:
    key: str
    delta: float
    original_posterior: float
    perturbed_posterior: float
    original_confidence: str
    perturbed_confidence: str
    band_changed: bool


def sensitivity_analysis(
    feature_keys: Sequence[str],
    deltas: Sequence[float] = (-0.2, -0.1, 0.1, 0.2),
    prior: float = DEFAULT_PRIOR,
    rates: Optional[Dict[str, FeatureRate]] = None,
) -> Dict:
    rates = rates or FEATURE_RATES
    baseline = score_evidence_keys(feature_keys, prior=prior, rates=rates)
    results: List[SensitivityResult] = []

    for key in sorted(set(feature_keys) & set(rates.keys())):
        for delta in deltas:
            perturbed = dict(rates)
            perturbed[key] = rates[key].with_perturbation(delta)
            scored = score_evidence_keys(feature_keys, prior=prior, rates=perturbed)
            results.append(SensitivityResult(
                key=key,
                delta=delta,
                original_posterior=baseline.posterior,
                perturbed_posterior=scored.posterior,
                original_confidence=baseline.confidence,
                perturbed_confidence=scored.confidence,
                band_changed=baseline.confidence != scored.confidence,
            ))

    high_stable = all(
        (not r.band_changed) or r.original_confidence in ("medium", "low", "none")
        for r in results
        if r.original_confidence in ("very_high", "high")
    )
    return {
        "baseline": baseline.to_dict(),
        "n_perturbations": len(results),
        "n_band_changes": sum(1 for r in results if r.band_changed),
        "high_confidence_stable": high_stable,
        "results": [asdict(r) for r in results],
    }


# Learned calibrator
@dataclass
class LogisticCalibrator:
    bias: float = 0.0
    coefficients: Dict[str, float] = field(default_factory=dict)
    feature_order: List[str] = field(default_factory=list)
    n_train: int = 0
    n_ai: int = 0
    n_non_ai: int = 0

    @classmethod
    def from_dict(cls, data: Dict) -> "LogisticCalibrator":
        return cls(
            bias=float(data.get("bias", 0.0)),
            coefficients={str(k): float(v) for k, v in (data.get("coefficients") or {}).items()},
            feature_order=[str(x) for x in (data.get("feature_order") or [])],
            n_train=int(data.get("n_train", 0)),
            n_ai=int(data.get("n_ai", 0)),
            n_non_ai=int(data.get("n_non_ai", 0)),
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

    def learned_weight(self, min_n: int = MIN_CORPUS_FOR_LEARNED_DOMINANCE) -> float:
        if not self.coefficients or self.n_train <= 0:
            return 0.0
        return min(1.0, self.n_train / float(min_n))


def combine_scores(
    bayesian: BayesianScore,
    calibrator: Optional[LogisticCalibrator],
    feature_keys: Sequence[str],
) -> BayesianScore:
    if calibrator is None or not calibrator.coefficients:
        return bayesian
    w = calibrator.learned_weight()
    if w <= 0:
        return bayesian
    learned = calibrator.predict_proba(feature_keys)
    blended = (1.0 - w) * bayesian.posterior + w * learned
    blended = min(max(blended, 1e-12), 1.0 - 1e-12)
    return BayesianScore(
        prior=bayesian.prior,
        posterior=blended,
        log_odds=math.log(blended / (1.0 - blended)),
        evidence_score=int(round(blended * 100)),
        confidence=posterior_to_confidence(blended),
        contributions=bayesian.contributions,
        blend_weight_learned=w,
        rate_source_summary=bayesian.rate_source_summary,
    )


def fit_logistic_calibrator(
    scans: Sequence[LabeledScan],
    feature_keys: Optional[Sequence[str]] = None,
    l2: float = 1.0,
    steps: int = 400,
    lr: float = 0.1,
) -> LogisticCalibrator:
    keys = list(feature_keys) if feature_keys else sorted({
        *FEATURE_RATES.keys(),
        *(f for s in scans for f in s.features),
    })
    rows = []
    for scan in scans:
        y = 1.0 if scan.label in ("ai", "AI", "positive", 1, True) else 0.0
        x = [1.0] + [1.0 if k in scan.features else 0.0 for k in keys]
        rows.append((x, y))
    if not rows:
        return LogisticCalibrator()

    w = [0.0] * (len(keys) + 1)
    n = float(len(rows))
    for _ in range(steps):
        grad = [0.0] * len(w)
        for x, y in rows:
            z = sum(wj * xj for wj, xj in zip(w, x))
            p = 1.0 / (1.0 + math.exp(-min(max(z, -40.0), 40.0)))
            err = p - y
            for j, xj in enumerate(x):
                grad[j] += err * xj
        for j in range(len(w)):
            pen = 0.0 if j == 0 else l2 * w[j]
            w[j] -= lr * ((grad[j] / n) + pen)

    n_ai = sum(1 for s in scans if s.label in ("ai", "AI", "positive", 1, True))
    n_non = len(scans) - n_ai
    return LogisticCalibrator(
        bias=w[0],
        coefficients={k: w[i + 1] for i, k in enumerate(keys)},
        feature_order=keys,
        n_train=len(scans),
        n_ai=n_ai,
        n_non_ai=n_non,
    )
