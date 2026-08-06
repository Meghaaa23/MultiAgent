from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Tuple


# Evidence classes
class EvidenceClass(str, Enum):
    BEHAVIORAL = "behavioral"
    LIVE_SURFACE = "live_surface"
    PASSIVE_STRUCTURAL = "passive_structural"
    PASSIVE_HINT = "passive_hint"
    # Alias: same value as PASSIVE_HINT so legacy references keep working.
    PASSIVE = "passive_hint"
    BRAND = "brand"


class Detection(str, Enum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    NOT_DETECTED = "not_detected"


_CLASS_RANK: Dict[EvidenceClass, int] = {
    EvidenceClass.BEHAVIORAL: 5,
    EvidenceClass.LIVE_SURFACE: 4,
    EvidenceClass.PASSIVE_STRUCTURAL: 3,
    EvidenceClass.PASSIVE_HINT: 2,
    EvidenceClass.BRAND: 1,
}


_CLASS_RULES: List[Tuple[re.Pattern, EvidenceClass]] = [
    (re.compile(r"^behavior_"), EvidenceClass.BEHAVIORAL),
    (re.compile(r"^error_"), EvidenceClass.LIVE_SURFACE),
    (re.compile(r"_endpoint_(?:200|401_403|405)$"), EvidenceClass.LIVE_SURFACE),
    (re.compile(r"_ai_(?:endpoint|field)$"), EvidenceClass.LIVE_SURFACE),
    (re.compile(
        r"^(?:sse_streaming_header|ai_response_header)$"
    ), EvidenceClass.LIVE_SURFACE),
    # Chunked transfer alone is not AI live surface (kept as hint if ever emitted).
    (re.compile(r"^sse_chunked_transfer$"), EvidenceClass.PASSIVE_HINT),
    # Product/framework headers and cookies are brand signals only —
    # they must not escalate detection without a live API/behavior surface.
    (re.compile(r"^framework_header$"), EvidenceClass.BRAND),
    (re.compile(r"^framework_identified$"), EvidenceClass.BRAND),
    (re.compile(r"^framework_cookie$"), EvidenceClass.PASSIVE_HINT),
    (re.compile(r"^(?:openapi|graphql)_schema$"), EvidenceClass.PASSIVE_STRUCTURAL),
    # Chatbot UI channel — same ordinal taxonomy as API evidence.
    # More specific chatbot_ui_* rules must precede the generic hint prefix.
    (re.compile(r"^behavior_chatbot_ui_"), EvidenceClass.BEHAVIORAL),
    (re.compile(r"^chatbot_ui_live_surface$"), EvidenceClass.LIVE_SURFACE),
    (re.compile(r"^chatbot_ui_structural$"), EvidenceClass.PASSIVE_STRUCTURAL),
    (re.compile(r"^(?:js_|sse_in_js|websocket_|robots_|sitemap_|csp_|chatbot_ui_)"),
     EvidenceClass.PASSIVE_HINT),
    # HTML/meta/favicon brand cues — not live surface.
    (re.compile(r"^(?:meta_ai_tag|dom_assistant_role|html_ai_form|"
                r"favicon_known_framework|page_title_ai|html_brand_signal)$"),
     EvidenceClass.BRAND),
]


_CONFIDENCE: Dict[Detection, str] = {
    Detection.CONFIRMED: "high",
    Detection.PROBABLE: "medium",
    Detection.POSSIBLE: "low",
    Detection.NOT_DETECTED: "none",
}


# Hints alone need a high bar — two robots lines must not reach PROBABLE.
PROBABLE_MIN_HINT = 4
# Back-compat alias for older imports/tests.
PROBABLE_MIN_PASSIVE = PROBABLE_MIN_HINT


def classify_evidence(key: str) -> EvidenceClass:
    for pattern, cls in _CLASS_RULES:
        if pattern.search(key):
            return cls
    return EvidenceClass.BRAND


def evidence_weight(key: str) -> int:
    return _CLASS_RANK[classify_evidence(key)]


@dataclass
class EvidenceGroup:
    behavioral: List[str] = field(default_factory=list)
    live_surface: List[str] = field(default_factory=list)
    passive_structural: List[str] = field(default_factory=list)
    passive_hint: List[str] = field(default_factory=list)
    brand: List[str] = field(default_factory=list)

    @property
    def passive(self) -> List[str]:
        """Legacy combined view (hints only — structural has its own bucket)."""
        return self.passive_hint

    def bucket(self, cls: EvidenceClass) -> List[str]:
        return {
            EvidenceClass.BEHAVIORAL: self.behavioral,
            EvidenceClass.LIVE_SURFACE: self.live_surface,
            EvidenceClass.PASSIVE_STRUCTURAL: self.passive_structural,
            EvidenceClass.PASSIVE_HINT: self.passive_hint,
            EvidenceClass.PASSIVE: self.passive_hint,
            EvidenceClass.BRAND: self.brand,
        }[cls]

    def as_dict(self) -> Dict[str, List[str]]:
        return {
            EvidenceClass.BEHAVIORAL.value: self.behavioral,
            EvidenceClass.LIVE_SURFACE.value: self.live_surface,
            EvidenceClass.PASSIVE_STRUCTURAL.value: self.passive_structural,
            EvidenceClass.PASSIVE_HINT.value: self.passive_hint,
            # Compat key for older readers.
            "passive": self.passive_hint,
            EvidenceClass.BRAND.value: self.brand,
        }


def group_evidence(keys: Iterable[str]) -> EvidenceGroup:
    group = EvidenceGroup()
    for key in dict.fromkeys(k for k in keys if k):
        group.bucket(classify_evidence(key)).append(key)
    return group


@dataclass
class DetectionResult:
    detection: Detection
    confidence: str
    is_ai: bool
    has_behavioral: bool
    has_live_surface: bool
    brand_only: bool
    classes: Dict[str, List[str]]

    def to_dict(self) -> Dict:
        return {
            "detection": self.detection.value,
            "confidence": self.confidence,
            "is_ai": self.is_ai,
            "has_behavioral": self.has_behavioral,
            "has_live_surface": self.has_live_surface,
            "brand_only": self.brand_only,
            "classes": self.classes,
        }


def score_evidence(keys: Iterable[str]) -> DetectionResult:
    group = group_evidence(keys)
    has_behavioral = bool(group.behavioral)
    has_live_surface = bool(group.behavioral or group.live_surface)
    any_passive = bool(group.passive_structural or group.passive_hint)
    structural = bool(group.behavioral or group.live_surface or any_passive)

    if has_live_surface:
        detection = Detection.CONFIRMED
    elif (
        len(group.passive_structural) >= 1
        or len(group.passive_hint) >= PROBABLE_MIN_HINT
    ):
        detection = Detection.PROBABLE
    elif any_passive or group.brand:
        detection = Detection.POSSIBLE
    else:
        detection = Detection.NOT_DETECTED

    return DetectionResult(
        detection=detection,
        confidence=_CONFIDENCE[detection],
        # Invariant: is_ai == has_live_surface (AI-shaped live evidence only).
        is_ai=has_live_surface,
        has_behavioral=has_behavioral,
        has_live_surface=has_live_surface,
        brand_only=bool(group.brand) and not structural,
        classes=group.as_dict(),
    )


def has_live_surface_evidence(keys: Iterable[str]) -> bool:
    group = group_evidence(keys)
    return bool(group.behavioral or group.live_surface)


def has_behavioral_evidence(keys: Iterable[str]) -> bool:
    return bool(group_evidence(keys).behavioral)


def has_brand_only_evidence(keys: Iterable[str]) -> bool:
    group = group_evidence(keys)
    return bool(group.brand) and not (
        group.behavioral
        or group.live_surface
        or group.passive_structural
        or group.passive_hint
    )
