from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Tuple


# Evidence classes
class EvidenceClass(str, Enum):
    BEHAVIORAL = "behavioral"
    LIVE_SURFACE = "live_surface"
    PASSIVE = "passive"
    BRAND = "brand"


class Detection(str, Enum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    NOT_DETECTED = "not_detected"


_CLASS_RANK: Dict[EvidenceClass, int] = {
    EvidenceClass.BEHAVIORAL: 4,
    EvidenceClass.LIVE_SURFACE: 3,
    EvidenceClass.PASSIVE: 2,
    EvidenceClass.BRAND: 1,
}


_CLASS_RULES: List[Tuple[re.Pattern, EvidenceClass]] = [
    (re.compile(r"^behavior_"), EvidenceClass.BEHAVIORAL),
    (re.compile(r"^error_"), EvidenceClass.LIVE_SURFACE),
    (re.compile(r"_endpoint_(?:200|401_403|405)$"), EvidenceClass.LIVE_SURFACE),
    (re.compile(r"_ai_(?:endpoint|field)$"), EvidenceClass.LIVE_SURFACE),
    (re.compile(
        r"^(?:sse_streaming_header|sse_chunked_transfer|ai_response_header|"
        r"framework_header)$"
    ), EvidenceClass.LIVE_SURFACE),
    (re.compile(r"^framework_cookie$"), EvidenceClass.PASSIVE),
    (re.compile(r"^(?:openapi|graphql)_schema$"), EvidenceClass.PASSIVE),
    (re.compile(r"^(?:js_|sse_in_js|websocket_|robots_|sitemap_|csp_)"), EvidenceClass.PASSIVE),
]


_CONFIDENCE: Dict[Detection, str] = {
    Detection.CONFIRMED: "high",
    Detection.PROBABLE: "medium",
    Detection.POSSIBLE: "low",
    Detection.NOT_DETECTED: "none",
}


PROBABLE_MIN_PASSIVE = 2


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
    passive: List[str] = field(default_factory=list)
    brand: List[str] = field(default_factory=list)

    def bucket(self, cls: EvidenceClass) -> List[str]:
        return {
            EvidenceClass.BEHAVIORAL: self.behavioral,
            EvidenceClass.LIVE_SURFACE: self.live_surface,
            EvidenceClass.PASSIVE: self.passive,
            EvidenceClass.BRAND: self.brand,
        }[cls]

    def as_dict(self) -> Dict[str, List[str]]:
        return {
            EvidenceClass.BEHAVIORAL.value: self.behavioral,
            EvidenceClass.LIVE_SURFACE.value: self.live_surface,
            EvidenceClass.PASSIVE.value: self.passive,
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
    structural = bool(group.behavioral or group.live_surface or group.passive)

    if has_live_surface:
        detection = Detection.CONFIRMED
    elif len(group.passive) >= PROBABLE_MIN_PASSIVE:
        detection = Detection.PROBABLE
    elif group.passive or group.brand:
        detection = Detection.POSSIBLE
    else:
        detection = Detection.NOT_DETECTED

    return DetectionResult(
        detection=detection,
        confidence=_CONFIDENCE[detection],
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
        group.behavioral or group.live_surface or group.passive
    )
