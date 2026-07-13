from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


@dataclass
class Signature:
    id: str
    kind: str
    name: str = ""
    evidence_class: str = "live_surface"
    capabilities: List[str] = field(default_factory=list)
    paths: List[Tuple[str, str]] = field(default_factory=list)
    body_patterns: List[re.Pattern] = field(default_factory=list)
    probe: Optional[Dict[str, Any]] = None
    source_file: str = ""

    def as_protocol_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "id": self.id,
            "paths": [p for p, _ in self.paths],
            "path_categories": dict(self.paths),
            "capabilities": list(self.capabilities),
            "evidence_class": self.evidence_class,
        }
        if self.body_patterns:
            out["body_patterns"] = [p.pattern for p in self.body_patterns]
        return out


@dataclass
class SignatureCatalog:
    universal: List[Signature] = field(default_factory=list)

    def protocol_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Protocol/capability labels only — never product names."""
        out: Dict[str, Dict[str, Any]] = {}
        for sig in self.universal:
            label = _protocol_label(sig)
            out[label] = sig.as_protocol_dict()
        return out

    def universal_probe_paths(self) -> List[Tuple[str, str]]:
        paths: List[Tuple[str, str]] = []
        seen = set()
        for sig in self.universal:
            for path, cat in sig.paths:
                if path in seen:
                    continue
                seen.add(path)
                paths.append((path, cat))
        return paths

    def openai_compatible_paths(self) -> List[Tuple[str, str]]:
        for sig in self.universal:
            if sig.id == "openai_compatible":
                return list(sig.paths)
        return [
            ("/v1/chat/completions", "chat"),
            ("/v1/completions", "chat"),
            ("/v1/models", "schema"),
            ("/api/chat/completions", "chat"),
        ]

    def seed_endpoint_ranking(self) -> List[Tuple[str, str]]:
        ranked: List[Tuple[str, str]] = []
        seen = set()
        for path, cat in self.openai_compatible_paths():
            if path in seen:
                continue
            seen.add(path)
            ranked.append((path, cat))
        for path, cat in self.universal_probe_paths():
            if path in seen:
                continue
            seen.add(path)
            ranked.append((path, cat))
        return ranked

    def injection_paths(self) -> List[str]:
        """Chat/inference paths suitable for vulnerability injection probes."""
        out: List[str] = []
        seen = set()
        for path, cat in self.universal_probe_paths():
            if cat not in ("chat", "ml", "embedding"):
                continue
            if path in seen:
                continue
            seen.add(path)
            out.append(path)
        return out


def _protocol_label(sig: Signature) -> str:
    if sig.id == "openai_compatible":
        return "OpenAI-compatible"
    return sig.name or sig.id.replace("_", " ")


def default_signatures_dir() -> Path:
    return Path(__file__).resolve().parent / "signatures"


def _compile_pattern(value: str) -> re.Pattern:
    try:
        return re.compile(value, re.I)
    except re.error:
        return re.compile(re.escape(value), re.I)


def _normalize_paths(raw: Any) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if not raw:
        return out
    for item in raw:
        if isinstance(item, str):
            path = item if item.startswith("/") else "/" + item
            out.append((path, _guess_category(path)))
        elif isinstance(item, dict):
            path = str(item.get("path") or "")
            if not path:
                continue
            if not path.startswith("/"):
                path = "/" + path
            cat = str(item.get("category") or _guess_category(path))
            out.append((path, cat))
    return out


def _guess_category(path: str) -> str:
    p = path.lower()
    if "embed" in p:
        return "embedding"
    if "graphql" in p:
        return "graphql"
    if any(x in p for x in (
        "chat", "completion", "generate", "ask", "message", "predict",
        "prediction", "run", "invoke", "queue",
    )):
        return "chat"
    if any(x in p for x in (
        "model", "tag", "health", "openapi", "swagger", "docs", "config",
        "info", "flow", "node", "workspace", "endpoint", "convo",
    )):
        return "schema"
    return "ml"


def _parse_signature(data: Dict[str, Any], source_file: str) -> Signature:
    meta = data.get("meta") or {}
    detection = data.get("detection") or {}
    body_patterns = [
        _compile_pattern(str(p))
        for p in (detection.get("body_patterns") or [])
    ]
    return Signature(
        id=str(data.get("id") or Path(source_file).stem),
        kind="universal",
        name=str(meta.get("name") or data.get("id") or Path(source_file).stem),
        evidence_class=str(
            data.get("class") or meta.get("class") or "live_surface"
        ),
        capabilities=[str(c) for c in (meta.get("capabilities") or [])],
        paths=_normalize_paths(detection.get("paths") or data.get("paths")),
        body_patterns=body_patterns,
        probe=detection.get("probe") or data.get("probe"),
        source_file=source_file,
    )


def _load_dir(directory: Path) -> List[Signature]:
    if yaml is None:
        raise RuntimeError("PyYAML is required to load signature packs")
    if not directory.is_dir():
        return []
    out: List[Signature] = []
    for file in sorted(directory.glob("*.yaml")) + sorted(directory.glob("*.yml")):
        with open(file, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if not isinstance(data, dict):
            continue
        out.append(_parse_signature(data, source_file=str(file)))
    return out


def load_signature_catalog(signatures_dir: Optional[str | Path] = None) -> SignatureCatalog:
    root = Path(signatures_dir) if signatures_dir else default_signatures_dir()
    return SignatureCatalog(universal=_load_dir(root / "universal"))


_CATALOG: Optional[SignatureCatalog] = None


def get_signature_catalog(reload: bool = False) -> SignatureCatalog:
    global _CATALOG
    if _CATALOG is None or reload:
        _CATALOG = load_signature_catalog()
    return _CATALOG
