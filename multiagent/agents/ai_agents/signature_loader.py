from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


# Signature model
@dataclass
class Signature:
    id: str
    kind: str
    name: str = ""
    evidence_class: str = "brand"
    capabilities: List[str] = field(default_factory=list)
    requires_live_surface: bool = False
    paths: List[Tuple[str, str]] = field(default_factory=list)
    headers: Dict[str, Optional[str]] = field(default_factory=dict)
    js_strings: List[str] = field(default_factory=list)
    js_globals: List[str] = field(default_factory=list)
    cookie_names: List[str] = field(default_factory=list)
    title_hints: List[str] = field(default_factory=list)
    body_patterns: List[re.Pattern] = field(default_factory=list)
    probe: Optional[Dict[str, Any]] = None
    source_file: str = ""

    def as_framework_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "paths": [p for p, _ in self.paths],
            "js_strings": list(self.js_strings),
            "capabilities": list(self.capabilities),
            "kind": self.kind,
            "requires_live_surface": self.requires_live_surface,
        }
        if self.headers:
            out["headers"] = dict(self.headers)
        if self.js_globals:
            out["js_globals"] = list(self.js_globals)
        if self.cookie_names:
            out["cookie_names"] = list(self.cookie_names)
        if self.title_hints:
            out["title_hints"] = list(self.title_hints)
        if self.body_patterns:
            out["body_patterns"] = [p.pattern for p in self.body_patterns]
        return out


@dataclass
class SignatureCatalog:
    universal: List[Signature] = field(default_factory=list)
    naming: List[Signature] = field(default_factory=list)

    def framework_signatures(self) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        for sig in self.naming:
            out[sig.name or sig.id] = sig.as_framework_dict()
        for sig in self.universal:
            if sig.id == "openai_compatible":
                out.setdefault("OpenAI-compatible", sig.as_framework_dict())
        return out

    def framework_probe_paths(self) -> Dict[str, List[Tuple[str, str]]]:
        out: Dict[str, List[Tuple[str, str]]] = {}
        for sig in self.naming:
            key = sig.name or sig.id
            if sig.paths:
                out[key] = list(sig.paths)
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
        """Always-probe OpenAI-protocol paths from the universal pack only."""
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
        # Prefer OpenAI-compatible paths first so unknown apps are found early.
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
        for sig in self.naming:
            for path, cat in sig.paths:
                if path in seen:
                    continue
                seen.add(path)
                ranked.append((path, cat))
        return ranked

    def naming_labels(self) -> set[str]:
        return {sig.name or sig.id for sig in self.naming}


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
            cat = _guess_category(path)
            out.append((path, cat))
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
    if any(x in p for x in ("embed",)):
        return "embedding"
    if any(x in p for x in ("graphql",)):
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


def _parse_signature(data: Dict[str, Any], kind: str, source_file: str) -> Signature:
    meta = data.get("meta") or {}
    detection = data.get("detection") or {}
    headers_raw = detection.get("headers") or {}
    headers = {
        str(k).lower(): (None if v in (None, "", ".*") else str(v))
        for k, v in headers_raw.items()
    }
    body_patterns = [
        _compile_pattern(str(p))
        for p in (detection.get("body_patterns") or [])
    ]
    return Signature(
        id=str(data.get("id") or Path(source_file).stem),
        kind=kind,
        name=str(meta.get("name") or data.get("id") or Path(source_file).stem),
        evidence_class=str(data.get("class") or meta.get("class") or (
            "live_surface" if kind == "universal" else "brand"
        )),
        capabilities=[str(c) for c in (meta.get("capabilities") or [])],
        requires_live_surface=bool(
            data.get("requires_live_surface", kind == "naming")
        ),
        paths=_normalize_paths(detection.get("paths") or data.get("paths")),
        headers=headers,
        js_strings=[str(x) for x in (detection.get("js_strings") or [])],
        js_globals=[str(x) for x in (detection.get("js_globals") or [])],
        cookie_names=[str(x) for x in (detection.get("cookie_names") or [])],
        title_hints=[str(x) for x in (detection.get("title_hints") or [])],
        body_patterns=body_patterns,
        probe=detection.get("probe") or data.get("probe"),
        source_file=source_file,
    )


def _load_dir(directory: Path, kind: str) -> List[Signature]:
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
        out.append(_parse_signature(data, kind=kind, source_file=str(file)))
    return out


def load_signature_catalog(signatures_dir: Optional[str | Path] = None) -> SignatureCatalog:
    root = Path(signatures_dir) if signatures_dir else default_signatures_dir()
    return SignatureCatalog(
        universal=_load_dir(root / "universal", "universal"),
        naming=_load_dir(root / "naming", "naming"),
    )


_CATALOG: Optional[SignatureCatalog] = None


def get_signature_catalog(reload: bool = False) -> SignatureCatalog:
    global _CATALOG
    if _CATALOG is None or reload:
        _CATALOG = load_signature_catalog()
    return _CATALOG
