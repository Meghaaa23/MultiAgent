from __future__ import annotations

import re
import json
import hashlib
import asyncio
import logging
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

try:
    from .ai_evidence_scoring import (
        classify_evidence,
        evidence_weight,
        has_live_surface_evidence,
        score_evidence,
    )
except ImportError:  # script / flat import (e.g. dev_ai_scan.py)
    try:
        from multiagent.agents.ai_agents.ai_evidence_scoring import (
            classify_evidence,
            evidence_weight,
            has_live_surface_evidence,
            score_evidence,
        )
    except ImportError:
        from ai_evidence_scoring import (
            classify_evidence,
            evidence_weight,
            has_live_surface_evidence,
            score_evidence,
        )

logger = logging.getLogger(__name__)


# Evidence classifiers (response shape) — not endpoint path catalogs.

MODEL_NAME_PATTERNS = [
    r'\b(gpt-?4|gpt-?3\.5|gpt-?4o)\b',
    r'\b(claude-?\d|claude-?(?:sonnet|opus|haiku))\b',
    r'\b(llama-?\d)',
    r'\b(mistral|mixtral|gemma|gemini|qwen|phi-?\d|deepseek)\b',
]

# Capability vocabulary used when labeling observed behavior / OpenAPI props.
KNOWN_CAPABILITIES = {
    "chat", "rag", "tool_calling", "memory", "code_execution",
    "email_send", "web_search", "browser", "sql", "filesystem",
    "shell", "python", "image_generation", "vision", "speech",
    "audio", "embedding", "multi_agent", "mcp", "workflow",
}

# Structural LLM / inference JSON shapes (product-agnostic).
AI_RESPONSE_BODY_PATTERNS = [
    r'"choices"\s*:\s*\[',
    r'"prompt_tokens"\s*:',
    r'"completion_tokens"\s*:',
    r'"finish_reason"\s*:',
    r'"usage"\s*:\s*\{',
    r'"model"\s*:\s*"[^"]{2,}"',
    r'"models"\s*:\s*\[',
    r'"embeddings"\s*:',
    r'"object"\s*:\s*"(?:model|list|chat\.completion|text_completion)',
    r'"tool_calls"\s*:',
    r'"function_call"\s*:',
    r'"input_tokens"\s*:',
    r'"output_tokens"\s*:',
    r'"generated_text"\s*:',
    r'"done"\s*:\s*(?:true|false)',
]

OPENAI_JSON_KEYS = (
    "choices", "model", "object", "data", "message", "response",
    "usage", "models", "generated_text", "error",
)

# Generic probe bodies — used only after a URL is discovered.
# Prefer OpenAPI-derived bodies when a schema is available for that path.
GENERIC_CHAT_PROBE = json.dumps({
    "messages": [{"role": "user", "content": "Hi"}],
    "max_tokens": 1,
    "stream": False,
}).encode()

GENERIC_PROMPT_PROBE = json.dumps({
    "prompt": "Hi",
    "input": "Hi",
    "query": "Hi",
    "text": "Hi",
    "max_tokens": 1,
}).encode()

LLM_RESPONSE_SIGNALS = [
    r"\bI\s+(?:am|can|will|don'?t|cannot|understand)\b",
    r"\bAs\s+an?\s+(?:AI|assistant|language model)\b",
    r"\bHow\s+(?:can|may)\s+I\s+(?:help|assist)\b",
]

ERROR_FINGERPRINTS: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r'"error"\s*:\s*\{.*?"type"\s*:', re.S),
     "error_openai_format", "OpenAI-compatible"),
    (re.compile(r'"messages"\s*.*?(required|missing|must be)', re.I),
     "error_missing_messages", "chat_api"),
    (re.compile(r'"model"\s*.*?(required|missing|must be)', re.I),
     "error_missing_model", "OpenAI-compatible"),
    (re.compile(r'"detail"\s*:.*?"msg"\s*:', re.S),
     "error_generic_validation", "api_validation"),
]

AI_RESPONSE_HEADERS = [
    "x-model-version", "x-model-id", "x-inference-time", "x-ai-backend",
    "x-ml-model", "x-openai-model", "openai-model", "openai-version",
    "x-inference-id", "x-model-name", "x-prediction-id",
]

# JS SDK string hits are passive discovery aids only (never set is_ai alone).
ML_LIBRARY_JS_SIGNATURES: Dict[str, List[str]] = {
    "OpenAI JS SDK":    ["openai.min.js", "from 'openai'", 'from "openai"', "new OpenAI("],
    "Anthropic JS SDK": ["@anthropic-ai/sdk", "new Anthropic("],
    "LangChain JS":     ["langchain", "@langchain/core"],
    "Transformers.js":  ["@xenova/transformers", "transformers.js"],
    "Vercel AI SDK":    ["ai/react", "useChat(", "useCompletion("],
}

SPA_CANARY_PATH = "/__scanner_canary_nonexistent_check_xyz789_do_not_create_this_route"

AI_TITLE_KEYWORDS = [
    "ai", "llm", "gpt", "chat", "assistant", "bot", "inference", "embedding",
]

# Filename / URL tokens that suggest an API map reference in HTML/JS.
_SPEC_REF_RE = re.compile(
    r"""(?P<path>/[^\s"'<>]*(?:openapi|swagger)[^\s"'<>]*\.(?:json|yaml|yml)|"""
    r"""/[^\s"'<>]*(?:api-docs|api/docs|v3/api-docs)[^\s"'<>]*)""",
    re.I,
)
_GRAPHQL_REF_RE = re.compile(
    r"""(?P<path>/[^\s"'<>]*(?:graphql|graphiql)[^\s"'<>]*)""",
    re.I,
)


def _looks_html_body(ct: str, body: str) -> bool:
    b = (body or "").strip().lower()
    return "html" in (ct or "").lower() or b.startswith(("<!doctype", "<html"))


def _looks_ai_api_json(body: str) -> bool:
    text = (body or "").strip()
    if not text or text in ("{}", "[]", "null"):
        return False
    if any(re.search(p, text, re.I) for p in AI_RESPONSE_BODY_PATTERNS):
        return True
    try:
        data = json.loads(text)
    except Exception:
        return False
    if isinstance(data, dict):
        if any(k in data for k in OPENAI_JSON_KEYS):
            return True
        err = data.get("error")
        if isinstance(err, dict):
            return True
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return any(k in data[0] for k in ("id", "object", "model", "created"))
    return False


def _is_soft_404_json(body: str) -> bool:
    text = (body or "").strip()
    if text in ("", "{}", "[]", "null"):
        return True
    try:
        data = json.loads(text)
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    if data.get("statusCode") in (404, 405):
        return True
    code = str(data.get("code") or data.get("error") or "").lower()
    if code in ("not_found", "enoent", "404"):
        return True
    msg = str(data.get("message") or data.get("msg") or "").lower()
    return "not found" in msg and len(data) <= 3


def _is_inference_path(path: str) -> bool:
    """Soft prioritization for already-discovered paths — never invents URLs."""
    p = (path or "").lower()
    return any(tok in p for tok in (
        "completion", "chat", "generate", "predict", "ask", "message",
        "run", "invoke", "llm", "inference",
    ))


def _probe_post_body(
    path: str,
    category: str,
    openapi_schema: Optional[Dict] = None,
) -> bytes:
    """Build a probe body from OpenAPI request schema when available."""
    derived = _body_from_openapi(path, openapi_schema)
    if derived is not None:
        return derived
    path_l = (path or "").lower()
    if "completions" in path_l and "chat" not in path_l:
        return GENERIC_PROMPT_PROBE
    if category in ("chat", "ml", "embedding") or _is_inference_path(path):
        return GENERIC_CHAT_PROBE
    return GENERIC_PROMPT_PROBE


def _body_from_openapi(path: str, schema: Optional[Dict]) -> Optional[bytes]:
    if not schema or not isinstance(schema, dict):
        return None
    paths = schema.get("paths") or {}
    methods = paths.get(path) or paths.get(path.rstrip("/")) or {}
    if not isinstance(methods, dict):
        return None
    for method in ("post", "put", "patch", "get"):
        op = methods.get(method)
        if not isinstance(op, dict):
            continue
        props = (
            ((op.get("requestBody") or {}).get("content") or {})
            .get("application/json", {})
            .get("schema", {})
            .get("properties")
        )
        if not isinstance(props, dict) or not props:
            continue
        body: Dict = {}
        for key, prop in props.items():
            kl = key.lower()
            if kl in ("messages",):
                body[key] = [{"role": "user", "content": "Hi"}]
            elif kl in ("prompt", "input", "query", "text", "question", "input_value"):
                body[key] = "Hi"
            elif kl in ("model",):
                body[key] = "default"
            elif kl in ("max_tokens", "max_new_tokens"):
                body[key] = 1
            elif kl in ("stream",):
                body[key] = False
            elif isinstance(prop, dict) and prop.get("type") == "object":
                body[key] = {}
            elif isinstance(prop, dict) and prop.get("type") == "array":
                body[key] = []
            else:
                body[key] = "Hi" if "str" in str(prop.get("type", "string")) else 0
        if body:
            return json.dumps(body).encode()
    return None


AI_DOM_PATTERNS = [
    r'role=["\']assistant["\']',
    r'data-role=["\'](?:bot|assistant)["\']',
    r'aria-label=["\'][^"\']*(?:ai|assistant|chatbot)[^"\']*["\']',
    r'data-message-role=["\']assistant["\']',
    r'<form[^>]+action=["\'][^"\']*(?:chat|predict|ask)[^"\']*["\']',
]

ATLAS_TECHNIQUE_MAP = {
    "chat":      "AML.T0051 - LLM Prompt Injection",
    "ml":        "AML.T0043 - Craft Adversarial Data",
    "schema":    "AML.T0063 - Discover AI Model Outputs",
    "upload":    "AML.T0018.002 - Embed Malware via Model Upload",
    "embedding": "AML.T0043 - Craft Adversarial Data",
    "graphql":   "AML.T0051 - LLM Prompt Injection",
}


@dataclass
class EvidenceItem:
    key:       str
    detail:    str
    weight:    int
    source:    str
    endpoint:  str = ""
    framework: str = ""
    evidence_class: str = ""

    @staticmethod
    def make(key: str, detail: str, source: str,
             endpoint: str = "", framework: str = "") -> "EvidenceItem":
        return EvidenceItem(
            key=key, detail=detail,
            weight=evidence_weight(key),
            source=source, endpoint=endpoint, framework=framework,
            evidence_class=classify_evidence(key).value,
        )


@dataclass
class AuthSignal:
    endpoint:    str
    auth_type:   str
    status_code: int
    detail:      str


ENDPOINT_TYPE_RULES: List[Tuple[re.Pattern, str, str]] = [
    # Segment-aware: /chat matches /chat or /chat/... but NOT /chatflows.
    (re.compile(r"/(?:chat|completions|generate|messages|ask|conversation|prediction|predict)(?:/|$)", re.I),
     "inference",  "critical"),
    (re.compile(r"/(?:embed|embeddings?)(?:/|$)", re.I),                           "embedding",  "high"),
    (re.compile(r"/(?:pull|push|delete|copy|create|import)(?:/|$)", re.I),         "management", "critical"),
    (re.compile(r"/(?:models?|tags|version|health|info|config)(?:/|$)", re.I),     "metadata",   "medium"),
    (re.compile(r"/(?:tool|function|plugin|action|execute|run)(?:/|$)", re.I),     "tool",       "high"),
    (re.compile(r"/(?:memory|store|recall|history)(?:/|$)", re.I),                 "memory",     "high"),
    (re.compile(r"/(?:search|retrieve|vector|rag)(?:/|$)", re.I),                  "retrieval",  "high"),
    (re.compile(r"/(?:agents?|orchestrat|workflow|plan)(?:/|$)", re.I),            "agentic",    "high"),
    (re.compile(r"/(?:upload|file|image|audio|vision)(?:/|$)", re.I),              "multimodal", "medium"),
    (re.compile(r"/(?:graphql|query)(?:/|$)", re.I),                               "graphql",    "high"),
    (re.compile(r"/(?:chatflows|flows|components|nodes|openapi|swagger|docs|schema)(?:/|$)", re.I),
     "schema",     "low"),
]


@dataclass
class EndpointRecord:
    url:           str
    path:          str
    endpoint_type: str
    risk:          str
    auth_required: bool = False
    auth_type:     str  = ""
    status_code:   int  = 200
    verified:      bool = True


def classify_endpoint(url: str, auth_signals: List[AuthSignal] = None) -> EndpointRecord:
    path = urllib.parse.urlparse(url).path
    ep_type = "unknown"
    risk    = "low"
    for pattern, t, r in ENDPOINT_TYPE_RULES:
        if pattern.search(path):
            ep_type = t
            risk    = r
            break

    auth_required = False
    auth_type     = ""
    for sig in (auth_signals or []):
        if sig.endpoint == url:
            auth_required = True
            auth_type     = sig.auth_type
            break

    return EndpointRecord(
        url=url, path=path,
        endpoint_type=ep_type, risk=risk,
        auth_required=auth_required, auth_type=auth_type,
    )


@dataclass
class FingerprintReport:
    is_ai_powered:    bool
    confidence:       str

    framework:            str   = ""
    framework_confidence: float = 0.0
    framework_signals:    List[str] = field(default_factory=list)
    protocol:             str   = ""
    inference_server:     str   = ""
    model_reported:       str   = ""

    infra_layer: str = ""
    app_layer:   str = ""

    capabilities:  List[str] = field(default_factory=list)

    ml_endpoints:           List[str]         = field(default_factory=list)
    classified_endpoints:   List[EndpointRecord] = field(default_factory=list)
    discovered_paths:       List[str]         = field(default_factory=list)
    auth_required_paths:    List[AuthSignal]  = field(default_factory=list)

    frameworks_detected: List[str] = field(default_factory=list)
    openapi_schema:      Dict       = field(default_factory=dict)
    graphql_types:       List[str]  = field(default_factory=list)
    technologies:        List[str]  = field(default_factory=list)
    deployment_signals:  Dict       = field(default_factory=dict)

    evidence_items:   List[EvidenceItem] = field(default_factory=list)
    atlas_techniques: List[str]          = field(default_factory=list)
    page_title:       str                = ""
    spa_catch_all:    bool               = False
    app_description:  str                = ""

    has_live_surface: bool = False
    ai_brand_only:    bool = False
    detection:        str  = "not_detected"
    evidence_classes: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "is_ai_powered":          self.is_ai_powered,
            "detection":              self.detection,
            "confidence":             self.confidence,
            "has_live_surface":       self.has_live_surface,
            "ai_brand_only":          self.ai_brand_only,
            "evidence_classes":       self.evidence_classes,
            "framework":              self.framework,
            "framework_confidence":   round(self.framework_confidence * 100, 1),
            "framework_signals":      self.framework_signals,
            "protocol":               self.protocol,
            "inference_server":       self.inference_server,
            "infra_layer":            self.infra_layer,
            "app_layer":              self.app_layer,
            "model_reported":         self.model_reported,
            "capabilities":           self.capabilities,
            "ml_endpoints":           self.ml_endpoints,
            "classified_endpoints": [
                {"url": e.url, "path": e.path, "type": e.endpoint_type,
                 "risk": e.risk, "auth_required": e.auth_required,
                 "auth_type": e.auth_type}
                for e in self.classified_endpoints
            ],
            "discovered_paths": self.discovered_paths,
            "auth_required_paths": [
                {"endpoint": a.endpoint, "auth_type": a.auth_type,
                 "status_code": a.status_code, "detail": a.detail}
                for a in self.auth_required_paths
            ],
            "frameworks_detected": self.frameworks_detected,
            "openapi_schema":      self.openapi_schema,
            "graphql_types":       self.graphql_types,
            "deployment_signals":  self.deployment_signals,
            "page_title":          self.page_title,
            "spa_catch_all":       self.spa_catch_all,
            "technologies":        self.technologies,
            "api_schema":          {"tools": [], "openapi": self.openapi_schema},
            "app_description":     self.app_description,
            "response_headers":    {},
            "chat_components":     [],
            "atlas_techniques":    self.atlas_techniques,
            "evidence_items": [
                {"key": e.key, "detail": e.detail, "weight": e.weight,
                 "evidence_class": e.evidence_class,
                 "source": e.source, "endpoint": e.endpoint, "framework": e.framework}
                for e in sorted(self.evidence_items, key=lambda x: x.weight, reverse=True)
            ],
        }

    def print_report(self) -> None:
        w = 62
        print(f"\n{'='*w}")
        print(f"  AI Fingerprint Report")
        print(f"{'='*w}")
        print(f"  Detection        : {self.detection.upper()}  (confidence={self.confidence})")
        print(f"  Live surface     : {self.has_live_surface}")
        if self.ai_brand_only:
            print(f"  Brand only       : True")
        if self.framework:
            pct = f"{self.framework_confidence*100:.0f}%"
            print(f"  Framework        : {self.framework}  (confidence {pct})")
            if self.framework_signals:
                print(f"  Matched signals  : {', '.join(self.framework_signals)}")
        if self.protocol:
            print(f"  Protocol         : {self.protocol}")
        if self.infra_layer and self.infra_layer != self.framework:
            print(f"  Infra layer      : {self.infra_layer}")
        if self.app_layer:
            print(f"  App layer        : {self.app_layer}")
        if self.model_reported:
            print(f"  Model            : {self.model_reported}")
        if self.capabilities:
            print(f"  Capabilities     : {', '.join(self.capabilities)}")
        if self.classified_endpoints:
            print(f"  Endpoints ({len(self.classified_endpoints)}):")
            risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
            for ep in sorted(self.classified_endpoints,
                             key=lambda e: risk_order.get(e.risk, 9)):
                auth_tag = f" [{ep.auth_type}]" if ep.auth_required else " [no auth]"
                print(f"    [{ep.risk.upper():8s}] {ep.endpoint_type:12s} {ep.path}{auth_tag}")
        if self.auth_required_paths:
            print(f"  Auth-gated       : {len(self.auth_required_paths)} endpoint(s) (not tested)")
        if self.deployment_signals:
            print(f"  Deployment       : {self.deployment_signals}")
        print(f"\n  Evidence (top 8):")
        for ev in sorted(self.evidence_items, key=lambda x: x.weight, reverse=True)[:8]:
            print(f"    [{ev.evidence_class:12s}] [{ev.source:10s}]  {ev.detail[:60]}")
        print(f"{'='*w}\n")


class AIFingerprintAgent:

    def __init__(
        self,
        timeout: int = 8,
        max_js_bundles: int = 3,
        max_js_bundle_bytes: int = 200_000,
        run_behavioral_probes: bool = True,
        probe_prompt: str = "In one sentence, describe the ocean.",
        probe_model: str = "gpt-3.5-turbo",
        nondeterminism_samples: int = 3,
        nondeterminism_low: float = 0.15,
        nondeterminism_high: float = 0.98,
    ):
        self.timeout                = timeout
        self.max_js_bundles         = max_js_bundles
        self.max_js_bundle_bytes    = max_js_bundle_bytes
        self.run_behavioral_probes  = run_behavioral_probes
        self.probe_prompt           = probe_prompt
        self.probe_model            = probe_model
        self.nondeterminism_samples = nondeterminism_samples
        self.nondeterminism_low     = nondeterminism_low
        self.nondeterminism_high    = nondeterminism_high

    async def fingerprint(
        self,
        target_url: str,
        discovered_endpoints: List[Dict] = None,
        page_html: str = "",
        response_headers: Dict = None,
        verbose: bool = False,
    ) -> Dict:
        report = await self._fingerprint_internal(
            target_url, discovered_endpoints or [],
            page_html, response_headers or {}, verbose)
        if verbose:
            report.print_report()
        return report.to_dict()

    async def _fingerprint_internal(
        self,
        target_url: str,
        discovered_endpoints: List[Dict],
        page_html: str,
        response_headers: Dict,
        verbose: bool,
    ) -> FingerprintReport:
        base = target_url.rstrip("/")

        if not page_html:
            # Bare urllib must not block the SSE event loop / heartbeats.
            loop = asyncio.get_event_loop()
            status, page_headers, page_html = await loop.run_in_executor(
                None, lambda: self._fetch(base, max_bytes=200_000))
            if not response_headers:
                response_headers = page_headers
            if not page_html:
                logger.warning(
                    "[fingerprint] empty root page body from %s (HTTP %s) — "
                    "host unreachable or returned no content",
                    base, status)

        spa_catch_all = await self._detect_spa_catch_all(base)
        if spa_catch_all and verbose:
            print("    [spa] catch-all/SPA fallback detected — using content-based probes")

        js_urls, html_evidence, extracted_links, page_title = (
            self._analyse_html(page_html, base, response_headers)
        )
        if spa_catch_all:
            html_evidence.append(EvidenceItem.make(
                "spa_catch_all",
                "SPA/catch-all routing detected (canary path returned app shell)",
                "passive"))

        # Phase 1 — discover application-specific candidates (no path catalog spray).
        parallel = await asyncio.gather(
            self._fetch_and_analyse_js(js_urls, base, verbose),
            self._fetch_robots_sitemap(base, verbose),
            self._analyse_headers_cookies(response_headers, verbose),
            return_exceptions=True,
        )
        js_r, passive_r, header_r = parallel

        all_evidence: List[EvidenceItem] = list(html_evidence)
        ml_endpoints:    List[str]  = []
        discovered_paths: List[str] = []
        all_frameworks:  List[str]  = []
        auth_signals:    List[AuthSignal] = []
        openapi_schema:  Dict       = {}
        graphql_types:   List[str]  = []
        js_api_paths:    List[str]  = []
        raw_html_js = ""
        candidates: List[str] = list(extracted_links)

        for r in [js_r, passive_r, header_r]:
            if isinstance(r, dict):
                all_evidence.extend(r.get("evidence", []))
                all_frameworks.extend(r.get("frameworks", []))

        if isinstance(js_r, dict):
            js_api_paths = js_r.get("api_paths", [])
            raw_html_js  = js_r.get("raw_js", "")
            discovered_paths.extend(js_api_paths)
            candidates.extend(js_api_paths)

        if isinstance(passive_r, dict):
            # Always record discovered paths for reporting; only probe
            # inference-shaped ones (status codes on /features/ are noise).
            for path in passive_r.get("paths", []) or []:
                discovered_paths.append(path)
                if _is_inference_path(path):
                    candidates.append(path)

        for ep in discovered_endpoints or []:
            url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
            if not url:
                continue
            path = urllib.parse.urlparse(url).path if "://" in url else url
            if path:
                candidates.append(path)
                discovered_paths.append(path)

        # Spec / GraphQL refs only if this app's HTML/JS/discovery mentioned them.
        surface_blob = "\n".join([
            page_html or "",
            raw_html_js or "",
            "\n".join(candidates),
        ])
        spec_refs = self._extract_spec_refs(surface_blob)
        graphql_refs = self._extract_graphql_refs(surface_blob)
        # Also treat discovered candidates that look like specs/graphql.
        for path in candidates:
            pl = path.lower()
            if any(x in pl for x in ("openapi", "swagger", "api-docs")):
                spec_refs.append(path)
            if "graphql" in pl or "graphiql" in pl:
                graphql_refs.append(path)

        openapi_r = await self._probe_openapi(
            base, self._normalize_candidate_paths(spec_refs), verbose)
        graphql_r = await self._probe_graphql(
            base, self._normalize_candidate_paths(graphql_refs), verbose)

        if isinstance(openapi_r, dict):
            all_evidence.extend(openapi_r.get("evidence", []))
            if openapi_r.get("found"):
                openapi_schema = openapi_r.get("schema", {})
                for ep in openapi_r.get("endpoints", []) or []:
                    path = urllib.parse.urlparse(ep).path if ep.startswith("http") else ep
                    if path:
                        candidates.append(path)
                        discovered_paths.append(path)

        if isinstance(graphql_r, dict):
            all_evidence.extend(graphql_r.get("evidence", []))
            graphql_types = graphql_r.get("types", [])
            for ep in graphql_r.get("endpoints", []) or []:
                path = urllib.parse.urlparse(ep).path if ep.startswith("http") else ep
                if path:
                    candidates.append(path)
                    discovered_paths.append(path)

        candidates = self._normalize_candidate_paths(candidates)
        if verbose:
            print(f"    [discover] {len(candidates)} candidate path(s) from app surface")

        # Phase 2 — probe only what this application exposed.
        if candidates:
            probe_r = await self._probe_candidates(
                base, candidates, verbose, spa_catch_all=spa_catch_all,
                openapi_schema=openapi_schema)
            if isinstance(probe_r, dict):
                all_evidence.extend(probe_r.get("evidence", []))
                ml_endpoints.extend(probe_r.get("endpoints", []))
                all_frameworks.extend(probe_r.get("frameworks", []))
                auth_signals.extend(probe_r.get("auth_signals", []))

        # Auth-gated AI endpoints are still AI surfaces — track them as endpoints.
        for sig in auth_signals:
            if sig.endpoint and sig.endpoint not in ml_endpoints:
                ml_endpoints.append(sig.endpoint)

        behav_r = None
        auth_urls = {a.endpoint for a in auth_signals}
        open_targets = [e for e in ml_endpoints if e not in auth_urls]
        if self.run_behavioral_probes and open_targets:
            behav_r = await self._behavioral_probes(open_targets[:2], verbose)
            if isinstance(behav_r, dict):
                all_evidence.extend(behav_r.get("evidence", []))
            nd_r = await self._nondeterminism_probe(open_targets[0], verbose)
            if isinstance(nd_r, dict):
                all_evidence.extend(nd_r.get("evidence", []))

        ml_endpoints     = list(dict.fromkeys(ml_endpoints))
        discovered_paths = list(dict.fromkeys(discovered_paths))
        all_frameworks   = list(dict.fromkeys(all_frameworks))

        # Deduplicate auth signals by endpoint.
        seen_auth: Set[str] = set()
        deduped_auth: List[AuthSignal] = []
        for sig in auth_signals:
            if sig.endpoint in seen_auth:
                continue
            seen_auth.add(sig.endpoint)
            deduped_auth.append(sig)
        auth_signals = deduped_auth

        framework_result = self._identify_protocol(
            page_html, raw_html_js, response_headers,
            ml_endpoints + discovered_paths, all_evidence)
        all_evidence.extend(framework_result.get("evidence", []))
        detected_framework   = framework_result.get("framework", "")
        detected_protocol    = framework_result.get("protocol", "")
        detected_infra       = framework_result.get("inference_server", "")

        # Live surface: evidence keys OR inference-shaped endpoints/auth only.
        # Non-inference AuthSignals (e.g. /admin 401) must not flip is_ai.
        evidence_keys = [ev.key for ev in all_evidence]
        live_from_keys = has_live_surface_evidence(evidence_keys)

        def _ep_path(ep: str) -> str:
            return urllib.parse.urlparse(ep).path if "://" in ep else ep

        live_from_ml = any(_is_inference_path(_ep_path(ep)) for ep in ml_endpoints)
        live_from_auth = any(
            _is_inference_path(_ep_path(sig.endpoint)) for sig in auth_signals
        )
        has_live_surface = live_from_keys or live_from_ml or live_from_auth

        if detected_framework and detected_framework not in all_frameworks:
            all_frameworks.insert(0, detected_framework)
        if detected_protocol and detected_protocol not in all_frameworks:
            all_frameworks.append(detected_protocol)

        capabilities = self._infer_capabilities(
            detected_framework, all_frameworks, openapi_schema,
            ml_endpoints, graphql_types)

        # Deduplicate evidence
        seen_ev: Set[Tuple[str, str]] = set()
        deduped_evidence: List[EvidenceItem] = []
        for ev in all_evidence:
            k = (ev.key, ev.detail)
            if k in seen_ev:
                continue
            seen_ev.add(k)
            deduped_evidence.append(ev)
        all_evidence = deduped_evidence

        # Taxonomy scoring
        evidence_keys = [ev.key for ev in all_evidence]
        detection = score_evidence(evidence_keys)
        confidence = detection.confidence
        ai_brand_only = detection.brand_only and not has_live_surface
        is_ai = has_live_surface

        atlas: List[str] = []
        for ep in ml_endpoints:
            path = urllib.parse.urlparse(ep).path.lower()
            if any(x in path for x in ["/chat", "/completions", "/generate", "/messages",
                                       "/ask", "/prediction", "/run"]):
                atlas.append(ATLAS_TECHNIQUE_MAP["chat"])
            elif any(x in path for x in ["/embed", "/embedding"]):
                atlas.append(ATLAS_TECHNIQUE_MAP["embedding"])
            else:
                atlas.append(ATLAS_TECHNIQUE_MAP["ml"])
        if openapi_schema:
            atlas.append(ATLAS_TECHNIQUE_MAP["schema"])
        if graphql_types:
            atlas.append(ATLAS_TECHNIQUE_MAP["graphql"])
        atlas = list(dict.fromkeys(atlas))

        model_reported = ""
        if isinstance(behav_r, dict):
            model_reported = behav_r.get("model_reported", "")

        classified = [
            classify_endpoint(ep, auth_signals)
            for ep in ml_endpoints
        ]

        deployment = {}
        for ev in all_evidence:
            if ev.source == "header" and "framework" in ev.key:
                deployment["server_header"] = ev.detail
            if "docker" in ev.detail.lower() or "container" in ev.detail.lower():
                deployment["containerized"] = True
        if spa_catch_all:
            deployment["spa_catch_all"] = True
        if auth_signals:
            deployment["authentication"] = list({a.auth_type for a in auth_signals})
        else:
            deployment["authentication"] = ["none"]

        PROTOCOL_LABELS = {"OpenAI-compatible", "chat_api"}
        infra_layer = detected_framework if detected_framework in PROTOCOL_LABELS else detected_infra
        app_layer   = ""

        meta_desc = ""
        m_desc = re.search(
            r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']',
            page_html or "", re.I)
        if not m_desc:
            m_desc = re.search(
                r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']description["\']',
                page_html or "", re.I)
        if m_desc:
            meta_desc = m_desc.group(1)[:240]

        return FingerprintReport(
            is_ai_powered         = is_ai,
            confidence            = confidence,
            framework             = detected_framework,
            framework_confidence  = framework_result.get("framework_confidence", 0.0),
            framework_signals     = framework_result.get("framework_signals", []),
            protocol              = detected_protocol,
            inference_server      = detected_infra,
            infra_layer           = infra_layer,
            app_layer             = app_layer,
            model_reported        = model_reported,
            capabilities          = capabilities,
            ml_endpoints          = ml_endpoints,
            classified_endpoints  = classified,
            discovered_paths      = discovered_paths,
            auth_required_paths   = auth_signals,
            frameworks_detected   = all_frameworks,
            openapi_schema        = openapi_schema,
            graphql_types         = graphql_types,
            technologies          = all_frameworks,
            deployment_signals    = deployment,
            evidence_items        = all_evidence,
            atlas_techniques      = atlas,
            page_title            = page_title,
            spa_catch_all         = spa_catch_all,
            app_description       = meta_desc,
            has_live_surface      = has_live_surface,
            ai_brand_only         = ai_brand_only,
            detection             = detection.detection.value,
            evidence_classes      = detection.classes,
        )

    def _analyse_html(
        self, html: str, base: str, headers: Dict
    ) -> Tuple[List[str], List[EvidenceItem], List[str], str]:
        """Return (js_urls, evidence, links, page_title)."""
        evidence: List[EvidenceItem] = []
        js_urls:  List[str]          = []
        links:    List[str]          = []
        page_title = ""

        if not html:
            return js_urls, evidence, links, page_title

        m_title = re.search(r"<title[^>]*>([^<]+)</title>", html, re.I)
        if m_title:
            page_title = re.sub(r"\s+", " ", m_title.group(1)).strip()
            title_low = page_title.lower()
            if any(kw in title_low for kw in AI_TITLE_KEYWORDS):
                evidence.append(EvidenceItem.make(
                    "page_title_ai", f"AI page title: {page_title[:80]}", "html"))
        else:
            title_low = ""

        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            src = m.group(1)
            if src.startswith("http://") or src.startswith("https://"):
                pass
            elif src.startswith("/"):
                src = base.rstrip("/") + src
            else:
                src = base.rstrip("/") + "/" + src
            if any(x in src for x in [
                "/assets/", "/static/", "/dist/", "/js/", "/build/",
                "/_next/", ".bundle.", "chunk", "main.", "app.", "index.",
                "/gradio_api/",
            ]):
                js_urls.append(src)
            elif src.endswith(".js") and (
                urllib.parse.urlparse(src).netloc == ""
                or urllib.parse.urlparse(src).netloc == urllib.parse.urlparse(base).netloc
            ):
                js_urls.append(src)

        for m in re.finditer(
            r'<meta[^>]+content=["\']([^"\']*(?:ai|llm|gpt|chatbot|assistant|'
            r'inference|embedding|language model)[^"\']*)["\']',
            html, re.I,
        ):
            evidence.append(EvidenceItem.make(
                "meta_ai_tag", f"AI meta tag: {m.group(1)[:60]}", "html"))

        for pattern in AI_DOM_PATTERNS:
            m = re.search(pattern, html, re.I)
            if m:
                ev_key = "html_ai_form" if "form" in pattern else "dom_assistant_role"
                evidence.append(EvidenceItem.make(ev_key, m.group(0)[:60], "html"))

        for m in re.finditer(r'href=["\']([^"\'#?]+)["\']', html, re.I):
            href = m.group(1)
            if href.startswith("/") and any(
                x in href.lower() for x in [
                    "/chat", "/api", "/playground", "/workspace",
                    "/dashboard", "/app", "/assistant", "/flow",
                    "/openapi", "/swagger", "/graphql", "/v1/", "/v2/",
                ]
            ):
                links.append(href)

        return (
            list(dict.fromkeys(js_urls)),
            evidence,
            list(dict.fromkeys(links)),
            page_title,
        )

    async def _detect_spa_catch_all(self, base: str) -> bool:
        loop = asyncio.get_event_loop()
        try:
            status, headers, body = await loop.run_in_executor(
                None, lambda: self._fetch(base + SPA_CANARY_PATH))
            if status == 200 and _looks_html_body(
                headers.get("Content-Type", "") or headers.get("content-type", ""),
                body,
            ):
                return True
            # Some SPAs return 200 with the same shell even for JSON Accept.
            if status == 200 and body and len(body) > 200:
                root_status, _, root_body = await loop.run_in_executor(
                    None, lambda: self._fetch(base))
                if root_status == 200 and root_body and body[:500] == root_body[:500]:
                    return True
        except Exception:
            pass
        return False

    async def _fetch_and_analyse_js(
        self, js_urls: List[str], base: str, verbose: bool
    ) -> Dict:
        evidence:   List[EvidenceItem] = []
        api_paths:  List[str]          = []
        frameworks: List[str]          = []
        raw_js_combined = ""

        loop = asyncio.get_event_loop()

        async def fetch_js(url: str) -> Tuple[str, str]:
            try:
                _, _, body = await loop.run_in_executor(
                    None, lambda: self._fetch(url, max_bytes=self.max_js_bundle_bytes))
                return url, body
            except Exception:
                return url, ""

        bundles = await asyncio.gather(
            *[fetch_js(u) for u in js_urls[: self.max_js_bundles * 3]],
            return_exceptions=True)

        processed = 0
        for item in bundles:
            if processed >= self.max_js_bundles:
                break
            if isinstance(item, Exception) or not isinstance(item, tuple):
                continue
            url, js = item
            if not js:
                continue
            processed += 1
            raw_js_combined += js[:50_000]

            if verbose:
                print(f"    [js] {url[-60:]} ({len(js)} bytes)")

            for sdk_name, patterns in ML_LIBRARY_JS_SIGNATURES.items():
                for pat in patterns:
                    if pat.lower() in js.lower():
                        evidence.append(EvidenceItem.make(
                            "js_ai_sdk", f"SDK: {sdk_name}", "js_bundle",
                            endpoint=url, framework=sdk_name))
                        frameworks.append(sdk_name)
                        break

            extracted = self._extract_api_paths_from_js(js)
            api_paths.extend(extracted)
            if extracted:
                evidence.append(EvidenceItem.make(
                    "js_api_path_extracted",
                    f"{len(extracted)} AI API path(s) in JS bundle",
                    "js_bundle", endpoint=url))

            for m in re.finditer(
                r'new\s+EventSource\s*\(\s*["\`]([^"\'`]+)["\`]', js, re.I):
                path = m.group(1).split("${")[0]
                if self._looks_api_candidate(path):
                    evidence.append(EvidenceItem.make(
                        "sse_in_js", f"EventSource({path[:50]})",
                        "js_bundle", endpoint=url))
                    api_paths.append(self._to_path(path))

            for m in re.finditer(
                r'new\s+WebSocket\s*\(\s*["\`]([^"\'`]+)["\`]', js, re.I):
                path = m.group(1)
                if any(x in path for x in ["/chat", "/ws", "/stream", "/agent"]):
                    evidence.append(EvidenceItem.make(
                        "websocket_ai_path", f"WebSocket({path[:50]})",
                        "js_bundle", endpoint=url))

        return {
            "evidence":  evidence,
            "api_paths": list(dict.fromkeys(api_paths)),
            "frameworks": list(dict.fromkeys(frameworks)),
            "raw_js":    raw_js_combined,
        }

    def _extract_api_paths_from_js(self, js: str) -> List[str]:
        found: Set[str] = set()
        # Explicit HTTP client calls.
        for m in re.finditer(
            r'(?:fetch|axios(?:\.get|\.post|\.put|\.delete|\.patch)?|'
            r'\$\.ajax|\$\.get|\$\.post)\s*\(\s*["\']([^"\']+)["\']',
            js, re.I,
        ):
            path = m.group(1)
            if self._looks_api_candidate(path):
                found.add(self._to_path(path))
        for m in re.finditer(
            r'(?:fetch|axios)\s*\(\s*`([^`]+)`', js):
            path = m.group(1).split("${")[0].rstrip("/")
            if self._looks_api_candidate(path):
                found.add(self._to_path(path))
        for m in re.finditer(
            r'\.open\s*\(\s*["\'][A-Z]+["\'],\s*["\']([^"\']+)["\']', js, re.I):
            path = m.group(1)
            if self._looks_api_candidate(path):
                found.add(self._to_path(path))
        # Quoted absolute paths that look like API routes (app-specific).
        for m in re.finditer(r'["\'](/[a-zA-Z0-9_\-./]{2,120})["\']', js):
            path = m.group(1).split("?")[0]
            if self._looks_api_candidate(path):
                found.add(self._to_path(path))
        return list(found)

    @staticmethod
    def _to_path(path: str) -> str:
        p = path.strip()
        if p.startswith("http://") or p.startswith("https://"):
            p = urllib.parse.urlparse(p).path
        if not p.startswith("/"):
            p = "/" + p.lstrip("/")
        return p.split("?")[0].split("#")[0] or "/"

    @staticmethod
    def _looks_api_candidate(path: str) -> bool:
        """Heuristic: keep likely API/route strings; drop static assets."""
        p = (path or "").strip()
        if not p or len(p) > 180:
            return False
        pl = p.lower()
        if any(pl.endswith(ext) for ext in (
            ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".ico", ".woff", ".woff2", ".ttf", ".mp4", ".webp",
        )):
            return False
        if any(x in pl for x in (
            "/assets/", "/static/", "/_next/", "/dist/", "/node_modules/",
            "webpack", "chunk",
        )):
            return False
        # Prefer paths that look routable / API-like.
        if pl.startswith("/") or pl.startswith("http"):
            return True
        return False

    @staticmethod
    def _guess_probe_category(path: str) -> str:
        p = (path or "").lower()
        if "embed" in p:
            return "embedding"
        if "graphql" in p or p.endswith("/query"):
            return "graphql"
        if any(x in p for x in (
            "chat", "completion", "generate", "ask", "message", "predict",
            "prediction", "run", "invoke", "queue", "agent", "llm",
        )):
            return "chat"
        if any(x in p for x in (
            "model", "tag", "health", "openapi", "swagger", "docs", "config",
            "info", "flow", "node", "workspace", "endpoint", "convo", "schema",
        )):
            return "schema"
        # Unknown paths must not be assumed chat — schema has stricter body gates.
        return "schema"

    @staticmethod
    def _normalize_candidate_paths(paths: List[str]) -> List[str]:
        out: List[str] = []
        seen = set()
        for raw in paths:
            if not raw:
                continue
            path = raw
            if "://" in path:
                path = urllib.parse.urlparse(path).path
            path = path if path.startswith("/") else "/" + path.lstrip("/")
            path = path.split("?")[0].split("#")[0]
            if not path or path == "/" or path in seen:
                continue
            if any(path.lower().endswith(ext) for ext in (
                ".js", ".css", ".map", ".png", ".jpg", ".svg", ".ico",
            )):
                continue
            seen.add(path)
            out.append(path)
        # Prefer likely inference paths first for faster confirmation.
        def _rank(p: str) -> Tuple[int, str]:
            pl = p.lower()
            if any(x in pl for x in ("chat", "completion", "generate", "predict", "ask", "run")):
                return (0, p)
            if any(x in pl for x in ("model", "flow", "agent", "message")):
                return (1, p)
            return (2, p)
        return sorted(out, key=_rank)[:80]

    @staticmethod
    def _extract_spec_refs(text: str) -> List[str]:
        found: List[str] = []
        for m in _SPEC_REF_RE.finditer(text or ""):
            found.append(m.group("path").split("?")[0])
        # Also catch quoted relative filenames without leading path noise.
        for m in re.finditer(
            r"""["']([^"']*(?:openapi|swagger)[^"']*\.(?:json|yaml|yml))["']""",
            text or "", re.I,
        ):
            p = m.group(1)
            if not p.startswith("/"):
                p = "/" + p.lstrip("./")
            found.append(p.split("?")[0])
        return found

    @staticmethod
    def _extract_graphql_refs(text: str) -> List[str]:
        found: List[str] = []
        for m in _GRAPHQL_REF_RE.finditer(text or ""):
            found.append(m.group("path").split("?")[0])
        return found

    async def _probe_openapi(
        self, base: str, spec_paths: List[str], verbose: bool
    ) -> Dict:
        """Fetch OpenAPI only at paths this application referenced."""
        evidence:     List[EvidenceItem] = []
        endpoints:    List[str]          = []
        capabilities: List[str]          = []
        schema:       Dict               = {}
        loop = asyncio.get_event_loop()

        if not spec_paths:
            return {
                "found": False, "evidence": evidence,
                "endpoints": endpoints, "capabilities": capabilities, "schema": schema,
            }

        for path in spec_paths:
            url = base + path
            try:
                status, _, body = await loop.run_in_executor(
                    None, lambda u=url: self._fetch(u, max_bytes=500_000))
                if status != 200 or not body:
                    continue
                spec = None
                try:
                    spec = json.loads(body)
                except json.JSONDecodeError:
                    if body.strip().startswith("openapi:"):
                        spec = self._parse_minimal_yaml_openapi(body)
                if not isinstance(spec, dict):
                    continue
                if not (spec.get("openapi") or spec.get("swagger") or spec.get("paths")):
                    continue
                schema = spec
                spec_path_map = spec.get("paths", {})
                evidence.append(EvidenceItem.make(
                    "openapi_schema",
                    f"OpenAPI spec at {path} ({len(spec_path_map)} paths)",
                    "openapi", endpoint=url))
                for ep_path, methods in spec_path_map.items():
                    endpoints.append(base + ep_path)
                    if any(x in ep_path.lower() for x in [
                        "/chat", "/completions", "/generate", "/embed",
                        "/predict", "/inference", "/model", "/messages",
                    ]):
                        evidence.append(EvidenceItem.make(
                            "openapi_ai_endpoint",
                            f"AI path in spec: {ep_path}",
                            "openapi", endpoint=base + ep_path))
                    if isinstance(methods, dict):
                        for method_def in methods.values():
                            if not isinstance(method_def, dict):
                                continue
                            props = ((method_def.get("requestBody", {}) or {})
                                     .get("content", {})
                                     .get("application/json", {})
                                     .get("schema", {})
                                     .get("properties", {}))
                            if "tools" in props or "functions" in props:
                                capabilities.append("tool_calling")
                            if "messages" in props:
                                capabilities.append("chat")
                            if "input" in props and "model" in props:
                                capabilities.append("embedding")
                if verbose:
                    print(f"    [openapi] {path}: {len(spec_path_map)} paths")
                break
            except Exception as exc:
                logger.debug(f"[OpenAPI] {url}: {exc}")

        return {
            "found": bool(schema), "evidence": evidence,
            "endpoints": list(dict.fromkeys(endpoints)),
            "capabilities": list(dict.fromkeys(capabilities)),
            "schema": schema,
        }

    @staticmethod
    def _parse_minimal_yaml_openapi(yaml_text: str) -> Optional[Dict]:
        result: Dict = {}
        paths: Dict  = {}
        for line in yaml_text.splitlines()[:30]:
            m = re.match(r'^(\w+)\s*:\s*(.+)$', line)
            if m:
                result[m.group(1)] = m.group(2).strip().strip('"\'')
        for line in yaml_text.splitlines():
            m = re.match(r'^  (/[^\s:]+)\s*:', line)
            if m:
                paths[m.group(1)] = {}
        if paths:
            result["paths"] = paths
        return result if result else None

    async def _probe_graphql(
        self, base: str, graphql_paths: List[str], verbose: bool
    ) -> Dict:
        """Probe GraphQL only at paths this application referenced."""
        evidence: List[EvidenceItem] = []
        endpoints: List[str]         = []
        types:     List[str]         = []
        loop = asyncio.get_event_loop()

        if not graphql_paths:
            return {"evidence": evidence, "endpoints": endpoints, "types": types}

        introspection_query = json.dumps({
            "query": "{ __schema { queryType { name } types { name } } }"
        }).encode()

        for path in graphql_paths:
            url = base + path
            try:
                status, resp_headers, body = await loop.run_in_executor(
                    None, lambda u=url: self._fetch(
                        u, data=introspection_query, method="POST",
                        max_bytes=50_000))
                if status not in (200, 400):
                    continue
                ct = resp_headers.get("Content-Type", "").lower()
                if "json" not in ct and status != 200:
                    continue
                try:
                    data = json.loads(body)
                except Exception:
                    continue

                schema_data = data.get("data", {})
                if schema_data and "__schema" in schema_data:
                    evidence.append(EvidenceItem.make(
                        "graphql_schema",
                        f"GraphQL introspection at {path}",
                        "graphql", endpoint=url))
                    endpoints.append(url)
                    gql_types = [
                        t.get("name", "") for t in
                        schema_data.get("__schema", {}).get("types", [])
                        if t.get("name", "")
                    ]
                    types.extend(gql_types)
                    ai_types = [t for t in gql_types if any(
                        x in t.lower() for x in
                        ["chat", "message", "conversation", "completion",
                         "embedding", "tool", "agent", "model", "stream"]
                    )]
                    if ai_types:
                        evidence.append(EvidenceItem.make(
                            "graphql_ai_field",
                            f"AI-related GraphQL types: {ai_types[:5]}",
                            "graphql", endpoint=url))
                    if verbose:
                        print(f"    [graphql] {path}: {len(gql_types)} types, "
                              f"ai={ai_types[:3]}")
                    break

                if status == 400 and "errors" in body.lower():
                    evidence.append(EvidenceItem.make(
                        "graphql_schema",
                        f"GraphQL endpoint at {path} (introspection disabled)",
                        "graphql", endpoint=url))
                    endpoints.append(url)
                    break

            except Exception:
                pass

        return {"evidence": evidence, "endpoints": endpoints, "types": types}

    async def _fetch_robots_sitemap(self, base: str, verbose: bool) -> Dict:
        evidence: List[EvidenceItem] = []
        paths:    List[str]          = []
        loop = asyncio.get_event_loop()

        try:
            _, _, body = await loop.run_in_executor(
                None, lambda: self._fetch(base + "/robots.txt"))
            if body:
                for line in body.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/" and self._looks_api_candidate(path):
                            evidence.append(EvidenceItem.make(
                                "robots_ai_path",
                                f"robots.txt {line[:60]}",
                                "passive"))
                            paths.append(self._to_path(path))
                    if line.lower().startswith("sitemap:"):
                        sitemap_url = line.split(":", 1)[1].strip()
                        try:
                            _, _, smap = await loop.run_in_executor(
                                None, lambda u=sitemap_url: self._fetch(u, max_bytes=50_000))
                            for m in re.finditer(r'<loc>([^<]+)</loc>', smap):
                                url = m.group(1).strip()
                                parsed = urllib.parse.urlparse(url)
                                if parsed.path and self._looks_api_candidate(parsed.path):
                                    evidence.append(EvidenceItem.make(
                                        "sitemap_ai_path",
                                        f"sitemap: {parsed.path[:60]}",
                                        "passive"))
                                    paths.append(self._to_path(parsed.path))
                        except Exception:
                            pass
        except Exception:
            pass

        return {"evidence": evidence, "paths": list(dict.fromkeys(paths))}

    async def _probe_candidates(
        self, base: str, candidates: List[str], verbose: bool,
        spa_catch_all: bool = False,
        openapi_schema: Optional[Dict] = None,
    ) -> Dict:
        """Probe application-discovered paths only — no catalog spray."""
        evidence:    List[EvidenceItem] = []
        endpoints:   List[str]          = []
        frameworks:  List[str]          = []
        auth_signals: List[AuthSignal]  = []
        loop = asyncio.get_event_loop()

        async def probe(path: str, category: str):
            url = base + path
            try:
                status, resp_headers, body = await loop.run_in_executor(
                    None, lambda: self._fetch(url))
                ct = (resp_headers.get("Content-Type")
                      or resp_headers.get("content-type") or "")
                needs_post = (
                    status in (404, 405)
                    or (status == 200 and _looks_html_body(ct, body))
                    or (spa_catch_all and status == 200 and category in (
                        "chat", "embedding", "ml", "graphql", "schema"))
                )
                if needs_post:
                    post_body = _probe_post_body(path, category, openapi_schema)
                    status, resp_headers, body = await loop.run_in_executor(
                        None,
                        lambda u=url, d=post_body: self._fetch(u, data=d, method="POST"),
                    )
                return self._evaluate_probe_response(
                    url, path, category, status, resp_headers, body,
                    auth_signals, spa_catch_all=spa_catch_all)
            except Exception:
                return None

        tasks = [
            probe(path, self._guess_probe_category(path))
            for path in candidates
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict) and r:
                evidence.extend(r.get("evidence", []))
                endpoints.extend(r.get("endpoints", []))
                frameworks.extend(r.get("frameworks", []))

        if verbose:
            print(f"    [probe] confirmed {len(set(endpoints))} live surface(s) "
                  f"from {len(candidates)} candidate(s)")

        return {
            "evidence":    evidence,
            "endpoints":   list(dict.fromkeys(endpoints)),
            "frameworks":  list(dict.fromkeys(frameworks)),
            "auth_signals": auth_signals,
        }

    def _evaluate_probe_response(
        self,
        url: str,
        path: str,
        category: str,
        status: int,
        headers: Dict,
        body: str,
        auth_signals: List[AuthSignal],
        spa_catch_all: bool = False,
    ) -> Dict:
        evidence:  List[EvidenceItem] = []
        endpoints: List[str]          = []
        frameworks: List[str]         = []

        if status == 0:
            return {}

        headers_low = {k.lower(): v for k, v in headers.items()}
        ct = headers_low.get("content-type", "")
        body_l = (body or "").lower()

        # SPA HTML responses are not API evidence.
        if _looks_html_body(ct, body):
            return {}

        if status == 200 and body:
            is_json = "json" in ct or body.strip()[:1] in "{["
            ai_shaped = is_json and _looks_ai_api_json(body)
            # 200 live-surface evidence requires an AI-shaped body — status alone
            # on an inference path is not enough (matches 401/405 path-shape gate).
            if ai_shaped:
                ev_key = ("chat_endpoint_200" if category == "chat" or _is_inference_path(path) else
                          "embedding_endpoint_200" if category == "embedding" else
                          "ml_endpoint_200")
                evidence.append(EvidenceItem.make(
                    ev_key,
                    f"AI body at {path} (HTTP 200)",
                    "probe", endpoint=url))
                endpoints.append(url)
                if category in ("chat", "schema") or _is_inference_path(path):
                    frameworks.append("OpenAI-compatible")

            if "text/event-stream" in ct:
                evidence.append(EvidenceItem.make(
                    "sse_streaming_header",
                    f"SSE at {path}", "probe", endpoint=url))
                endpoints.append(url)

            if "chunked" in headers_low.get("transfer-encoding", ""):
                evidence.append(EvidenceItem.make(
                    "sse_chunked_transfer",
                    f"Chunked transfer at {path}", "probe", endpoint=url))

            # Schema/config endpoints with AI-shaped JSON only.
            if (category == "schema" and ai_shaped and url not in endpoints):
                evidence.append(EvidenceItem.make(
                    "ml_endpoint_200",
                    f"AI schema/config at {path} (HTTP 200)",
                    "probe", endpoint=url))
                endpoints.append(url)
                if any(k in body_l for k in ("choices", '"object"', "chat.completion")):
                    frameworks.append("OpenAI-compatible")

        if status in (401, 403):
            auth_type = self._detect_auth_type(headers_low, body_l)
            auth_signals.append(AuthSignal(
                endpoint=url, auth_type=auth_type,
                status_code=status,
                detail=f"Auth required ({auth_type}) at {path}"))
            # Auth is always recorded; AI live-surface only on inference paths.
            if _is_inference_path(path):
                evidence.append(EvidenceItem.make(
                    "ml_endpoint_401_403",
                    f"Auth-gated {path} (HTTP {status}, {auth_type})",
                    "probe", endpoint=url))
                endpoints.append(url)

        # 405 is noise on SPA catch-alls and on non-inference paths.
        if (status == 405 and not spa_catch_all and _is_inference_path(path)):
            evidence.append(EvidenceItem.make(
                "ml_endpoint_405",
                f"Endpoint exists {path} (HTTP 405)",
                "probe", endpoint=url))
            endpoints.append(url)

        if status in (400, 422) and body:
            fw = self._fingerprint_error_body(body, url, evidence)
            if fw:
                frameworks.append(fw)
                if url not in endpoints:
                    endpoints.append(url)
            elif category in ("chat", "embedding", "ml") and (
                "json" in ct or body.strip()[:1] in "{["
            ):
                # Handler reached with validation error => real API surface.
                evidence.append(EvidenceItem.make(
                    "error_generic_validation",
                    f"API validation response at {path} (HTTP {status})",
                    "probe", endpoint=url))
                endpoints.append(url)

        for h in AI_RESPONSE_HEADERS:
            if h in headers_low:
                evidence.append(EvidenceItem.make(
                    "ai_response_header",
                    f"{h}: {headers_low[h][:50]}",
                    "probe", endpoint=url))
                endpoints.append(url)
                break

        return {
            "evidence":  evidence,
            "endpoints": list(dict.fromkeys(endpoints)),
            "frameworks": frameworks,
        }

    @staticmethod
    def _detect_auth_type(headers_low: Dict, body_l: str) -> str:
        www_auth = headers_low.get("www-authenticate", "").lower()
        if "bearer" in www_auth or "jwt" in body_l or "token" in www_auth:
            return "bearer"
        if "api" in www_auth and "key" in www_auth:
            return "api_key"
        if "basic" in www_auth:
            return "basic"
        if "oauth" in www_auth or "oauth" in body_l:
            return "oauth"
        if "session" in body_l or "cookie" in body_l:
            return "cookie"
        return "unknown"

    def _fingerprint_error_body(
        self, body: str, url: str, evidence: List[EvidenceItem]
    ) -> Optional[str]:
        for pattern, ev_key, framework in ERROR_FINGERPRINTS:
            if pattern.search(body):
                evidence.append(EvidenceItem.make(
                    ev_key,
                    f"{framework} error at {urllib.parse.urlparse(url).path}",
                    "probe", endpoint=url, framework=framework))
                return framework
        return None

    async def _behavioral_probes(
        self, candidate_endpoints: List[str], verbose: bool
    ) -> Dict:
        evidence:      List[EvidenceItem] = []
        model_reported: str              = ""
        loop = asyncio.get_event_loop()

        PROBE_A = json.dumps({
            "model": "gpt-3.5-turbo",
            "messages": [{"role": "user", "content": "Hello"}],
        }).encode()

        PROBE_B = json.dumps({
            "model": "gpt-3.5-turbo",
            "messages": [{"role": "user", "content": "What model are you?"}],
        }).encode()

        for endpoint in candidate_endpoints[:2]:
            for probe_name, probe_data in [("hello", PROBE_A), ("model_query", PROBE_B)]:
                try:
                    status, resp_headers, body = await loop.run_in_executor(
                        None, lambda u=endpoint, d=probe_data: self._fetch(
                            u, data=d, method="POST"))
                    if status not in (200, 201):
                        continue

                    text = ""
                    try:
                        parsed = json.loads(body)
                        text = (
                            parsed.get("choices", [{}])[0]
                            .get("message", {}).get("content", "")
                            or parsed.get("response", "")
                            or parsed.get("message", {}).get("content", "")
                            or body
                        )
                    except Exception:
                        text = body

                    if not text:
                        continue

                    if probe_name == "hello":
                        if any(re.search(sig, text, re.I) for sig in LLM_RESPONSE_SIGNALS):
                            evidence.append(EvidenceItem.make(
                                "behavior_llm_response",
                                f"LLM-shaped response to 'Hello' at "
                                f"{urllib.parse.urlparse(endpoint).path}",
                                "behavior", endpoint=endpoint))
                            if verbose:
                                print(f"    [behavior] LLM response at {endpoint}")

                    if probe_name == "model_query":
                        for pattern in MODEL_NAME_PATTERNS:
                            m = re.search(pattern, text, re.I)
                            if m:
                                model_reported = m.group(0)
                                evidence.append(EvidenceItem.make(
                                    "behavior_model_reported",
                                    f"Model self-report: {model_reported}",
                                    "behavior", endpoint=endpoint))
                                if verbose:
                                    print(f"    [behavior] model={model_reported}")
                                break

                    ct = resp_headers.get("Content-Type", "").lower()
                    if "event-stream" in ct:
                        evidence.append(EvidenceItem.make(
                            "behavior_streaming",
                            f"Streaming response at "
                            f"{urllib.parse.urlparse(endpoint).path}",
                            "behavior", endpoint=endpoint))

                except Exception as e:
                    logger.debug(f"Behavioral probe failed on {endpoint}: {e}")

        return {"evidence": evidence, "model_reported": model_reported}

    async def _nondeterminism_probe(self, endpoint: str, verbose: bool) -> Dict:
        evidence: List[EvidenceItem] = []
        loop = asyncio.get_event_loop()
        payload = json.dumps({
            "model": self.probe_model,
            "messages": [{"role": "user", "content": self.probe_prompt}],
        }).encode()

        responses: List[str] = []
        for _ in range(max(2, self.nondeterminism_samples)):
            try:
                status, _, body = await loop.run_in_executor(
                    None,
                    lambda ep=endpoint, data=payload: self._fetch(
                        ep, data=data, method="POST"),
                )
                if status in (200, 201) and body:
                    text = self._extract_text(body)
                    if text:
                        responses.append(text)
            except Exception:
                continue

        if len(responses) < 2:
            return {"evidence": evidence}

        divergences = [
            self._token_divergence(responses[i], responses[j])
            for i in range(len(responses))
            for j in range(i + 1, len(responses))
        ]
        mean_div = sum(divergences) / len(divergences)
        if self.nondeterminism_low < mean_div < self.nondeterminism_high:
            evidence.append(EvidenceItem.make(
                "behavior_nondeterministic",
                f"Non-deterministic output over {len(responses)} samples "
                f"(mean divergence {mean_div:.2f})",
                "behavior", endpoint=endpoint))
            if verbose:
                print(f"    [behavior] non-determinism at {endpoint} div={mean_div:.2f}")
        return {"evidence": evidence}

    @staticmethod
    def _token_divergence(a: str, b: str) -> float:
        ta = set(re.findall(r"\w+", a.lower()))
        tb = set(re.findall(r"\w+", b.lower()))
        if not ta and not tb:
            return 0.0
        if not ta or not tb:
            return 1.0
        return 1.0 - len(ta & tb) / len(ta | tb)

    @staticmethod
    def _extract_text(body: str) -> str:
        try:
            data = json.loads(body)
        except Exception:
            return body
        if isinstance(data, dict):
            choices = data.get("choices")
            if isinstance(choices, list) and choices:
                message = choices[0].get("message", {})
                if isinstance(message, dict) and message.get("content"):
                    return str(message["content"])
                if choices[0].get("text"):
                    return str(choices[0]["text"])
            for candidate in ("response", "answer", "text", "generated_text"):
                if data.get(candidate):
                    return str(data[candidate])
            message = data.get("message", {})
            if isinstance(message, dict) and message.get("content"):
                return str(message["content"])
        return body

    async def _analyse_headers_cookies(
        self, headers: Dict, verbose: bool
    ) -> Dict:
        evidence:   List[EvidenceItem] = []
        frameworks: List[str]          = []
        headers_low = {k.lower(): v for k, v in headers.items()}

        for h in AI_RESPONSE_HEADERS:
            if h in headers_low:
                evidence.append(EvidenceItem.make(
                    "ai_response_header",
                    f"{h}: {headers_low[h][:50]}", "header"))
                break

        return {"evidence": evidence, "frameworks": list(dict.fromkeys(frameworks))}

    def _identify_protocol(
        self,
        html: str,
        js: str,
        headers: Dict,
        known_endpoints: List[str],
        existing_evidence: List[EvidenceItem],
    ) -> Dict:
        """Label protocol from live evidence shapes — not path catalogs."""
        evidence: List[EvidenceItem] = []
        keys = {ev.key for ev in existing_evidence}
        signals: List[str] = []
        framework = ""
        protocol = ""

        if keys & {
            "chat_endpoint_200", "error_openai_format", "error_missing_messages",
            "error_missing_model", "embedding_endpoint_200",
        }:
            framework = "OpenAI-compatible"
            protocol = "OpenAI-compatible"
            signals.append("live_surface")
        elif "ml_endpoint_200" in keys:
            # Label-only. Bare validation / auth status codes are not enough —
            # those fire on any REST API and must not imply an AI framework.
            framework = "chat_api"
            protocol = "chat_api"
            signals.append("ai_shaped_ml_surface")

        fw_confidence = 0.8 if framework else 0.0
        if framework:
            evidence.append(EvidenceItem.make(
                "framework_identified",
                f"Protocol: {framework} signals={signals[:4]}",
                "passive", framework=framework))

        return {
            "evidence":             evidence,
            "framework":            framework,
            "framework_confidence": fw_confidence,
            "framework_signals":    signals,
            "protocol":             protocol or framework,
            "inference_server":     framework,
        }

    def _infer_capabilities(
        self,
        framework: str,
        all_frameworks: List[str],
        openapi_schema: Dict,
        endpoints: List[str],
        graphql_types: List[str],
    ) -> List[str]:
        caps: Set[str] = set()

        if framework in ("OpenAI-compatible", "chat_api"):
            caps.add("chat")

        if openapi_schema:
            caps.add("chat")
            spec_paths = openapi_schema.get("paths", {})
            for path in spec_paths:
                path_l = path.lower()
                if "embed" in path_l:
                    caps.add("embedding")
                if "image" in path_l or "vision" in path_l:
                    caps.add("image_generation")
                if "audio" in path_l or "speech" in path_l:
                    caps.add("speech")
                if "search" in path_l:
                    caps.add("web_search")
                if "tool" in path_l or "function" in path_l:
                    caps.add("tool_calling")
                if "memory" in path_l or "remember" in path_l:
                    caps.add("memory")

        for ep in endpoints:
            path = urllib.parse.urlparse(ep).path.lower()
            if "embed" in path:
                caps.add("embedding")
            if "rag" in path or "retriev" in path or "vector" in path:
                caps.add("rag")
            if "memory" in path:
                caps.add("memory")
            if "agent" in path:
                caps.add("multi_agent")
            if "tool" in path:
                caps.add("tool_calling")
            if "code" in path or "exec" in path:
                caps.add("code_execution")

        for t in graphql_types:
            t_l = t.lower()
            if "chat" in t_l or "message" in t_l:
                caps.add("chat")
            if "tool" in t_l:
                caps.add("tool_calling")
            if "embed" in t_l:
                caps.add("embedding")
            if "agent" in t_l:
                caps.add("multi_agent")

        return sorted(cap for cap in caps if cap in KNOWN_CAPABILITIES)

    async def _confirm_js_extracted_paths(
        self, base: str, paths: List[str], verbose: bool
    ) -> Dict:
        return await self._confirm_js_paths(base, paths, verbose)

    async def _confirm_js_paths(
        self, base: str, paths: List[str], verbose: bool,
        spa_catch_all: bool = False,
    ) -> Dict:
        evidence:  List[EvidenceItem] = []
        endpoints: List[str]          = []
        auth_signals: List[AuthSignal] = []
        loop = asyncio.get_event_loop()

        async def probe(path: str):
            if not path.startswith("/"):
                path = "/" + path.lstrip("/")
            url = base + path
            try:
                status, hdrs, body = await loop.run_in_executor(
                    None, lambda: self._fetch(
                        url, data=b"{}", method="POST"))
                ct = hdrs.get("Content-Type") or hdrs.get("content-type") or ""
                if status == 0 or _looks_html_body(ct, body):
                    status, hdrs, body = await loop.run_in_executor(
                        None, lambda: self._fetch(url))
                r = self._evaluate_probe_response(
                    url, path, "chat", status, hdrs, body, auth_signals,
                    spa_catch_all=spa_catch_all)
                if r:
                    evidence.extend(r.get("evidence", []))
                    endpoints.extend(r.get("endpoints", []))
            except Exception:
                pass

        await asyncio.gather(*[probe(p) for p in paths[:8]], return_exceptions=True)
        return {
            "evidence": evidence,
            "endpoints": list(dict.fromkeys(endpoints)),
            "auth_signals": auth_signals,
        }

    async def _check_discovered_endpoints(
        self, endpoints: List[Dict]
    ) -> Dict:
        evidence:    List[EvidenceItem] = []
        ml_endpoints: List[str]         = []
        loop = asyncio.get_event_loop()

        for ep in (endpoints or []):
            url    = ep.get("url", "")
            status = ep.get("status", 0)
            if status == 200:
                try:
                    _, hdrs, body = await loop.run_in_executor(
                        None, lambda u=url: self._fetch(u))
                    if "json" in hdrs.get("Content-Type", "").lower() and body:
                        if any(re.search(p, body, re.I)
                               for p in AI_RESPONSE_BODY_PATTERNS):
                            ml_endpoints.append(url)
                            path = urllib.parse.urlparse(url).path
                            evidence.append(EvidenceItem.make(
                                "ml_endpoint_200",
                                f"AI body at discovered endpoint {path}",
                                "probe", endpoint=url))
                except Exception:
                    pass

        return {"evidence": evidence, "endpoints": list(dict.fromkeys(ml_endpoints))}

    def _fetch(
        self,
        url: str,
        max_bytes: int = 8192,
        method: str = "GET",
        data: Optional[bytes] = None,
    ) -> Tuple[int, Dict, str]:
        def _once(target: str) -> Tuple[int, Dict, str]:
            req = urllib.request.Request(
                target, data=data,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; AISecurityScanner/1.0)",
                    "Accept":     "text/html,application/json,application/xhtml+xml,*/*;q=0.8",
                    **({"Content-Type": "application/json"} if data else {}),
                },
                method=method,
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read(max_bytes).decode("utf-8", errors="replace")
                return resp.status, dict(resp.headers), body

        try:
            return _once(url)
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(max(2048, max_bytes)).decode("utf-8", errors="replace")
            except Exception:
                body = ""
            return exc.code, dict(exc.headers) if exc.headers else {}, body
        except Exception as exc:
            # localhost often resolves to ::1 first; retry 127.0.0.1 for dual-stack hosts.
            alt = None
            if "://localhost" in url.lower() or "://[::1]" in url.lower():
                alt = (url.replace("://localhost", "://127.0.0.1")
                          .replace("://Localhost", "://127.0.0.1")
                          .replace("://[::1]", "://127.0.0.1"))
            if alt and alt != url:
                try:
                    return _once(alt)
                except urllib.error.HTTPError as exc2:
                    try:
                        body = exc2.read(max(2048, max_bytes)).decode("utf-8", errors="replace")
                    except Exception:
                        body = ""
                    return exc2.code, dict(exc2.headers) if exc2.headers else {}, body
                except Exception as exc2:
                    logger.warning("[fingerprint] fetch failed %s (%s); retry %s also failed (%s)",
                                   url, exc, alt, exc2)
                    return 0, {}, ""
            logger.warning("[fingerprint] fetch failed %s: %s", url, exc)
            return 0, {}, ""