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

logger = logging.getLogger(__name__)

# Negative-control path — must never exist on a real target.
SCANNER_CANARY_PATH = (
    "/__scanner_canary_nonexistent_check_xyz789_do_not_create_this_route"
)

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


@dataclass
class ProbeCanary:
    """Negative-control baseline for seed-path probes.

    CDN/WAF marketing sites often return the same status for every unknown
    path (301 catch-all) or every POST (blanket 403). Anything matching the
    canary is noise, not an auth-gated AI surface.
    """
    get_status: int = 0
    post_status: int = 0
    get_body_prefix: str = ""
    post_body_prefix: str = ""

    @property
    def redirect_catch_all(self) -> bool:
        return self.get_status in _REDIRECT_STATUSES

    @property
    def post_waf_catch_all(self) -> bool:
        return self.post_status in (401, 403)


EVIDENCE_WEIGHTS: Dict[str, int] = {
    "openapi_schema":           18,
    "openapi_ai_endpoint":      14,
    "graphql_schema":           14,
    "graphql_ai_field":         12,

    "framework_identified":     30,
    "framework_header":         15,
    "framework_cookie":         10,

    "behavior_llm_response":    22,
    "behavior_model_reported":  20,
    "behavior_streaming":       14,

    "chat_endpoint_200":        14,
    "embedding_endpoint_200":   10,
    "tool_endpoint_200":        10,
    "ml_endpoint_200":           8,
    "ml_endpoint_401_403":       6,
    "ml_endpoint_405":           5,

    "error_openai_format":      12,
    "error_missing_messages":   10,
    "error_missing_model":       8,
    "error_triton_format":       8,
    "error_huggingface_format":  7,
    "error_generic_validation":  4,

    "sse_streaming_header":     10,
    "sse_chunked_transfer":      8,
    "sse_in_js":                 6,
    "websocket_ai_path":         6,

    "ai_response_header":        7,

    "js_ai_sdk":                 7,
    "js_api_path_extracted":     5,

    "robots_ai_path":            5,
    "sitemap_ai_path":           4,
    "csp_ai_domain":             6,
    "meta_ai_tag":               4,
    "favicon_known_framework":   5,
    "page_title_ai":             8,
    "dom_assistant_role":        3,
    "html_ai_form":              3,

    # Chatbot UI channel (Playwright / static HTML) — ordinal tiers.
    "behavior_chatbot_ui_confirmed": 22,
    "chatbot_ui_live_surface":       14,
    "chatbot_ui_structural":          6,
    "chatbot_ui_hint":                2,
    "chatbot_ui_third_party":         1,
}

# Generic title cues only — never product/application brand names.
AI_TITLE_KEYWORDS = (
    "llm", "gpt", "chatbot", "assistant", "copilot", "rag", "inference",
)

CONFIDENCE_BANDS = [
    (100, "very_high"),
    ( 65, "high"),
    ( 40, "medium"),
    ( 20, "low"),
    (  0, "none"),
]


def score_to_confidence(score: int) -> str:
    for threshold, label in CONFIDENCE_BANDS:
        if score >= threshold:
            return label
    return "none"


# Protocol / response-shape signatures only — no product/application names.
# Naming here is a protocol label (e.g. OpenAI-compatible), never an app brand.
FRAMEWORK_SIGNATURES: Dict[str, Dict] = {
    "OpenAI-compatible": {
        "paths": [
            "/v1/chat/completions", "/v1/completions", "/v1/models",
            "/v1/embeddings", "/api/chat/completions",
        ],
        "body_patterns": [
            r'"choices"\s*:\s*\[',
            r'"object"\s*:\s*"chat\.completion"',
            r'"finish_reason"',
        ],
        "capabilities": ["chat", "embedding", "image_generation"],
    },
}


LIVE_SURFACE_EVIDENCE_KEYS = {
    "behavior_llm_response",
    "behavior_model_reported",
    "behavior_streaming",
    "chat_endpoint_200",
    "embedding_endpoint_200",
    "tool_endpoint_200",
    "ml_endpoint_200",
    "ml_endpoint_401_403",
    # Bare HTTP 405 is NOT live surface — CDNs often 405 every unknown POST.
    "openapi_schema",
    "openapi_ai_endpoint",
    "graphql_schema",
    "graphql_ai_field",
    "error_openai_format",
    "error_missing_messages",
    "error_missing_model",
    "sse_streaming_header",
    "ai_response_header",
    "behavior_chatbot_ui_confirmed",
    "chatbot_ui_live_surface",
}

_INFERENCE_PATH_RE = re.compile(
    r"/(?:chat|completions?|generate|messages|ask|predict(?:ion)?|"
    r"embeddings?|inference|invoke|run|agents?|convos?|conversations?)\b",
    re.I,
)


def _is_inference_path(path: str) -> bool:
    return bool(_INFERENCE_PATH_RE.search(path or ""))


MODEL_NAME_PATTERNS = [
    r'\b(gpt-?4|gpt-?3\.5|gpt-?4o)\b',
    r'\b(claude-?3|claude-?3\.5|claude-?sonnet|claude-?opus|claude-?haiku)\b',
    r'\b(llama-?[23]|llama-?\d)',
    r'\b(mistral|mixtral)\b',
    r'\b(gemma|gemini)\b',
    r'\b(qwen\d?|qwen-?\d)',
    r'\b(phi-?\d|phi-?3)\b',
    r'\b(deepseek)\b',
    r'\b(command-?r)\b',
]

EXTENDED_CAPABILITIES = [
    "chat", "rag", "tool_calling", "memory", "code_execution",
    "email_send", "web_search", "browser", "sql", "filesystem",
    "shell", "python", "image_generation", "vision", "speech",
    "audio", "calendar", "slack", "github", "vector_db",
    "mcp", "workflow", "multi_agent", "embedding", "terminal",
    "cloud", "image_input",
]

AI_RESPONSE_BODY_PATTERNS = [
    r'"choices"\s*:\s*\[',
    r'"prompt_tokens"\s*:',
    r'"completion_tokens"\s*:',
    r'"finish_reason"\s*:',
    r'"usage"\s*:\s*\{',
    r'"model"\s*:\s*"[^"]{2,}"',
    r'"models"\s*:\s*\[',
    r'"logits"\s*:',
    r'"embeddings"\s*:',
    r'"probabilities"\s*:',
    r'"predictions"\s*:',
    r'"done"\s*:\s*(?:true|false)',
    r'"done_reason"\s*:',
    r'"total_duration"\s*:',
    r'"eval_count"\s*:',
    r'"object"\s*:\s*"(?:model|list|chat\.completion|text_completion)',
    r'"chatId"\s*:',
    r'"sourceDocuments"\s*:',
    r'"agentReasoning"\s*:',
    r'"tool_calls"\s*:',
    r'"function_call"\s*:',
    r'"input_tokens"\s*:',
    r'"output_tokens"\s*:',
    r'"chunk"\s*:',
    r'"retrieval"\s*:',
    r'"generated_text"\s*:',
]

LLM_RESPONSE_SIGNALS = [
    r"\bI\s+(?:am|can|will|don'?t|cannot|understand)\b",
    r"\bAs\s+an?\s+(?:AI|assistant|language model)\b",
    r"\bI'?m\s+(?:here|happy|glad|sorry)\b",
    r"\bHow\s+(?:can|may)\s+I\s+(?:help|assist)\b",
    r"\bThank\s+you\s+for\b",
    r"\bIs\s+there\s+anything\b",
]

ERROR_FINGERPRINTS: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r'"error"\s*:\s*\{.*?"type"\s*:', re.S),
     "error_openai_format", "OpenAI-compatible"),
    (re.compile(r'"messages"\s*.*?(required|missing|must be)', re.I),
     "error_missing_messages", "chat_api"),
    (re.compile(r'"model"\s*.*?(required|missing|must be)', re.I),
     "error_missing_model", "OpenAI-compatible"),
    (re.compile(r'"error"\s*:\s*"Request for unknown model', re.I),
     "error_triton_format", "Triton"),
    (re.compile(r'"error"\s*:\s*"Input validation error', re.I),
     "error_huggingface_format", "HuggingFace-TGI"),
    (re.compile(r'"detail"\s*:.*?"msg"\s*:', re.S),
     "error_generic_validation", "FastAPI/Pydantic"),
]

AI_RESPONSE_HEADERS = [
    "x-model-version", "x-model-id", "x-inference-time", "x-ai-backend",
    "x-ml-model", "x-openai-model", "x-anthropic-model", "openai-model",
    "openai-version", "x-inference-id", "x-model-name", "x-prediction-id",
    "x-ollama-version",
]

AI_CSP_DOMAINS = [
    "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com",
    "api.cohere.ai", "api.mistral.ai", "api.groq.com", "api.together.xyz",
    "api.replicate.com", "api.perplexity.ai", "api.huggingface.co",
]

ML_LIBRARY_JS_SIGNATURES: Dict[str, List[str]] = {
    "OpenAI JS SDK":    ["openai.min.js", "from 'openai'", 'from "openai"', "new OpenAI("],
    "Anthropic JS SDK": ["@anthropic-ai/sdk", "new Anthropic("],
    "Cohere JS":        ["cohere-ai", "new CohereClient"],
    "LangChain JS":     ["langchain", "@langchain/core"],
    "Transformers.js":  ["@xenova/transformers", "transformers.js"],
    "TensorFlow.js":    ["@tensorflow/tfjs", "tf.tensor"],
    "ONNX Runtime":     ["onnxruntime-web", "ort.InferenceSession"],
    "Replicate JS":     ["replicate", "new Replicate("],
    "Groq JS":          ["groq-sdk", "new Groq("],
    "Mistral JS":       ["@mistralai/mistralai", "new MistralClient"],
    "Vercel AI SDK":    ["ai/react", "useChat(", "useCompletion("],
}

SEED_ENDPOINT_RANKING: List[Tuple[str, str]] = [
    ("/openapi.json",         "schema"),
    ("/swagger.json",         "schema"),
    ("/api-docs",             "schema"),
    ("/api/openapi.json",     "schema"),
    ("/graphql",              "graphql"),
    ("/api/graphql",          "graphql"),
    ("/v1/chat/completions",  "chat"),
    ("/api/chat/completions", "chat"),
    ("/api/chat",             "chat"),
    ("/v1/completions",       "chat"),
    ("/v1/embeddings",        "embedding"),
    ("/api/embeddings",       "embedding"),
    ("/api/v1/prediction",    "chat"),
    ("/api/generate",         "chat"),
    ("/api/tags",             "schema"),
    ("/v1/models",            "schema"),
    ("/api/models",           "schema"),
    ("/v2/health/ready",      "schema"),
    ("/v2/models",            "schema"),
    ("/api/predict",          "ml"),
    ("/predict",              "ml"),
    ("/invocations",          "ml"),
    ("/predictions",          "ml"),
    ("/runs",                 "chat"),
    ("/threads",              "chat"),
    # Common chat/agent path shapes (product-agnostic)
    ("/api/ask",              "chat"),
    ("/api/messages",         "chat"),
    ("/api/convos",           "schema"),
    ("/api/endpoints",        "schema"),
    ("/api/agents",           "chat"),
    ("/api/workspace",        "schema"),
    ("/api/chat-messages",    "chat"),
]

OPENAPI_SPEC_PATHS = [
    "/openapi.json", "/openapi.yaml",
    "/swagger.json", "/swagger.yaml",
    "/api-docs", "/api/docs",
    "/api/openapi.json", "/api/openapi.yaml",
    "/v1/openapi.json", "/v3/api-docs",
    "/docs/openapi.json",
]

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

    @staticmethod
    def make(key: str, detail: str, source: str,
             endpoint: str = "", framework: str = "") -> "EvidenceItem":
        return EvidenceItem(
            key=key, detail=detail,
            weight=EVIDENCE_WEIGHTS.get(key, 0),
            source=source, endpoint=endpoint, framework=framework,
        )


@dataclass
class AuthSignal:
    endpoint:    str
    auth_type:   str
    status_code: int
    detail:      str


ENDPOINT_TYPE_RULES: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"/(chat|completions|generate|messages|ask|conversation)", re.I), "inference",  "critical"),
    (re.compile(r"/(embed|embedding)", re.I),                                      "embedding",  "high"),
    (re.compile(r"/(pull|push|delete|copy|create|import)", re.I),                  "management", "critical"),
    (re.compile(r"/(model|models|tags|version|health|info|config)", re.I),         "metadata",   "medium"),
    (re.compile(r"/(tool|function|plugin|action|execute|run)", re.I),              "tool",       "high"),
    (re.compile(r"/(memory|store|recall|history)", re.I),                          "memory",     "high"),
    (re.compile(r"/(search|retrieve|vector|rag)", re.I),                           "retrieval",  "high"),
    (re.compile(r"/(agent|orchestrat|workflow|plan)", re.I),                       "agentic",    "high"),
    (re.compile(r"/(upload|file|image|audio|vision)", re.I),                       "multimodal", "medium"),
    (re.compile(r"/(graphql|query)", re.I),                                        "graphql",    "high"),
    (re.compile(r"/(openapi|swagger|docs|schema)", re.I),                          "schema",     "low"),
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
    evidence_score:   int

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
    chat_components:  List[Dict]         = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "is_ai_powered":          self.is_ai_powered,
            "confidence":             self.confidence,
            "evidence_score":         self.evidence_score,
            "framework":              self.framework if self.framework_confidence > 0 else "",
            "framework_confidence":   round(self.framework_confidence * 100, 1),
            "framework_signals":      (
                self.framework_signals if self.framework_confidence > 0 else []
            ),
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
            "page_title":          "",
            "technologies":        self.technologies,
            "api_schema":          {"tools": [], "openapi": self.openapi_schema},
            "app_description":     "",
            "response_headers":    {},
            "chat_components":     self.chat_components,
            "atlas_techniques":    self.atlas_techniques,
            "evidence_items": [
                {"key": e.key, "detail": e.detail, "weight": e.weight,
                 "source": e.source, "endpoint": e.endpoint, "framework": e.framework}
                for e in sorted(self.evidence_items, key=lambda x: x.weight, reverse=True)
            ],
        }

    def print_report(self) -> None:
        w = 62
        print(f"\n{'='*w}")
        print(f"  AI Fingerprint Report")
        print(f"{'='*w}")
        print(f"  Confidence       : {self.confidence.upper()} (score={self.evidence_score})")
        if self.framework and self.framework_confidence > 0:
            pct = f"{self.framework_confidence*100:.0f}%"
            print(f"  Framework        : {self.framework}  (confidence {pct})")
            if self.framework_signals:
                print(f"  Matched signals  : {', '.join(self.framework_signals)}")
        elif self.framework and self.framework_confidence <= 0:
            # Path-only / unconfirmed protocol labels must not look authoritative.
            pass
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
        if self.chat_components:
            print(f"  Chat UI          : {len(self.chat_components)} widget(s)")
            for w in self.chat_components[:5]:
                if not isinstance(w, dict):
                    continue
                print(
                    f"    - tier={w.get('tier') or '?'} "
                    f"scope={w.get('ownership') or w.get('scope') or '?'} "
                    f"provider={w.get('provider') or '-'} "
                    f"via={w.get('source') or '?'}"
                )
        if self.deployment_signals:
            print(f"  Deployment       : {self.deployment_signals}")
        print(f"\n  Evidence (top 8):")
        for ev in sorted(self.evidence_items, key=lambda x: x.weight, reverse=True)[:8]:
            print(f"    +{ev.weight:3d}  [{ev.source:10s}]  {ev.detail[:60]}")
        print(f"{'='*w}\n")


class AIFingerprintAgent:

    def __init__(
        self,
        timeout: int = 8,
        max_js_bundles: int = 3,
        max_js_bundle_bytes: int = 200_000,
        run_behavioral_probes: bool = True,
    ):
        self.timeout               = timeout
        self.max_js_bundles        = max_js_bundles
        self.max_js_bundle_bytes   = max_js_bundle_bytes
        self.run_behavioral_probes = run_behavioral_probes

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
            _, page_headers, page_html = self._fetch(base)
            if not response_headers:
                response_headers = page_headers

        js_urls, html_evidence, extracted_links = self._analyse_html(
            page_html, base, response_headers)

        parallel = await asyncio.gather(
            self._fetch_and_analyse_js(js_urls, base, verbose),
            self._probe_openapi(base, verbose),
            self._probe_graphql(base, verbose),
            self._fetch_robots_sitemap(base, verbose),
            self._probe_ranked_endpoints(
                base, extracted_links, verbose),
            self._analyse_headers_cookies(response_headers, verbose),
            return_exceptions=True,
        )
        js_r, openapi_r, graphql_r, passive_r, probe_r, header_r = parallel

        all_evidence: List[EvidenceItem] = list(html_evidence)
        ml_endpoints:    List[str]  = []
        discovered_paths: List[str] = []
        all_frameworks:  List[str]  = []
        auth_signals:    List[AuthSignal] = []
        openapi_schema:  Dict       = {}
        graphql_types:   List[str]  = []
        js_api_paths:    List[str]  = []
        raw_html_js = ""

        for r in [js_r, openapi_r, graphql_r, passive_r, probe_r, header_r]:
            if isinstance(r, dict):
                all_evidence.extend(r.get("evidence", []))
                ml_endpoints.extend(r.get("endpoints", []))
                all_frameworks.extend(r.get("frameworks", []))
                auth_signals.extend(r.get("auth_signals", []))

        if isinstance(js_r, dict):
            js_api_paths = js_r.get("api_paths", [])
            raw_html_js  = js_r.get("raw_js", "")
            discovered_paths.extend(js_api_paths)

        if isinstance(openapi_r, dict) and openapi_r.get("found"):
            openapi_schema = openapi_r.get("schema", {})

        if isinstance(graphql_r, dict):
            graphql_types = graphql_r.get("types", [])

        if isinstance(passive_r, dict):
            discovered_paths.extend(passive_r.get("paths", []))

        behav_r = None
        probe_targets = (ml_endpoints or [base + p for p, _ in SEED_ENDPOINT_RANKING
                                          if "chat" in _ or _ == "ml"])
        if self.run_behavioral_probes and probe_targets:
            behav_r = await self._behavioral_probes(probe_targets[:2], verbose)
            if isinstance(behav_r, dict):
                all_evidence.extend(behav_r.get("evidence", []))

        if js_api_paths:
            extra = await self._confirm_js_paths(base, js_api_paths, verbose)
            if isinstance(extra, dict):
                all_evidence.extend(extra.get("evidence", []))
                ml_endpoints.extend(extra.get("endpoints", []))

        if discovered_endpoints:
            disc_r = await self._check_discovered_endpoints(discovered_endpoints)
            if isinstance(disc_r, dict):
                all_evidence.extend(disc_r.get("evidence", []))
                ml_endpoints.extend(disc_r.get("endpoints", []))

        ml_endpoints     = list(dict.fromkeys(ml_endpoints))
        discovered_paths = list(dict.fromkeys(discovered_paths))
        all_frameworks   = list(dict.fromkeys(all_frameworks))

        framework_result = self._identify_framework(
            page_html, raw_html_js, response_headers,
            ml_endpoints + discovered_paths, all_evidence)
        all_evidence.extend(framework_result.get("evidence", []))
        detected_framework   = framework_result.get("framework", "")
        detected_protocol    = framework_result.get("protocol", "")
        detected_infra       = framework_result.get("inference_server", "")
        if detected_framework and detected_framework not in all_frameworks:
            all_frameworks.insert(0, detected_framework)
        if detected_protocol and detected_protocol not in all_frameworks:
            all_frameworks.append(detected_protocol)

        capabilities = self._infer_capabilities(
            detected_framework, all_frameworks, openapi_schema,
            ml_endpoints, graphql_types)

        # Deduplicate identical evidence rows (brand + framework probes overlap).
        seen_ev: Set[Tuple[str, str]] = set()
        deduped: List[EvidenceItem] = []
        for ev in all_evidence:
            k = (ev.key, ev.detail)
            if k in seen_ev:
                continue
            seen_ev.add(k)
            deduped.append(ev)
        all_evidence = deduped

        # Drop weak 405 spray if nothing else confirms a live AI surface.
        # Marketing CDNs often 405 every seeded inference path.
        weak_405 = [ev for ev in all_evidence if ev.key == "ml_endpoint_405"]
        has_strong_live = bool(
            ml_endpoints
            or any(_is_inference_path(urllib.parse.urlparse(a.endpoint).path)
                   for a in auth_signals)
            or any(ev.key in {
                "behavior_llm_response", "behavior_model_reported",
                "behavior_streaming", "chat_endpoint_200", "ml_endpoint_200",
                "ml_endpoint_401_403", "openapi_schema", "openapi_ai_endpoint",
                "error_openai_format", "error_missing_messages", "error_missing_model",
            } for ev in all_evidence)
        )
        if len(weak_405) >= 3 and not has_strong_live:
            all_evidence = [ev for ev in all_evidence if ev.key != "ml_endpoint_405"]

        # Static HTML chatbot widget discovery (Playwright enrich is optional
        # in the scan harness / dev_ai_scan). Passive hints alone do not flip
        # is_ai — only live_surface / behavioral chatbot tiers do.
        chat_components: List[Dict] = []
        try:
            from .chatbot_ui_probe import (
                detect_chatbot_from_html,
                evidence_key_for_tier,
                ui_warrants_vuln,
                widgets_to_chat_components,
            )
        except ImportError:
            try:
                from multiagent.agents.ai_agents.chatbot_ui_probe import (
                    detect_chatbot_from_html,
                    evidence_key_for_tier,
                    ui_warrants_vuln,
                    widgets_to_chat_components,
                )
            except ImportError:
                detect_chatbot_from_html = None  # type: ignore
                ui_warrants_vuln = None  # type: ignore

        if detect_chatbot_from_html is not None:
            try:
                widgets = detect_chatbot_from_html(page_html or "", base)
                chat_components = widgets_to_chat_components(widgets)
                for w in widgets:
                    key = evidence_key_for_tier(
                        getattr(w, "tier", "") or "passive_hint",
                        getattr(w, "scope", "") or "",
                    )
                    all_evidence.append(EvidenceItem.make(
                        key,
                        getattr(w, "detail", None)
                        or f"Chatbot UI surface ({key})",
                        "chatbot_ui",
                    ))
            except Exception as exc:
                logger.debug("chatbot HTML detect failed: %s", exc)
                chat_components = []

        total_score = sum(ev.weight for ev in all_evidence)
        confidence  = score_to_confidence(total_score)

        # Product-agnostic gate: only live behavioural / API / chatbot surface.
        evidence_keys = {ev.key for ev in all_evidence}
        live_from_keys = bool(evidence_keys & LIVE_SURFACE_EVIDENCE_KEYS)
        live_from_ml = any(
            _is_inference_path(urllib.parse.urlparse(ep).path) for ep in ml_endpoints
        )
        live_from_auth = any(
            _is_inference_path(urllib.parse.urlparse(a.endpoint).path)
            for a in auth_signals
        )
        live_from_chat_ui = bool(
            ui_warrants_vuln and ui_warrants_vuln(chat_components)
        )
        is_ai = live_from_keys or live_from_ml or live_from_auth or live_from_chat_ui

        atlas: List[str] = []
        for ep in ml_endpoints:
            path = urllib.parse.urlparse(ep).path.lower()
            if any(x in path for x in ["/chat", "/completions", "/generate", "/messages"]):
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
        if auth_signals:
            deployment["authentication"] = list({a.auth_type for a in auth_signals})
        else:
            deployment["authentication"] = ["none"]

        PROTOCOL_LABELS = {"OpenAI-compatible"}
        infra_layer = detected_framework if detected_framework in PROTOCOL_LABELS else detected_infra
        app_layer   = ""

        return FingerprintReport(
            is_ai_powered         = is_ai,
            confidence            = confidence,
            evidence_score        = total_score,
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
            chat_components       = chat_components,
        )

    def _analyse_html(
        self, html: str, base: str, headers: Dict
    ) -> Tuple[List[str], List[EvidenceItem], List[str]]:
        evidence: List[EvidenceItem] = []
        js_urls:  List[str]          = []
        links:    List[str]          = []

        if not html:
            return js_urls, evidence, links

        m_title = re.search(r"<title[^>]*>([^<]+)</title>", html, re.I)
        page_title = re.sub(r"\s+", " ", m_title.group(1)).strip() if m_title else ""
        title_low = page_title.lower()
        # Passive cue only — never sufficient alone for is_ai.
        if page_title and (
            re.search(r"(?:^|[^a-z])ai(?:[^a-z]|$)", title_low)
            or any(kw in title_low for kw in AI_TITLE_KEYWORDS)
        ):
            evidence.append(EvidenceItem.make(
                "page_title_ai", f"AI page title: {page_title[:80]}", "html"))

        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            src = m.group(1)
            if not src.startswith("http"):
                src = base + ("" if src.startswith("/") else "/") + src.lstrip("/")
            if any(x in src for x in [
                "/assets/", "/static/", "/dist/", "/js/", "/build/",
                "/_next/", ".bundle.", "chunk", "main.", "app.", "index.",
            ]):
                js_urls.append(src)

        for m in re.finditer(
            r'<meta[^>]+content=["\']([^"\']*(?:ai|llm|gpt|chatbot|assistant|'
            r'copilot|rag|inference)[^"\']*)["\']',
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
                    "/dashboard", "/app", "/assistant",
                ]
            ):
                links.append(href)

        csp_header = headers.get("Content-Security-Policy", "")
        if not csp_header:
            m = re.search(r'<meta[^>]+content=["\']([^"\']*connect-src[^"\']*)["\']',
                          html, re.I)
            if m:
                csp_header = m.group(1)
        if csp_header:
            for domain in AI_CSP_DOMAINS:
                if domain in csp_header:
                    evidence.append(EvidenceItem.make(
                        "csp_ai_domain",
                        f"CSP connect-src includes {domain}", "passive"))

        return list(dict.fromkeys(js_urls)), evidence, list(dict.fromkeys(links))

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
                if self._is_ai_api_path(path):
                    evidence.append(EvidenceItem.make(
                        "sse_in_js", f"EventSource({path[:50]})",
                        "js_bundle", endpoint=url))
                    api_paths.append(path)

            for m in re.finditer(
                r'new\s+WebSocket\s*\(\s*["\`]([^"\'`]+)["\`]', js, re.I):
                path = m.group(1)
                if any(x in path for x in ["/chat", "/ws", "/stream", "/agent"]):
                    evidence.append(EvidenceItem.make(
                        "websocket_ai_path", f"WebSocket({path[:50]})",
                        "js_bundle", endpoint=url))

            for fw_name, sig in FRAMEWORK_SIGNATURES.items():
                for gs in sig.get("js_globals", []):
                    if gs in js:
                        evidence.append(EvidenceItem.make(
                            "js_ai_sdk", f"JS global {gs} -> {fw_name}",
                            "js_bundle", framework=fw_name))
                        frameworks.append(fw_name)

        return {
            "evidence":  evidence,
            "api_paths": list(dict.fromkeys(api_paths)),
            "frameworks": list(dict.fromkeys(frameworks)),
            "raw_js":    raw_js_combined,
        }

    def _extract_api_paths_from_js(self, js: str) -> List[str]:
        found: Set[str] = set()
        for m in re.finditer(
            r'(?:fetch|axios(?:\.get|\.post)?)\s*\(\s*["\']([^"\']+)["\']', js, re.I):
            path = m.group(1)
            if self._is_ai_api_path(path):
                found.add(path if path.startswith("/") else "/" + path.lstrip("/"))
        for m in re.finditer(r'(?:fetch|axios)\s*\(\s*`([^`]+)`', js):
            path = m.group(1).split("${")[0].rstrip("/")
            if self._is_ai_api_path(path):
                found.add(path if path.startswith("/") else "/" + path.lstrip("/"))
        for m in re.finditer(
            r'\.open\s*\(\s*["\'][A-Z]+["\'],\s*["\']([^"\']+)["\']', js, re.I):
            path = m.group(1)
            if self._is_ai_api_path(path):
                found.add(path if path.startswith("/") else "/" + path.lstrip("/"))
        return list(found)

    @staticmethod
    def _is_ai_api_path(path: str) -> bool:
        """True for inference-ish path segments — not substring traps like /generated_."""
        parts = [p for p in (path or "").lower().split("/") if p]
        if not parts:
            return False
        # Exact segment hits (avoid /generated_sitemap matching /generate).
        ai_segments = {
            "chat", "completions", "completion", "generate", "predict",
            "prediction", "embeddings", "embedding", "inference", "infer",
            "messages", "message", "ask", "runs", "threads", "assistants",
            "agents", "agent", "convos", "conversations", "llm",
        }
        if any(
            seg in ai_segments or seg.split(".")[0] in ai_segments
            for seg in parts
        ):
            return True
        joined = "/" + "/".join(parts)
        return bool(_INFERENCE_PATH_RE.search(joined))

    @staticmethod
    def _is_meaningful_405(headers_low: Dict, body: str) -> bool:
        """CDN/marketing sites often return 405 for every unknown POST — ignore those."""
        allow = (headers_low.get("allow") or "").upper()
        if any(m in allow for m in ("POST", "PUT", "PATCH")):
            return True
        body = body or ""
        ct = (headers_low.get("content-type") or "").lower()
        if "json" in ct and body.strip()[:1] in ("{", "["):
            if any(re.search(p, body, re.I) for p in AI_RESPONSE_BODY_PATTERNS):
                return True
            for pattern, _, _ in ERROR_FINGERPRINTS:
                if pattern.search(body):
                    return True
        return False

    @staticmethod
    def _is_meaningful_auth(
        status: int,
        headers_low: Dict,
        body: str,
        canary: Optional[ProbeCanary] = None,
    ) -> bool:
        """401/403 counts as auth-gated AI only when it differs from WAF noise.

        Blanket CDN/WAF 403 on every POST (Freshworks-style) must not escalate.
        """
        if status not in (401, 403):
            return False
        # Negative control: same status as canary POST ⇒ WAF/bot wall, not an API.
        if canary and canary.post_status and status == canary.post_status:
            # Still allow through if the body/headers look like a real API auth challenge.
            www = (headers_low.get("www-authenticate") or "").strip()
            body = body or ""
            ct = (headers_low.get("content-type") or "").lower()
            if www:
                return True
            if "json" in ct and body.strip()[:1] in ("{", "["):
                for pattern, _, _ in ERROR_FINGERPRINTS:
                    if pattern.search(body):
                        return True
                if any(re.search(p, body, re.I) for p in AI_RESPONSE_BODY_PATTERNS):
                    return True
                # Generic {"message":"Unauthorized"} with JSON is weak but OK when
                # canary body is not JSON (differential content).
                canary_prefix = (canary.post_body_prefix or "").lstrip()
                if canary_prefix[:1] not in ("{", "["):
                    return True
            return False
        return True

    async def _calibrate_probe_canary(self, base: str) -> ProbeCanary:
        """GET + POST negative controls before trusting seed-path statuses."""
        loop = asyncio.get_event_loop()
        url = base.rstrip("/") + SCANNER_CANARY_PATH
        try:
            get_status, _, get_body = await loop.run_in_executor(
                None, lambda: self._fetch(url, method="GET", allow_redirects=False))
        except Exception:
            get_status, get_body = 0, ""
        try:
            post_status, _, post_body = await loop.run_in_executor(
                None,
                lambda: self._fetch(
                    url, method="POST", data=b"{}", allow_redirects=False,
                ),
            )
        except Exception:
            post_status, post_body = 0, ""
        canary = ProbeCanary(
            get_status=get_status or 0,
            post_status=post_status or 0,
            get_body_prefix=(get_body or "")[:120],
            post_body_prefix=(post_body or "")[:120],
        )
        if canary.redirect_catch_all or canary.post_waf_catch_all:
            logger.info(
                "[fingerprint] canary baseline get=%s post=%s redirect_all=%s post_waf=%s",
                canary.get_status, canary.post_status,
                canary.redirect_catch_all, canary.post_waf_catch_all,
            )
        return canary

    async def _probe_openapi(self, base: str, verbose: bool) -> Dict:
        evidence:     List[EvidenceItem] = []
        endpoints:    List[str]          = []
        capabilities: List[str]          = []
        schema:       Dict               = {}
        loop = asyncio.get_event_loop()

        for path in OPENAPI_SPEC_PATHS:
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
                spec_paths = spec.get("paths", {})
                evidence.append(EvidenceItem.make(
                    "openapi_schema",
                    f"OpenAPI spec at {path} ({len(spec_paths)} paths)",
                    "openapi", endpoint=url))
                for ep_path, methods in spec_paths.items():
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
                    print(f"    [openapi] {path}: {len(spec_paths)} paths")
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

    async def _probe_graphql(self, base: str, verbose: bool) -> Dict:
        evidence: List[EvidenceItem] = []
        endpoints: List[str]         = []
        types:     List[str]         = []
        loop = asyncio.get_event_loop()

        graphql_paths = ["/graphql", "/api/graphql", "/graphiql",
                         "/v1/graphql", "/query"]

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
                        if self._is_ai_api_path(path):
                            evidence.append(EvidenceItem.make(
                                "robots_ai_path",
                                f"robots.txt {line[:60]}",
                                "passive"))
                            paths.append(path)
                    if line.lower().startswith("sitemap:"):
                        sitemap_url = line.split(":", 1)[1].strip()
                        try:
                            _, _, smap = await loop.run_in_executor(
                                None, lambda u=sitemap_url: self._fetch(u, max_bytes=50_000))
                            for m in re.finditer(r'<loc>([^<]+)</loc>', smap):
                                url = m.group(1).strip()
                                parsed = urllib.parse.urlparse(url)
                                if self._is_ai_api_path(parsed.path):
                                    evidence.append(EvidenceItem.make(
                                        "sitemap_ai_path",
                                        f"sitemap: {parsed.path[:60]}",
                                        "passive"))
                                    paths.append(parsed.path)
                        except Exception:
                            pass
        except Exception:
            pass

        return {"evidence": evidence, "paths": list(dict.fromkeys(paths))}

    async def _probe_ranked_endpoints(
        self, base: str, extra_paths: List[str], verbose: bool
    ) -> Dict:
        evidence:    List[EvidenceItem] = []
        endpoints:   List[str]          = []
        frameworks:  List[str]          = []
        auth_signals: List[AuthSignal]  = []
        loop = asyncio.get_event_loop()
        confirmed = 0

        canary = await self._calibrate_probe_canary(base)
        if verbose and (canary.redirect_catch_all or canary.post_waf_catch_all):
            print(
                f"    [canary] GET={canary.get_status} POST={canary.post_status} "
                f"(redirect_all={canary.redirect_catch_all}, "
                f"post_waf={canary.post_waf_catch_all})"
            )

        ordered = (
            [(p, c) for p, c in SEED_ENDPOINT_RANKING if c == "schema"] +
            [(p, c) for p, c in SEED_ENDPOINT_RANKING if c == "chat"] +
            [(p, c) for p, c in SEED_ENDPOINT_RANKING if c in ("embedding", "ml", "graphql")]
        )

        async def probe(path: str, category: str):
            url = base + path
            try:
                status, resp_headers, body = await loop.run_in_executor(
                    None, lambda: self._fetch(url, allow_redirects=False))
                # Redirect-all CDNs: same 3xx as canary is not an endpoint hit.
                if (
                    canary.redirect_catch_all
                    and status in _REDIRECT_STATUSES
                    and status == canary.get_status
                ):
                    return {}
                if status in (404, 405) and category in ("chat", "embedding", "ml", "graphql"):
                    status, resp_headers, body = await loop.run_in_executor(
                        None,
                        lambda: self._fetch(
                            url, data=b"{}", method="POST", allow_redirects=False,
                        ),
                    )
                # Also try POST when GET is a catch-all redirect (no resource).
                elif (
                    status in _REDIRECT_STATUSES
                    and category in ("chat", "embedding", "ml", "graphql")
                ):
                    status, resp_headers, body = await loop.run_in_executor(
                        None,
                        lambda: self._fetch(
                            url, data=b"{}", method="POST", allow_redirects=False,
                        ),
                    )
                return self._evaluate_probe_response(
                    url, path, category, status, resp_headers, body,
                    auth_signals, canary=canary)
            except Exception:
                return None

        schema_paths = [(p, c) for p, c in ordered if c == "schema"]
        schema_results = await asyncio.gather(
            *[probe(p, c) for p, c in schema_paths], return_exceptions=True)
        for r in schema_results:
            if isinstance(r, dict) and r:
                evidence.extend(r.get("evidence", []))
                endpoints.extend(r.get("endpoints", []))
                frameworks.extend(r.get("frameworks", []))
                confirmed += len(r.get("endpoints", []))

        for path, category in ordered:
            if confirmed >= 6:
                break
            if category == "schema":
                continue
            r = await probe(path, category)
            if isinstance(r, dict) and r:
                evidence.extend(r.get("evidence", []))
                new_eps = r.get("endpoints", [])
                if new_eps:
                    endpoints.extend(new_eps)
                    confirmed += len(new_eps)
                frameworks.extend(r.get("frameworks", []))

        return {
            "evidence":    evidence,
            "endpoints":   list(dict.fromkeys(endpoints)),
            "frameworks":  list(dict.fromkeys(frameworks)),
            "auth_signals": auth_signals,
            "canary": canary,
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
        canary: Optional[ProbeCanary] = None,
    ) -> Dict:
        evidence:  List[EvidenceItem] = []
        endpoints: List[str]          = []
        frameworks: List[str]         = []

        if status == 0:
            return {}

        # Same redirect as canary GET ⇒ catch-all, not a real path.
        if (
            canary
            and canary.redirect_catch_all
            and status in _REDIRECT_STATUSES
            and status == canary.get_status
        ):
            return {}

        headers_low = {k.lower(): v for k, v in headers.items()}
        ct = headers_low.get("content-type", "")
        body_l = (body or "").lower()

        if status == 200 and body:
            if "json" in ct and any(re.search(p, body, re.I)
                                    for p in AI_RESPONSE_BODY_PATTERNS):
                ev_key = ("chat_endpoint_200" if category == "chat" else
                          "embedding_endpoint_200" if category == "embedding" else
                          "ml_endpoint_200")
                evidence.append(EvidenceItem.make(
                    ev_key, f"AI body at {path} (HTTP 200)",
                    "probe", endpoint=url))
                endpoints.append(url)

            if "text/event-stream" in ct:
                evidence.append(EvidenceItem.make(
                    "sse_streaming_header",
                    f"SSE at {path}", "probe", endpoint=url))
                endpoints.append(url)

            if "chunked" in headers_low.get("transfer-encoding", ""):
                evidence.append(EvidenceItem.make(
                    "sse_chunked_transfer",
                    f"Chunked transfer at {path}", "probe", endpoint=url))

        if status in (401, 403):
            if not self._is_meaningful_auth(status, headers_low, body or "", canary):
                return {
                    "evidence": evidence,
                    "endpoints": endpoints,
                    "frameworks": frameworks,
                }
            auth_type = self._detect_auth_type(headers_low, body_l)
            auth_signals.append(AuthSignal(
                endpoint=url, auth_type=auth_type,
                status_code=status,
                detail=f"Auth required ({auth_type}) at {path}"))
            if category in ("chat", "embedding", "ml", "graphql"):
                evidence.append(EvidenceItem.make(
                    "ml_endpoint_401_403",
                    f"Auth-gated {path} (HTTP {status}, {auth_type})",
                    "probe", endpoint=url))
                # Auth-gated inference paths are live surface even without a body.
                endpoints.append(url)

        if status == 405 and category in ("chat", "embedding", "ml"):
            # Ignore CDN/marketing catch-all 405s (Zendesk-style FP).
            if self._is_meaningful_405(headers_low, body):
                evidence.append(EvidenceItem.make(
                    "ml_endpoint_405",
                    f"Endpoint exists {path} (HTTP 405, Allow/API body confirmed)",
                    "probe", endpoint=url))
                endpoints.append(url)

        if status in (400, 422) and body:
            fw = self._fingerprint_error_body(body, url, evidence)
            if fw:
                frameworks.append(fw)
                if url not in endpoints:
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

                except Exception:
                    pass

        return {"evidence": evidence, "model_reported": model_reported}

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

        server = headers_low.get("server", "") + " " + headers_low.get("x-powered-by", "")
        for fw_name, sig in FRAMEWORK_SIGNATURES.items():
            for k, v in (sig.get("headers") or {}).items():
                if k in headers_low:
                    if v is None or v.lower() in headers_low.get(k, "").lower():
                        evidence.append(EvidenceItem.make(
                            "framework_header",
                            f"Header {k} matches {fw_name}",
                            "header", framework=fw_name))
                        frameworks.append(fw_name)

        cookies = headers_low.get("set-cookie", "")
        for fw_name, sig in FRAMEWORK_SIGNATURES.items():
            for cookie_name in sig.get("cookie_names", []):
                if cookie_name.lower() in cookies.lower():
                    evidence.append(EvidenceItem.make(
                        "framework_cookie",
                        f"Cookie '{cookie_name}' matches {fw_name}",
                        "header", framework=fw_name))
                    frameworks.append(fw_name)

        return {"evidence": evidence, "frameworks": list(dict.fromkeys(frameworks))}

    def _identify_framework(
        self,
        html: str,
        js: str,
        headers: Dict,
        known_endpoints: List[str],
        existing_evidence: List[EvidenceItem],
    ) -> Dict:
        evidence:    List[EvidenceItem] = []
        headers_low = {k.lower(): v for k, v in headers.items()}
        combined_text = (html + js).lower()
        known_paths = {urllib.parse.urlparse(ep).path for ep in known_endpoints}

        scores:          Dict[str, int]       = {}
        matched_signals: Dict[str, List[str]] = {}

        for fw_name, sig in FRAMEWORK_SIGNATURES.items():
            score   = 0
            signals = []

            for p in sig.get("paths", []):
                if any(p in kp for kp in known_paths) or p in combined_text:
                    score += 3
                    signals.append(f"path:{p}")

            # No title_hints / product js_strings — protocol paths/headers/body only.
            for k, v in (sig.get("headers") or {}).items():
                if k in headers_low:
                    if v is None or v.lower() in headers_low[k].lower():
                        score += 5
                        signals.append(f"header:{k}")

            cookie_header = headers_low.get("set-cookie", "")
            for cn in sig.get("cookie_names", []):
                if cn.lower() in cookie_header.lower():
                    score += 3
                    signals.append(f"cookie:{cn}")

            for pat in sig.get("body_patterns", []):
                for ev in existing_evidence:
                    if re.search(pat, ev.detail, re.I):
                        score += 2
                        signals.append(f"body:{pat[:20]}")
                        break

            if score > 0:
                scores[fw_name]          = score
                matched_signals[fw_name] = signals

        PROTOCOL_ONLY_LABELS = {"OpenAI-compatible"}
        MAX_POSSIBLE_SCORE   = 12

        best_fw       = ""
        best_score    = 0
        best_protocol = ""

        for fw, sc in scores.items():
            if fw in PROTOCOL_ONLY_LABELS:
                if sc > 0:
                    best_protocol = fw
                continue
            if sc > best_score:
                best_score = sc
                best_fw = fw

        if not best_fw and best_protocol:
            best_fw = best_protocol
            best_score = scores.get(best_protocol, 0)
            best_protocol = ""

        # Protocol path-membership alone (no body/header) is not enough to
        # claim a framework — those paths often came from WAF noise.
        if best_fw in PROTOCOL_ONLY_LABELS:
            fw_signals_tmp = matched_signals.get(best_fw, [])
            non_path = [s for s in fw_signals_tmp if not s.startswith("path:")]
            if not non_path and best_score > 0:
                # Keep as weak protocol hint only when score is path-only.
                best_protocol = best_fw
                best_fw = ""
                best_score = 0

        fw_confidence = min(best_score / MAX_POSSIBLE_SCORE, 1.0) if best_fw else 0.0
        fw_signals    = matched_signals.get(best_fw, []) if best_fw else []

        if best_fw and best_score >= 3 and fw_confidence > 0:
            pct = f"{fw_confidence*100:.0f}%"
            evidence.append(EvidenceItem.make(
                "framework_identified",
                f"Framework: {best_fw} confidence={pct} signals={fw_signals[:4]}",
                "passive", framework=best_fw))

        INFERENCE_SERVER_NAMES = set(FRAMEWORK_SIGNATURES.keys()) - PROTOCOL_ONLY_LABELS
        infra = ""
        for fw_name in ([best_fw] if best_fw else []) + sorted(
            scores.keys(), key=lambda x: scores.get(x, 0), reverse=True
        ):
            if not fw_name:
                continue
            sig = FRAMEWORK_SIGNATURES.get(fw_name, {})
            if sig.get("paths") and any(
                any(p in kp for kp in known_paths)
                for p in sig.get("paths", [])
                if any(x in p for x in ["/api/", "/v1/", "/v2/"])
            ):
                # Only attribute infra when framework confidence is real.
                if fw_name == best_fw and fw_confidence > 0:
                    infra = fw_name
                    break
                if fw_name not in PROTOCOL_ONLY_LABELS:
                    infra = fw_name
                    break

        return {
            "evidence":            evidence,
            "framework":           best_fw if fw_confidence > 0 else "",
            "framework_confidence": fw_confidence,
            "framework_signals":   fw_signals,
            "protocol":            best_protocol,
            "inference_server":    infra if fw_confidence > 0 else (infra if infra and infra not in PROTOCOL_ONLY_LABELS else ""),
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

        if framework and framework in FRAMEWORK_SIGNATURES:
            caps.update(FRAMEWORK_SIGNATURES[framework].get("capabilities", []))

        PROTOCOL_LABELS = {"OpenAI-compatible"}
        for fw in all_frameworks:
            if fw in PROTOCOL_LABELS:
                continue
            if fw in FRAMEWORK_SIGNATURES and fw != framework:
                caps.update(FRAMEWORK_SIGNATURES[fw].get("capabilities", []))

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

        return sorted(cap for cap in caps if cap in EXTENDED_CAPABILITIES)

    async def _confirm_js_extracted_paths(
        self, base: str, paths: List[str], verbose: bool
    ) -> Dict:
        return await self._confirm_js_paths(base, paths, verbose)

    async def _confirm_js_paths(
        self, base: str, paths: List[str], verbose: bool
    ) -> Dict:
        evidence:  List[EvidenceItem] = []
        endpoints: List[str]          = []
        loop = asyncio.get_event_loop()

        async def probe(path: str):
            url = base + path
            try:
                status, hdrs, body = await loop.run_in_executor(
                    None, lambda: self._fetch(
                        url, data=b"{}", method="POST"))
                if status == 0:
                    status, hdrs, body = await loop.run_in_executor(
                        None, lambda: self._fetch(url))
                r = self._evaluate_probe_response(
                    url, path, "chat", status, hdrs, body, [])
                if r:
                    evidence.extend(r.get("evidence", []))
                    endpoints.extend(r.get("endpoints", []))
            except Exception:
                pass

        await asyncio.gather(*[probe(p) for p in paths[:8]], return_exceptions=True)
        return {"evidence": evidence, "endpoints": list(dict.fromkeys(endpoints))}

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
        allow_redirects: bool = True,
    ) -> Tuple[int, Dict, str]:
        try:
            req = urllib.request.Request(
                url, data=data,
                headers={
                    "User-Agent": "Mozilla/5.0 (SecurityScanner)",
                    "Accept":     "application/json, text/html, */*",
                    **({"Content-Type": "application/json"} if data else {}),
                },
                method=method,
            )
            if allow_redirects:
                opener = urllib.request.build_opener()
            else:
                class _NoRedirect(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
                        return None

                opener = urllib.request.build_opener(_NoRedirect)
            with opener.open(req, timeout=self.timeout) as resp:
                body = resp.read(max_bytes).decode("utf-8", errors="replace")
                return resp.status, dict(resp.headers), body
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(2048).decode("utf-8", errors="replace")
            except Exception:
                body = ""
            return exc.code, dict(exc.headers) if exc.headers else {}, body
        except Exception:
            return 0, {}, ""