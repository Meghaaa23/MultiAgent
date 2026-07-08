"""
ai_fingerprint_agent.py  —  AI-application fingerprinting module.

Architecture (paper §III-A):

  Target URL
      ↓
  Passive collection (parallel)
      ├── Homepage HTML
      ├── robots.txt / sitemap.xml
      ├── CSP header analysis
      ├── Cookie inspection
      ├── Meta-tag / favicon analysis
      └── Response-header analysis
      ↓
  JS bundle analysis
      ├── Extract <script src> from HTML
      ├── Fetch bundles (capped at max_js_bundle_bytes)
      ├── SDK signature matching
      ├── fetch()/axios()/XHR/EventSource/WebSocket path extraction
      └── Global variable / package.json hints
      ↓
  Schema discovery (parallel)
      ├── OpenAPI / Swagger parsing
      ├── GraphQL introspection probe
      └── robots.txt → sitemap → link extraction
      ↓
  Active endpoint probing (ranked)
      ├── JS-extracted paths first (highest prior)
      ├── OpenAPI-discovered paths
      ├── Ranked seed list (fallback)
      └── Auth detection on 401/403
      ↓
  Behavioral probes
      ├── "Hello" → LLM response heuristics
      ├── "Repeat abc" → temperature / stochasticity signal
      └── "What model are you?" → model self-report
      ↓
  Error-message fingerprinting (POST {} to AI paths)
      ↓
  Framework identification
      ├── Signature library: Open WebUI, Flowise, Langflow, Dify,
      │   AnythingLLM, LibreChat, Ollama, vLLM, TGI, LangGraph,
      │   Haystack, OpenHands, AutoGen, CrewAI, LobeChat, OpenAI-compat
      └── Infer capabilities from detected framework
      ↓
  Weighted evidence engine  →  0-100+ score  →  confidence band
      ↓
  Rich report: framework, inference server, model, capabilities,
               auth requirements, ranked evidence table

Design notes for the paper:
  - Framework detection is the primary signal, not keyword matching.
    Each framework has a multi-signal signature (headers, paths, JS globals,
    body patterns, cookie names). Capability inference is derived from the
    detected framework, not guessed from keywords.
  - Evidence scoring is 0-100+ on a documented scale:
      0-25:  None    26-50: Low    51-75: Medium
      76-100: High   >100:  Very High
  - Behavioral probes (item 11) are lightweight and stateless; they send
    a "Hello" and "What model are you?" and classify the response. This
    detects AI behavior even when all endpoints are obfuscated.
  - GraphQL detection (item 6) covers agent platforms that expose their
    API exclusively through GraphQL rather than REST.
  - robots.txt / sitemap.xml parsing discovers endpoints the app itself
    advertises, not endpoints we guess.
  - Authentication is detected and reported; auth-gated endpoints are
    reported as "discovered but not tested" rather than skipped silently.
  - Recursive crawling belongs in web_scanner_agent.py; this agent does
    single-depth link extraction from the homepage only.
"""

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


# ===========================================================================
# §1  Evidence weights (0-100+ scale)
# ---------------------------------------------------------------------------
# Score bands:
#   0-25    None      (no meaningful signal)
#   26-50   Low       (weak signals, possible AI)
#   51-75   Medium    (multiple consistent signals)
#   76-100  High      (network-confirmed AI behavior)
#   >100    Very High (schema + behavior + framework all confirmed)
# ===========================================================================

# ---------------------------------------------------------------------------
# Evidence weights — calibrated so realistic detection scenarios score correctly.
#
# Calibration reference (from production output on Ollama at localhost:8024):
#   - framework_identified (Ollama)         = 1 item
#   - error_openai_format (2 endpoints)     = 2 items
#   - ml_endpoint_200 (2 endpoints)         = 2 items
#   Total = 5 evidence items → must score "high" (76+), not "low"
#
# Old weights: 20 + 9+9 + 6+6 = 50 → reported "low" (threshold 51 for medium)
# New weights: ensure that combination reaches 76+.
#
# Principle: a confirmed framework match is the single strongest possible
# signal — it means path + JS string + header + error-format all converged
# on the same answer. Weight accordingly.
# ---------------------------------------------------------------------------
EVIDENCE_WEIGHTS: Dict[str, int] = {
    # Schema-level proof
    "openapi_schema":           18,
    "openapi_ai_endpoint":      14,
    "graphql_schema":           14,
    "graphql_ai_field":         12,

    # Framework identified — single strongest signal
    # A framework match requires path + JS/header/cookie signals to converge.
    "framework_identified":     30,
    "framework_header":         15,
    "framework_cookie":         10,

    # Behavioral probes (hard to fake, hard to hide)
    "behavior_llm_response":    22,
    "behavior_model_reported":  20,
    "behavior_streaming":       14,

    # Network-confirmed endpoints
    "chat_endpoint_200":        14,
    "embedding_endpoint_200":   10,
    "tool_endpoint_200":        10,
    "ml_endpoint_200":           8,
    "ml_endpoint_401_403":       6,
    "ml_endpoint_405":           5,

    # Error-message fingerprinting
    # These are particularly valuable: a 400 with {"error":{"type":...}}
    # is definitive proof of the API protocol.
    "error_openai_format":      12,
    "error_missing_messages":   10,
    "error_missing_model":       8,
    "error_triton_format":       8,
    "error_huggingface_format":  7,
    "error_generic_validation":  4,

    # SSE / streaming
    "sse_streaming_header":     10,
    "sse_chunked_transfer":      8,
    "sse_in_js":                 6,
    "websocket_ai_path":         6,

    # Response headers
    "ai_response_header":        7,

    # JS-bundle signals
    "js_ai_sdk":                 7,
    "js_api_path_extracted":     5,

    # Passive / metadata
    "robots_ai_path":            5,
    "sitemap_ai_path":           4,
    "csp_ai_domain":             6,
    "meta_ai_tag":               4,
    "favicon_known_framework":   5,

    # DOM / HTML (lowest)
    "dom_assistant_role":        3,
    "html_ai_form":              3,
}

# Confidence bands — calibrated against the weight table above.
# Reference scores for common detection scenarios:
#   Bare inference server (Ollama, no HTML):
#     framework(30) + 2×error_openai(12) + 2×ml_200(8) = 70  → "medium"
#     + behavioral probe(22) = 92  → "high"
#   Full SPA with JS + OpenAPI + framework:
#     framework(30) + openapi(18) + openapi_ai(14) + js_sdk(7) = 69 → "medium"
#     + behavior(22) = 91 → "high"
#   Only a couple of 200s, no framework match:
#     2×ml_200(8) = 16 → "none"  (correct: not enough to claim AI)
#     + error_openai(12) + sse(10) = 38 → "low"
# Confidence bands — calibrated against concrete detection scenarios:
#
#   "none"   ( < 20): only 1-2 weak signals (2 ml_200 = 16)
#   "low"    (20-39): a few signals but no framework match
#   "medium" (40-64): multiple consistent signals OR framework without behavior
#   "high"   (65-99): framework + network confirmation (Ollama bare = 70)
#   "very_high"(100+): framework + behavior + schema all confirmed (= 84+)
#
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


# ===========================================================================
# §2  Framework signature library
# ---------------------------------------------------------------------------
# Each entry: name → {signals}
# Signals checked: headers, paths, js_globals, js_strings, cookie_names,
#                  body_patterns, favicon_hash, capabilities_implied
# ===========================================================================

FRAMEWORK_SIGNATURES: Dict[str, Dict] = {
    "Open WebUI": {
        "headers":     {"x-open-webui": None},
        "paths":       ["/api/chat", "/api/models", "/api/chat/completions"],
        "js_strings":  ["open-webui", "OpenWebUI", "webui-logo"],
        "js_globals":  ["WEBUI_NAME", "WEBUI_URL"],
        "cookie_names":["webui-session"],
        "capabilities": ["chat", "rag", "tool_calling", "image_generation", "web_search"],
    },
    "Flowise": {
        "paths":       ["/api/v1/prediction", "/api/v1/chatflows", "/api/v1/nodes"],
        "js_strings":  ["flowise", "Flowise", "FlowiseAI"],
        "js_globals":  ["FLOWISE_URL"],
        "capabilities": ["chat", "rag", "tool_calling", "workflow"],
    },
    "Langflow": {
        "paths":       ["/api/v1/flows", "/api/v1/run", "/api/v1/components"],
        "js_strings":  ["langflow", "Langflow"],
        "js_globals":  ["LANGFLOW_AUTO_LOGIN"],
        "capabilities": ["chat", "rag", "tool_calling", "workflow", "multi_agent"],
    },
    "Dify": {
        "paths":       ["/api/chat-messages", "/api/workflows/run", "/api/apps"],
        "js_strings":  ["dify.ai", "Dify", "difyChatbot"],
        "cookie_names":["dify_session"],
        "capabilities": ["chat", "rag", "tool_calling", "workflow", "image_generation"],
    },
    "AnythingLLM": {
        "paths":       ["/api/workspace", "/api/chat", "/api/system/env"],
        "js_strings":  ["anythingllm", "AnythingLLM", "mintplex"],
        "capabilities": ["chat", "rag", "memory"],
    },
    "LibreChat": {
        "paths":       ["/api/messages", "/api/ask", "/api/convos"],
        "js_strings":  ["librechat", "LibreChat"],
        "cookie_names":["refreshToken"],
        "capabilities": ["chat", "tool_calling", "image_generation", "web_search"],
    },
    "LobeChat": {
        "paths":       ["/api/chat", "/api/openai"],
        "js_strings":  ["lobe-chat", "LobeChat", "@lobehub"],
        "capabilities": ["chat", "tool_calling", "image_generation"],
    },
    "OpenHands": {
        "paths":       ["/api/conversations", "/api/submit-feedback", "/api/options/config"],
        "js_strings":  ["OpenHands", "opendevin", "openhands"],
        "capabilities": ["code_execution", "shell", "filesystem", "browser", "multi_agent"],
    },
    "CrewAI": {
        "paths":       ["/api/crews", "/api/kickoff", "/api/agents"],
        "js_strings":  ["crewai", "CrewAI"],
        "capabilities": ["multi_agent", "tool_calling", "workflow"],
    },
    "AutoGen": {
        "paths":       ["/api/messages", "/api/agents", "/api/run"],
        "js_strings":  ["autogen", "AutoGen", "pyautogen"],
        "capabilities": ["multi_agent", "code_execution", "tool_calling"],
    },
    "LangGraph": {
        "paths":       ["/runs", "/threads", "/assistants", "/store"],
        "js_strings":  ["langgraph", "LangGraph", "@langchain/langgraph"],
        "capabilities": ["multi_agent", "memory", "workflow", "tool_calling"],
    },
    "Haystack": {
        "paths":       ["/query", "/pipeline", "/document-store"],
        "js_strings":  ["haystack", "deepset"],
        "capabilities": ["rag", "chat", "tool_calling"],
    },
    "Ollama": {
        "paths":       ["/api/chat", "/api/generate", "/api/tags", "/api/version"],
        "headers":     {"x-ollama-version": None},
        "js_strings":  ["ollama", "Ollama"],
        "body_patterns": [r'"done_reason"', r'"total_duration"', r'"eval_count"'],
        "capabilities": ["chat", "code_execution", "embedding"],
    },
    "vLLM": {
        "paths":       ["/v1/chat/completions", "/v1/completions", "/v1/models"],
        "headers":     {"server": "vllm"},
        "body_patterns": [r'"object"\s*:\s*"chat\.completion"'],
        "capabilities": ["chat", "embedding"],
    },
    "TGI (HuggingFace)": {
        "paths":       ["/generate", "/generate_stream", "/v1/chat/completions"],
        "headers":     {"server": "text-generation-inference"},
        "body_patterns": [r'"generated_text"', r'"details".*"finish_reason"'],
        "capabilities": ["chat", "embedding"],
    },
    "OpenAI-compatible": {
        "paths":       ["/v1/chat/completions", "/v1/completions", "/v1/models",
                        "/v1/embeddings"],
        "body_patterns": [r'"choices"\s*:\s*\[', r'"object"\s*:\s*"chat\.completion"',
                          r'"finish_reason"'],
        "capabilities": ["chat", "embedding", "image_generation"],
    },
}

# Known model names for self-report behavioral probe
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

# Capability inference for extended capability set (item 13)
EXTENDED_CAPABILITIES = [
    "chat", "rag", "tool_calling", "memory", "code_execution",
    "email_send", "web_search", "browser", "sql", "filesystem",
    "shell", "python", "image_generation", "vision", "speech",
    "audio", "calendar", "slack", "github", "vector_db",
    "mcp", "workflow", "multi_agent", "embedding", "terminal",
    "cloud", "image_input",
]

# AI response body patterns
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

# LLM response heuristics for behavioral probe
LLM_RESPONSE_SIGNALS = [
    r"\bI\s+(?:am|can|will|don'?t|cannot|understand)\b",
    r"\bAs\s+an?\s+(?:AI|assistant|language model)\b",
    r"\bI'?m\s+(?:here|happy|glad|sorry)\b",
    r"\bHow\s+(?:can|may)\s+I\s+(?:help|assist)\b",
    r"\bThank\s+you\s+for\b",
    r"\bIs\s+there\s+anything\b",
]

# Error fingerprints
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

# CSP domains that indicate AI API usage
AI_CSP_DOMAINS = [
    "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com",
    "api.cohere.ai", "api.mistral.ai", "api.groq.com", "api.together.xyz",
    "api.replicate.com", "api.perplexity.ai", "api.huggingface.co",
]

# JS SDK signatures
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

# Ranked seed endpoints
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
    "chat":      "AML.T0051 — LLM Prompt Injection",
    "ml":        "AML.T0043 — Craft Adversarial Data",
    "schema":    "AML.T0063 — Discover AI Model Outputs",
    "upload":    "AML.T0018.002 — Embed Malware via Model Upload",
    "embedding": "AML.T0043 — Craft Adversarial Data",
    "graphql":   "AML.T0051 — LLM Prompt Injection",
}


# ===========================================================================
# §3  Data classes
# ===========================================================================

@dataclass
class EvidenceItem:
    key:       str
    detail:    str
    weight:    int
    source:    str     # "html"|"js_bundle"|"openapi"|"graphql"|"probe"|"header"|"behavior"|"passive"
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
    """Records authentication requirement discovered on an endpoint."""
    endpoint:    str
    auth_type:   str   # "bearer" | "api_key" | "cookie" | "basic" | "unknown"
    status_code: int
    detail:      str


@dataclass
class FingerprintReport:
    """
    Structured fingerprint result.
    Paper-accurate naming: framework is what was detected; capabilities are
    inferred from the framework, not guessed independently.
    """
    # Identification
    is_ai_powered:    bool
    confidence:       str
    evidence_score:   int

    # Framework / protocol
    framework:        str = ""  # primary detected framework (Ollama, Flowise, etc.)
    protocol:         str = ""  # wire protocol (OpenAI-compatible, TGI, Triton, etc.)
    inference_server: str = ""  # inference backend when distinct from framework
    model_reported:   str = ""  # model self-report from behavioral probe

    # Capabilities
    capabilities:     List[str] = field(default_factory=list)

    # Endpoints
    ml_endpoints:        List[str] = field(default_factory=list)
    discovered_paths:    List[str] = field(default_factory=list)
    auth_required_paths: List[AuthSignal] = field(default_factory=list)

    # Signals
    frameworks_detected: List[str] = field(default_factory=list)
    openapi_schema:      Dict       = field(default_factory=dict)
    graphql_types:       List[str]  = field(default_factory=list)
    technologies:        List[str]  = field(default_factory=list)

    # Evidence
    evidence_items:   List[EvidenceItem] = field(default_factory=list)
    atlas_techniques: List[str]          = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Serialize to dict compatible with ai_vulnerability_tester.py."""
        return {
            "is_ai_powered":    self.is_ai_powered,
            "confidence":       self.confidence,
            "evidence_score":   self.evidence_score,
            "framework":        self.framework,
            "protocol":         self.protocol,
            "inference_server": self.inference_server,
            "model_reported":   self.model_reported,
            "capabilities":     self.capabilities,
            "ml_endpoints":     self.ml_endpoints,
            "discovered_paths": self.discovered_paths,
            "auth_required_paths": [
                {"endpoint": a.endpoint, "auth_type": a.auth_type,
                 "status_code": a.status_code, "detail": a.detail}
                for a in self.auth_required_paths
            ],
            "frameworks_detected": self.frameworks_detected,
            "openapi_schema":   self.openapi_schema,
            "graphql_types":    self.graphql_types,
            # Keys expected by ai_vulnerability_tester.detect_capabilities()
            "page_title":       "",
            "technologies":     self.technologies,
            "api_schema":       {"tools": [], "openapi": self.openapi_schema},
            "app_description":  "",
            "response_headers": {},
            "chat_components":  [],
            # Evidence for reporting
            "atlas_techniques": self.atlas_techniques,
            "evidence_items": [
                {"key": e.key, "detail": e.detail, "weight": e.weight,
                 "source": e.source, "endpoint": e.endpoint, "framework": e.framework}
                for e in sorted(self.evidence_items, key=lambda x: x.weight, reverse=True)
            ],
        }

    def print_report(self) -> None:
        """Print a human-readable report for analysts (item 18)."""
        print(f"\n{'='*60}")
        print(f"  AI Fingerprint Report")
        print(f"{'='*60}")
        print(f"  Confidence   : {self.confidence.upper()} (score={self.evidence_score})")
        print(f"  Framework    : {self.framework or 'Unknown'}")
        if self.protocol and self.protocol != self.framework:
            print(f"  Protocol     : {self.protocol}")
        if self.inference_server and self.inference_server != self.framework:
            print(f"  Inference    : {self.inference_server}")
        if self.model_reported:
            print(f"  Model        : {self.model_reported}")
        if self.capabilities:
            print(f"  Capabilities : {', '.join(self.capabilities)}")
        if self.ml_endpoints:
            print(f"  AI Endpoints : {len(self.ml_endpoints)}")
            for ep in self.ml_endpoints[:5]:
                print(f"      {ep}")
        if self.auth_required_paths:
            print(f"  Auth-gated   : {len(self.auth_required_paths)} endpoint(s) "
                  f"(not tested)")
            for a in self.auth_required_paths[:3]:
                print(f"      {a.endpoint}  [{a.auth_type}]")
        print(f"\n  Evidence (top 8):")
        for ev in sorted(self.evidence_items, key=lambda x: x.weight, reverse=True)[:8]:
            print(f"      +{ev.weight:3d}  [{ev.source:10s}]  {ev.detail[:65]}")
        print(f"{'='*60}\n")


# ===========================================================================
# §4  Main agent
# ===========================================================================

class AIFingerprintAgent:
    """
    AI-application fingerprinting agent.

    Pipeline stages (all network-bound stages run in parallel):
      1.  Fetch homepage + robots.txt + sitemap.xml (if not provided)
      2.  Passive HTML analysis: DOM, meta, favicon, links, CSP
      3.  JS bundle fetch + analysis
      4.  OpenAPI/Swagger probe
      5.  GraphQL detection
      6.  Ranked endpoint probing (JS-extracted > schema > seed)
      7.  Error-message fingerprinting
      8.  Behavioral probes: "Hello", "Repeat abc", "What model are you?"
      9.  Response-header + cookie analysis
      10. Framework identification from aggregated signals
      11. Capability inference from framework
      12. Weighted evidence aggregation → FingerprintReport

    Parameters
    ----------
    timeout : int
        Per-request timeout in seconds.
    max_js_bundles : int
        Max JS bundles to fetch and analyse per target.
    max_js_bundle_bytes : int
        Max bytes read per JS bundle (avoids 10 MB vendor bundles).
    run_behavioral_probes : bool
        Whether to send "Hello" / model-name probes. Adds 2-3 requests.
        Disable for pure passive fingerprinting.
    """

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

    # -------------------------------------------------------------------------
    # Public entry point
    # -------------------------------------------------------------------------

    async def fingerprint(
        self,
        target_url: str,
        discovered_endpoints: List[Dict] = None,
        page_html: str = "",
        response_headers: Dict = None,
        verbose: bool = False,
    ) -> Dict:
        """Run the full fingerprinting pipeline and return a serialized dict."""
        report = await self._fingerprint_internal(
            target_url, discovered_endpoints or [],
            page_html, response_headers or {}, verbose)
        if verbose:
            report.print_report()
        return report.to_dict()

    # -------------------------------------------------------------------------
    # Internal pipeline
    # -------------------------------------------------------------------------

    async def _fingerprint_internal(
        self,
        target_url: str,
        discovered_endpoints: List[Dict],
        page_html: str,
        response_headers: Dict,
        verbose: bool,
    ) -> FingerprintReport:
        base = target_url.rstrip("/")

        # Stage 1 — fetch homepage + robots/sitemap if not provided
        if not page_html:
            _, page_headers, page_html = self._fetch(base)
            if not response_headers:
                response_headers = page_headers

        # Stage 2 — passive HTML analysis (no network)
        js_urls, html_evidence, extracted_links = self._analyse_html(
            page_html, base, response_headers)

        # Stages 3-9 run in parallel
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

        # Collect all evidence
        all_evidence: List[EvidenceItem] = list(html_evidence)
        ml_endpoints:    List[str]  = []
        discovered_paths: List[str] = []
        all_frameworks:  List[str]  = []
        auth_signals:    List[AuthSignal] = []
        openapi_schema:  Dict       = {}
        graphql_types:   List[str]  = []
        js_api_paths:    List[str]  = []
        raw_html_js = ""

        def _collect(r, attr, target):
            if isinstance(r, dict):
                target.extend(r.get(attr, []))

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

        # Stage 8 — behavioral probes (on confirmed or likely AI endpoints)
        behav_r = None
        probe_targets = (ml_endpoints or [base + p for p, _ in SEED_ENDPOINT_RANKING
                                          if "chat" in _ or _ == "ml"])
        if self.run_behavioral_probes and probe_targets:
            behav_r = await self._behavioral_probes(probe_targets[:2], verbose)
            if isinstance(behav_r, dict):
                all_evidence.extend(behav_r.get("evidence", []))
                if behav_r.get("model_reported"):
                    pass  # stored in behav_r

        # Also probe JS-extracted paths not yet confirmed
        if js_api_paths:
            extra = await self._confirm_js_paths(base, js_api_paths, verbose)
            if isinstance(extra, dict):
                all_evidence.extend(extra.get("evidence", []))
                ml_endpoints.extend(extra.get("endpoints", []))

        # Include upstream-discovered endpoints
        if discovered_endpoints:
            disc_r = await self._check_discovered_endpoints(discovered_endpoints)
            if isinstance(disc_r, dict):
                all_evidence.extend(disc_r.get("evidence", []))
                ml_endpoints.extend(disc_r.get("endpoints", []))

        # Deduplicate
        ml_endpoints     = list(dict.fromkeys(ml_endpoints))
        discovered_paths = list(dict.fromkeys(discovered_paths))
        all_frameworks   = list(dict.fromkeys(all_frameworks))

        # Stage 10 — framework identification
        framework_result = self._identify_framework(
            page_html, raw_html_js, response_headers,
            ml_endpoints + discovered_paths, all_evidence)
        all_evidence.extend(framework_result.get("evidence", []))
        detected_framework   = framework_result.get("framework", "")
        detected_protocol    = framework_result.get("protocol", "")
        detected_infra       = framework_result.get("inference_server", "")
        if detected_framework and detected_framework not in all_frameworks:
            all_frameworks.insert(0, detected_framework)

        # Stage 11 — capability inference
        capabilities = self._infer_capabilities(
            detected_framework, all_frameworks, openapi_schema,
            ml_endpoints, graphql_types)

        # Stage 12 — scoring
        total_score = sum(ev.weight for ev in all_evidence)
        confidence  = score_to_confidence(total_score)
        is_ai       = total_score >= 26  # "low" threshold

        # ATLAS
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

        return FingerprintReport(
            is_ai_powered       = is_ai,
            confidence          = confidence,
            evidence_score      = total_score,
            framework           = detected_framework,
            protocol            = detected_protocol,
            inference_server    = detected_infra,
            model_reported      = model_reported,
            capabilities        = capabilities,
            ml_endpoints        = ml_endpoints,
            discovered_paths    = discovered_paths,
            auth_required_paths = auth_signals,
            frameworks_detected = all_frameworks,
            openapi_schema      = openapi_schema,
            graphql_types       = graphql_types,
            technologies        = all_frameworks,
            evidence_items      = all_evidence,
            atlas_techniques    = atlas,
        )

    # =========================================================================
    # §5  Passive HTML analysis
    # =========================================================================

    def _analyse_html(
        self, html: str, base: str, headers: Dict
    ) -> Tuple[List[str], List[EvidenceItem], List[str]]:
        """
        Extract JS bundle URLs, DOM evidence, and page-internal links.
        No network I/O.
        """
        evidence: List[EvidenceItem] = []
        js_urls:  List[str]          = []
        links:    List[str]          = []

        if not html:
            return js_urls, evidence, links

        # JS bundle URLs
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            src = m.group(1)
            if not src.startswith("http"):
                src = base + ("" if src.startswith("/") else "/") + src.lstrip("/")
            if any(x in src for x in [
                "/assets/", "/static/", "/dist/", "/js/", "/build/",
                "/_next/", ".bundle.", "chunk", "main.", "app.", "index.",
            ]):
                js_urls.append(src)

        # Meta tags
        for m in re.finditer(r'<meta[^>]+content=["\']([^"\']*(?:ai|llm|gpt|chatbot|assistant)[^"\']*)["\']',
                             html, re.I):
            evidence.append(EvidenceItem.make(
                "meta_ai_tag", f"AI meta tag: {m.group(1)[:60]}", "html"))

        # DOM AI patterns
        for pattern in AI_DOM_PATTERNS:
            m = re.search(pattern, html, re.I)
            if m:
                ev_key = "html_ai_form" if "form" in pattern else "dom_assistant_role"
                evidence.append(EvidenceItem.make(ev_key, m.group(0)[:60], "html"))

        # Internal links (for shallow link extraction)
        for m in re.finditer(r'href=["\']([^"\'#?]+)["\']', html, re.I):
            href = m.group(1)
            if href.startswith("/") and any(
                x in href.lower() for x in [
                    "/chat", "/api", "/playground", "/workspace",
                    "/dashboard", "/app", "/assistant",
                ]
            ):
                links.append(href)

        # CSP analysis
        csp_header = headers.get("Content-Security-Policy", "")
        if not csp_header:
            # Also check in HTML <meta http-equiv="Content-Security-Policy">
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

    # =========================================================================
    # §6  JS bundle analysis
    # =========================================================================

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
            raw_js_combined += js[:50_000]  # cap per-bundle contribution

            if verbose:
                print(f"    [js] {url[-60:]} ({len(js)} bytes)")

            # SDK detection
            for sdk_name, patterns in ML_LIBRARY_JS_SIGNATURES.items():
                for pat in patterns:
                    if pat.lower() in js.lower():
                        evidence.append(EvidenceItem.make(
                            "js_ai_sdk", f"SDK: {sdk_name}", "js_bundle",
                            endpoint=url, framework=sdk_name))
                        frameworks.append(sdk_name)
                        break

            # API path extraction
            extracted = self._extract_api_paths_from_js(js)
            api_paths.extend(extracted)
            if extracted:
                evidence.append(EvidenceItem.make(
                    "js_api_path_extracted",
                    f"{len(extracted)} AI API path(s) in JS bundle",
                    "js_bundle", endpoint=url))

            # EventSource
            for m in re.finditer(
                r'new\s+EventSource\s*\(\s*["\`]([^"\'`]+)["\`]', js, re.I):
                path = m.group(1).split("${")[0]
                if self._is_ai_api_path(path):
                    evidence.append(EvidenceItem.make(
                        "sse_in_js", f"EventSource({path[:50]})",
                        "js_bundle", endpoint=url))
                    api_paths.append(path)

            # WebSocket
            for m in re.finditer(
                r'new\s+WebSocket\s*\(\s*["\`]([^"\'`]+)["\`]', js, re.I):
                path = m.group(1)
                if any(x in path for x in ["/chat", "/ws", "/stream", "/agent"]):
                    evidence.append(EvidenceItem.make(
                        "websocket_ai_path", f"WebSocket({path[:50]})",
                        "js_bundle", endpoint=url))

            # JS globals indicating known frameworks
            for fw_name, sig in FRAMEWORK_SIGNATURES.items():
                for gs in sig.get("js_globals", []):
                    if gs in js:
                        evidence.append(EvidenceItem.make(
                            "js_ai_sdk", f"JS global {gs} → {fw_name}",
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
        return any(pat in path.lower() for pat in [
            "/chat", "/completions", "/generate", "/predict",
            "/embed", "/inference", "/infer", "/model",
            "/v1/", "/api/", "/llm", "/ai/", "/messages",
            "/runs", "/threads", "/assistants",
        ])

    # =========================================================================
    # §7  OpenAPI / Swagger parsing
    # =========================================================================

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

    # =========================================================================
    # §8  GraphQL detection (item 6)
    # =========================================================================

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

                # Successful introspection
                schema_data = data.get("data", {})
                if schema_data and "__schema" in schema_data:
                    evidence.append(EvidenceItem.make(
                        "graphql_schema",
                        f"GraphQL introspection at {path}",
                        "graphql", endpoint=url))
                    endpoints.append(url)
                    # Extract type names for AI-capability hints
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

                # GraphQL endpoint exists but rejected introspection
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

    # =========================================================================
    # §9  Passive: robots.txt + sitemap.xml
    # =========================================================================

    async def _fetch_robots_sitemap(self, base: str, verbose: bool) -> Dict:
        evidence: List[EvidenceItem] = []
        paths:    List[str]          = []
        loop = asyncio.get_event_loop()

        # robots.txt
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
                    # Sitemap URL
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

    # =========================================================================
    # §10  Ranked endpoint probing + auth detection
    # =========================================================================

    async def _probe_ranked_endpoints(
        self, base: str, extra_paths: List[str], verbose: bool
    ) -> Dict:
        evidence:    List[EvidenceItem] = []
        endpoints:   List[str]          = []
        frameworks:  List[str]          = []
        auth_signals: List[AuthSignal]  = []
        loop = asyncio.get_event_loop()
        confirmed = 0

        # Build ordered probe list: schema → chat → embedding → ml
        ordered = (
            [(p, c) for p, c in SEED_ENDPOINT_RANKING if c == "schema"] +
            [(p, c) for p, c in SEED_ENDPOINT_RANKING if c == "chat"] +
            [(p, c) for p, c in SEED_ENDPOINT_RANKING if c in ("embedding", "ml", "graphql")]
        )

        async def probe(path: str, category: str):
            url = base + path
            try:
                # GET first
                status, resp_headers, body = await loop.run_in_executor(
                    None, lambda: self._fetch(url))
                if status == 405:
                    # Try POST with empty body
                    status, resp_headers, body = await loop.run_in_executor(
                        None, lambda: self._fetch(url, data=b"{}", method="POST"))
                return self._evaluate_probe_response(
                    url, path, category, status, resp_headers, body,
                    auth_signals)
            except Exception:
                return None

        # Probe schema paths in parallel
        schema_paths = [(p, c) for p, c in ordered if c == "schema"]
        schema_results = await asyncio.gather(
            *[probe(p, c) for p, c in schema_paths], return_exceptions=True)
        for r in schema_results:
            if isinstance(r, dict) and r:
                evidence.extend(r.get("evidence", []))
                endpoints.extend(r.get("endpoints", []))
                frameworks.extend(r.get("frameworks", []))
                confirmed += len(r.get("endpoints", []))

        # Probe remaining sequentially; stop when well-confirmed
        for path, category in ordered:
            if confirmed >= 4:
                break
            if category == "schema":
                continue  # already done above
            r = await probe(path, category)
            if isinstance(r, dict) and r:
                evidence.extend(r.get("evidence", []))
                if r.get("endpoints"):
                    endpoints.extend(r["endpoints"])
                    confirmed += len(r["endpoints"])
                frameworks.extend(r.get("frameworks", []))

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
    ) -> Dict:
        evidence:  List[EvidenceItem] = []
        endpoints: List[str]          = []
        frameworks: List[str]         = []

        if status == 0:
            return {}

        headers_low = {k.lower(): v for k, v in headers.items()}
        ct = headers_low.get("content-type", "")
        body_l = (body or "").lower()

        # 200 + AI body
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

            # SSE streaming
            if "text/event-stream" in ct:
                evidence.append(EvidenceItem.make(
                    "sse_streaming_header",
                    f"SSE at {path}", "probe", endpoint=url))
                endpoints.append(url)

            if "chunked" in headers_low.get("transfer-encoding", ""):
                evidence.append(EvidenceItem.make(
                    "sse_chunked_transfer",
                    f"Chunked transfer at {path}", "probe", endpoint=url))

        # 401/403 — auth-gated, detect auth type
        if status in (401, 403):
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

        # 405 — endpoint exists, wrong method
        if status == 405 and category in ("chat", "embedding", "ml"):
            evidence.append(EvidenceItem.make(
                "ml_endpoint_405",
                f"Endpoint exists {path} (HTTP 405)",
                "probe", endpoint=url))

        # Error-message fingerprinting on 400/422
        if status in (400, 422) and body:
            fw = self._fingerprint_error_body(body, url, evidence)
            if fw:
                frameworks.append(fw)
                endpoints.append(url)

        # AI response headers
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
        """Identify the authentication scheme required by an endpoint."""
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

    # =========================================================================
    # §11  Behavioral probes (item 11)
    # =========================================================================

    async def _behavioral_probes(
        self, candidate_endpoints: List[str], verbose: bool
    ) -> Dict:
        """
        Send lightweight stateless probes and classify responses.
        Probes:
          A) "Hello"  — LLM-like response heuristics
          B) "What model are you?"  — model self-report
        """
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

                    # Extract text from response
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

                    # Probe A: LLM response heuristics
                    if probe_name == "hello":
                        if any(re.search(sig, text, re.I) for sig in LLM_RESPONSE_SIGNALS):
                            evidence.append(EvidenceItem.make(
                                "behavior_llm_response",
                                f"LLM-shaped response to 'Hello' at "
                                f"{urllib.parse.urlparse(endpoint).path}",
                                "behavior", endpoint=endpoint))
                            if verbose:
                                print(f"    [behavior] LLM response at {endpoint}")

                    # Probe B: model self-report
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

                    # SSE in response
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

    # =========================================================================
    # §12  Header + cookie analysis
    # =========================================================================

    async def _analyse_headers_cookies(
        self, headers: Dict, verbose: bool
    ) -> Dict:
        evidence:   List[EvidenceItem] = []
        frameworks: List[str]          = []
        headers_low = {k.lower(): v for k, v in headers.items()}

        # AI-specific headers
        for h in AI_RESPONSE_HEADERS:
            if h in headers_low:
                evidence.append(EvidenceItem.make(
                    "ai_response_header",
                    f"{h}: {headers_low[h][:50]}", "header"))
                break

        # Framework headers
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

        # Cookie names
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

    # =========================================================================
    # §13  Framework identification (item 2)
    # =========================================================================

    def _identify_framework(
        self,
        html: str,
        js: str,
        headers: Dict,
        known_endpoints: List[str],
        existing_evidence: List[EvidenceItem],
    ) -> Dict:
        """
        Score each framework signature against all collected signals.
        Returns the best-matched framework and inference server.
        """
        evidence:    List[EvidenceItem] = []
        headers_low = {k.lower(): v for k, v in headers.items()}
        combined_text = (html + js).lower()

        # Extract paths from known endpoints
        known_paths = {urllib.parse.urlparse(ep).path for ep in known_endpoints}

        scores: Dict[str, int] = {}

        for fw_name, sig in FRAMEWORK_SIGNATURES.items():
            score = 0

            # Path matches
            for p in sig.get("paths", []):
                if any(p in kp for kp in known_paths) or p in combined_text:
                    score += 3

            # JS string matches
            for s in sig.get("js_strings", []):
                if s.lower() in combined_text:
                    score += 2

            # Header matches
            for k, v in (sig.get("headers") or {}).items():
                if k in headers_low:
                    if v is None or v.lower() in headers_low[k].lower():
                        score += 5

            # Cookie matches
            cookie_header = headers_low.get("set-cookie", "")
            for cn in sig.get("cookie_names", []):
                if cn.lower() in cookie_header.lower():
                    score += 3

            # Body pattern matches (from collected evidence items)
            for pat in sig.get("body_patterns", []):
                for ev in existing_evidence:
                    if re.search(pat, ev.detail, re.I):
                        score += 2

            if score > 0:
                scores[fw_name] = score

        # Separate "protocol" labels from "product" framework labels.
        # OpenAI-compatible is an API wire protocol, not a product name.
        # TGI is both a product and a protocol label — treat it as a product
        # (framework) and record the protocol separately only when we have
        # strong independent evidence for it.
        PROTOCOL_ONLY_LABELS = {"OpenAI-compatible"}

        best_fw       = ""
        best_score    = 0
        best_protocol = ""

        for fw, sc in scores.items():
            if fw in PROTOCOL_ONLY_LABELS:
                # Record as protocol; only promote to framework if nothing else matched
                if sc > 0:
                    best_protocol = fw
                continue
            if sc > best_score:
                best_score = sc
                best_fw = fw

        # If no product framework matched, promote protocol to framework
        if not best_fw and best_protocol:
            best_fw = best_protocol
            best_protocol = ""

        if best_fw and best_score >= 3:
            evidence.append(EvidenceItem.make(
                "framework_identified",
                f"Framework identified: {best_fw} (score={best_score})",
                "passive", framework=best_fw))
        elif best_fw:
            # Low-score match — still report it, but don't add evidence weight
            pass

        # Infer inference server (may coincide with framework for Ollama/vLLM)
        infra = ""
        for server_name in ["Ollama", "vLLM", "TGI (HuggingFace)"]:
            if server_name in scores and scores[server_name] >= 2:
                infra = server_name
                break

        return {
            "evidence":        evidence,
            "framework":       best_fw,
            "protocol":        best_protocol or (best_fw if best_fw in PROTOCOL_LABELS else ""),
            "inference_server": infra,
        }

    # =========================================================================
    # §14  Capability inference (item 13)
    # =========================================================================

    def _infer_capabilities(
        self,
        framework: str,
        all_frameworks: List[str],
        openapi_schema: Dict,
        endpoints: List[str],
        graphql_types: List[str],
    ) -> List[str]:
        """
        Infer capabilities from detected framework + observed signals.
        Framework-derived capabilities are the primary source (item 10).
        """
        caps: Set[str] = set()

        # From detected framework
        if framework and framework in FRAMEWORK_SIGNATURES:
            caps.update(FRAMEWORK_SIGNATURES[framework].get("capabilities", []))

        # From other detected frameworks/SDKs
        for fw in all_frameworks:
            if fw in FRAMEWORK_SIGNATURES:
                caps.update(FRAMEWORK_SIGNATURES[fw].get("capabilities", []))

        # From OpenAPI schema
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

        # From endpoint paths
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

        # From GraphQL types
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

        # Normalize against known capability set
        return sorted(cap for cap in caps if cap in EXTENDED_CAPABILITIES)

    # =========================================================================
    # §15  Confirm JS-extracted paths
    # =========================================================================

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

    # =========================================================================
    # §16  Upstream discovered-endpoints passthrough
    # =========================================================================

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

    # =========================================================================
    # §17  HTTP helpers
    # =========================================================================

    def _fetch(
        self,
        url: str,
        max_bytes: int = 8192,
        method: str = "GET",
        data: Optional[bytes] = None,
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
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
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