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


FRAMEWORK_SIGNATURES: Dict[str, Dict] = {
    "Open WebUI": {
        "headers":     {"x-open-webui": None},
        "paths":       ["/api/chat", "/api/models", "/api/chat/completions",
                        "/api/v1/models", "/ollama/api/tags", "/api/v1/auths"],
        "js_strings":  ["open-webui", "OpenWebUI", "open webui", "webui-logo",
                        "Open WebUI"],
        "js_globals":  ["WEBUI_NAME", "WEBUI_URL"],
        "cookie_names":["webui-session", "token"],
        "title_hints": ["open webui", "openwebui"],
        "capabilities": ["chat", "rag", "tool_calling", "image_generation", "web_search"],
    },
    "Flowise": {
        "paths":       ["/api/v1/prediction", "/api/v1/chatflows", "/api/v1/nodes",
                        "/api/v1/ping", "/api/v1/chatflows-streaming"],
        "js_strings":  ["flowise", "Flowise", "FlowiseAI"],
        "js_globals":  ["FLOWISE_URL"],
        "title_hints": ["flowise"],
        "capabilities": ["chat", "rag", "tool_calling", "workflow"],
    },
    "Langflow": {
        "paths":       ["/api/v1/flows", "/api/v1/run", "/api/v1/components",
                        "/api/v1/all", "/api/v1/build", "/health"],
        "js_strings":  ["langflow", "Langflow"],
        "js_globals":  ["LANGFLOW_AUTO_LOGIN"],
        "title_hints": ["langflow"],
        "capabilities": ["chat", "rag", "tool_calling", "workflow", "multi_agent"],
    },
    "Gradio": {
        "paths":       ["/config", "/info", "/queue/join", "/run/predict",
                        "/call/predict", "/gradio_api/info", "/gradio_api/config"],
        "js_strings":  ["gradio", "Gradio", "__gradio_mode__", "gradio-app",
                        "gradio_api"],
        "title_hints": ["gradio", "langflow"],
        "capabilities": ["chat", "image_generation"],
    },
    "Dify": {
        "paths":       ["/api/chat-messages", "/api/workflows/run", "/api/apps"],
        "js_strings":  ["dify.ai", "Dify", "difyChatbot"],
        "cookie_names":["dify_session"],
        "title_hints": ["dify"],
        "capabilities": ["chat", "rag", "tool_calling", "workflow", "image_generation"],
    },
    "AnythingLLM": {
        "paths":       ["/api/workspace", "/api/chat", "/api/system/env",
                        "/api/v1/openai/chat/completions", "/api/embed"],
        "js_strings":  ["anythingllm", "AnythingLLM", "mintplex", "anything-llm"],
        "title_hints": ["anythingllm", "anything llm"],
        "capabilities": ["chat", "rag", "memory"],
    },
    "LibreChat": {
        "paths":       ["/api/messages", "/api/ask", "/api/convos",
                        "/api/agents", "/api/models", "/api/endpoints"],
        "js_strings":  ["librechat", "LibreChat"],
        "cookie_names":["refreshToken"],
        "title_hints": ["librechat"],
        "capabilities": ["chat", "tool_calling", "image_generation", "web_search"],
    },
    "LobeChat": {
        "paths":       ["/api/chat", "/api/openai"],
        "js_strings":  ["lobe-chat", "LobeChat", "@lobehub"],
        "title_hints": ["lobechat", "lobe chat"],
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
        "paths":       ["/api/chat", "/api/generate", "/api/tags", "/api/version",
                        "/api/show", "/api/pull", "/api/delete", "/api/copy"],
        "headers":     {"x-ollama-version": None},
        "js_strings":  ["ollama", "Ollama"],
        "body_patterns": [r'"done_reason"', r'"total_duration"', r'"eval_count"'],
        "capabilities": ["chat", "embedding"],
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

OPENAI_JSON_KEYS = (
    "choices", "model", "object", "data", "message", "response",
    "usage", "models", "generated_text", "error",
)

UNIVERSAL_OPENAI_PATHS: List[Tuple[str, str]] = [
    ("/v1/chat/completions", "chat"),
    ("/v1/completions", "chat"),
    ("/v1/models", "schema"),
    ("/api/chat/completions", "chat"),
]

OPENAI_CHAT_PROBE = json.dumps({
    "model": "gpt-3.5-turbo",
    "messages": [{"role": "user", "content": "Hi"}],
    "max_tokens": 1,
    "stream": False,
}).encode()

OPENAI_COMPLETIONS_PROBE = json.dumps({
    "model": "gpt-3.5-turbo",
    "prompt": "Hi",
    "max_tokens": 1,
}).encode()

INFERENCE_PATH_RE = re.compile(
    r"/(?:v\d+/)?(?:chat/)?completions(?:/|$)"
    r"|/api/(?:chat|generate|ask|messages|prediction|predict)(?:/|$)"
    r"|/run(?:/|$)|/invoke(?:/$)",
    re.I,
)

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
    ("/api/v1/models",        "schema"),
    ("/v2/health/ready",      "schema"),
    ("/v2/models",            "schema"),
    ("/api/predict",          "ml"),
    ("/predict",              "ml"),
    ("/invocations",          "ml"),
    ("/predictions",          "ml"),
    ("/runs",                 "chat"),
    ("/threads",              "chat"),
    # Framework-specific seeds (SPA UIs often hide these behind auth)
    ("/api/v1/chatflows",     "schema"),
    ("/api/v1/flows",         "schema"),
    ("/api/v1/run",           "chat"),
    ("/api/v1/components",    "schema"),
    ("/api/v1/nodes",         "schema"),
    ("/api/v1/ping",          "schema"),
    ("/api/ask",              "chat"),
    ("/api/messages",         "chat"),
    ("/api/convos",           "schema"),
    ("/api/endpoints",        "schema"),
    ("/api/workspace",        "schema"),
    ("/api/system/env",       "schema"),
    ("/api/v1/openai/chat/completions", "chat"),
    ("/ollama/api/tags",      "schema"),
    ("/config",               "schema"),
    ("/info",                 "schema"),
    ("/queue/join",           "chat"),
    ("/run/predict",          "chat"),
    ("/gradio_api/info",      "schema"),
    ("/api/chat-messages",    "chat"),
]

# Extra paths probed once a framework is identified from HTML/JS brand signals.
FRAMEWORK_PROBE_PATHS: Dict[str, List[Tuple[str, str]]] = {
    "Open WebUI": [
        ("/api/models", "schema"),
        ("/api/v1/models", "schema"),
        ("/api/chat", "chat"),
        ("/api/chat/completions", "chat"),
        ("/api/v1/chat/completions", "chat"),
        ("/ollama/api/tags", "schema"),
        ("/api/v1/auths", "schema"),
    ],
    "Flowise": [
        ("/api/v1/prediction", "chat"),
        ("/api/v1/chatflows", "schema"),
        ("/api/v1/nodes", "schema"),
        ("/api/v1/ping", "schema"),
    ],
    "Langflow": [
        ("/api/v1/flows", "schema"),
        ("/api/v1/run", "chat"),
        ("/api/v1/components", "schema"),
        ("/api/v1/all", "schema"),
        ("/health", "schema"),
    ],
    "Gradio": [
        ("/config", "schema"),
        ("/info", "schema"),
        ("/queue/join", "chat"),
        ("/run/predict", "chat"),
        ("/gradio_api/info", "schema"),
    ],
    "AnythingLLM": [
        ("/api/workspace", "schema"),
        ("/api/chat", "chat"),
        ("/api/system/env", "schema"),
        ("/api/v1/openai/chat/completions", "chat"),
    ],
    "LibreChat": [
        ("/api/ask", "chat"),
        ("/api/messages", "chat"),
        ("/api/convos", "schema"),
        ("/api/models", "schema"),
        ("/api/endpoints", "schema"),
        ("/api/agents", "chat"),
        ("/v1/chat/completions", "chat"),
        ("/v1/models", "schema"),
    ],
    "Dify": [
        ("/api/chat-messages", "chat"),
        ("/api/workflows/run", "chat"),
        ("/api/apps", "schema"),
    ],
    "Ollama": [
        ("/api/tags", "schema"),
        ("/api/chat", "chat"),
        ("/api/generate", "chat"),
        ("/v1/chat/completions", "chat"),
        ("/v1/models", "schema"),
    ],
}

SPA_CANARY_PATH = "/__scanner_canary_nonexistent_check_xyz789_do_not_create_this_route"

AI_TITLE_KEYWORDS = [
    "ai", "llm", "gpt", "chat", "assistant", "bot", "openai", "claude",
    "ollama", "webui", "flowise", "langflow", "librechat", "gradio",
    "dify", "anythingllm", "lobe", "huggingface", "inference",
]


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


def _is_inference_path(path: str) -> bool:
    return bool(INFERENCE_PATH_RE.search(path or ""))


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


def _probe_post_body(path: str, category: str) -> bytes:
    path_l = (path or "").lower()
    if "completions" in path_l and "chat" not in path_l:
        return OPENAI_COMPLETIONS_PROBE
    if category in ("chat", "ml") or _is_inference_path(path):
        return OPENAI_CHAT_PROBE
    return b"{}"


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
            # Gradio/Langflow shells can exceed 8 KiB before useful markers appear.
            status, page_headers, page_html = self._fetch(base, max_bytes=200_000)
            if not response_headers:
                response_headers = page_headers
            if not page_html:
                logger.warning(
                    "[fingerprint] empty root page body from %s (HTTP %s) — "
                    "host unreachable or returned no content",
                    base, status)
                # Still probe Gradio/Langflow config even when the root shell is empty.

        spa_catch_all = await self._detect_spa_catch_all(base)
        if spa_catch_all and verbose:
            print("    [spa] catch-all/SPA fallback detected — using content-based probes")

        js_urls, html_evidence, extracted_links, page_title, brand_frameworks = (
            self._analyse_html(page_html, base, response_headers)
        )
        if spa_catch_all:
            html_evidence.append(EvidenceItem.make(
                "spa_catch_all",
                "SPA/catch-all routing detected (canary path returned app shell)",
                "passive"))

        # Always try Gradio config early — Langflow/Gradio often lack obvious HTML brands.
        gradio_hint = await self._probe_gradio_surface(base, verbose)
        gradio_endpoints: List[str] = []
        if isinstance(gradio_hint, dict):
            html_evidence.extend(gradio_hint.get("evidence", []))
            gradio_endpoints = list(gradio_hint.get("endpoints", []))
            for fw in gradio_hint.get("frameworks", []):
                if fw not in brand_frameworks:
                    brand_frameworks.append(fw)

        # Prefer framework-specific seeds when brand is already visible in HTML.
        extra_seed_paths = list(extracted_links)
        for fw in brand_frameworks:
            for path, _cat in FRAMEWORK_PROBE_PATHS.get(fw, []):
                extra_seed_paths.append(path)

        parallel = await asyncio.gather(
            self._fetch_and_analyse_js(js_urls, base, verbose),
            self._probe_openapi(base, verbose),
            self._probe_graphql(base, verbose),
            self._fetch_robots_sitemap(base, verbose),
            self._probe_ranked_endpoints(
                base, extra_seed_paths, verbose, spa_catch_all=spa_catch_all),
            self._analyse_headers_cookies(response_headers, verbose),
            return_exceptions=True,
        )
        js_r, openapi_r, graphql_r, passive_r, probe_r, header_r = parallel

        all_evidence: List[EvidenceItem] = list(html_evidence)
        ml_endpoints:    List[str]  = list(gradio_endpoints)
        discovered_paths: List[str] = []
        all_frameworks:  List[str]  = list(brand_frameworks)
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
            # JS may reveal a framework brand we missed in HTML.
            for fw in js_r.get("frameworks", []):
                if fw in FRAMEWORK_SIGNATURES and fw not in brand_frameworks:
                    brand_frameworks.append(fw)

        if isinstance(openapi_r, dict) and openapi_r.get("found"):
            openapi_schema = openapi_r.get("schema", {})

        if isinstance(graphql_r, dict):
            graphql_types = graphql_r.get("types", [])

        if isinstance(passive_r, dict):
            discovered_paths.extend(passive_r.get("paths", []))

        # Second-pass: probe framework-specific paths once JS/HTML brands are known.
        fw_hint = brand_frameworks[:]
        for fw in all_frameworks:
            if fw in FRAMEWORK_PROBE_PATHS and fw not in fw_hint:
                fw_hint.append(fw)
        if fw_hint:
            fw_probe = await self._probe_framework_paths(
                base, fw_hint, verbose, spa_catch_all=spa_catch_all)
            if isinstance(fw_probe, dict):
                all_evidence.extend(fw_probe.get("evidence", []))
                ml_endpoints.extend(fw_probe.get("endpoints", []))
                all_frameworks.extend(fw_probe.get("frameworks", []))
                auth_signals.extend(fw_probe.get("auth_signals", []))

        # Auth-gated AI endpoints are still AI surfaces — track them as endpoints.
        for sig in auth_signals:
            if sig.endpoint and sig.endpoint not in ml_endpoints:
                ml_endpoints.append(sig.endpoint)

        behav_r = None
        # Prefer unauthenticated chat endpoints for behavioral probes.
        auth_urls = {a.endpoint for a in auth_signals}
        open_targets = [e for e in ml_endpoints if e not in auth_urls]
        probe_targets = open_targets or [
            base + p for p, cat in SEED_ENDPOINT_RANKING
            if cat in ("chat", "ml")
        ]
        if self.run_behavioral_probes and probe_targets:
            behav_r = await self._behavioral_probes(probe_targets[:2], verbose)
            if isinstance(behav_r, dict):
                all_evidence.extend(behav_r.get("evidence", []))
            nd_r = await self._nondeterminism_probe(probe_targets[0], verbose)
            if isinstance(nd_r, dict):
                all_evidence.extend(nd_r.get("evidence", []))

        if js_api_paths:
            extra = await self._confirm_js_paths(
                base, js_api_paths, verbose, spa_catch_all=spa_catch_all)
            if isinstance(extra, dict):
                all_evidence.extend(extra.get("evidence", []))
                ml_endpoints.extend(extra.get("endpoints", []))
                auth_signals.extend(extra.get("auth_signals", []))

        if discovered_endpoints:
            disc_r = await self._check_discovered_endpoints(discovered_endpoints)
            if isinstance(disc_r, dict):
                all_evidence.extend(disc_r.get("evidence", []))
                ml_endpoints.extend(disc_r.get("endpoints", []))

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

        framework_result = self._identify_framework(
            page_html, raw_html_js, response_headers,
            ml_endpoints + discovered_paths, all_evidence)
        all_evidence.extend(framework_result.get("evidence", []))
        detected_framework   = framework_result.get("framework", "")
        detected_protocol    = framework_result.get("protocol", "")
        detected_infra       = framework_result.get("inference_server", "")

        # Live surface
        evidence_keys = [ev.key for ev in all_evidence]
        live_from_paths = bool(ml_endpoints or auth_signals)
        live_from_keys = has_live_surface_evidence(evidence_keys)
        has_live_surface = live_from_paths or live_from_keys

        if not detected_framework and brand_frameworks and has_live_surface:
            detected_framework = brand_frameworks[0]
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
        ai_brand_only = (
            (bool(brand_frameworks) or detection.brand_only)
            and not has_live_surface
        )
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

        INFRA_FRAMEWORKS = {"Ollama", "vLLM", "TGI (HuggingFace)", "OpenAI-compatible",
                            "Triton", "TorchServe", "SageMaker"}
        infra_layer = detected_framework if detected_framework in INFRA_FRAMEWORKS else detected_infra
        app_layer   = detected_framework if detected_framework not in INFRA_FRAMEWORKS else ""

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
    ) -> Tuple[List[str], List[EvidenceItem], List[str], str, List[str]]:
        """Return (js_urls, evidence, links, page_title, brand_frameworks)."""
        evidence: List[EvidenceItem] = []
        js_urls:  List[str]          = []
        links:    List[str]          = []
        brands:   List[str]          = []
        page_title = ""

        if not html:
            return js_urls, evidence, links, page_title, brands

        m_title = re.search(r"<title[^>]*>([^<]+)</title>", html, re.I)
        if m_title:
            page_title = re.sub(r"\s+", " ", m_title.group(1)).strip()
            title_low = page_title.lower()
            if any(kw in title_low for kw in AI_TITLE_KEYWORDS):
                evidence.append(EvidenceItem.make(
                    "page_title_ai", f"AI page title: {page_title[:80]}", "html"))
        else:
            title_low = ""

        # Brand / product name signals in title + early HTML (before JS fetch).
        html_low = html[:80_000].lower()
        for fw_name, sig in FRAMEWORK_SIGNATURES.items():
            hit = False
            for hint in sig.get("title_hints", []):
                if hint and hint in title_low:
                    hit = True
                    break
            if not hit:
                for s in sig.get("js_strings", []):
                    if s.lower() in html_low:
                        hit = True
                        break
            if hit:
                brands.append(fw_name)
                evidence.append(EvidenceItem.make(
                    "html_brand_signal",
                    f"Brand/product signal for {fw_name}",
                    "html", framework=fw_name))

        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            src = m.group(1)
            if not src.startswith("http"):
                src = base + ("" if src.startswith("/") else "/") + src.lstrip("/")
            if any(x in src for x in [
                "/assets/", "/static/", "/dist/", "/js/", "/build/",
                "/_next/", ".bundle.", "chunk", "main.", "app.", "index.",
                "/gradio_api/",
            ]):
                js_urls.append(src)
            # Also keep any same-origin script that looks like an app bundle.
            elif src.endswith(".js") and (
                urllib.parse.urlparse(src).netloc == ""
                or urllib.parse.urlparse(src).netloc == urllib.parse.urlparse(base).netloc
            ):
                js_urls.append(src)

        for m in re.finditer(
            r'<meta[^>]+content=["\']([^"\']*(?:ai|llm|gpt|chatbot|assistant|'
            r'flowise|langflow|librechat|open.?webui|ollama|gradio|dify|'
            r'anythingllm|langchain)[^"\']*)["\']',
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

        return (
            list(dict.fromkeys(js_urls)),
            evidence,
            list(dict.fromkeys(links)),
            page_title,
            list(dict.fromkeys(brands)),
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

    async def _probe_gradio_surface(self, base: str, verbose: bool) -> Dict:
        """Probe Gradio/Langflow config endpoints that often miss HTML brand signals."""
        evidence: List[EvidenceItem] = []
        endpoints: List[str] = []
        frameworks: List[str] = []
        loop = asyncio.get_event_loop()
        paths = [
            "/config", "/info", "/gradio_api/info", "/gradio_api/config",
            "/api/v1/flows", "/api/v1/all", "/health",
        ]
        for path in paths:
            url = base + path
            try:
                status, headers, body = await loop.run_in_executor(
                    None, lambda u=url: self._fetch(u, max_bytes=50_000))
                if status != 200 or not body or _looks_html_body(
                    headers.get("Content-Type", "") or headers.get("content-type", ""),
                    body,
                ):
                    continue
                body_l = body.lower()
                ct = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
                if "json" not in ct and body.strip()[:1] not in "{[":
                    continue
                if any(k in body_l for k in ("gradio", "components", "dependencies")):
                    evidence.append(EvidenceItem.make(
                        "ml_endpoint_200",
                        f"Gradio/config surface at {path}",
                        "probe", endpoint=url, framework="Gradio"))
                    endpoints.append(url)
                    frameworks.append("Gradio")
                    if verbose:
                        print(f"    [gradio] {path} confirmed")
                if "langflow" in body_l or path.startswith("/api/v1/"):
                    if '"flows"' in body_l or "langflow" in body_l or path in (
                        "/api/v1/flows", "/api/v1/all",
                    ):
                        evidence.append(EvidenceItem.make(
                            "ml_endpoint_200",
                            f"Langflow API surface at {path}",
                            "probe", endpoint=url, framework="Langflow"))
                        endpoints.append(url)
                        frameworks.append("Langflow")
                        if verbose:
                            print(f"    [langflow] {path} confirmed")
            except Exception:
                continue
        return {
            "evidence": evidence,
            "endpoints": list(dict.fromkeys(endpoints)),
            "frameworks": list(dict.fromkeys(frameworks)),
        }

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
        return any(pat in path.lower() for pat in [
            "/chat", "/completions", "/generate", "/predict",
            "/embed", "/inference", "/infer", "/model",
            "/v1/", "/api/", "/llm", "/ai/", "/messages",
            "/runs", "/threads", "/assistants",
        ])

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
        self, base: str, extra_paths: List[str], verbose: bool,
        spa_catch_all: bool = False,
    ) -> Dict:
        evidence:    List[EvidenceItem] = []
        endpoints:   List[str]          = []
        frameworks:  List[str]          = []
        auth_signals: List[AuthSignal]  = []
        loop = asyncio.get_event_loop()
        confirmed = 0

        ordered = (
            [(p, c) for p, c in SEED_ENDPOINT_RANKING if c == "schema"] +
            [(p, c) for p, c in SEED_ENDPOINT_RANKING if c == "chat"] +
            [(p, c) for p, c in SEED_ENDPOINT_RANKING if c in ("embedding", "ml", "graphql")]
        )
        for p in extra_paths:
            path = p if p.startswith("/") else "/" + p
            if not any(path == existing for existing, _ in ordered):
                cat = "chat" if self._is_ai_api_path(path) else "schema"
                ordered.append((path, cat))

        always = list(UNIVERSAL_OPENAI_PATHS)
        always_set = {p for p, _ in always}

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
                        "chat", "embedding", "ml", "graphql"))
                )
                if needs_post and category in ("chat", "embedding", "ml", "graphql", "schema"):
                    post_body = _probe_post_body(path, category)
                    status, resp_headers, body = await loop.run_in_executor(
                        None,
                        lambda u=url, d=post_body: self._fetch(u, data=d, method="POST"),
                    )
                return self._evaluate_probe_response(
                    url, path, category, status, resp_headers, body,
                    auth_signals, spa_catch_all=spa_catch_all)
            except Exception:
                return None

        schema_paths = [(p, c) for p, c in ordered if c == "schema"]
        schema_results = await asyncio.gather(
            *[probe(p, c) for p, c in schema_paths[:20]], return_exceptions=True)
        open_hits = 0
        for r in schema_results:
            if isinstance(r, dict) and r:
                evidence.extend(r.get("evidence", []))
                endpoints.extend(r.get("endpoints", []))
                frameworks.extend(r.get("frameworks", []))
                for ev in r.get("evidence", []):
                    if getattr(ev, "key", "").endswith("_200"):
                        open_hits += 1

        for path, category in ordered:
            if path in always_set:
                continue
            if open_hits >= 8 and category != "chat":
                continue
            if open_hits >= 8 and category == "chat" and confirmed >= 12:
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
                for ev in r.get("evidence", []):
                    if getattr(ev, "key", "").endswith("_200"):
                        open_hits += 1
                frameworks.extend(r.get("frameworks", []))

        # Always probe OpenAI-compatible passthroughs — auth-gated /api/* must not starve them.
        for path, category in always:
            if any(urllib.parse.urlparse(e).path == path for e in endpoints):
                continue
            r = await probe(path, category)
            if isinstance(r, dict) and r:
                evidence.extend(r.get("evidence", []))
                endpoints.extend(r.get("endpoints", []))
                frameworks.extend(r.get("frameworks", []))
                confirmed += len(r.get("endpoints", []))
                if verbose and r.get("endpoints"):
                    print(f"    [openai-probe] open surface {path}")
                elif verbose:
                    print(f"    [openai-probe] no surface at {path}")

        return {
            "evidence":    evidence,
            "endpoints":   list(dict.fromkeys(endpoints)),
            "frameworks":  list(dict.fromkeys(frameworks)),
            "auth_signals": auth_signals,
        }

    async def _probe_framework_paths(
        self,
        base: str,
        frameworks: List[str],
        verbose: bool,
        spa_catch_all: bool = False,
    ) -> Dict:
        evidence: List[EvidenceItem] = []
        endpoints: List[str] = []
        fw_hits: List[str] = []
        auth_signals: List[AuthSignal] = []
        loop = asyncio.get_event_loop()
        seen_paths: Set[str] = set()

        async def probe(path: str, category: str):
            if path in seen_paths:
                return None
            seen_paths.add(path)
            url = base + path
            try:
                status, resp_headers, body = await loop.run_in_executor(
                    None, lambda: self._fetch(url))
                ct = (resp_headers.get("Content-Type")
                      or resp_headers.get("content-type") or "")
                if (status in (404, 405)
                        or (status == 200 and _looks_html_body(ct, body))
                        or spa_catch_all):
                    post_body = _probe_post_body(path, category)
                    status, resp_headers, body = await loop.run_in_executor(
                        None,
                        lambda u=url, d=post_body: self._fetch(u, data=d, method="POST"),
                    )
                return self._evaluate_probe_response(
                    url, path, category, status, resp_headers, body,
                    auth_signals, spa_catch_all=spa_catch_all)
            except Exception:
                return None

        tasks = []
        for fw in frameworks:
            for path, cat in FRAMEWORK_PROBE_PATHS.get(fw, []):
                tasks.append(probe(path, cat))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict) and r:
                evidence.extend(r.get("evidence", []))
                endpoints.extend(r.get("endpoints", []))
                fw_hits.extend(r.get("frameworks", []))

        if verbose and endpoints:
            print(f"    [framework-probe] confirmed {len(endpoints)} path(s)")

        return {
            "evidence": evidence,
            "endpoints": list(dict.fromkeys(endpoints)),
            "frameworks": list(dict.fromkeys(fw_hits)),
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
            inference_live = (
                _is_inference_path(path)
                and is_json
                and not _looks_html_body(ct, body)
                and not _is_soft_404_json(body)
            )
            if ai_shaped or inference_live:
                ev_key = ("chat_endpoint_200" if category == "chat" or _is_inference_path(path) else
                          "embedding_endpoint_200" if category == "embedding" else
                          "ml_endpoint_200")
                detail = (
                    f"AI body at {path} (HTTP 200)"
                    if ai_shaped else
                    f"Open inference handler at {path} (HTTP 200 JSON)"
                )
                evidence.append(EvidenceItem.make(
                    ev_key, detail, "probe", endpoint=url))
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

            # Gradio /config and similar schema endpoints.
            if category == "schema" and is_json and url not in endpoints:
                if any(k in body_l for k in (
                    "gradio", "components", "dependencies", "models",
                    "chatflows", "flows", "ollama", "openai", "langflow",
                )):
                    evidence.append(EvidenceItem.make(
                        "ml_endpoint_200",
                        f"AI schema/config at {path} (HTTP 200)",
                        "probe", endpoint=url))
                    endpoints.append(url)
                    if "gradio" in body_l:
                        frameworks.append("Gradio")
                    if "langflow" in body_l:
                        frameworks.append("Langflow")

        elif status == 200 and _is_inference_path(path) and "json" in ct:
            evidence.append(EvidenceItem.make(
                "chat_endpoint_200",
                f"Open inference handler at {path} (HTTP 200)",
                "probe", endpoint=url))
            endpoints.append(url)
            frameworks.append("OpenAI-compatible")

        if status in (401, 403):
            auth_type = self._detect_auth_type(headers_low, body_l)
            auth_signals.append(AuthSignal(
                endpoint=url, auth_type=auth_type,
                status_code=status,
                detail=f"Auth required ({auth_type}) at {path}"))
            # Any AI-related category (including schema/model lists) counts.
            if category in ("chat", "embedding", "ml", "graphql", "schema"):
                evidence.append(EvidenceItem.make(
                    "ml_endpoint_401_403",
                    f"Auth-gated {path} (HTTP {status}, {auth_type})",
                    "probe", endpoint=url))
                endpoints.append(url)

        # On SPA catch-alls, POST→405 is noise for almost every path — ignore it.
        # Only trust 405 on non-SPA targets, and only for real inference categories.
        if (status == 405 and not spa_catch_all
                and category in ("chat", "embedding", "ml")):
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

            for s in sig.get("js_strings", []):
                if s.lower() in combined_text:
                    score += 2
                    signals.append(f"js:{s}")

            for hint in sig.get("title_hints", []):
                if hint and hint in combined_text:
                    score += 4
                    signals.append(f"title:{hint}")
                    break

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
            best_protocol = ""

        fw_confidence = min(best_score / MAX_POSSIBLE_SCORE, 1.0) if best_fw else 0.0
        fw_signals    = matched_signals.get(best_fw, [])

        if best_fw and best_score >= 3:
            pct = f"{fw_confidence*100:.0f}%"
            evidence.append(EvidenceItem.make(
                "framework_identified",
                f"Framework: {best_fw} confidence={pct} signals={fw_signals[:4]}",
                "passive", framework=best_fw))

        INFERENCE_SERVER_NAMES = set(FRAMEWORK_SIGNATURES.keys()) - PROTOCOL_ONLY_LABELS
        infra = ""
        for fw_name in [best_fw] + sorted(scores.keys(), key=lambda x: scores.get(x,0), reverse=True):
            sig = FRAMEWORK_SIGNATURES.get(fw_name, {})
            if sig.get("paths") and any(
                any(p in kp for kp in known_paths)
                for p in sig.get("paths", [])
                if any(x in p for x in ["/api/", "/v1/", "/v2/"])
            ):
                infra = fw_name
                break

        return {
            "evidence":            evidence,
            "framework":           best_fw,
            "framework_confidence": fw_confidence,
            "framework_signals":   fw_signals,
            "protocol":            best_protocol,
            "inference_server":    infra or best_fw,
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