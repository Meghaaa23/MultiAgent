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
    "html_brand_signal":        12,
    "spa_catch_all":             2,

    "dom_assistant_role":        3,
    "html_ai_form":              3,

    "discovery_openapi_ranked": 12,
    "discovery_js_path":         6,
    "discovery_semantic":        4,
}

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

# ---------------------------------------------------------------------------
# Discovery layer (extract → rank → verify)
# Hardcoded full-path catalogs are NOT the primary strategy. Candidates come
# from OpenAPI, JS/HTML, robots/sitemap, and semantic expansion of observed
# nouns. PROTOCOL_BOOTSTRAP is last-resort only when discovery finds nothing.
# ---------------------------------------------------------------------------

# Noun / action segments used to *score* and *expand* observed paths — not a
# catalog of endpoints to spray.
AI_PATH_NOUNS = frozenset({
    "assistant", "assistants", "agent", "agents", "copilot", "llm", "chat",
    "ai", "bot", "bots", "completion", "completions", "embedding", "embeddings",
    "model", "models", "predict", "prediction", "inference", "generate",
    "rag", "workflow", "workflows", "message", "messages", "prompt", "prompts",
    "query", "ask", "invoke", "run", "stream", "respond", "reply",
    "conversation", "conversations", "thread", "threads",
})

AI_PATH_ACTIONS = (
    "query", "ask", "chat", "complete", "completions", "generate", "predict",
    "prediction", "invoke", "run", "message", "messages", "prompt", "infer",
    "search", "embed", "embeddings", "stream", "respond", "reply", "complete",
)

INFERENCE_BODY_FIELDS = frozenset({
    "messages", "prompt", "query", "input", "question", "text",
    "content", "instruction", "inputs", "user_input", "message",
})

# Spec / introspection surfaces only — used to *find* schemas, not inference APIs.
SCHEMA_BOOTSTRAP: List[Tuple[str, str]] = [
    ("/openapi.json",     "schema"),
    ("/swagger.json",     "schema"),
    ("/api-docs",         "schema"),
    ("/api/openapi.json", "schema"),
    ("/v3/api-docs",      "schema"),
    ("/graphql",          "graphql"),
    ("/api/graphql",      "graphql"),
    ("/config",           "schema"),
    ("/info",             "schema"),
    ("/gradio_api/info",  "schema"),
]

# Last resort when extract→rank found zero candidates (bare protocol servers).
PROTOCOL_BOOTSTRAP: List[Tuple[str, str]] = [
    ("/v1/models",            "schema"),
    ("/api/tags",             "schema"),
    ("/v1/chat/completions",  "chat"),
    ("/api/chat",             "chat"),
    ("/api/generate",         "chat"),
    ("/v1/embeddings",        "embedding"),
]

# Backward-compatible alias (tests / callers may still reference the old name).
SEED_ENDPOINT_RANKING: List[Tuple[str, str]] = SCHEMA_BOOTSTRAP + PROTOCOL_BOOTSTRAP


STATIC_ASSET_RE = re.compile(
    r"\.(?:js|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|webp|avif)(?:$|\?)",
    re.I,
)


def is_static_asset_path(path: str) -> bool:
    p = (path or "").split("?")[0].lower()
    if STATIC_ASSET_RE.search(p):
        return True
    # Bundler / frontend asset directories — never API surfaces.
    return any(seg in p for seg in (
        "/_app/", "/assets/", "/static/", "/dist/", "/build/",
        "/_next/", "/immutable/", "/node_modules/",
    ))


def _path_segments(path: str) -> List[str]:
    return [s for s in (path or "").lower().split("/") if s and s != "api"
            and not re.fullmatch(r"v\d+", s)]


def score_path_semantics(path: str) -> int:
    """Score how likely a path is an AI/inference surface (0 = ignore)."""
    segs = _path_segments(path)
    if not segs:
        return 0
    score = 0
    nouns = [s for s in segs if s in AI_PATH_NOUNS]
    actions = [s for s in segs if s in AI_PATH_ACTIONS]
    score += 3 * len(nouns) + 4 * len(actions)
    # Compound like /assistant/query is strong.
    if nouns and actions and set(nouns) != set(actions):
        score += 6
    low = (path or "").lower()
    if any(p in low for p in ("/api/", "/v1/", "/v2/", "/graphql")):
        score += 1
    return score


def is_inference_like_path(path: str) -> bool:
    """True when path looks like it accepts prompts / runs models."""
    segs = _path_segments(path)
    if not segs:
        return False
    actions = AI_PATH_ACTIONS
    if any(s in actions for s in segs):
        return True
    # Single-segment nouns that are themselves actions (chat, predict, …)
    return any(s in ("chat", "predict", "prediction", "generate", "inference",
                     "completions", "query", "ask", "invoke", "run", "messages")
               for s in segs)


def expand_semantic_candidates(observed_paths: List[str],
                               text_hints: List[str] = None) -> List[str]:
    """Generate candidate paths from nouns seen in links/JS/title — not a fixed catalog."""
    nouns: Set[str] = set()
    for p in observed_paths or []:
        for seg in _path_segments(p):
            if seg in AI_PATH_NOUNS:
                nouns.add(seg)
    for hint in text_hints or []:
        low = (hint or "").lower()
        for noun in AI_PATH_NOUNS:
            if re.search(rf"\b{re.escape(noun)}\b", low):
                nouns.add(noun)
    # Prefer product-ish nouns for expansion.
    expand_nouns = [n for n in nouns if n in (
        "assistant", "assistants", "agent", "agents", "copilot", "llm",
        "bot", "bots", "chat", "ai", "rag", "workflow", "workflows",
    )]
    out: List[str] = []
    for noun in expand_nouns[:6]:
        for action in AI_PATH_ACTIONS:
            if action == noun:
                continue
            out.append(f"/{noun}/{action}")
            out.append(f"/api/{noun}/{action}")
            out.append(f"/api/v1/{noun}/{action}")
    # Dedupe, cap.
    return list(dict.fromkeys(out))[:48]


def _openapi_json_properties(method_def: Dict) -> Set[str]:
    props: Set[str] = set()
    if not isinstance(method_def, dict):
        return props
    content = ((method_def.get("requestBody") or {}).get("content") or {})
    for _ct, media in content.items():
        if not isinstance(media, dict):
            continue
        schema = media.get("schema") or {}
        raw = schema.get("properties") or {}
        if isinstance(raw, dict):
            props.update(raw.keys())
        # Resolve simple $ref-less allOf/oneOf first object.
        for key in ("allOf", "oneOf", "anyOf"):
            for part in schema.get(key) or []:
                if isinstance(part, dict) and isinstance(part.get("properties"), dict):
                    props.update(part["properties"].keys())
    return props


def rank_openapi_paths(schema: Dict) -> List[Tuple[str, str, int]]:
    """Return (path, category, score) ranked by POST + inference body fields."""
    ranked: List[Tuple[str, str, int]] = []
    for ep_path, methods in (schema or {}).get("paths", {}).items():
        if not isinstance(methods, dict):
            continue
        score = score_path_semantics(ep_path)
        category = "schema"
        for method, defn in methods.items():
            if not isinstance(defn, dict):
                continue
            m = method.lower()
            if m in ("post", "put", "patch"):
                score += 5
                props = _openapi_json_properties(defn)
                hits = INFERENCE_BODY_FIELDS & props
                if hits:
                    score += 10 * len(hits)
                    category = "chat"
                elif is_inference_like_path(ep_path):
                    category = "chat"
                    score += 3
            elif m == "get" and is_inference_like_path(ep_path):
                score += 1
        if score <= 0 and category == "schema":
            # Still keep documented paths — low priority verification.
            score = 1
        ranked.append((ep_path, category, score))
    ranked.sort(key=lambda x: -x[2])
    return ranked

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
    # Segment-aware: /chat matches /chat or /chat/... but NOT /chatflows.
    (re.compile(r"/(?:chat|completions|generate|messages|ask|conversation|prediction|predict|query|invoke)(?:/|$)", re.I),
     "inference",  "critical"),
    (re.compile(r"/(?:embed|embeddings?)(?:/|$)", re.I),                           "embedding",  "high"),
    (re.compile(r"/(?:pull|push|delete|copy|create|import)(?:/|$)", re.I),         "management", "critical"),
    (re.compile(r"/(?:models?|tags|version|health|info|config)(?:/|$)", re.I),     "metadata",   "medium"),
    (re.compile(r"/(?:tool|function|plugin|action|execute|run)(?:/|$)", re.I),     "tool",       "high"),
    (re.compile(r"/(?:memory|store|recall|history)(?:/|$)", re.I),                 "memory",     "high"),
    (re.compile(r"/(?:search|retrieve|vector|rag)(?:/|$)", re.I),                  "retrieval",  "high"),
    (re.compile(r"/(?:agents?|orchestrat|workflow|plan)(?:/|$)", re.I),            "agentic",    "high"),
    (re.compile(r"/(?:upload|file|image|audio|vision)(?:/|$)", re.I),              "multimodal", "medium"),
    (re.compile(r"/(?:graphql)(?:/|$)", re.I),                                     "graphql",    "high"),
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
    page_title:       str                = ""
    spa_catch_all:    bool               = False
    app_description:  str                = ""

    def to_dict(self) -> Dict:
        return {
            "is_ai_powered":          self.is_ai_powered,
            "confidence":             self.confidence,
            "evidence_score":         self.evidence_score,
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

        # Phase 1 — passive extract (no inference path spraying).
        parallel = await asyncio.gather(
            self._fetch_and_analyse_js(js_urls, base, verbose),
            self._probe_openapi(base, verbose),
            self._probe_graphql(base, verbose),
            self._fetch_robots_sitemap(base, verbose),
            self._analyse_headers_cookies(response_headers, verbose),
            return_exceptions=True,
        )
        js_r, openapi_r, graphql_r, passive_r, header_r = parallel

        all_evidence: List[EvidenceItem] = list(html_evidence)
        ml_endpoints:    List[str]  = list(gradio_endpoints)
        discovered_paths: List[str] = []
        all_frameworks:  List[str]  = list(brand_frameworks)
        auth_signals:    List[AuthSignal] = []
        openapi_schema:  Dict       = {}
        graphql_types:   List[str]  = []
        js_api_paths:    List[str]  = []
        raw_html_js = ""

        for r in [js_r, openapi_r, graphql_r, passive_r, header_r]:
            if isinstance(r, dict):
                all_evidence.extend(r.get("evidence", []))
                ml_endpoints.extend(r.get("endpoints", []))
                all_frameworks.extend(r.get("frameworks", []))
                auth_signals.extend(r.get("auth_signals", []))

        if isinstance(js_r, dict):
            js_api_paths = js_r.get("api_paths", [])
            raw_html_js  = js_r.get("raw_js", "")
            discovered_paths.extend(js_api_paths)
            for fw in js_r.get("frameworks", []):
                if fw in FRAMEWORK_SIGNATURES and fw not in brand_frameworks:
                    brand_frameworks.append(fw)

        if isinstance(openapi_r, dict) and openapi_r.get("found"):
            openapi_schema = openapi_r.get("schema", {})
            discovered_paths.extend(
                urllib.parse.urlparse(u).path
                for u in openapi_r.get("endpoints", [])
                if isinstance(u, str)
            )

        if isinstance(graphql_r, dict):
            graphql_types = graphql_r.get("types", [])

        if isinstance(passive_r, dict):
            discovered_paths.extend(passive_r.get("paths", []))

        # Phase 2 — rank candidates from discoveries (not a hardcoded path catalog).
        text_hints = [page_title or "", *(brand_frameworks or [])]
        candidates = self._build_discovery_candidates(
            html_links=extracted_links,
            js_paths=js_api_paths,
            openapi_schema=openapi_schema,
            robots_paths=list(passive_r.get("paths", []) if isinstance(passive_r, dict) else []),
            brand_frameworks=brand_frameworks,
            text_hints=text_hints,
            extra_paths=extra_seed_paths,
        )
        discovered_paths.extend(p for p, _c, _s in candidates)

        if verbose and candidates:
            top = ", ".join(f"{p}({s})" for p, _c, s in candidates[:8])
            print(f"    [discovery] {len(candidates)} candidate(s): {top}")

        # Phase 3 — verify ranked candidates (POST-aware).
        probe_r = await self._probe_ranked_endpoints(
            base, candidates, verbose, spa_catch_all=spa_catch_all)
        if isinstance(probe_r, dict):
            all_evidence.extend(probe_r.get("evidence", []))
            ml_endpoints.extend(probe_r.get("endpoints", []))
            all_frameworks.extend(probe_r.get("frameworks", []))
            auth_signals.extend(probe_r.get("auth_signals", []))

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
        # Fall back to top discovery chat candidates, not a hardcoded spray list.
        if not open_targets:
            open_targets = [
                base + p for p, cat, _s in candidates
                if cat in ("chat", "ml", "embedding")
            ][:4]
        probe_targets = open_targets
        if self.run_behavioral_probes and probe_targets:
            behav_r = await self._behavioral_probes(probe_targets[:2], verbose)
            if isinstance(behav_r, dict):
                all_evidence.extend(behav_r.get("evidence", []))

        # Confirm JS / discovery paths that weren't already verified.
        confirm_paths = list(dict.fromkeys(
            js_api_paths + [p for p, c, s in candidates if c == "chat" and s >= 6]
        ))
        if confirm_paths:
            extra = await self._confirm_js_paths(
                base, confirm_paths, verbose, spa_catch_all=spa_catch_all)
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
        if not detected_framework and brand_frameworks:
            detected_framework = brand_frameworks[0]
        if detected_framework and detected_framework not in all_frameworks:
            all_frameworks.insert(0, detected_framework)
        if detected_protocol and detected_protocol not in all_frameworks:
            all_frameworks.append(detected_protocol)

        capabilities = self._infer_capabilities(
            detected_framework, all_frameworks, openapi_schema,
            ml_endpoints, graphql_types)

        # Deduplicate evidence by (key, detail) to avoid meta-tag spam.
        seen_ev: Set[Tuple[str, str]] = set()
        deduped_evidence: List[EvidenceItem] = []
        for ev in all_evidence:
            k = (ev.key, ev.detail)
            if k in seen_ev:
                continue
            seen_ev.add(k)
            deduped_evidence.append(ev)
        all_evidence = deduped_evidence

        total_score = sum(ev.weight for ev in all_evidence)
        confidence  = score_to_confidence(total_score)
        is_ai       = total_score >= 20 or bool(detected_framework and total_score >= 12)

        atlas: List[str] = []
        for ep in ml_endpoints:
            path = urllib.parse.urlparse(ep).path.lower()
            if any(x in path for x in ["/chat", "/completions", "/generate", "/messages",
                                       "/ask", "/prediction", "/run", "/query",
                                       "/assistant", "/invoke"]):
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
            page_title            = page_title,
            spa_catch_all         = spa_catch_all,
            app_description       = meta_desc,
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
            if not href.startswith("/") or is_static_asset_path(href):
                continue
            low = href.lower()
            # Segment-aware: "/app" must not match "/_app/..." asset paths.
            segs = set(_path_segments(href))
            if (
                score_path_semantics(href) > 0
                or segs & {"chat", "api", "playground", "workspace", "dashboard",
                           "app", "assistant", "agent", "copilot", "flow",
                           "query", "ask"}
                or any(low.startswith(p) for p in (
                    "/api/", "/chat/", "/assistant/", "/agent/", "/copilot/",
                ))
            ):
                links.append(href)

        # Forms that POST to custom AI endpoints.
        for m in re.finditer(
            r'<form[^>]+action=["\']([^"\']+)["\']', html, re.I
        ):
            action = m.group(1)
            if action.startswith("/") and score_path_semantics(action) > 0:
                links.append(action)

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
        """Extract API-looking paths from JS; rank/filter by semantics (not a fixed list)."""
        found: Set[str] = set()
        patterns = [
            r'(?:fetch|axios(?:\.\w+)?)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'\.open\s*\(\s*[\'"][A-Z]+[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]',
            r'(?:url|path|endpoint|href|action|baseURL|BASE_URL)\s*[:=]\s*[\'"`](/[^\'"`\s]{2,120})[\'"`]',
            r'[\'"`](/(?:api|v\d+|assistant|agent|agents|copilot|llm|ai|chat|'
            r'predict|query|ask|generate|messages|completions)[^\'"`?\s]{0,100})[\'"`]',
        ]
        for pat in patterns:
            for m in re.finditer(pat, js, re.I):
                raw = m.group(1).split("${")[0].rstrip("/")
                if not raw or raw.startswith("http") and "://" in raw:
                    # Absolute same-path only — keep path component.
                    if raw.startswith("http"):
                        raw = urllib.parse.urlparse(raw).path or ""
                if not raw.startswith("/"):
                    continue
                if len(raw) > 120 or " " in raw:
                    continue
                # Static assets are not API surfaces.
                if is_static_asset_path(raw):
                    continue
                if score_path_semantics(raw) > 0 or self._is_ai_api_path(raw):
                    found.add(raw)
        return list(found)

    @staticmethod
    def _is_ai_api_path(path: str) -> bool:
        low = (path or "").lower()
        if score_path_semantics(low) >= 3:
            return True
        return any(pat in low for pat in [
            "/chat", "/completions", "/generate", "/predict",
            "/embed", "/inference", "/infer", "/model",
            "/v1/", "/api/", "/llm", "/ai/", "/messages",
            "/runs", "/threads", "/assistant", "/agent",
            "/copilot", "/query", "/ask", "/invoke",
        ])

    def _build_discovery_candidates(
        self,
        html_links: List[str],
        js_paths: List[str],
        openapi_schema: Dict,
        robots_paths: List[str],
        brand_frameworks: List[str],
        text_hints: List[str],
        extra_paths: List[str] = None,
    ) -> List[Tuple[str, str, int]]:
        """Build (path, category, score) from discoveries — extract → rank."""
        scored: Dict[str, Tuple[str, int]] = {}

        def _add(path: str, category: str, score: int):
            if not path:
                return
            path = path if path.startswith("/") else "/" + path.lstrip("/")
            # Drop obvious non-API pages / static assets.
            if path in ("/", "/favicon.ico", "/robots.txt", "/sitemap.xml"):
                return
            if is_static_asset_path(path):
                return
            prev = scored.get(path)
            if prev is None or score > prev[1]:
                # Prefer chat category if either says chat.
                cat = category
                if prev and prev[0] == "chat":
                    cat = "chat"
                scored[path] = (cat, score)

        # OpenAPI — strongest signal (POST + body fields).
        for path, cat, score in rank_openapi_paths(openapi_schema or {}):
            _add(path, cat, score + 8)

        # JS-extracted paths.
        for path in js_paths or []:
            s = score_path_semantics(path)
            cat = "chat" if is_inference_like_path(path) else "schema"
            _add(path, cat, max(s, 4) + 4)

        # HTML links.
        for path in html_links or []:
            s = score_path_semantics(path)
            cat = "chat" if is_inference_like_path(path) else "schema"
            _add(path, cat, max(s, 2) + 2)

        # robots / sitemap.
        for path in robots_paths or []:
            s = score_path_semantics(path)
            if s <= 0 and not self._is_ai_api_path(path):
                continue
            cat = "chat" if is_inference_like_path(path) else "schema"
            _add(path, cat, max(s, 2) + 1)

        # Semantic expansion from observed nouns (e.g. /assistant → /assistant/query).
        observed = list(scored.keys()) + list(js_paths or []) + list(html_links or [])
        for path in expand_semantic_candidates(observed, text_hints):
            s = score_path_semantics(path)
            _add(path, "chat" if is_inference_like_path(path) else "schema", s + 2)

        # Brand-known framework paths (confirmation, not universal spray).
        for fw in brand_frameworks or []:
            for path, cat in FRAMEWORK_PROBE_PATHS.get(fw, []):
                _add(path, cat, 5)

        for path in extra_paths or []:
            p = path if path.startswith("/") else "/" + str(path).lstrip("/")
            cat = "chat" if is_inference_like_path(p) else "schema"
            _add(p, cat, max(score_path_semantics(p), 2))

        # Schema bootstrap always available (find OpenAPI / Gradio config).
        for path, cat in SCHEMA_BOOTSTRAP:
            _add(path, cat, 2)

        ranked = [(p, c, s) for p, (c, s) in scored.items()]
        ranked.sort(key=lambda x: (-x[2], x[0]))

        # Last resort: protocol bootstrap only when discovery is empty of chat-like paths.
        if not any(c == "chat" for _p, c, _s in ranked):
            for path, cat in PROTOCOL_BOOTSTRAP:
                _add(path, cat, 1)
            ranked = [(p, c, s) for p, (c, s) in scored.items()]
            ranked.sort(key=lambda x: (-x[2], x[0]))

        return ranked[:60]

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

                for ep_path, cat, score in rank_openapi_paths(spec):
                    # Only promote high-confidence inference paths into ml_endpoints;
                    # lower-ranked paths are still verified via the discovery probe queue.
                    if cat == "chat" or score >= 10:
                        endpoints.append(base + ep_path)
                        evidence.append(EvidenceItem.make(
                            "openapi_ai_endpoint",
                            f"Ranked AI path in spec: {ep_path} (score={score})",
                            "openapi", endpoint=base + ep_path))
                        evidence.append(EvidenceItem.make(
                            "discovery_openapi_ranked",
                            f"OpenAPI ranked {ep_path} as {cat}",
                            "openapi", endpoint=base + ep_path))
                    elif score >= 3:
                        # Keep as discovered candidate path (absolute → path only later).
                        endpoints.append(base + ep_path)

                for _ep_path, methods in spec_paths.items():
                    if not isinstance(methods, dict):
                        continue
                    for method_def in methods.values():
                        if not isinstance(method_def, dict):
                            continue
                        props = _openapi_json_properties(method_def)
                        if "tools" in props or "functions" in props:
                            capabilities.append("tool_calling")
                        if "messages" in props or "prompt" in props or "query" in props:
                            capabilities.append("chat")
                        if "input" in props and "model" in props:
                            capabilities.append("embedding")
                if verbose:
                    print(f"    [openapi] {path}: {len(spec_paths)} paths "
                          f"({sum(1 for _, c, _ in rank_openapi_paths(spec) if c == 'chat')} inference-ranked)")
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
        self, base: str, extra_paths, verbose: bool,
        spa_catch_all: bool = False,
    ) -> Dict:
        """Verify discovery candidates. `extra_paths` may be str paths or (path, cat, score)."""
        evidence:    List[EvidenceItem] = []
        endpoints:   List[str]          = []
        frameworks:  List[str]          = []
        auth_signals: List[AuthSignal]  = []
        loop = asyncio.get_event_loop()
        confirmed = 0

        ordered: List[Tuple[str, str]] = []
        for item in extra_paths or []:
            if isinstance(item, tuple) and len(item) >= 2:
                path, cat = item[0], item[1]
            else:
                path = str(item)
                cat = "chat" if is_inference_like_path(path) else "schema"
            path = path if path.startswith("/") else "/" + path.lstrip("/")
            if not any(path == existing for existing, _ in ordered):
                ordered.append((path, cat))

        # If caller passed nothing, only schema bootstrap (never spray inference catalog).
        if not ordered:
            ordered = list(SCHEMA_BOOTSTRAP)

        async def probe(path: str, category: str):
            url = base + path
            try:
                # Inference-like paths: POST-first (custom APIs are often POST-only).
                if category in ("chat", "embedding", "ml", "graphql") or is_inference_like_path(path):
                    status, resp_headers, body = await loop.run_in_executor(
                        None, lambda: self._fetch(url, data=b"{}", method="POST"))
                    ct = (resp_headers.get("Content-Type")
                          or resp_headers.get("content-type") or "")
                    if status in (404, 405) or _looks_html_body(ct, body) or status == 0:
                        status, resp_headers, body = await loop.run_in_executor(
                            None, lambda: self._fetch(url))
                else:
                    status, resp_headers, body = await loop.run_in_executor(
                        None, lambda: self._fetch(url))
                    ct = (resp_headers.get("Content-Type")
                          or resp_headers.get("content-type") or "")
                    needs_post = (
                        status in (404, 405)
                        or (status == 200 and _looks_html_body(ct, body))
                        or (spa_catch_all and status == 200)
                    )
                    if needs_post:
                        status, resp_headers, body = await loop.run_in_executor(
                            None, lambda: self._fetch(url, data=b"{}", method="POST"))
                return self._evaluate_probe_response(
                    url, path, category, status, resp_headers, body,
                    auth_signals, spa_catch_all=spa_catch_all)
            except Exception:
                return None

        schema_paths = [(p, c) for p, c in ordered if c == "schema"]
        other_paths = [(p, c) for p, c in ordered if c != "schema"]

        schema_results = await asyncio.gather(
            *[probe(p, c) for p, c in schema_paths[:20]], return_exceptions=True)
        for r in schema_results:
            if isinstance(r, dict) and r:
                evidence.extend(r.get("evidence", []))
                endpoints.extend(r.get("endpoints", []))
                frameworks.extend(r.get("frameworks", []))
                confirmed += len(r.get("endpoints", []))

        for path, category in other_paths:
            if confirmed >= 12:
                break
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
                    status, resp_headers, body = await loop.run_in_executor(
                        None, lambda: self._fetch(url, data=b"{}", method="POST"))
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
            if ("json" in ct or body.strip()[:1] in "{[") and any(
                re.search(p, body, re.I) for p in AI_RESPONSE_BODY_PATTERNS
            ):
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

            # Gradio /config and similar schema endpoints.
            if category == "schema" and ("json" in ct or body.strip()[:1] in "{["):
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

        if status in (401, 403):
            auth_type = self._detect_auth_type(headers_low, body_l)
            auth_signals.append(AuthSignal(
                endpoint=url, auth_type=auth_type,
                status_code=status,
                detail=f"Auth required ({auth_type}) at {path}"))
            # Any AI-related category, or inference-like custom path (e.g. /assistant/query).
            if category in ("chat", "embedding", "ml", "graphql", "schema") or is_inference_like_path(path):
                evidence.append(EvidenceItem.make(
                    "ml_endpoint_401_403",
                    f"Auth-gated {path} (HTTP {status}, {auth_type})",
                    "probe", endpoint=url))
                endpoints.append(url)

        # On SPA catch-alls, POST→405 is noise for almost every path — ignore it.
        # Only trust 405 on non-SPA targets, and only for real inference categories.
        if (status == 405 and not spa_catch_all
                and (category in ("chat", "embedding", "ml") or is_inference_like_path(path))):
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
            elif (category in ("chat", "embedding", "ml") or is_inference_like_path(path)) and (
                "json" in ct or body.strip()[:1] in "{["
            ):
                # Handler reached with validation error => real API surface.
                # Includes custom paths like /assistant/query even if categorized schema.
                evidence.append(EvidenceItem.make(
                    "error_generic_validation",
                    f"API validation response at {path} (HTTP {status})",
                    "probe", endpoint=url))
                endpoints.append(url)
            elif any(f in body_l for f in (
                "prompt", "messages", "query", "input", "question", "model",
            )) and ("json" in ct or body.strip()[:1] in "{["):
                evidence.append(EvidenceItem.make(
                    "error_generic_validation",
                    f"API validation (inference fields) at {path} (HTTP {status})",
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
        auth_signals: List[AuthSignal]  = []
        loop = asyncio.get_event_loop()

        for ep in (endpoints or []):
            url    = ep.get("url", "")
            if not url:
                continue
            method = str(ep.get("method") or "GET").upper()
            path = urllib.parse.urlparse(url).path
            try:
                if method in ("POST", "PUT", "PATCH") or is_inference_like_path(path):
                    status, hdrs, body = await loop.run_in_executor(
                        None, lambda u=url: self._fetch(u, data=b"{}", method="POST"))
                else:
                    status, hdrs, body = await loop.run_in_executor(
                        None, lambda u=url: self._fetch(u))
                r = self._evaluate_probe_response(
                    url, path,
                    "chat" if is_inference_like_path(path) else "schema",
                    status, hdrs, body, auth_signals)
                if r:
                    evidence.extend(r.get("evidence", []))
                    ml_endpoints.extend(r.get("endpoints", []))
            except Exception:
                pass

        return {
            "evidence": evidence,
            "endpoints": list(dict.fromkeys(ml_endpoints)),
            "auth_signals": auth_signals,
        }

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