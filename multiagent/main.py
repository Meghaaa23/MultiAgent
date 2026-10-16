

import os
import sys
import asyncio
import json
import secrets

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from typing import Optional, Dict, List, Any
from enum import Enum
from datetime import datetime

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from agents.threat_modeling_agent import ThreatModelingAgent
from agents.webappscanner.ssrf_guard import SSRFBlocked
from agents.webappscanner import scan_limits
import logging
import traceback

from openai import OpenAI

from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_agentchat.conditions import TextMentionTermination, MaxMessageTermination
from autogen_agentchat.messages import TextMessage, UserMessage
from autogen_core.models import CreateResult, RequestUsage
from autogen_agentchat.base import Response, TaskResult

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv()

class FinishReason(str, Enum):
    STOP           = "stop"
    LENGTH         = "length"
    FUNCTION_CALLS = "function_calls"
    CONTENT_FILTER = "content_filter"
    UNKNOWN        = "unknown"

    def __str__(self):
        return self.value

from openai import AzureOpenAI

llama_base_url = os.getenv("LLAMA_BASE_URL", "http://localhost:8080")
llama_model    = os.getenv("LLAMA_MODEL_NAME", "Qwen-2.5")

# Per-LLM-call timeout and retry budget. With the scan itself run-to-completion
# (no SCAN_TIMEOUT_SECONDS), these bound a single hung model request so one
# stuck call cannot stall the whole scan. 90s matches YuraScanner's apiTimeout;
# the SDK applies exponential backoff + Retry-After across retries.
def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default

def _env_int(name: str, default: int) -> int:
    try:
        return max(0, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default

llm_call_timeout = _env_float("LLM_CALL_TIMEOUT_SECONDS", 90.0)
llm_max_retries  = _env_int("LLM_MAX_RETRIES", 4)

local_client = OpenAI(
    base_url=f"{llama_base_url}/v1",
    api_key="not-needed",
    timeout=300.0,
    max_retries=0,
)

azure_api_key    = os.getenv("AZURE_OPENAI_API_KEY")
azure_endpoint   = os.getenv("AZURE_OPENAI_ENDPOINT")
azure_deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
azure_api_version= os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01")

azure_client = AzureOpenAI(
    api_key=azure_api_key,
    azure_endpoint=azure_endpoint,
    api_version=azure_api_version,
    timeout=llm_call_timeout,
    max_retries=llm_max_retries,
) if azure_api_key and azure_endpoint else None

active_provider = os.getenv("ACTIVE_MODEL_PROVIDER", "azure")

def get_active_client():
    if active_provider == "azure" and azure_client:
        return azure_client, azure_deployment
    return local_client, llama_model

def get_config_list():
    if active_provider == "azure" and azure_api_key:
        return [{
            "model":       azure_deployment,
            "api_type":    "azure",
            "api_key":     azure_api_key,
            "base_url":    azure_endpoint,
            "api_version": azure_api_version,
        }]
    return [{
        "model":          llama_model,
        "api_type":       "openai",
        "openai_api_key": "not-needed",
        "base_url":       f"{llama_base_url}/v1",
    }]

client      = local_client
config_list = get_config_list()

# ---------------------------------------------------------------------------
# Authentication (F2 remediation) + caller identity (F3)
#
# A single, central Bearer-token guard applied to every route via the FastAPI
# ``dependencies=[...]`` constructor argument. Only ``GET /health`` is public
# (so container / load-balancer health checks keep working). Tokens come
# exclusively from the environment (API_AUTH_TOKEN, plus an optional
# comma-separated API_AUTH_TOKENS for distinct callers) and are never hardcoded
# or shipped to the frontend. If no token is configured the guard fails closed
# (503) so a missing config can never silently disable auth.
#
# For F3, the matched token also establishes a stable, server-derived caller
# identity (a salted hash of the token, never the raw token) stored on
# request.state.caller_id and used for session ownership. Deployments with a
# single shared token keep exactly the F2 behavior and have a single caller
# identity; adding tokens via API_AUTH_TOKENS yields distinct callers.
# ---------------------------------------------------------------------------
API_AUTH_TOKEN = os.getenv("API_AUTH_TOKEN")

# Paths reachable without a credential. Keep this minimal.
_PUBLIC_PATHS = frozenset({"/health"})


def _valid_tokens() -> List[str]:
    """Current set of accepted tokens, read from the environment."""
    tokens: List[str] = []
    single = os.getenv("API_AUTH_TOKEN")
    if single and single.strip():
        tokens.append(single.strip())
    for t in (os.getenv("API_AUTH_TOKENS") or "").split(","):
        t = t.strip()
        if t:
            tokens.append(t)
    return tokens


async def require_auth(request: Request) -> None:
    """Central Bearer-token check for all non-public endpoints."""
    if request.url.path in _PUBLIC_PATHS:
        return

    tokens = _valid_tokens()
    if not tokens:
        # Fail closed: refuse protected traffic until the operator configures a
        # token rather than defaulting to an open, unauthenticated service.
        logger.error(
            "No API token configured; refusing protected request to %s",
            request.url.path,
        )
        raise HTTPException(
            status_code=503,
            detail="Server authentication is not configured (API_AUTH_TOKEN unset).",
        )

    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status_code=401,
            detail="Missing or malformed Authorization header (expected 'Bearer <token>').",
            headers={"WWW-Authenticate": "Bearer"},
        )

    presented = token.strip()
    # Constant-time comparison against each accepted token to avoid timing leaks.
    matched = False
    for valid in tokens:
        if secrets.compare_digest(presented, valid):
            matched = True
            break
    if not matched:
        raise HTTPException(status_code=403, detail="Invalid API credentials.")

    # F3: derive a stable, non-reversible caller identity from the credential.
    request.state.caller_id = scan_limits.caller_key(header)


app = FastAPI(
    title="Multi-Agent Threat Modeling System with Web Scanning + AI Backdoor Detection",
    description="AutoGen + Threat Modeling + Web Scanning + AI Backdoor Analysis",
    version="7.0.0",
    dependencies=[Depends(require_auth)],
)

@app.on_event("startup")
async def _note_browser_loop_mode() -> None:
    """Playwright needs a subprocess-capable loop. On Windows `uvicorn --reload`"""
    import sys as _sys
    if _sys.platform != "win32":
        return
    loop_name = type(asyncio.get_event_loop()).__name__
    if "Selector" in loop_name:
        logger.info(
            "[startup] Event loop is %s (typical under --reload); browser-driven "
            "crawling will run on a Proactor compatibility thread.", loop_name)

ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:4200,http://ems885-sidc-lab"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

# ---------------------------------------------------------------------------
# Safe error handling (F6 remediation)
#
# Clients get stable, generic messages for unexpected failures; the full
# exception and traceback are logged server-side only. Intentional HTTP errors
# (HTTPException: 400/401/403/404/429/503/504 with their safe, authored
# messages) are dispatched by FastAPI's own HTTPException handler and are not
# affected by the catch-all below.
# ---------------------------------------------------------------------------
GENERIC_ERROR = "Internal server error"


def _safe_error_message(exc: Exception) -> str:
    """Client-safe text: the authored message for known-safe errors, else generic.

    Used where an error must be reported inside a 200/stream body (so it cannot
    be an HTTPException). Never returns raw exception text for unknown errors.
    """
    if isinstance(exc, SSRFBlocked):
        return "Target host is not permitted by the server's SSRF egress policy."
    if isinstance(exc, scan_limits.ScanBusy):
        return "Scanner is at capacity; try again shortly."
    if isinstance(exc, scan_limits.ScanTimeout):
        return "Scan exceeded its time budget."
    if isinstance(exc, scan_limits.RateLimited):
        return "Scan rate limit exceeded. Please slow down."
    return GENERIC_ERROR


@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception):
    # Defense-in-depth: any exception that escapes an endpoint becomes a generic
    # 500. The real error + traceback go to server logs only.
    logger.error(
        "Unhandled error on %s %s: %s\n%s",
        request.method, request.url.path, type(exc).__name__,
        traceback.format_exc(),
    )
    return JSONResponse(status_code=500, content={"detail": GENERIC_ERROR})

from agents.qa_agent import set_config

set_config(config_list)

async def web_search_wrapper(query: str) -> List[Dict]:
    try:
        logger.info(f"Web search: {query[:50]}...")
        from ddgs import DDGS
        ddgs    = DDGS()
        results = []
        for item in ddgs.text(query, max_results=10):
            results.append({
                "title":   item.get("title", ""),
                "url":     item.get("href", ""),
                "snippet": item.get("body", ""),
            })
        logger.info(f"Found {len(results)} results")
        return results
    except Exception as e:
        logger.error(f"Web search failed: {e}")
        return []

try:
    active_client, active_model = get_active_client()
    threat_modeling_agent = ThreatModelingAgent(
        openai_client=active_client,
        web_search_function=web_search_wrapper,
        llm_model=active_model,
    )
    logger.info("Threat Modeling Agent initialized")
except Exception as e:
    logger.warning(f"Threat Modeling Agent init failed: {e}", exc_info=True)
    threat_modeling_agent = None

logger.info("All agents initialized")

def message_to_openai_format(message):
    if isinstance(message, (UserMessage, TextMessage)):
        if hasattr(message, 'source') and message.source and \
                message.source not in ['user', None]:
            return {"role": "assistant", "content": message.content}
        return {"role": "user", "content": message.content}
    elif hasattr(message, 'content'):
        if hasattr(message, 'source'):
            if message.source == 'user':
                return {"role": "user", "content": message.content}
            elif message.source:
                return {"role": "assistant", "content": message.content}
        return {"role": "user", "content": str(message.content)}
    return {"role": "user", "content": str(message)}

def clean_message_history(messages):
    cleaned   = []
    last_role = None
    for msg in messages:
        role    = msg.get("role")
        content = msg.get("content", "")
        if not content or not str(content).strip():
            continue
        if role == "assistant" and last_role == "assistant":
            logger.warning("Skipping consecutive assistant message")
            continue
        cleaned.append(msg)
        last_role = role
    if cleaned and cleaned[0].get("role") == "assistant":
        cleaned = cleaned[1:]
    return cleaned or [{"role": "user", "content": "Hello"}]

class LocalLlamaChatCompletionClient:

    def __init__(self, client, model_name):
        self.client     = client
        self.model_name = model_name
        self.model_info = {
            "name":             model_name,
            "max_tokens":       4096,
            "context_length":   4096,
            "vision":           False,
            "supports_chat":    True,
            "function_calling": False,
            "json_output":      False,
            "family":           "llama",
        }

    async def create(self, messages, max_tokens=4096, temperature=0.1,
                     top_p=0.9, stream=False, **kwargs):
        api_messages = [message_to_openai_format(m) for m in messages]
        api_messages = clean_message_history(api_messages)
        if not api_messages:
            return CreateResult(
                content="No valid messages",
                usage=RequestUsage(prompt_tokens=0, completion_tokens=0),
                finish_reason=FinishReason.STOP, cached=False,
            )
        try:
            loop     = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.client.chat.completions.create(
                    model=self.model_name, messages=api_messages,
                    max_tokens=max_tokens, temperature=temperature,
                    top_p=top_p, stream=False,
                )
            )
            if not response or not response.choices:
                return CreateResult(
                    content="No response from LLM",
                    usage=RequestUsage(prompt_tokens=0, completion_tokens=0),
                    finish_reason=FinishReason.UNKNOWN, cached=False,
                )
            choice     = response.choices[0]
            usage_data = getattr(response, "usage", None)
            usage      = RequestUsage(
                prompt_tokens=getattr(usage_data, "prompt_tokens", 0),
                completion_tokens=getattr(usage_data, "completion_tokens", 0),
            ) if usage_data else RequestUsage(prompt_tokens=0, completion_tokens=0)

            finish_reason = {
                "stop":   FinishReason.STOP,
                "length": FinishReason.LENGTH,
            }.get(choice.finish_reason, FinishReason.UNKNOWN)

            return CreateResult(
                content=choice.message.content or "",
                usage=usage, finish_reason=finish_reason, cached=False,
            )
        except Exception as e:
            logger.exception(f"LLM call failed: {e}")
            return CreateResult(
                content="The language model request could not be completed.",
                usage=RequestUsage(prompt_tokens=0, completion_tokens=0),
                finish_reason=FinishReason.UNKNOWN, cached=False,
            )

    async def create_stream(self, messages, **kwargs):
        raise NotImplementedError("Streaming not implemented")

_init_client, _init_model = get_active_client()
model_client = LocalLlamaChatCompletionClient(_init_client, _init_model)

session_teams: Dict[str, RoundRobinGroupChat] = {}
session_histories: Dict[str, List[Dict[str, str]]] = {}

# ---------------------------------------------------------------------------
# Session ownership (F3 remediation)
#
# session_id is supplied by the client and must NOT be treated as proof of
# ownership. Every session is bound to the server-derived caller identity
# (request.state.caller_id, set by require_auth) that first created it. A
# caller may only access sessions it owns. Unknown or ownerless (legacy)
# sessions fail closed, and denied access returns 404 so the existence of
# another caller's session is never confirmed.
# ---------------------------------------------------------------------------
session_owners: Dict[str, str] = {}


def _caller_id(request: Request) -> str:
    cid = getattr(request.state, "caller_id", None)
    if not cid:
        # require_auth always sets this for protected routes; fail closed.
        raise HTTPException(status_code=401, detail="Unauthenticated.")
    return cid


def _session_denied() -> HTTPException:
    # Uniform, non-disclosing response for any ownership failure.
    return HTTPException(status_code=404, detail="Session not found.")


def _authorize_session(session_id: str, caller_id: str, *, create: bool) -> None:
    """Enforce that ``caller_id`` owns ``session_id``.

    create=True (query/scan/write paths): claim a brand-new session for the
    caller; reject if it belongs to someone else or is an ownerless legacy
    session. create=False (read/list/delete): reject anything not owned.
    """
    owner = session_owners.get(session_id)
    if owner is not None:
        if owner != caller_id:
            raise _session_denied()
        return
    # No recorded owner.
    if session_id in session_histories or session_id in session_teams:
        # Pre-existing session without ownership metadata -> fail closed.
        raise _session_denied()
    if create:
        session_owners[session_id] = caller_id
        return
    raise _session_denied()


def _default_session_id(prefix: str, caller_id: str) -> str:
    """Caller-scoped default so callers that omit session_id never collide."""
    return f"{prefix}:{caller_id}"


SYSTEM_PROMPT = (
    "You are an intelligent cybersecurity assistant. "
    "Answer clearly using cybersecurity knowledge. "
    "Cite well-known standards (OWASP, NIST, CISA, MITRE) when relevant. "
    "Be conversational and practical."
)

async def answer_with_llm(question: str, session_id: str) -> str:
    """Direct LLM answer with simple session memory (no AutoGen dependency)."""
    client, model_name = get_active_client()
    history = session_histories.setdefault(session_id, [])

    messages: List[Dict[str, str]] = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.extend(history[-12:])
    messages.append({"role": "user", "content": question})

    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(
        None,
        lambda: client.chat.completions.create(
            model=model_name,
            messages=messages,
            max_tokens=2048,
            temperature=0.3,
        ),
    )
    answer = ""
    if response and response.choices:
        answer = (response.choices[0].message.content or "").strip()
    if not answer:
        answer = "I could not generate a response. Please try again."

    history.append({"role": "user", "content": question})
    history.append({"role": "assistant", "content": answer})
    session_histories[session_id] = history[-20:]
    return answer

async def get_or_create_team(session_id: str) -> RoundRobinGroupChat:
    if session_id in session_teams:
        return session_teams[session_id]
    rag_assistant = AssistantAgent(
        name="security_assistant",
        model_client=model_client,
        system_message=SYSTEM_PROMPT,
    )
    team = RoundRobinGroupChat(
        participants=[rag_assistant],
        termination_condition=MaxMessageTermination(max_messages=5),
    )
    session_teams[session_id] = team
    return team

def clear_session_team(session_id: str):
    session_teams.pop(session_id, None)
    session_histories.pop(session_id, None)

async def get_team_history(session_id: str) -> List[Dict]:
    if session_id in session_histories:
        return list(session_histories[session_id])
    if session_id not in session_teams:
        return []
    team    = session_teams[session_id]
    history = []
    if hasattr(team, '_message_thread'):
        for msg in team._message_thread:
            if hasattr(msg, 'content') and hasattr(msg, 'source'):
                history.append({
                    "role":    "user" if msg.source == "user" else "assistant",
                    "content": msg.content,
                })
    return history

_AUTH_KEYS = ("username", "password", "login_url",
              "username_selector", "password_selector", "success_indicator")


def _auth_from_body(raw: Any) -> Optional[Dict[str, str]]:
    """Normalise the optional login block; None unless username+password given."""
    if not isinstance(raw, dict):
        return None
    auth = {k: str(raw.get(k) or "").strip() for k in _AUTH_KEYS}
    auth["password"] = str(raw.get("password") or "")
    if not auth["username"] or not auth["password"]:
        return None
    return auth


def _format_sse(event_type: str, data: dict) -> str:
    return f"event: {event_type}\ndata: {json.dumps(data, default=str)}\n\n"


async def _await_with_heartbeat(coro, *, phase: str, step: int, total_steps: int,
                                message: str, percent: int, interval: float = 5.0):
    """Await a long coroutine while keeping the SSE connection warm.

    Yields ``("beat", sse_str)`` every ``interval`` seconds the coroutine is
    still running, then ``("done", result)`` once. ``asyncio.shield`` keeps the
    periodic timeout from cancelling the real work.

    Without this, a multi-minute phase (deep crawl, hybrid research, report
    synthesis) sends no bytes; an idle reverse proxy or socket then drops the
    stream, the client falls back to the blocking endpoint, and the whole
    pipeline re-runs — surfacing as "0 Unknown Error" in the browser.
    """
    task = asyncio.create_task(coro)
    while True:
        try:
            result = await asyncio.wait_for(asyncio.shield(task), timeout=interval)
            yield ("done", result)
            return
        except asyncio.TimeoutError:
            yield ("beat", _format_sse("progress", {
                "phase": phase, "step": step, "total_steps": total_steps,
                "message": message, "percent": percent,
            }))

@app.get("/")
async def root():
    return {
        "status":  "healthy",
        "service": "Multi-Agent Threat Modeling + Web Scanner + AI Backdoor Detection",
        "version": "7.0.0",
        "features": [
            "AutoGen orchestration",
            "Persistent conversation memory",
            "Threat Modeling (STRIDE + ATLAS)",
            "Web Application Scanning",
            "CVE/NVD/OSV lookup",
            "XSS/SQLi/CSRF vulnerability testing",
            "AI Backdoor Detection",
            "AVID AI vulnerability database lookup",
            "ATLAS strategic recommendations",
        ],
        "endpoints": {
            "/query/":           "Main endpoint (auto-routes)",
            "/query/stream":     "SSE streaming endpoint",
            "/scan/":            "Dedicated web scanning",
            "/threat-modeling/": "Security analysis",
            "/health":           "System health",
            "/sessions":         "Active sessions",
        },
    }

@app.get("/health")
async def health_check():
    scanner_ok = bool(
        threat_modeling_agent and getattr(threat_modeling_agent, "web_scanner", None)
    )
    return {
        "status":          "healthy",
        "agents":          "ready",
        "autogen":         "enabled",
        "threat_modeling": "available" if threat_modeling_agent else "not initialized",
        "web_scanner":     "available" if scanner_ok else "not initialized",
        "web_scanning":    "enabled" if scanner_ok else "unavailable",
        "ai_backdoor":     "enabled",
        "avid_lookup":     "enabled",
        "active_sessions": len(session_teams),
    }

@app.post("/query/")
async def query_with_full_autogen(request: Request):
    """Main query endpoint."""
    try:
        logger.info("=" * 80)
        logger.info("QUERY REQUEST")
        logger.info("=" * 80)

        body        = await request.json()
        question    = body.get("question")
        caller_id   = _caller_id(request)
        session_id  = body.get("session_id") or _default_session_id("default", caller_id)
        auth        = _auth_from_body(body.get("auth"))
        if not question:
            raise HTTPException(status_code=400, detail="Missing question")

        # F3: bind/verify session ownership (claims a new session for this caller).
        _authorize_session(session_id, caller_id, create=True)

        logger.info(f"Question: {question}")
        logger.info(f"Session:  {session_id}")

        is_security_query = False
        is_web_scan = False

        if threat_modeling_agent:
            try:
                is_security_query = threat_modeling_agent.is_security_query(question)
                is_web_scan = threat_modeling_agent.is_web_scan_request(question)
            except Exception as e:
                logger.warning(f"Classification failed, using keyword fallback: {e}")
                is_security_query = threat_modeling_agent._keyword_fallback(question)
                is_web_scan = threat_modeling_agent.is_web_scan_request(question)

            logger.info(
                f"Classification: security={is_security_query} | web_scan={is_web_scan}"
            )

            if is_web_scan:
                logger.info("ROUTING → ThreatModelingAgent (web scan + AI detection)")
                try:
                    scan_limits.check_rate_limit(
                        scan_limits.caller_key(request.headers.get("Authorization"))
                    )
                except scan_limits.RateLimited as e:
                    raise HTTPException(
                        status_code=429,
                        detail="Scan rate limit exceeded. Please slow down.",
                        headers={"Retry-After": str(e.retry_after)},
                    )
                try:
                    target_url = threat_modeling_agent._extract_url_from_query(question)
                    if auth:
                        logger.info(f"Authenticated scan requested as {auth['username']!r}")
                    result = await threat_modeling_agent.analyze(
                        user_query=question,
                        verbose=True,
                        use_cache=False,
                        enable_web_scan=True,
                        target_url=target_url,
                        auth=auth,
                    )
                    scan_data = (
                        result.get("reasoning_chain", {}).get("scan_results") or {}
                    )
                    return JSONResponse({
                        "answer":               result.get("report", "Scan completed."),
                        "report_sections":      result.get("report_sections", []),
                        "route":                "threat_modeling_with_scan",
                        "session_id":           session_id,
                        "cached":               False,
                        "reasoning_chain":      result.get("reasoning_chain"),
                        "scan_performed":       result.get("web_scan_performed", False),
                        "target_url":           target_url,
                        "auth":                 scan_data.get("auth") or {"enabled": False},
                        "vulnerabilities_found": (scan_data.get("confirmed_vulns", 0) + scan_data.get("potential_vulns", 0)),
                    "is_ai_powered":        scan_data.get("is_ai_powered", False),
                    "ai_vulns_found":       len([
                        f for f in scan_data.get("vulnerabilities", [])
                        if f.get("category") == "ai_vulnerability"
                    ]),
                    "avid_findings":        (
                        scan_data.get("avid_findings", 0)
                        if isinstance(scan_data.get("avid_findings", 0), int)
                        else len(scan_data.get("avid_findings") or [])
                    ),
                    "strategic_recommendations": (
                        scan_data.get("strategic_recommendations", 0)
                        if isinstance(scan_data.get("strategic_recommendations", 0), int)
                        else len(scan_data.get("strategic_recommendations") or [])
                    ),
                    })
                except scan_limits.ScanBusy as e:
                    raise HTTPException(
                        status_code=503,
                        detail="Scanner is at capacity; try again shortly.",
                        headers={"Retry-After": str(e.retry_after)},
                    )
                except scan_limits.ScanTimeout as e:
                    raise HTTPException(status_code=504, detail="Scan exceeded its time budget.")
                except Exception as e:
                    logger.error(f"Web scan failed: {e}\n{traceback.format_exc()}")
                    return JSONResponse({
                        "answer": (
                            "The web scan could not be completed. "
                            "Falling back to a general security answer.\n\n"
                            + await answer_with_llm(question, session_id)
                        ),
                        "session_id": session_id,
                        "route": "scan_error_fallback",
                    }, status_code=200)

        try:
            final_answer = await answer_with_llm(question, session_id)
        except Exception as e:
            logger.error(f"LLM answer failed: {e}\n{traceback.format_exc()}")
            try:
                team = await get_or_create_team(session_id)
                result = await team.run(
                    task=(
                        f"**User Question:** {question}\n\n"
                        f"**Instructions:** Answer clearly using cybersecurity knowledge."
                    )
                )
                final_answer = ""
                if result and result.messages:
                    for msg in reversed(result.messages):
                        if hasattr(msg, 'content') and msg.content:
                            content = str(msg.content).strip()
                            if content and len(content) > 20:
                                final_answer = content
                                break
                if not final_answer:
                    final_answer = "A response could not be generated. Please try again."
            except Exception as e2:
                logger.error(f"AutoGen fallback failed: {e2}\n{traceback.format_exc()}")
                raise HTTPException(status_code=500, detail=GENERIC_ERROR)

        history = await get_team_history(session_id)
        logger.info(f"QUERY COMPLETE — {len(final_answer)} chars")

        return JSONResponse({
            "answer":                final_answer,
            "session_id":            session_id,
            "route":                 "llm",
            "query_type":            "llm",
            "conversation_messages": len(history),
            "team_persistent":       True,
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"QUERY FAILED: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=GENERIC_ERROR)

class StreamQueryRequest(BaseModel):
    question:   str
    session_id: Optional[str] = None
    auth:       Optional[Dict[str, Any]] = None

@app.post("/query/stream")
async def query_stream(request: StreamQueryRequest, http: Request):

    async def event_generator():
        try:
            question   = request.question
            try:
                caller_id = _caller_id(http)
            except HTTPException:
                yield _format_sse("error", {"message": "Unauthenticated."})
                return
            session_id = request.session_id or _default_session_id("default", caller_id)
            auth       = _auth_from_body(request.auth)

            # F3: bind/verify session ownership before any session read/write.
            try:
                _authorize_session(session_id, caller_id, create=True)
            except HTTPException:
                yield _format_sse("error", {"message": "Session not found."})
                return

            yield _format_sse("progress", {
                "phase": "classification", "step": 1, "total_steps": 6,
                "message": "Analyzing your query...", "percent": 5,
            })
            await asyncio.sleep(0)

            if not threat_modeling_agent:
                yield _format_sse("error", {"message": "Agent not initialized"})
                return

            is_security = threat_modeling_agent.is_security_query(question)
            is_web_scan = threat_modeling_agent.is_web_scan_request(question)

            yield _format_sse("progress", {
                "phase": "classification", "step": 1, "total_steps": 6,
                "message": (
                    f"Query type: {'Security' if is_security else 'General'}"
                    + (" · Web scan target detected" if is_web_scan else "")
                ),
                "percent": 10,
            })
            await asyncio.sleep(0)

            # F5: rate-limit expensive scan initiation (per authenticated caller).
            if is_security and is_web_scan:
                try:
                    scan_limits.check_rate_limit(
                        scan_limits.caller_key(http.headers.get("Authorization"))
                    )
                except scan_limits.RateLimited as e:
                    yield _format_sse("error", {
                        "message": (
                            f"Scan rate limit exceeded. Retry after "
                            f"{e.retry_after}s."
                        )
                    })
                    return

            if not is_security or (is_security and not is_web_scan):
                yield _format_sse("progress", {
                    "phase": "report_generation", "step": 2, "total_steps": 3,
                    "message": "Generating answer...", "percent": 40,
                })
                await asyncio.sleep(0)

                try:
                    final_answer = await answer_with_llm(question, session_id)
                except Exception as e:
                    logger.error(f"Stream LLM error: {e}\n{traceback.format_exc()}")
                    final_answer = "A response could not be generated. Please try again."

                yield _format_sse("progress", {
                    "phase": "report_generation", "step": 3, "total_steps": 3,
                    "message": "Response ready!", "percent": 100,
                })
                await asyncio.sleep(0)

                yield _format_sse("result", {
                    "answer":     final_answer,
                    "query":      question,
                    "cached":     False,
                    "session_id": session_id,
                    "timestamp":  datetime.now().isoformat(),
                })
                return

            # Active web scan: the report is built entirely from the scanner's
            # evidence, so we skip the decompose -> web-search -> STRIDE-LLM chain.
            # It produced nothing synthesize_comprehensive_report reads, and its
            # silent web-search phase was the main source of the SSE gap that
            # dropped the stream and forced the blocking /query/ fallback
            # ("0 Unknown Error"). Straight to scanning (with 5s heartbeats).
            target_url = threat_modeling_agent._extract_url_from_query(question)

            yield _format_sse("progress", {
                "phase": "active_scanning", "step": 2, "total_steps": 4,
                "message": (
                    f"Preparing active scan of {target_url}..."
                    if target_url else "Preparing active scan..."
                ),
                "percent": 15,
            })
            await asyncio.sleep(0)

            scan_results = None
            if is_web_scan and target_url:
                scanner = threat_modeling_agent.ensure_web_scanner()
                if not scanner:
                    yield _format_sse("progress", {
                        "phase": "active_scanning", "step": 2, "total_steps": 4,
                        "message": (
                            "Active scanner unavailable — check backend logs / "
                            "Playwright install."
                        ),
                        "percent": 60,
                    })
                    await asyncio.sleep(0)
                else:
                    yield _format_sse("progress", {
                        "phase": "active_scanning", "step": 2, "total_steps": 4,
                        "message": (
                            f"Logging in as {auth['username']} and scanning {target_url}..."
                            if auth else
                            f"Scanning {target_url} · detecting AI components..."
                        ),
                        "percent": 20,
                    })
                    await asyncio.sleep(0)

                    scan_task = asyncio.create_task(
                        scanner.scan_application(
                            target_url=target_url,
                            verbose=True,
                            auth=auth,
                        )
                    )

                    heartbeats = [
                        "Fingerprinting tech stack...",
                        "Discovering endpoints...",
                        "Detecting AI/ML components...",
                        "Deep crawling (shared session)...",
                        "Testing XSS / SQLi...",
                        "Verifying findings...",
                    ]
                    hb_idx, base_pct = 0, 25
                    while not scan_task.done():
                        await asyncio.sleep(5)
                        if scan_task.done():
                            break
                        yield _format_sse("progress", {
                            "phase": "active_scanning", "step": 2, "total_steps": 4,
                            "message": heartbeats[hb_idx % len(heartbeats)],
                            "percent": min(80, base_pct + 2),
                        })
                        hb_idx   += 1
                        base_pct  = min(80, base_pct + 2)
                        await asyncio.sleep(0)

                    scan_results = await scan_task
                    vuln_count   = len(scan_results.get('vulnerabilities', []))
                    ai_powered   = scan_results.get("is_ai_powered", False)
                    auth_info    = scan_results.get("auth") or {}
                    if auth_info.get("enabled"):
                        yield _format_sse("progress", {
                            "phase": "active_scanning", "step": 2, "total_steps": 4,
                            "message": (
                                f"Authenticated as {auth_info.get('username')}"
                                if auth_info.get("logged_in") else
                                f"Login failed ({auth_info.get('error')}) — scanned unauthenticated"
                            ),
                            "percent": 82,
                        })
                        await asyncio.sleep(0)

                    yield _format_sse("progress", {
                        "phase": "active_scanning", "step": 2, "total_steps": 4,
                        "message": (
                            f"Scan complete · {vuln_count} vulns · "
                            + ("AI components detected" if ai_powered else "no AI detected")
                        ),
                        "percent": 84,
                    })
                    await asyncio.sleep(0)

            yield _format_sse("progress", {
                "phase": "report_generation", "step": 3, "total_steps": 4,
                "message": "Synthesizing evidence-based report...", "percent": 88,
            })
            await asyncio.sleep(0)

            final_report, report_sections = None, None
            async for _kind, _val in _await_with_heartbeat(
                threat_modeling_agent.synthesize_comprehensive_report(
                    question, None, [], scan_results, target_url
                ),
                phase="report_generation", step=3, total_steps=4,
                message="Synthesizing evidence-based report...", percent=92,
            ):
                if _kind == "beat":
                    yield _val
                else:
                    final_report, report_sections = _val

            yield _format_sse("progress", {
                "phase": "report_generation", "step": 4, "total_steps": 4,
                "message": "Report ready!", "percent": 100,
            })
            await asyncio.sleep(0)

            yield _format_sse("result", {
                "answer":           final_report,
                "report":           final_report,
                "report_sections":  report_sections,
                "query":            question,
                "web_scan_performed": bool(is_web_scan and scan_results),
                "target_url":       target_url,
                "is_ai_powered":    (scan_results or {}).get("is_ai_powered", False),
                "auth":             (scan_results or {}).get("auth") or {"enabled": False},
                "cached":           False,
                "timestamp":        datetime.now().isoformat(),
            })

        except Exception as e:
            logger.error(f"Stream error: {e}\n{traceback.format_exc()}")
            # Known-safe errors (SSRF/busy/timeout/rate-limit) keep their authored
            # message; anything else becomes a generic message. Never raw str(e).
            yield _format_sse("error", {"message": _safe_error_message(e)})

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection":    "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

@app.post("/scan/")
async def scan_web_application(request: Request):
    try:
        body          = await request.json()
        target_url    = body.get("target_url")
        caller_id     = _caller_id(request)
        session_id    = body.get("session_id") or _default_session_id("scan", caller_id)
        ai_auth_token = body.get("ai_auth_token") or body.get("auth_token")
        auth          = _auth_from_body(body.get("auth"))

        if not target_url:
            raise HTTPException(status_code=400, detail="Missing target_url")
        if not threat_modeling_agent:
            raise HTTPException(status_code=503, detail="Scanner not available")

        # F3: a caller may only use session IDs it owns (scan results are not
        # stored server-side per session, but this keeps the label consistent
        # and prevents referencing another caller's session id).
        _authorize_session(session_id, caller_id, create=True)

        try:
            scan_limits.check_rate_limit(
                scan_limits.caller_key(request.headers.get("Authorization"))
            )
        except scan_limits.RateLimited as e:
            raise HTTPException(
                status_code=429,
                detail="Scan rate limit exceeded. Please slow down.",
                headers={"Retry-After": str(e.retry_after)},
            )

        logger.info(f"SCAN: {target_url}"
                    + (" (AI pipeline authenticated)" if ai_auth_token else "")
                    + (f" (login as {auth['username']!r})" if auth else ""))

        result     = await threat_modeling_agent.analyze(
            user_query=f"Scan {target_url} for security vulnerabilities",
            verbose=True, use_cache=False,
            enable_web_scan=True, target_url=target_url,
            ai_auth_token=ai_auth_token, auth=auth,
        )
        scan_data  = result.get("reasoning_chain", {}).get("scan_results") or {}

        return JSONResponse({
            "target_url":    target_url,
            "scan_complete": True,
            "scan_scope":    scan_data.get("scan_scope", "blackbox_unauth"),
            "auth":          scan_data.get("auth") or {"enabled": False},
            "report":        result["report"],
            "scan_summary":  {
                "tasks_generated":    scan_data.get("tasks_generated", 0),
                "tasks_executed":     scan_data.get("tasks_executed", 0),
                "forms_discovered":   scan_data.get("forms_discovered", 0),
                "urls_discovered":    scan_data.get("urls_discovered", 0),
                "vulnerabilities_found": (
                    scan_data.get("confirmed_count", 0)
                    + scan_data.get("potential_count", 0)
                ),
                "not_assessed_count": len(scan_data.get("not_assessed_endpoints") or []),
                "scan_duration":      scan_data.get("scan_duration", 0),
                "coverage_assessment": scan_data.get("coverage_assessment") or {},
                "eval_metrics":       scan_data.get("eval_metrics") or {},
                "ai_surfaces_discovered": (
                    (scan_data.get("eval_metrics") or {}).get("ai_surfaces_discovered", 0)
                ),
                "ai_surfaces_unauthenticated": (
                    (scan_data.get("eval_metrics") or {}).get(
                        "ai_surfaces_unauthenticated", 0
                    )
                ),
                "prompt_injection_attempted": (
                    (scan_data.get("eval_metrics") or {}).get(
                        "prompt_injection_attempted", 0
                    )
                ),
                "prompt_injection_confirmed": (
                    (scan_data.get("eval_metrics") or {}).get(
                        "prompt_injection_confirmed", 0
                    )
                ),
                "endpoint_coverage_percent": (
                    (scan_data.get("eval_metrics") or {}).get(
                        "endpoint_coverage_percent",
                        (scan_data.get("coverage_assessment") or {}).get(
                            "coverage_percent", 0
                        ),
                    )
                ),
                "is_ai_powered":      scan_data.get("is_ai_powered", False),
                "ai_scan_authenticated": scan_data.get("ai_scan_authenticated", False),
                "avid_findings":      scan_data.get("avid_findings", 0),
                "strategic_recs":     scan_data.get("strategic_recommendations", 0),
            },
            "vulnerabilities":        scan_data.get("vulnerabilities", []),
            "endpoints_discovered":   scan_data.get("endpoints_discovered", []),
            "not_assessed_endpoints": scan_data.get("not_assessed_endpoints", []),
            "coverage_assessment":    scan_data.get("coverage_assessment") or {},
            "stride_threats":         scan_data.get("stride_threats", []),
            "verified_cves":          scan_data.get("verified_cves") or [],
            "session_id":             session_id,
        })

    except HTTPException:
        raise
    except SSRFBlocked as e:
        logger.warning(f"SCAN BLOCKED by SSRF policy: {e}")
        raise HTTPException(
            status_code=403,
            detail="Target host is not permitted by the server's SSRF egress policy.",
        )
    except scan_limits.ScanBusy as e:
        raise HTTPException(
            status_code=503,
            detail="Scanner is at capacity; try again shortly.",
            headers={"Retry-After": str(e.retry_after)},
        )
    except scan_limits.ScanTimeout as e:
        logger.warning(f"SCAN TIMEOUT: {e}")
        raise HTTPException(status_code=504, detail="Scan exceeded its time budget.")
    except Exception as e:
        logger.error(f"SCAN FAILED: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=GENERIC_ERROR)

@app.post("/threat-modeling/")
async def threat_modeling_query(request: Request):
    try:
        body       = await request.json()
        question   = body.get("question")
        session_id = body.get("session_id", "default")

        if not question:
            raise HTTPException(status_code=400, detail="Missing question")
        if not threat_modeling_agent:
            raise HTTPException(status_code=503, detail="Agent not available")

        if not threat_modeling_agent.is_security_query(question):
            return JSONResponse({
                "answer":           "Not security-related. Use /query/ for general questions.",
                "is_security_query": False,
                "session_id":       session_id,
            })

        result = await threat_modeling_agent.analyze(user_query=question, verbose=True)

        return JSONResponse({
            "answer":          result["report"],
            "session_id":      session_id,
            "query_type":      "threat_modeling",
            "reasoning_chain": result["reasoning_chain"],
            "sources_used":    result["reasoning_chain"]["research_summary"].get("kb_sources", []),
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"THREAT-MODELING FAILED: {e}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=GENERIC_ERROR)

@app.get("/session/{session_id}/history")
async def get_session_history(session_id: str, request: Request):
    # F3: only the owning caller may read a session's history (404 otherwise,
    # so another caller's session existence is never confirmed).
    _authorize_session(session_id, _caller_id(request), create=False)
    history  = await get_team_history(session_id)
    qa_pairs = [
        {"turn": (i // 2) + 1,
         "question": history[i]["content"],
         "answer":   history[i + 1]["content"]}
        for i in range(0, len(history) - 1, 2)
    ]
    return {
        "session_id":    session_id,
        "exists":        bool(history),
        "total_messages": len(history),
        "total_turns":   len(qa_pairs),
        "history":       qa_pairs,
    }

@app.post("/clear-session/{session_id}")
async def clear_session(session_id: str, request: Request):
    # F3: only the owning caller may clear a session.
    _authorize_session(session_id, _caller_id(request), create=False)
    clear_session_team(session_id)
    session_owners.pop(session_id, None)
    return {"message": f"Session {session_id} cleared", "success": True}

@app.get("/sessions")
async def list_active_sessions(request: Request):
    # F3: enumerate only the authenticated caller's own sessions.
    caller_id = _caller_id(request)
    sessions = []
    for sid, owner in session_owners.items():
        if owner != caller_id:
            continue
        history = await get_team_history(sid)
        sessions.append({
            "session_id":     sid,
            "total_messages": len(history),
            "total_turns":    len(history) // 2,
        })
    return {"total_sessions": len(sessions), "sessions": sessions}

class ModelSettingsUpdate(BaseModel):
    provider: str

@app.get("/settings/model")
async def get_model_settings():
    global active_provider
    client_ok, model_name = get_active_client()
    return {
        "active_provider": active_provider,
        "model_name":      model_name,
        "azure_available": azure_client is not None,
        "local_available": True,
        "providers": {
            "local": {
                "name":      "Local Qwen (llama.cpp)",
                "model":     llama_model,
                "available": True,
            },
            "azure": {
                "name":      f"Azure OpenAI ({azure_deployment})",
                "model":     azure_deployment,
                "available": azure_client is not None,
            }
        }
    }

def _require_admin(request: Request) -> None:
    """Authorize a deployment-wide (admin) operation (F4).

    Changing the global model provider is a deployment-level action, not an
    ordinary scanner operation. It requires a separate privileged credential
    (API_ADMIN_TOKEN) presented in the X-Admin-Token header, in addition to the
    normal F2 authentication already enforced by require_auth. This is NOT the
    session-ownership mechanism and does NOT accept any client-supplied role.

    Fails closed: if API_ADMIN_TOKEN is unset, the operation is refused. The
    response never reveals whether an admin token is configured, and the token
    is never logged.
    """
    admin_token = os.getenv("API_ADMIN_TOKEN")
    presented = request.headers.get("X-Admin-Token", "")
    if (not admin_token) or (not presented) or (
        not secrets.compare_digest(presented, admin_token)
    ):
        raise HTTPException(
            status_code=403,
            detail="Administrative privileges are required for this operation.",
        )


@app.post("/settings/model")
async def update_model_settings(body: ModelSettingsUpdate, request: Request):
    global active_provider, model_client, config_list
    # F4: deployment-wide model switching is an admin-only operation. Ordinary
    # authenticated callers (API_AUTH_TOKEN/API_AUTH_TOKENS) cannot change it.
    _require_admin(request)

    if body.provider not in ["local", "azure"]:
        raise HTTPException(status_code=400, detail="Provider must be 'local' or 'azure'")
    if body.provider == "azure" and not azure_client:
        raise HTTPException(status_code=400, detail="Azure credentials not configured")

    active_provider = body.provider
    config_list     = get_config_list()

    active_client, active_model = get_active_client()
    model_client = LocalLlamaChatCompletionClient(active_client, active_model)

    # F4: do NOT clear other callers' sessions as a side effect of a config
    # change. The primary answer path reads the active provider fresh on each
    # call, and the scanner uses its own client fixed at init, so no global
    # session reset is needed. Per-caller clearing remains via /clear-session.

    logger.info(f"Model provider switched to: {active_provider} (admin)")
    return {
        "success":         True,
        "active_provider": active_provider,
        "model_name":      active_model,
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8001))
    # Bind to loopback by default; set HOST=0.0.0.0 explicitly to expose it
    # (e.g. inside a container behind a published port / reverse proxy).
    host = os.getenv("HOST", "127.0.0.1")
    logger.info(f"Starting on {host}:{port}")
    uvicorn.run(
        app, host=host, port=port,
        log_level="info",
        timeout_keep_alive=300,
        timeout_graceful_shutdown=30,
    )
