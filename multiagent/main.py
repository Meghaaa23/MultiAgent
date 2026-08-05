# main.py


import os
import asyncio
import json
from typing import Optional, Dict, List, Any
from enum import Enum
from datetime import datetime

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from agents.threat_modeling_agent import ThreatModelingAgent
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

# ============================================================================
# CONFIGURATION
# ============================================================================

class FinishReason(str, Enum):
    STOP           = "stop"
    LENGTH         = "length"
    FUNCTION_CALLS = "function_calls"
    CONTENT_FILTER = "content_filter"
    UNKNOWN        = "unknown"

    def __str__(self):
        return self.value


from openai import AzureOpenAI

# ── Local llama.cpp config ─────────────────────────────────────
llama_base_url = os.getenv("LLAMA_BASE_URL", "http://localhost:8080")
llama_model    = os.getenv("LLAMA_MODEL_NAME", "Qwen-2.5")

local_client = OpenAI(
    base_url=f"{llama_base_url}/v1",
    api_key="not-needed",
    timeout=300.0,
    max_retries=0,
)

# ── Azure OpenAI config ────────────────────────────────────────
azure_api_key    = os.getenv("AZURE_OPENAI_API_KEY")
azure_endpoint   = os.getenv("AZURE_OPENAI_ENDPOINT")
azure_deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
azure_api_version= os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01")

azure_client = AzureOpenAI(
    api_key=azure_api_key,
    azure_endpoint=azure_endpoint,
    api_version=azure_api_version,
) if azure_api_key and azure_endpoint else None

# ── Active provide ─────────────────────────
active_provider = os.getenv("ACTIVE_MODEL_PROVIDER", "azure")  # "local" or "azure"

def get_active_client():
    if active_provider == "azure" and azure_client:
        return azure_client, azure_deployment
    return local_client, llama_model

# ── config_list for AutoGen (rebuilt dynamically) ─────────────
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

# Keep backward compat
client      = local_client
config_list = get_config_list()

# ============================================================================
# FASTAPI SETUP
# ============================================================================

app = FastAPI(
    title="Multi-Agent Threat Modeling System with Web Scanning + AI Backdoor Detection",
    description="AutoGen + Threat Modeling + Web Scanning + AI Backdoor Analysis",
    version="7.0.0",
)

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

# ============================================================================
# AGENT INITIALIZATION
# ============================================================================

from agents.qa_agent import set_config

set_config(config_list)

# ============================================================================
# WEB SEARCH
# ============================================================================

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

# ============================================================================
# THREAT MODELING AGENT
# ============================================================================

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

# ============================================================================
# AUTOGEN LLM CLIENT
# ============================================================================

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
                content=f"Error: {str(e)}",
                usage=RequestUsage(prompt_tokens=0, completion_tokens=0),
                finish_reason=FinishReason.UNKNOWN, cached=False,
            )

    async def create_stream(self, messages, **kwargs):
        raise NotImplementedError("Streaming not implemented")


_init_client, _init_model = get_active_client()
model_client = LocalLlamaChatCompletionClient(_init_client, _init_model)

# ============================================================================
# AUTOGEN SESSION MANAGEMENT
# ============================================================================

session_teams: Dict[str, RoundRobinGroupChat] = {}
session_histories: Dict[str, List[Dict[str, str]]] = {}

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
    messages.extend(history[-12:])  # keep recent turns
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

# =============================================================================
# UTILITIES
# =============================================================================

def _format_sse(event_type: str, data: dict) -> str:
    return f"event: {event_type}\ndata: {json.dumps(data, default=str)}\n\n"

# ============================================================================
# ROOT / HEALTH
# ============================================================================

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

# =============================================================================
# /query/ ENDPOINT
# =============================================================================

@app.post("/query/")
async def query_with_full_autogen(request: Request):
    """
    Main query endpoint.

    Route A — Web scan request (URL present) → ThreatModelingAgent
    Route B — General / security question → direct LLM answer
    """
    try:
        logger.info("=" * 80)
        logger.info("QUERY REQUEST")
        logger.info("=" * 80)

        body        = await request.json()
        question    = body.get("question")
        session_id  = body.get("session_id", "default")
        if not question:
            raise HTTPException(status_code=400, detail="Missing question")

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
                    target_url = threat_modeling_agent._extract_url_from_query(question)
                    result = await threat_modeling_agent.analyze(
                        user_query=question,
                        verbose=True,
                        use_cache=False,
                        enable_web_scan=True,
                        target_url=target_url,
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
                except Exception as e:
                    logger.error(f"Web scan failed: {e}\n{traceback.format_exc()}")
                    return JSONResponse({
                        "answer": (
                            f"Web scan failed: {e}\n\n"
                            "Falling back to a general security answer.\n\n"
                            + await answer_with_llm(question, session_id)
                        ),
                        "session_id": session_id,
                        "route": "scan_error_fallback",
                        "error": str(e),
                    }, status_code=200)

        # General / security Q&A via direct LLM (more reliable than AutoGen alone)
        try:
            final_answer = await answer_with_llm(question, session_id)
        except Exception as e:
            logger.error(f"LLM answer failed: {e}\n{traceback.format_exc()}")
            # Last resort: try AutoGen team
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
                    final_answer = f"Error generating response: {e}"
            except Exception as e2:
                logger.error(f"AutoGen fallback failed: {e2}")
                raise HTTPException(
                    status_code=500,
                    detail=(
                        f"LLM call failed: {e}. AutoGen fallback failed: {e2}. "
                        "Check AZURE_OPENAI_* or local llama.cpp settings."
                    ),
                )

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
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# STREAMING ENDPOINT
# ============================================================================

class StreamQueryRequest(BaseModel):
    question:   str
    session_id: Optional[str] = None


@app.post("/query/stream")
async def query_stream(request: StreamQueryRequest):

    async def event_generator():
        try:
            question   = request.question
            session_id = request.session_id or "default"

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

            # ── Non-web-scan question ─────────────────────────────────
            if not is_security or (is_security and not is_web_scan):
                yield _format_sse("progress", {
                    "phase": "report_generation", "step": 2, "total_steps": 3,
                    "message": "Generating answer...", "percent": 40,
                })
                await asyncio.sleep(0)

                try:
                    final_answer = await answer_with_llm(question, session_id)
                except Exception as e:
                    logger.error(f"Stream LLM error: {e}")
                    final_answer = f"Error generating response: {str(e)}"

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

            # ── Security + web scan path ───────────────────────────────
            yield _format_sse("progress", {
                "phase": "knowledge_gathering", "step": 2, "total_steps": 6,
                "message": "Decomposing security question...", "percent": 15,
            })
            await asyncio.sleep(0)

            decomposition = await threat_modeling_agent.decompose_query(question)
            sub_q_count   = (
                len(decomposition.get('task_1_system_understanding', []))
                + len(decomposition.get('task_2_security_analysis', []))
            )

            target_url   = threat_modeling_agent._extract_url_from_query(question)
            known_vulns  = await threat_modeling_agent.search_known_vulnerabilities_web(
                question, target_url, verbose=True
            )

            yield _format_sse("progress", {
                "phase": "knowledge_gathering", "step": 2, "total_steps": 6,
                "message": f"{sub_q_count} sub-questions · {len(known_vulns)} CVE references",
                "percent": 35,
            })
            await asyncio.sleep(0)

            research = await threat_modeling_agent.research_sub_questions_hybrid(
                decomposition, verbose=True
            )

            yield _format_sse("progress", {
                "phase": "knowledge_gathering", "step": 3, "total_steps": 6,
                "message": "Knowledge gathering complete", "percent": 45,
            })
            await asyncio.sleep(0)

            # Active scanning
            scan_results = None
            if is_web_scan and target_url:
                scanner = threat_modeling_agent.ensure_web_scanner()
                if not scanner:
                    yield _format_sse("progress", {
                        "phase": "active_scanning", "step": 4, "total_steps": 6,
                        "message": (
                            "Active scanner unavailable — generating report from "
                            "web research only. Check backend logs / Playwright install."
                        ),
                        "percent": 60,
                    })
                    await asyncio.sleep(0)
                else:
                    yield _format_sse("progress", {
                        "phase": "active_scanning", "step": 4, "total_steps": 6,
                        "message": f"Scanning {target_url} · detecting AI components...",
                        "percent": 48,
                    })
                    await asyncio.sleep(0)

                    scan_task = asyncio.create_task(
                        scanner.scan_application(
                            target_url=target_url, max_time_minutes=15, verbose=True,
                        )
                    )

                    heartbeats = [
                        "Fingerprinting tech stack...",
                        "Detecting AI/ML components...",
                        "Querying AVID database...",
                        "Testing ML endpoints...",
                        "Testing XSS / SQLi...",
                        "Verifying findings...",
                    ]
                    hb_idx, base_pct = 0, 50
                    while not scan_task.done():
                        await asyncio.sleep(5)
                        if scan_task.done():
                            break
                        yield _format_sse("progress", {
                            "phase": "active_scanning", "step": 4, "total_steps": 6,
                            "message": heartbeats[hb_idx % len(heartbeats)],
                            "percent": min(63, base_pct + 2),
                        })
                        hb_idx   += 1
                        base_pct  = min(63, base_pct + 2)
                        await asyncio.sleep(0)

                    scan_results = await scan_task
                    vuln_count   = len(scan_results.get('vulnerabilities', []))
                    ai_powered   = scan_results.get("is_ai_powered", False)

                    yield _format_sse("progress", {
                        "phase": "active_scanning", "step": 4, "total_steps": 6,
                        "message": (
                            f"Scan complete · {vuln_count} vulns · "
                            + ("AI components detected" if ai_powered else "no AI detected")
                        ),
                        "percent": 65,
                    })
                    await asyncio.sleep(0)

            # Report generation
            formatted_research = threat_modeling_agent.format_research_hybrid(research)

            yield _format_sse("progress", {
                "phase": "report_generation", "step": 5, "total_steps": 6,
                "message": "Applying STRIDE + ATLAS threat model...", "percent": 70,
            })
            await asyncio.sleep(0)

            threat_model = await threat_modeling_agent.apply_stride_framework(
                question, formatted_research, known_vulns, scan_results
            )

            yield _format_sse("progress", {
                "phase": "report_generation", "step": 5, "total_steps": 6,
                "message": "Synthesizing final report...", "percent": 82,
            })
            await asyncio.sleep(0)

            final_report, report_sections = await threat_modeling_agent.synthesize_comprehensive_report(
                question, threat_model, known_vulns, scan_results, target_url
            )

            yield _format_sse("progress", {
                "phase": "report_generation", "step": 6, "total_steps": 6,
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
                "cached":           False,
                "timestamp":        datetime.now().isoformat(),
            })

        except Exception as e:
            logger.error(f"Stream error: {e}\n{traceback.format_exc()}")
            yield _format_sse("error", {"message": str(e)})

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection":    "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

# ============================================================================
# DEDICATED SCAN ENDPOINT
# ============================================================================

@app.post("/scan/")
async def scan_web_application(request: Request):
    try:
        body       = await request.json()
        target_url = body.get("target_url")
        session_id = body.get("session_id", "scan-default")

        if not target_url:
            raise HTTPException(status_code=400, detail="Missing target_url")
        if not threat_modeling_agent:
            raise HTTPException(status_code=503, detail="Scanner not available")

        logger.info(f"SCAN: {target_url}")

        result     = await threat_modeling_agent.analyze(
            user_query=f"Scan {target_url} for security vulnerabilities",
            verbose=True, use_cache=False,
            enable_web_scan=True, target_url=target_url,
        )
        scan_data  = result.get("reasoning_chain", {}).get("scan_results") or {}

        return JSONResponse({
            "target_url":    target_url,
            "scan_complete": True,
            "scan_scope":    scan_data.get("scan_scope", "blackbox_unauth"),
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
                # AI backdoor fields
                "is_ai_powered":      scan_data.get("is_ai_powered", False),
                "avid_findings":      scan_data.get("avid_findings", 0),
                "strategic_recs":     scan_data.get("strategic_recommendations", 0),
            },
            "vulnerabilities":        scan_data.get("vulnerabilities", []),
            "endpoints_discovered":   scan_data.get("endpoints_discovered", []),
            "not_assessed_endpoints": scan_data.get("not_assessed_endpoints", []),
            "stride_threats":         scan_data.get("stride_threats", []),
            "verified_cves":          scan_data.get("verified_cves") or [],
            "session_id":             session_id,
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"SCAN FAILED: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# THREAT MODELING ENDPOINT
# ============================================================================

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
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# SESSION ENDPOINTS
# ============================================================================

@app.get("/session/{session_id}/history")
async def get_session_history(session_id: str):
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
async def clear_session(session_id: str):
    clear_session_team(session_id)
    return {"message": f"Session {session_id} cleared", "success": True}


@app.get("/sessions")
async def list_active_sessions():
    sessions = []
    for sid in session_teams:
        history = await get_team_history(sid)
        sessions.append({
            "session_id":     sid,
            "total_messages": len(history),
            "total_turns":    len(history) // 2,
        })
    return {"total_sessions": len(sessions), "sessions": sessions}




# ============================================================================
# MODEL SETTINGS ENDPOINT
# ============================================================================

class ModelSettingsUpdate(BaseModel):
    provider: str  # "local" or "azure"

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

@app.post("/settings/model")
async def update_model_settings(body: ModelSettingsUpdate):
    global active_provider, model_client, config_list
    if body.provider not in ["local", "azure"]:
        raise HTTPException(status_code=400, detail="Provider must be 'local' or 'azure'")
    if body.provider == "azure" and not azure_client:
        raise HTTPException(status_code=400, detail="Azure credentials not configured")

    active_provider = body.provider
    config_list     = get_config_list()

    # Rebuild the AutoGen model client
    active_client, active_model = get_active_client()
    model_client = LocalLlamaChatCompletionClient(active_client, active_model)

    # Clear all sessions so they use the new model
    session_teams.clear()

    logger.info(f"Model provider switched to: {active_provider}")
    return {
        "success":         True,
        "active_provider": active_provider,
        "model_name":      active_model,
        "sessions_cleared": True,
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    logger.info(f"Starting on {host}:{port}")
    uvicorn.run(
        app, host=host, port=port,
        log_level="info",
        timeout_keep_alive=300,
        timeout_graceful_shutdown=30,
    )