# agents/webappscanner/ai_fingerprint_agent.py
"""
AIFingerprintAgent
==================
Detects whether a web application uses AI/ML components using
universal black-box signals only.

Architecture (per design spec):
  - Traditional scanning always runs first
  - This agent runs on every scan to check for AI components
  - If AI detected → escalate to specialized AI vuln tests
  - If not detected → skip AI section entirely (no speculation)

Detection philosophy:
  NO platform-specific names (no gradio, streamlit, chatbot widget names).
  ONLY universal signals that ANY AI system exposes regardless of framework:

  Strong signals (concrete, network-level — trigger escalation):
    1. ML API endpoints that actually respond (200/401/403/405)
    2. AI-specific HTTP response headers (x-model-id, openai-version, etc.)
    3. Model file upload endpoints accepting .pkl/.pt/.onnx
    4. AI response body patterns (logits, embeddings, prompt_tokens, choices)

  Weak signals (HTML/JS — need strong corroboration):
    5. ML library JS imports (TensorFlow.js, ONNX Runtime, OpenAI SDK)
    6. SSE streaming to inference endpoints (EventSource → /completions)
    7. Structured assistant/role patterns in DOM

Confidence tiers:
  high:   strong >= 2, OR (strong >= 1 AND weak >= 2)
  medium: strong == 1
  low:    weak signals only → is_ai_powered = False (no escalation)
"""

import re
import json
import asyncio
import logging
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


ML_ENDPOINT_PATTERNS = [
    r"/predict/?$",
    r"/prediction/?$",
    r"/inference/?$",
    r"/infer/?$",
    r"/classify/?$",
    r"/classification/?$",
    r"/score/?$",
    r"/scores/?$",
    r"/embed/?$",
    r"/embeddings/?$",
    r"/encode/?$",
    r"/vectorize/?$",
    r"/similarity/?$",
    r"/recommend/?$",
    r"/recommendations/?$",
    r"/rank/?$",
    r"/detect/?$",
    r"/detection/?$",
    r"/recognize/?$",
    r"/recognition/?$",
    r"/ocr/?$",
    r"/chat/?$",
    r"/completions/?$",
    r"/generate/?$",
    r"/generation/?$",
    r"/v1/chat/completions",
    r"/v1/completions",
    r"/api/chat",
    r"/api/generate",
    r"/api/predict",
    r"/api/inference",
    r"/api/embeddings",
    r"/api/model",
    r"/api/ml",
    r"/api/ai",
    r"/ml/",
    r"/ai/",
    r"/model/?$",
    r"/models/?$",
    r"/model/info",
    r"/v1/models",
    r"/invocations",
    r"/predictions",
    r"/serving",
    r"/api/tags",               
    r"/api/version",            
    r"/api/health",             
    r"/api/config",              
    r"/v2/health/ready",         
    r"/v2/models",             
    r"/openai/",                
    r"/ollama/", 
    r"/v1/embeddings",
    r"/v1/responses",
    r"/v1/assistants",
    r"/v1/threads",
    r"/v1/vector_stores",
    r"/v1/files",

    r"/api/embeds",
    r"/api/vector",
    r"/api/search", 

    r"/rag",
    r"/retrieval",

    r"/vector",
    r"/vectors",

    r"/agent",
    r"/agents",

    r"/assistant",
    r"/assistants",

    r"/chatbot",
    r"/bot",

    r"/conversation",
    r"/conversations",

    r"/message",        
    r"/messages",

    r"/ask",

    r"/completion",

    r"/llm",

    r"/generateStream",

    r"/stream"               
]

AI_RESPONSE_HEADERS = [
    "x-model-version",
    "x-model-id",
    "x-inference-time",
    "x-ai-backend",
    "x-ml-model",
    "x-openai-model",
    "x-anthropic-model",
    "openai-model",
    "openai-version",
    "x-inference-id",
    "x-model-name",
    "x-prediction-id",
    "x-request-id",
    "x-trace-id"
]

AI_SERVING_FRAMEWORKS = [
    "tensorflow", "pytorch", "triton", "torchserve",
    "sagemaker", "onnx", "ollama", "vllm", "tgi",
    "ray serve", "bentoml", "seldon", "mlflow",
]



MODEL_FILE_EXTENSIONS = [
    ".pkl", ".pickle",
    ".pt", ".pth",
    ".h5", ".hdf5",
    ".onnx",
    ".safetensors",
    ".gguf",
    ".mlmodel",
    ".joblib",
    ".bin"
    
]



AI_RESPONSE_BODY_PATTERNS = [
    
    r'"choices"\s*:\s*\[',          
    r'"prompt_tokens"\s*:',           
    r'"completion_tokens"\s*:',       
    r'"finish_reason"\s*:',           
    r'"usage"\s*:\s*\{',            
    r'"model"\s*:\s*"[^"]*"',        
    r'"models"\s*:\s*\[',           

   
    r'"logits"\s*:',                  
    r'"embeddings"\s*:',              
    r'"probabilities"\s*:',           
    r'"predictions"\s*:',             
    r'"confidence"\s*:',             

    # Ollama-specific
    r'"done"\s*:\s*(?:true|false)',   
    r'"done_reason"\s*:',             
    r'"total_duration"\s*:',          
    r'"eval_count"\s*:',              

    
    r'"object"\s*:\s*"(?:model|list)"', 
    r'"model_name"\s*:',              
    r'"model_version"\s*:',           

    # Generic ML serving
    r'"version"\s*:\s*"[0-9]',      
    r'"score"\s*:\s*[\d.]+',        
    r'"labels"\s*:\s*\[',           
   
    r'"chatId"\s*:',                
    r'"sourceDocuments"\s*:',         
    r'"agentReasoning"\s*:',          
    r'"sessionId"\s*:\s*"[^"]{8,}"', 
    r'"tool_calls"\s*:',
    r'"function_call"\s*:',
    r'"assistant"\s*:',
    r'"messages"\s*:',
    r'"input_tokens"\s*:',
    r'"output_tokens"\s*:',
    r'"context"\s*:',
    r'"vector"\s*:',
    r'"chunk"\s*:',
    r'"retrieval"\s*:'
]


ML_LIBRARY_JS_SIGNATURES = {
    "TensorFlow.js":    [r"@tensorflow/tfjs", r"tensorflow\.js", r"tf\.tensor"],
    "ONNX Runtime Web": [r"onnxruntime-web", r"ort\.InferenceSession"],
    "Transformers.js":  [r"@xenova/transformers", r"transformers\.js"],
    "OpenAI JS SDK":    [r"openai\.min\.js", r"from ['\"]openai['\"]", r"new OpenAI\("],
    "Anthropic JS SDK": [r"@anthropic-ai/sdk", r"new Anthropic\("],
    "Cohere JS":        [r"cohere-ai", r"new CohereClient"],
    "LangChain JS":     [r"langchain", r"@langchain/core"],
    "Replicate JS":     [r"replicate", r"new Replicate\("],
    "Groq JS":          [r"groq-sdk", r"new Groq\("],
    "Brain.js":         [r"brain\.js", r"brain/browser"],
    "ml5.js":           [r"ml5\.js", r"ml5library"],
    
}



SSE_STREAMING_PATTERNS = [
    r"EventSource\(['\"][^'\"]*(?:completions|generate|chat|infer)[^'\"]*['\"]",
    r"fetch\([^)]*(?:completions|generate|chat|infer)[^)]*stream.*true",
    r"getReader\(\).*(?:completions|generate|chat)",
    r"text/event-stream",
]


AI_DOM_PATTERNS = [
    r'role=["\']assistant["\']',
    r'data-role=["\'](?:bot|assistant)["\']',
    r'aria-label=["\'][^"\']*(?:ai|assistant)[^"\']*["\']',
    r'data-message-role=["\']assistant["\']',
]



ATLAS_TECHNIQUE_MAP = {
    "ml_endpoint":    "AML.T0043 — Craft Adversarial Data",
    "model_upload":   "AML.T0018.002 — Embed Malware via Model Upload",
    "missing_auth":   "AML.T0044 — Full ML Model Access",
    "model_metadata": "AML.T0063 — Discover AI Model Outputs",
    "ai_library":     "AML.T0019 — Exploit Public-Facing ML Application",
    "llm_endpoint":   "AML.T0051 — LLM Prompt Injection",
}


class AIFingerprintAgent:
    """
    Universal AI/ML component detector.
    Uses only behavioral signals — no hardcoded platform or product names.
    """

    def __init__(self, timeout: int = 8):
        self.timeout = timeout

    async def fingerprint(self,
                           target_url: str,
                           discovered_endpoints: List[Dict],
                           page_html: str = "",
                           response_headers: Dict = None,
                           verbose: bool = False) -> Dict:

        if verbose:
            print(f"\n  AI Fingerprint Agent — {target_url}")

        base = target_url.rstrip("/")
        result = {
            "is_ai_powered":          False,
            "confidence":             "low",
            "ml_endpoints":           [],
            "ml_libraries":           [],
            "model_upload_endpoints": [],
            "ai_headers":             {},
            "sse_signals":            [],
            "dom_signals":            [],
            "evidence":               [],
            "atlas_techniques":       [],
        }

        checks = await asyncio.gather(
            self._check_discovered_endpoints(discovered_endpoints, verbose),
            self._check_response_headers(response_headers or {}, verbose),
            self._check_ml_libraries_in_html(page_html, verbose),
            self._check_sse_patterns_in_html(page_html, verbose),
            self._check_dom_ai_patterns(page_html, verbose),
            self._probe_ml_endpoints(base, verbose),
            return_exceptions=True
        )

        endpoint_r, header_r, library_r, sse_r, dom_r, probe_r = checks

        if isinstance(endpoint_r, dict):
            result["ml_endpoints"].extend(endpoint_r.get("endpoints", []))
            result["model_upload_endpoints"].extend(endpoint_r.get("upload_endpoints", []))
            result["evidence"].extend(endpoint_r.get("evidence", []))

        if isinstance(header_r, dict):
            result["ai_headers"].update(header_r.get("headers", {}))
            result["evidence"].extend(header_r.get("evidence", []))

        if isinstance(library_r, dict):
            result["ml_libraries"].extend(library_r.get("libraries", []))
            result["evidence"].extend(library_r.get("evidence", []))

        if isinstance(sse_r, dict):
            result["sse_signals"].extend(sse_r.get("signals", []))
            result["evidence"].extend(sse_r.get("evidence", []))

        if isinstance(dom_r, dict):
            result["dom_signals"].extend(dom_r.get("signals", []))
            result["evidence"].extend(dom_r.get("evidence", []))

        if isinstance(probe_r, dict):
            result["ml_endpoints"].extend(probe_r.get("endpoints", []))
            result["model_upload_endpoints"].extend(probe_r.get("upload_endpoints", []))
            result["evidence"].extend(probe_r.get("evidence", []))

        for key in ["ml_endpoints", "ml_libraries", "model_upload_endpoints",
                    "sse_signals", "dom_signals", "evidence"]:
            result[key] = list(dict.fromkeys(result[key]))

        strong = (
            len(result["ml_endpoints"]) +
            len(result["ai_headers"]) +
            len(result["model_upload_endpoints"])
        )
        weak = (
            len(result["ml_libraries"]) +
            len(result["sse_signals"]) +
            len(result["dom_signals"])
        )

        if strong >= 2 or (strong >= 1 and weak >= 2):
            result["is_ai_powered"] = True
            result["confidence"]    = "high"
        elif strong >= 1:
            result["is_ai_powered"] = True
            result["confidence"]    = "medium"
        else:
            result["is_ai_powered"] = False
            result["confidence"]    = "low"
            if weak > 0:
                result["evidence"].append(
                    f"Weak AI signals found ({weak}) — no network-level confirmation. "
                    f"AI-specific testing skipped."
                )

        if result["ml_endpoints"]:
            result["atlas_techniques"].append(ATLAS_TECHNIQUE_MAP["ml_endpoint"])
            llm_paths = ["/chat", "/completions", "/generate"]
            if any(any(p in ep for p in llm_paths) for ep in result["ml_endpoints"]):
                result["atlas_techniques"].append(ATLAS_TECHNIQUE_MAP["llm_endpoint"])
        if result["model_upload_endpoints"]:
            result["atlas_techniques"].append(ATLAS_TECHNIQUE_MAP["model_upload"])
        if result["ml_libraries"]:
            result["atlas_techniques"].append(ATLAS_TECHNIQUE_MAP["ai_library"])
        result["atlas_techniques"] = list(dict.fromkeys(result["atlas_techniques"]))

        if verbose:
            if result["is_ai_powered"]:
                print(f"    AI-powered [{result['confidence']}] "
                      f"strong={strong} weak={weak}")
                print(f"      Endpoints: {result['ml_endpoints'][:3]}")
                print(f"      Libraries: {result['ml_libraries'][:3]}")
            else:
                print(f"   ℹ No AI/ML detected (strong={strong}, weak={weak})")

        return result

    async def _check_discovered_endpoints(self, endpoints: List[Dict],
                                           verbose: bool) -> Dict:
        ml_endpoints     = []
        upload_endpoints = []
        evidence         = []

        for ep in endpoints:
            url    = ep.get("url", "")
            path   = urllib.parse.urlparse(url).path.lower()
            status = ep.get("status", 0)

           
            for pattern in ML_ENDPOINT_PATTERNS:
                if re.search(pattern, path, re.IGNORECASE):
                    ml_endpoints.append(url)
                    evidence.append(f"ML endpoint pattern match: {path}")
                    break

            if status == 200 and url not in ml_endpoints:
                try:
                    loop = asyncio.get_event_loop()
                    _, resp_headers, body = await loop.run_in_executor(
                        None, lambda u=url: self._fetch(u)
                    )
                    ct = resp_headers.get("Content-Type", "").lower()
                    if "json" in ct and body:
                        if any(re.search(p, body, re.IGNORECASE)
                               for p in AI_RESPONSE_BODY_PATTERNS):
                            ml_endpoints.append(url)
                            evidence.append(
                                f"ML API confirmed by response body at {path}"
                            )
                        
                        resp_lower = {k.lower(): v for k, v in resp_headers.items()}
                        if any(h in resp_lower for h in AI_RESPONSE_HEADERS):
                            if url not in ml_endpoints:
                                ml_endpoints.append(url)
                                evidence.append(
                                    f"ML API confirmed by response headers at {path}"
                                )
                except Exception:
                    pass

            if ep.get("method") in ("POST", "PUT"):
                for ext in MODEL_FILE_EXTENSIONS:
                    if ext.lstrip(".") in path:
                        upload_endpoints.append(url)
                        evidence.append(f"Model upload endpoint: {path}")
                        break

        return {"endpoints": list(dict.fromkeys(ml_endpoints)),
                "upload_endpoints": list(dict.fromkeys(upload_endpoints)),
                "evidence": evidence}

    async def _check_response_headers(self, headers: Dict,
                                       verbose: bool) -> Dict:
        ai_headers = {}
        evidence   = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        for header in AI_RESPONSE_HEADERS:
            if header in headers_lower:
                val = headers_lower[header]
                ai_headers[header] = val
                evidence.append(f"AI response header: {header}: {val[:60]}")
        powered_by = headers_lower.get("x-powered-by", "")
        for framework in AI_SERVING_FRAMEWORKS:
            if framework in powered_by.lower():
                ai_headers["x-powered-by"] = powered_by
                evidence.append(f"AI serving framework in X-Powered-By: {powered_by}")
                break
        return {"headers": ai_headers, "evidence": evidence}

    async def _check_ml_libraries_in_html(self, html: str,
                                           verbose: bool) -> Dict:
        if not html:
            return {"libraries": [], "evidence": []}
        libraries = []
        evidence  = []
        for library, patterns in ML_LIBRARY_JS_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    libraries.append(library)
                    evidence.append(f"ML JS library in source: {library}")
                    break
        return {"libraries": libraries, "evidence": evidence}

    async def _check_sse_patterns_in_html(self, html: str,
                                           verbose: bool) -> Dict:
        if not html:
            return {"signals": [], "evidence": []}
        signals  = []
        evidence = []
        for pattern in SSE_STREAMING_PATTERNS:
            m = re.search(pattern, html, re.IGNORECASE)
            if m:
                matched = m.group(0)[:80]
                signals.append(matched)
                evidence.append(f"SSE streaming to AI endpoint: {matched}")
        return {"signals": signals, "evidence": evidence}

    async def _check_dom_ai_patterns(self, html: str,
                                      verbose: bool) -> Dict:
        if not html:
            return {"signals": [], "evidence": []}
        signals  = []
        evidence = []
        for pattern in AI_DOM_PATTERNS:
            m = re.search(pattern, html, re.IGNORECASE)
            if m:
                matched = m.group(0)[:60]
                signals.append(matched)
                evidence.append(f"AI DOM pattern: {matched}")
        return {"signals": signals[:3], "evidence": evidence[:3]}

    async def _probe_ml_endpoints(self, base: str,
                                   verbose: bool) -> Dict:
        """
        Actively probe universal ML serving paths.
        Only endpoints that actually respond are flagged.
        """
        probe_paths = [
            
            "/v1/models",
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/embeddings",
            "/v1/images/generations",
            "/openai/v1/models",          

            # Ollama-specific
            "/api/tags",                  
            "/api/generate",
            "/api/chat",
            "/api/version",              

            # OpenWebUI-specific
            "/api/models",
            "/api/config",
            "/api/health",
            "/api/chat/completions",

            # Generic ML serving
            "/api/predict",
            "/api/inference",
            "/api/model",
            "/api/embeddings",
            "/api/v1",
            "/api/v1/models",
            "/api/v1/generate",
            "/api/v1/chat",
            "/api/v1/model",
            "/api/v1/prediction",         

            # AnythingLLM / generic
            "/api/docs",                  
            "/api/health",
            "/health",
            "/ping",                    

            # Framework-specific serving
            "/invocations",               
            "/predictions",              
            "/predict",
            "/inference",
            "/classify",
            "/summarize",

            # Triton Inference Server
            "/v2/health/ready",
            "/v2/models",

            # Model upload
            "/upload/model",
            "/api/upload",
            "/ml/predict",
            # Additional paths missed above
            "/models",                    
            "/api/v1/chatflows",          
            "/api/v1/models",
        ]

        ml_endpoints     = []
        upload_endpoints = []
        evidence         = []

        async def probe(path: str):
            url = base + path
            try:
                loop = asyncio.get_event_loop()
                status, resp_headers, body = await loop.run_in_executor(
                    None, lambda: self._fetch(url)
                )
                if status not in (200, 401, 403, 405):
                    return

                content_type = resp_headers.get("Content-Type", "").lower()
                is_json      = "json" in content_type

                
                if is_json and body:
                    if any(re.search(p, body, re.IGNORECASE)
                           for p in AI_RESPONSE_BODY_PATTERNS):
                        ml_endpoints.append(url)
                        evidence.append(
                            f"ML API confirmed by response body at {path} (HTTP {status})"
                        )
                        return

                
                resp_lower = {k.lower(): v for k, v in resp_headers.items()}
                if any(h in resp_lower for h in AI_RESPONSE_HEADERS):
                    ml_endpoints.append(url)
                    evidence.append(
                        f"ML API confirmed by response headers at {path} (HTTP {status})"
                    )
                    return

          
                is_html = "html" in content_type
                if status in (401, 403, 405) and not is_html:
                    for pattern in ML_ENDPOINT_PATTERNS:
                        if re.search(pattern, path, re.IGNORECASE):
                            ml_endpoints.append(url)
                            evidence.append(
                                f"ML endpoint confirmed (HTTP {status} non-HTML): {path}"
                            )
                            break

            
                if status == 405 and (
                    "upload" in path or any(
                        ext.lstrip(".") in path for ext in MODEL_FILE_EXTENSIONS
                    )
                ):
                    upload_endpoints.append(url)
                    evidence.append(f"Model upload endpoint (HTTP {status}): {path}")

            except Exception:
                pass

        await asyncio.gather(*[probe(p) for p in probe_paths],
                             return_exceptions=True)

        return {"endpoints": ml_endpoints,
                "upload_endpoints": upload_endpoints,
                "evidence": evidence}

    def _fetch(self, url: str) -> Tuple[int, Dict, str]:
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (SecurityScanner)",
                         "Accept":     "application/json, */*"}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read(4096).decode("utf-8", errors="replace")
                return resp.status, dict(resp.headers), body
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers) if e.headers else {}, ""
        except Exception:
            return 0, {}, ""