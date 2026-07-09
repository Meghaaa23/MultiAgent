import os
import asyncio
import logging
import ipaddress
import httpx
import json
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timezone
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class AIInfraThreat:
    attack_name:     str
    attack_plane:    str
    stride_category: str
    severity:        str
    description:     str
    evidence:        str
    status:          str = "Surface"
    basis:           str = "observed"
    verified:        str = "not_attempted"
    cve_reference:   str = ""
    atlas_technique: str = ""
    mitigation:      str = ""


@dataclass
class AIInfraScanResult:
    target_url:      str
    scan_time:       str
    ai_stack:        dict
    reachability:    str = "unknown"
    threats:         list[AIInfraThreat] = field(default_factory=list)
    build_threats:   list[AIInfraThreat] = field(default_factory=list)
    deploy_threats:  list[AIInfraThreat] = field(default_factory=list)
    runtime_threats: list[AIInfraThreat] = field(default_factory=list)
    orch_threats:    list[AIInfraThreat] = field(default_factory=list)
    summary:         str = ""
    error:           str = ""
    catch_all_detected: bool = False
    auth_protected_endpoints: list[str] = field(default_factory=list)


RAY_SERVE_PATHS = [
    "/-/routes", "/api/serve/routes", "/-/healthz",
    "/api/serve/deployments", "/api/jobs/", "/dashboard",
]

OLLAMA_PATHS = [
    "/api/tags", "/api/generate", "/api/chat", "/api/show",
    "/api/pull", "/api/delete", "/api/copy",
]

VLLM_PATHS = [
    "/v1/models", "/v1/completions", "/v1/chat/completions", "/health", "/metrics",
]

TGI_PATHS = [
    "/info", "/generate", "/generate_stream", "/metrics", "/health",
]

TORCHSERVE_PATHS = [
    "/ping", "/models", "/api/description", "/metrics",
    "/predictions", "/management/api/v1/models",
]

TRITON_PATHS = [
    "/v2/models", "/v2/health/ready", "/v2/health/live",
    "/v2/repository/models", "/metrics",
]

LANGSERVE_PATHS = [
    "/chat/playground", "/invoke", "/batch", "/stream", "/docs",
]

KUBERNETES_PATHS = [
    "/api/v1", "/apis", "/healthz", "/readyz", "/metrics",
    "/api/v1/namespaces", "/api/v1/pods",
]

UNIVERSAL_PATHS = [
    "/metrics", "/health", "/healthz", "/readyz", "/docs",
    "/openapi.json", "/v1/models", "/v1/chat/completions",
    "/api/tags", "/api/generate",
]

MANAGEMENT_PATHS = [
    "/api/pull", "/api/delete", "/api/copy", "/api/serve/deployments",
    "/api/jobs/", "/management/api/v1/models", "/v2/repository/models",
]

WRITE_ENDPOINTS = {
    "/api/pull":                 ("model pull",        "CRITICAL", "AML.T0010"),
    "/api/delete":               ("model delete",      "CRITICAL", "AML.T0029"),
    "/api/copy":                 ("model copy",        "HIGH",     "AML.T0010"),
    "/management/api/v1/models": ("model register",    "CRITICAL", "AML.T0010"),
    "/api/serve/deployments":    ("deployment config", "CRITICAL", "AML.T0010"),
    "/api/jobs/":                ("code execution",    "CRITICAL", "AML.T0010"),
    "/v2/repository/models":     ("model register",    "CRITICAL", "AML.T0010"),
}

INFO_ENDPOINTS = {
    "/api/show":     ("model metadata",         "MEDIUM", "AML.T0044"),
    "/api/tags":     ("Ollama model list",      "MEDIUM", "AML.T0044"),
    "/v1/models":    ("OpenAI-style model list", "MEDIUM", "AML.T0044"),
    "/v2/models":    ("Triton model list",      "MEDIUM", "AML.T0044"),
    "/info":         ("service metadata",       "MEDIUM", "AML.T0044"),
    "/openapi.json": ("API schema",             "LOW",    "AML.T0044"),
}

GENERIC_PATHS = {
    "/docs", "/health", "/healthz", "/readyz",
    "/metrics", "/openapi.json", "/info", "/ping",
}

AI_BODY_SIGNALS = [
    "model", "ollama", "vllm", "embedding", "inference",
    "completion", "generate", "torch", "tensorflow", "llm",
    "cuda", "gpu", "triton", "ray", "bentoml", "langchain",
    "huggingface", "transformers", "tokenizer", "checkpoint",
]

CANARY_PATH = "/__scanner_canary_nonexistent_check_xyz789_do_not_create_this_route"

INFERENCE_PATHS = [
    "/v1/chat/completions", "/v1/completions",
    "/api/generate", "/api/chat", "/generate",
]

TRAINING_PATHS = ["/train", "/fine-tune", "/finetune", "/training", "/api/train"]

HIGH_IMPACT_CAPS = {"code_execution", "shell", "python", "email_send", "tool_calling", "mcp"}
MED_IMPACT_CAPS  = {"memory", "multi_agent", "web_search", "browser", "retrieval", "rag"}

_SEV_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _normalize_caps(capabilities) -> set:
    return {str(c).lower() for c in (capabilities or [])}


def _reachability(target_url: str) -> str:
    host = urlparse(target_url).hostname or ""
    if host == "localhost" or host.endswith(".localhost"):
        return "loopback"
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:
            return "loopback"
        if ip.is_private or ip.is_link_local:
            return "private"
        return "public"
    except ValueError:
        return "public"


def _cap_severity(severity: str, reachability: str) -> str:
    if reachability in ("loopback", "private") and severity in _SEV_ORDER:
        return _SEV_ORDER[max(0, _SEV_ORDER.index(severity) - 1)]
    return severity


def _inference_severity(reachability: str) -> str:
    return "CRITICAL" if reachability == "public" else "MEDIUM"


def _injection_surface_severity(capabilities) -> str:
    caps = _normalize_caps(capabilities)
    if caps & HIGH_IMPACT_CAPS:
        return "CRITICAL"
    if caps & MED_IMPACT_CAPS:
        return "HIGH"
    return "MEDIUM"


def _extraction_surface_severity(capabilities) -> str:
    caps = _normalize_caps(capabilities)
    if caps & HIGH_IMPACT_CAPS:
        return "HIGH"
    return "MEDIUM"


def _has_data(status: int, body: str) -> bool:
    if status != 200:
        return False
    b = (body or "").strip().lower()
    return b not in ("", "{}", "[]", "null")


class AIInfraAgent:

    def __init__(self, openai_client=None, timeout: int = 15, llm_model: str = None):
        self.client    = openai_client
        self.timeout   = timeout
        self.llm_model = llm_model or os.getenv("AZURE_OPENAI_DEPLOYMENT", "MultiAgentLLM")

    async def scan(self, target_url: str, ai_stack: Optional[dict] = None) -> AIInfraScanResult:
        target_url   = target_url.rstrip("/")
        reachability = _reachability(target_url)
        result = AIInfraScanResult(
            target_url=target_url,
            scan_time=datetime.now(timezone.utc).isoformat(),
            ai_stack=ai_stack or {},
            reachability=reachability,
        )
        logger.info(f"[AIInfraAgent] Starting AI infra threat scan -> {target_url} "
                    f"(reachability={reachability})")
        try:
            for ev in (ai_stack or {}).get("evidence", []):
                if "HTTP 401" in ev or "HTTP 403" in ev:
                    for ep in (ai_stack or {}).get("ml_endpoints", []):
                        if urlparse(ep).path in ev and ep not in result.auth_protected_endpoints:
                            result.auth_protected_endpoints.append(ep)

            capabilities = (ai_stack or {}).get("capabilities", [])

            exposed, catch_all = await self._probe_ai_endpoints(target_url, ai_stack)
            result.catch_all_detected = catch_all

            result.build_threats   = await self._analyze_build_plane(target_url, ai_stack, exposed, reachability)
            result.deploy_threats  = await self._analyze_deployment_plane(target_url, exposed, reachability)
            result.runtime_threats = await self._analyze_runtime_plane(target_url, exposed, capabilities, reachability)
            result.orch_threats    = await self._analyze_orchestration_plane(target_url, exposed, reachability)

            all_threats = (
                result.build_threats + result.deploy_threats +
                result.runtime_threats + result.orch_threats
            )
            result.threats = all_threats
            result.summary = self._synthesize_report(
                target_url, ai_stack, all_threats, catch_all,
                result.auth_protected_endpoints, capabilities, reachability
            )
        except Exception as e:
            logger.error(f"[AIInfraAgent] Scan error: {e}", exc_info=True)
            result.error = str(e)
        return result

    async def _detect_catch_all(self, base_url: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as http:
                r = await http.get(f"{base_url}{CANARY_PATH}",
                                   headers={"User-Agent": "Mozilla/5.0"})
                if r.status_code == 200:
                    logger.warning(
                        f"[AIInfraAgent] Catch-all/SPA-fallback detected at {base_url} "
                        f"(nonexistent path returned 200). Switching to content-based verification."
                    )
                    return True
        except Exception:
            pass
        return False

    async def _probe_ai_endpoints(self, base_url: str, ai_stack: Optional[dict]):
        is_catch_all = await self._detect_catch_all(base_url)

        confirmed       = ai_stack.get("ml_endpoints", []) if ai_stack else []
        confirmed_paths = [urlparse(e).path for e in confirmed]

        paths_to_probe = []
        if any(p in confirmed_paths for p in ["/api/tags", "/api/generate", "/api/chat"]):
            paths_to_probe += OLLAMA_PATHS
        if any(p in confirmed_paths for p in ["/v1/models", "/v1/chat/completions"]):
            paths_to_probe += VLLM_PATHS
            paths_to_probe += LANGSERVE_PATHS
        if any(p in confirmed_paths for p in ["/-/routes", "/-/healthz", "/api/serve/deployments"]):
            paths_to_probe += RAY_SERVE_PATHS
        if any(p in confirmed_paths for p in ["/generate", "/generate_stream", "/info"]):
            paths_to_probe += TGI_PATHS
        if any(p in confirmed_paths for p in ["/ping", "/predictions", "/models"]):
            paths_to_probe += TORCHSERVE_PATHS
        if any(p in confirmed_paths for p in ["/v2/models", "/v2/health/ready"]):
            paths_to_probe += TRITON_PATHS

        paths_to_probe += UNIVERSAL_PATHS
        paths_to_probe += MANAGEMENT_PATHS
        paths_to_probe += KUBERNETES_PATHS
        paths_to_probe  = list(dict.fromkeys(paths_to_probe))

        if is_catch_all:
            exposed = await self._probe_with_content_check(base_url, paths_to_probe)
            return exposed, True

        raw_exposed = {}
        async with httpx.AsyncClient(
            timeout=self.timeout, verify=False, follow_redirects=True
        ) as http:
            tasks   = [self._probe_path(http, base_url, p) for p in paths_to_probe]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for path, res in zip(paths_to_probe, results):
            if isinstance(res, Exception):
                continue
            status, snippet = res
            if status in (404, 405, 501, 502, 503, 0):
                continue
            if status == 403 and not confirmed_paths:
                continue
            raw_exposed[path] = {"status": status, "body": snippet}

        exposed = {}
        for path, data in raw_exposed.items():
            if path in GENERIC_PATHS:
                body_lower = data.get("body", "").lower()
                if not any(signal in body_lower for signal in AI_BODY_SIGNALS):
                    logger.debug(f"[AIInfraAgent] Skipping generic path {path} "
                                 f"[{data['status']}] - no AI body signals")
                    continue
            exposed[path] = data
            logger.info(f"[AIInfraAgent] EXPOSED -> {path} [{data['status']}]")

        return exposed, False

    async def _probe_with_content_check(self, base_url: str, paths_to_probe: list) -> dict:
        exposed = {}
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as http:
            for path in paths_to_probe:
                try:
                    r = await http.get(f"{base_url}{path}",
                                       headers={"User-Agent": "Mozilla/5.0"})
                    ct   = r.headers.get("content-type", "").lower()
                    body = r.text[:500] if r.text else ""
                    body_stripped = body.strip().lower()
                    if "html" in ct or body_stripped.startswith(("<!doctype", "<html")):
                        continue
                    if "json" not in ct:
                        continue
                    if body_stripped in ("", "{}", "[]", "null"):
                        continue
                    exposed[path] = {"status": r.status_code, "body": body[:300]}
                    logger.info(f"[AIInfraAgent] EXPOSED (content-verified) -> {path} "
                                f"[{r.status_code}]")
                except Exception:
                    continue
        return exposed

    async def _probe_path(self, http: httpx.AsyncClient, base: str, path: str):
        headers = {"User-Agent": "Mozilla/5.0"}
        try:
            if "delete" in path:
                r = await http.request("DELETE", f"{base}{path}", headers=headers)
                return r.status_code, r.text[:300] if r.text else ""
            r = await http.get(f"{base}{path}", headers=headers)
            if r.status_code != 405:
                return r.status_code, r.text[:300] if r.text else ""
            r = await http.post(f"{base}{path}", json={}, headers=headers)
            return r.status_code, r.text[:300] if r.text else ""
        except Exception:
            return 0, ""

    async def _analyze_build_plane(self, url, ai_stack, exposed, reachability):
        threats         = []
        confirmed       = ai_stack.get("ml_endpoints", []) if ai_stack else []
        confirmed_paths = [urlparse(e).path for e in confirmed]

        if "/api/pull" in exposed:
            threats.append(AIInfraThreat(
                attack_name="Model Weight Substitution (contingent on unverified download)",
                attack_plane="BUILD",
                stride_category="Tampering",
                severity=_cap_severity("MEDIUM", reachability),
                status="Potential",
                basis="inferred",
                verified="no",
                description=(
                    "The model pull endpoint is reachable without authentication. If the pull "
                    "path does not verify weight integrity, an attacker on the download path "
                    "could substitute backdoored weights. Whether integrity verification is "
                    "performed cannot be determined by remote scanning; this is inferred, not "
                    "observed."
                ),
                evidence=("/api/pull reachable without auth; weight-integrity verification and "
                          "substitution not evaluated"),
                atlas_technique="AML.T0010",
                mitigation=("Verify model digest before loading. Restrict pull to authenticated "
                            "admins. Pin sources to a private registry."),
            ))

        training_hit = [p for p in TRAINING_PATHS if p in confirmed_paths or p in exposed]
        if training_hit:
            threats.append(AIInfraThreat(
                attack_name="Training/Fine-Tuning Endpoint Exposed",
                attack_plane="BUILD",
                stride_category="Tampering",
                severity=_cap_severity("CRITICAL", reachability),
                status="Potential",
                basis="observed",
                verified="not_attempted",
                description=(
                    "A training or fine-tuning endpoint is reachable. If the model is fine-tuned "
                    "on interaction data, an attacker could inject poisoned examples. The "
                    "endpoint's reachability is observed; the poisoning action was not attempted."
                ),
                evidence="Training/fine-tuning endpoint reachable at: " + ", ".join(training_hit),
                atlas_technique="AML.T0020",
                mitigation=("Gate fine-tuning behind authentication. Validate training-data "
                            "provenance. Run backdoor detection before promoting a fine-tuned model."),
            ))

        return threats

    async def _analyze_deployment_plane(self, url, exposed, reachability):
        threats = []

        serve_signals  = ["/-/routes", "/api/serve/deployments", "/-/healthz", "/api/jobs/"]
        detected_serve = [p for p in serve_signals if p in exposed]

        if detected_serve:
            threats.append(AIInfraThreat(
                attack_name="OOM-Triggered Deployment Restart Window",
                attack_plane="DEPLOYMENT",
                stride_category="Tampering",
                severity=_cap_severity("HIGH", reachability),
                status="Surface",
                basis="inferred",
                verified="no",
                description=(
                    "Fault-tolerant actor restart creates a recovery window during which "
                    "checkpoints are rehydrated from disk. An attacker with local filesystem "
                    "access could substitute checkpoint content. Exploitation requires local "
                    "access, which is not remotely observable; only the exposed serve-management "
                    "surface is observed."
                ),
                evidence="Serving management endpoints detected at: " + ", ".join(detected_serve),
                atlas_technique="AML.T0044",
                mitigation=("Restrict checkpoint directories with filesystem ACLs. Enable TLS for "
                            "inter-node communication. Set per-replica memory limits."),
            ))

        if "/-/routes" in exposed:
            d = exposed["/-/routes"]
            if _has_data(d["status"], d.get("body", "")):
                threats.append(AIInfraThreat(
                    attack_name="AI Model Route Table Disclosure",
                    attack_plane="DEPLOYMENT",
                    stride_category="Information Disclosure",
                    severity=_cap_severity("MEDIUM", reachability),
                    status="Confirmed",
                    basis="observed",
                    verified="yes",
                    description=("The model serving route table returned deployed model names and "
                                 "routing paths, enabling enumeration of every model on the cluster."),
                    evidence=f"HTTP {d['status']} at /-/routes returned content: {d['body'][:200]}",
                    mitigation="Restrict the route table endpoint to the internal network. Add auth middleware.",
                ))
            else:
                threats.append(AIInfraThreat(
                    attack_name="Route Table Endpoint Reachable",
                    attack_plane="DEPLOYMENT",
                    stride_category="Information Disclosure",
                    severity=_cap_severity("LOW", reachability),
                    status="Potential",
                    basis="observed",
                    verified="not_attempted",
                    description=("The route table endpoint is reachable but returned no data on this "
                                 "probe; it would disclose deployment routing with valid access."),
                    evidence=f"HTTP {d['status']} at /-/routes (no data returned on probe)",
                    mitigation="Restrict the route table endpoint to the internal network.",
                ))

        return threats

    async def _analyze_runtime_plane(self, url, exposed, capabilities, reachability):
        threats = []
        exposed_inference = [p for p in INFERENCE_PATHS if p in exposed]

        if exposed_inference:
            threats.append(AIInfraThreat(
                attack_name="Unauthenticated Inference Endpoint",
                attack_plane="RUNTIME",
                stride_category="Spoofing",
                severity=_inference_severity(reachability),
                status="Confirmed",
                basis="observed",
                verified="not_attempted",
                description=(
                    "Model inference endpoints respond without an authentication challenge. Risk "
                    "is deployment-dependent: an unauthenticated inference endpoint is expected on "
                    f"loopback/private hosts and severe when internet-exposed (reachability="
                    f"{reachability}). The unauthenticated-reachable state is observed; abuse was "
                    "not attempted here."
                ),
                evidence="Unauthenticated inference reachable at: " + ", ".join(exposed_inference),
                atlas_technique="AML.T0040",
                mitigation=("Require API-key or token auth on inference endpoints if reachable by "
                            "untrusted users. Enforce per-client rate limits. Front the server with "
                            "an authenticating reverse proxy."),
            ))

            threats.append(AIInfraThreat(
                attack_name="Prompt Injection Attack Surface",
                attack_plane="RUNTIME",
                stride_category="Tampering",
                severity=_injection_surface_severity(capabilities),
                status="Surface",
                basis="inferred",
                verified="no",
                description=(
                    "The reachable inference endpoint exposes a prompt-injection surface. Impact is "
                    f"scaled by detected capabilities "
                    f"({', '.join(capabilities) if capabilities else 'bare inference, no tools/memory'}). "
                    "Exploitability is confirmed only by the prompt-injection tester; injection was "
                    "not executed here."
                ),
                evidence="Direct inference endpoint reachable without auth: " + exposed_inference[0],
                atlas_technique="AML.T0051",
                mitigation=("Separate system prompt from user input at the API layer. Add "
                            "input/output guardrails. Apply least privilege to reachable tools."),
            ))

            threats.append(AIInfraThreat(
                attack_name="Model Extraction Surface",
                attack_plane="RUNTIME",
                stride_category="Information Disclosure",
                severity=_extraction_surface_severity(capabilities),
                status="Surface",
                basis="inferred",
                verified="no",
                description=("An unauthenticated inference endpoint may permit query-and-record "
                             "extraction of a surrogate model. Rate limiting was not evaluated "
                             "(single probe), and extraction was not attempted."),
                evidence="Unauthenticated inference reachable; rate limiting not evaluated (single probe)",
                atlas_technique="AML.T0044",
                mitigation="Rate-limit per client. Monitor for extraction-shaped query patterns.",
            ))

            threats.append(AIInfraThreat(
                attack_name="Resource-Exhaustion Surface (long-context / KV-cache)",
                attack_plane="RUNTIME",
                stride_category="Denial of Service",
                severity="MEDIUM",
                status="Surface",
                basis="inferred",
                verified="no",
                description=("Without token or context caps, max-context or concurrent requests "
                             "could exhaust memory. Token/context limits and concurrency were not "
                             "evaluated; no DoS was attempted."),
                evidence="Unauthenticated inference reachable; token/context limits not evaluated",
                atlas_technique="AML.T0029",
                mitigation="Cap max_tokens and context length. Set per-pod memory limits.",
            ))

        if "/metrics" in exposed:
            d = exposed["/metrics"]
            if _has_data(d["status"], d.get("body", "")):
                threats.append(AIInfraThreat(
                    attack_name="Metrics Endpoint Information Disclosure",
                    attack_plane="RUNTIME",
                    stride_category="Information Disclosure",
                    severity=_cap_severity("MEDIUM", reachability),
                    status="Confirmed",
                    basis="observed",
                    verified="yes",
                    description=("The /metrics endpoint returned operational telemetry: model paths, "
                                 "per-request token counts, memory/GPU utilization, service names."),
                    evidence=f"HTTP {d['status']} at /metrics returned content: {d['body'][:200]}",
                    mitigation="Restrict /metrics to the monitoring network. Require scrape auth.",
                ))

        return threats

    async def _analyze_orchestration_plane(self, url, exposed, reachability):
        threats = []

        for path, (action, severity, atlas) in WRITE_ENDPOINTS.items():
            if path not in exposed:
                continue
            d           = exposed[path]
            status_note = "(reached handler, requires body) " if d["status"] == 400 else ""
            threats.append(AIInfraThreat(
                attack_name=f"{action.title()} API Exposed (management endpoint)",
                attack_plane="ORCHESTRATION",
                stride_category="Elevation of Privilege",
                severity=_cap_severity(severity, reachability),
                status="Potential",
                basis="observed",
                verified="not_attempted",
                description=(
                    f"The {action} management endpoint ({path}) is reachable with no auth challenge "
                    f"(request reached the handler rather than returning 401/403). This confirms the "
                    f"route exists and is unauthenticated; it does NOT confirm the {action} action "
                    f"succeeds without credentials — the destructive request was not sent."
                ),
                evidence=f"HTTP {d['status']} {status_note}at {path}; {action} not verified",
                atlas_technique=atlas,
                mitigation=f"Restrict {path} to authenticated users or localhost only.",
            ))

        for path, (info_type, severity, atlas) in INFO_ENDPOINTS.items():
            if path not in exposed or path in WRITE_ENDPOINTS:
                continue
            d = exposed[path]
            if _has_data(d["status"], d.get("body", "")):
                threats.append(AIInfraThreat(
                    attack_name=f"{info_type.title()} Disclosure",
                    attack_plane="ORCHESTRATION",
                    stride_category="Information Disclosure",
                    severity=_cap_severity(severity, reachability),
                    status="Confirmed",
                    basis="observed",
                    verified="yes",
                    description=(f"The {path} endpoint returned {info_type} without authentication."),
                    evidence=f"HTTP {d['status']} at {path} returned content: {d['body'][:150]}",
                    atlas_technique=atlas,
                    mitigation=f"Restrict {path} to the internal network or add authentication.",
                ))
            else:
                threats.append(AIInfraThreat(
                    attack_name=f"{info_type.title()} Endpoint Reachable",
                    attack_plane="ORCHESTRATION",
                    stride_category="Information Disclosure",
                    severity=_cap_severity("LOW", reachability),
                    status="Potential",
                    basis="observed",
                    verified="not_attempted",
                    description=(f"The {path} endpoint is reachable but disclosed no data on this "
                                 f"probe; it would return {info_type} given valid input."),
                    evidence=f"HTTP {d['status']} at {path} (no data returned on probe)",
                    atlas_technique=atlas,
                    mitigation=f"Restrict {path} to the internal network or add authentication.",
                ))

        k8s_exposed = [p for p in KUBERNETES_PATHS if p in exposed]
        if k8s_exposed:
            threats.append(AIInfraThreat(
                attack_name="Kubernetes Control Plane API Reachable",
                attack_plane="ORCHESTRATION",
                stride_category="Elevation of Privilege",
                severity=_cap_severity("CRITICAL", reachability),
                status="Confirmed",
                basis="observed",
                verified="not_attempted",
                description=("Kubernetes API server endpoints are reachable. A reachable API server "
                             "should never be publicly exposed; enumeration/exec/secret-read were "
                             "not attempted."),
                evidence="K8s API reachable at: " + ", ".join(k8s_exposed),
                mitigation=("The Kubernetes API server must not be publicly reachable. Enable RBAC. "
                            "Use network policies to restrict access to control plane nodes."),
            ))

        return threats

    def _synthesize_report(self, url, ai_stack, threats, catch_all_detected=False,
                           auth_protected_endpoints=None, capabilities=None,
                           reachability="unknown"):
        auth_protected_endpoints = auth_protected_endpoints or []
        capabilities = capabilities or []

        if not threats:
            base = "No AI infrastructure findings."
            if catch_all_detected:
                base += (" Target uses catch-all/SPA routing; exposure verified by response "
                         "content, not status code alone.")
            if auth_protected_endpoints:
                base += (f" {len(auth_protected_endpoints)} AI endpoint(s) present but correctly "
                         f"require authentication: {', '.join(auth_protected_endpoints[:5])}.")
            return base

        confirmed = [t for t in threats if t.status == "Confirmed"]
        surface   = [t for t in threats if t.status == "Surface"]
        potential = [t for t in threats if t.status == "Potential"]

        def _line(t):
            return (f"  - [{t.severity}] {t.attack_name} ({t.attack_plane}/{t.stride_category}) "
                    f"[basis={t.basis}; verified={t.verified}] - {t.evidence}")

        parts = [
            f"AI infrastructure findings for {url}  (reachability={reachability})",
            f"{len(confirmed)} confirmed, {len(surface)} attack-surface, {len(potential)} potential.",
            "Legend: basis=observed|inferred, verified=yes|no|not_attempted.",
        ]
        if capabilities:
            parts.append(f"Detected capabilities: {', '.join(capabilities)}.")
        if confirmed:
            parts.append("\nConfirmed (directly observed):")
            parts += [_line(t) for t in confirmed]
        if surface:
            parts.append("\nAttack surface (inferred from a confirmed finding; not verified):")
            parts += [_line(t) for t in surface]
        if potential:
            parts.append("\nPotential (reachable/inferred; harmful action not verified):")
            parts += [_line(t) for t in potential]
        if auth_protected_endpoints:
            parts.append(f"\nSecure configuration: {len(auth_protected_endpoints)} AI endpoint(s) "
                         f"correctly require authentication: {', '.join(auth_protected_endpoints[:5])}.")
        if catch_all_detected:
            parts.append("\nExposure verified by response content (catch-all/SPA routing detected).")

        return "\n".join(parts)

    def format_for_stride_report(self, result: AIInfraScanResult) -> dict:
        findings = []
        for t in result.threats:
            findings.append({
                "name":        t.attack_name,
                "category":    t.stride_category,
                "severity":    t.severity,
                "status":      t.status,
                "basis":       t.basis,
                "verified":    t.verified,
                "layer":       f"AI Infrastructure - {t.attack_plane}",
                "description": t.description,
                "evidence":    t.evidence,
                "mitigation":  t.mitigation,
                "references": {
                    "atlas": t.atlas_technique,
                    "cve":   t.cve_reference,
                    "paper": "Edge GenAI on Distributed AI Infrastructure"
                }
            })
        confirmed = sum(1 for t in result.threats if t.status == "Confirmed")
        surface   = sum(1 for t in result.threats if t.status == "Surface")
        potential = sum(1 for t in result.threats if t.status == "Potential")
        return {
            "scan_type":      "AI_INFRASTRUCTURE",
            "target":         result.target_url,
            "scan_time":      result.scan_time,
            "reachability":   result.reachability,
            "ai_stack":       result.ai_stack,
            "threat_count":   len(result.threats),
            "confirmed_count": confirmed,
            "surface_count":   surface,
            "potential_count": potential,
            "findings":       findings,
            "summary":        result.summary,
            "catch_all_detected": result.catch_all_detected,
            "auth_protected_endpoints": result.auth_protected_endpoints,
            "planes_covered": ["BUILD", "DEPLOYMENT", "RUNTIME", "ORCHESTRATION"]
        }