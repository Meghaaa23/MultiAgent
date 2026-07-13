"""
Tests for universal AI app detection across SPA UIs, auth-gated APIs,
and framework-specific endpoint selection.
"""
import asyncio
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from multiagent.agents.ai_agents.ai_fingerprint import (
    AIFingerprintAgent,
    FRAMEWORK_PROBE_PATHS,
    FRAMEWORK_SIGNATURES,
    _looks_html_body,
    classify_endpoint,
)
from multiagent.agents.ai_agents.Ai_Infra_agent import (
    AIInfraAgent,
    _is_k8s_body,
)
from multiagent.agents.ai_agents.ai_vulnerability_test import (
    AIVulnerabilityTester,
    detect_application_type,
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _run_server(handler_class, port: int):
    srv = HTTPServer(("127.0.0.1", port), handler_class)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


class SpaOpenWebUIHandler(BaseHTTPRequestHandler):
    """Simulates Open WebUI: SPA catch-all HTML + auth-gated JSON APIs."""

    SHELL = (
        "<!DOCTYPE html><html><head><title>Open WebUI</title>"
        "<meta name='description' content='Chat with AI models'>"
        "</head><body><div id='app'>Open WebUI</div>"
        "<script src='/assets/index.js'></script></body></html>"
    )

    def _html(self):
        data = self.SHELL.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, status: int, obj: dict):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path.startswith("/assets/"):
            body = b'const WEBUI_NAME="Open WebUI"; fetch("/api/chat");'
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path in ("/api/models", "/api/v1/models", "/api/chat",
                    "/api/chat/completions", "/ollama/api/tags"):
            self._json(401, {"detail": "Not authenticated"})
            return
        # Catch-all SPA shell
        self._html()

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        path = self.path.split("?")[0]
        if path in ("/api/chat", "/api/chat/completions",
                    "/api/v1/chat/completions", "/v1/chat/completions"):
            self._json(401, {"detail": "Not authenticated"})
            return
        if path in ("/api/models", "/api/v1/models"):
            self._json(401, {"detail": "Not authenticated"})
            return
        self._html()

    def log_message(self, *args):
        pass


class SpaLangflowHandler(BaseHTTPRequestHandler):
    """Simulates Langflow/Gradio-style UI with real /api/v1/flows JSON."""

    SHELL = (
        "<!DOCTYPE html><html><head><title>Langflow</title></head>"
        "<body>langflow</body></html>"
    )

    def _html(self):
        data = self.SHELL.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, status: int, obj):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path == "/api/v1/flows":
            self._json(200, {"flows": [{"id": "1", "name": "demo"}]})
            return
        if path == "/api/v1/components":
            self._json(200, {"components": []})
            return
        if path == "/health":
            self._json(200, {"status": "ok"})
            return
        if path == "/config":
            self._json(200, {"version": "1.0", "components": [], "gradio": False})
            return
        self._html()

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        path = self.path.split("?")[0]
        if path == "/api/v1/run":
            self._json(422, {"detail": [{"msg": "field required", "loc": ["body"]}]})
            return
        self._html()

    def log_message(self, *args):
        pass


# ---------------------------------------------------------------------------
# Unit: HTML brand / SPA helpers
# ---------------------------------------------------------------------------

def test_html_brand_open_webui():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    _, ev, _, title, brands = agent._analyse_html(
        "<html><head><title>Open WebUI</title></head></html>",
        "http://localhost:3001", {},
    )
    assert title == "Open WebUI"
    assert "Open WebUI" in brands
    assert any(e.key == "html_brand_signal" for e in ev)


def test_html_brand_flowise_and_langflow():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    _, _, _, title, brands = agent._analyse_html(
        "<html><head><title>Flowise - Build AI Agents, Visually</title></head></html>",
        "http://x", {},
    )
    assert "Flowise" in brands
    _, _, _, title, brands = agent._analyse_html(
        "<html><head><title>Langflow</title></head><body>langflow</body></html>",
        "http://x", {},
    )
    assert "Langflow" in brands


def test_looks_html_body():
    assert _looks_html_body("text/html", "<html></html>")
    assert _looks_html_body("", "<!DOCTYPE html><html>")
    assert not _looks_html_body("application/json", '{"models":[]}')


def test_auth_gated_probe_counts_as_endpoint():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    auth = []
    r = agent._evaluate_probe_response(
        "http://x/api/v1/prediction", "/api/v1/prediction", "chat",
        401, {"Content-Type": "application/json"},
        '{"detail":"Unauthorized"}', auth,
    )
    assert r["endpoints"] == ["http://x/api/v1/prediction"]
    assert any(e.key == "ml_endpoint_401_403" for e in r["evidence"])
    assert len(auth) == 1


def test_spa_405_ignored():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    r = agent._evaluate_probe_response(
        "http://x/openapi.json", "/openapi.json", "schema",
        405, {"Content-Type": "application/json"}, "", [],
        spa_catch_all=True,
    )
    assert r["endpoints"] == []
    r2 = agent._evaluate_probe_response(
        "http://x/api/chat", "/api/chat", "chat",
        405, {"Content-Type": "text/plain"}, "", [],
        spa_catch_all=True,
    )
    assert r2["endpoints"] == []


def test_html_probe_response_ignored():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    r = agent._evaluate_probe_response(
        "http://x/api/chat", "/api/chat", "chat",
        200, {"Content-Type": "text/html"},
        "<!DOCTYPE html><html><body>spa</body></html>", [],
    )
    assert r == {}


def test_injection_capable_requires_inference_segment():
    t = AIVulnerabilityTester(enable_embeddings=False, max_requests=5)
    assert t._is_injection_capable("http://x/api/chat")
    assert t._is_injection_capable("http://x/api/chat/completions")
    assert t._is_injection_capable("http://x/api/v1/prediction")
    assert not t._is_injection_capable("http://x/api-docs")
    assert not t._is_injection_capable("http://x/api/v1/chatflows")
    assert not t._is_injection_capable("http://x/openapi.json")
    assert not t._is_injection_capable("http://x/api/models")


def test_classify_endpoint_segment_boundaries():
    chatflows = classify_endpoint("http://x/api/v1/chatflows")
    assert chatflows.endpoint_type == "schema"
    assert chatflows.risk == "low"

    chat = classify_endpoint("http://x/api/chat")
    assert chat.endpoint_type == "inference"
    assert chat.risk == "critical"

    prediction = classify_endpoint("http://x/api/v1/prediction")
    assert prediction.endpoint_type == "inference"

    agents = classify_endpoint("http://x/api/agents")
    assert agents.endpoint_type == "agentic"


def test_framework_probe_paths_cover_target_apps():
    for name in ("Open WebUI", "Flowise", "Langflow", "LibreChat",
                 "AnythingLLM", "Gradio"):
        assert name in FRAMEWORK_SIGNATURES
        assert name in FRAMEWORK_PROBE_PATHS


# ---------------------------------------------------------------------------
# Unit: infra classify / k8s
# ---------------------------------------------------------------------------

def test_infra_classify_spa_and_auth():
    agent = AIInfraAgent()
    assert agent._classify(
        200, "<!DOCTYPE html><html>", "text/html", "/api/tags", False, True
    ) == "skip"
    assert agent._classify(
        401, '{"error":"auth"}', "application/json", "/api/v1/prediction", True, True
    ) == "auth"
    assert agent._classify(
        404, "not found", "text/plain", "/api/generate", False, True
    ) == "skip"
    assert agent._classify(
        200, '{"models":[{"name":"x"}]}', "application/json", "/api/tags", True, False
    ) == "exposed"
    assert agent._classify(
        200, "Welcome", "text/plain", "/api/pull", False, True
    ) == "skip"


def test_k8s_body_strict():
    assert not _is_k8s_body('{"error":"no"}')
    assert not _is_k8s_body('{"apiVersion":"v1"}')
    assert _is_k8s_body('{"kind":"PodList","apiVersion":"v1","items":[]}')


def test_infra_select_paths_spa_avoids_k8s():
    agent = AIInfraAgent()
    paths = agent._select_paths(
        ["/api/v1/prediction"],
        {"framework": "Flowise"},
        catch_all=True,
    )
    assert "/api/v1/namespaces" not in paths
    assert "/api/v1/pods" not in paths
    assert "/api/v1/prediction" in paths or "/api/v1/chatflows" in paths


# ---------------------------------------------------------------------------
# Unit: vuln tester framework fallbacks
# ---------------------------------------------------------------------------

def test_vuln_framework_endpoint_fallback():
    t = AIVulnerabilityTester(enable_embeddings=False, max_requests=5)
    flowise = t._build_endpoint_list([], [], "http://localhost:3100",
                                     {"framework": "Flowise"})
    assert flowise == ["http://localhost:3100/api/v1/prediction"]
    openwebui = t._build_endpoint_list([], [], "http://localhost:3001",
                                       {"framework": "Open WebUI"})
    assert any("/api/chat" in e for e in openwebui)
    langflow = t._build_endpoint_list([], [], "http://localhost:7860",
                                      {"framework": "Langflow"})
    assert langflow == ["http://localhost:7860/api/v1/run"]


def test_app_detect_framework_shortcuts():
    assert detect_application_type(
        {"framework": "Ollama", "ml_endpoints": []}
    ).value == "inference_server"


# ---------------------------------------------------------------------------
# Integration: fingerprint against mock SPA apps
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fingerprint_openwebui_spa():
    port = _free_port()
    srv = _run_server(SpaOpenWebUIHandler, port)
    try:
        agent = AIFingerprintAgent(timeout=3, run_behavioral_probes=False)
        result = await agent.fingerprint(f"http://127.0.0.1:{port}", verbose=False)
        assert result["spa_catch_all"] is True
        assert result["is_ai_powered"] is True
        assert result["has_live_surface"] is True
        assert result["ai_brand_only"] is False
        assert result["posterior"] > 0.5
        assert result["framework"] == "Open WebUI"
        assert result["evidence_score"] > 0
        assert result["ml_endpoints"] or result["auth_required_paths"]
        # Auth-gated chat/models should be discovered
        auth_eps = [a["endpoint"] for a in result["auth_required_paths"]]
        all_eps = result["ml_endpoints"] + auth_eps
        assert any("/api/" in e for e in all_eps)
    finally:
        srv.shutdown()


@pytest.mark.asyncio
async def test_fingerprint_langflow_spa():
    port = _free_port()
    srv = _run_server(SpaLangflowHandler, port)
    try:
        agent = AIFingerprintAgent(timeout=3, run_behavioral_probes=False)
        result = await agent.fingerprint(f"http://127.0.0.1:{port}", verbose=False)
        assert result["is_ai_powered"] is True
        assert result["has_live_surface"] is True
        assert "Langflow" in (result["framework"], *result.get("frameworks_detected", []))
        assert any("/api/v1/flows" in e or "/api/v1/run" in e
                   for e in result["ml_endpoints"])
    finally:
        srv.shutdown()


@pytest.mark.asyncio
async def test_infra_no_false_k8s_on_spa_flowise():
    port = _free_port()
    srv = _run_server(SpaOpenWebUIHandler, port)
    try:
        fp = {
            "framework": "Open WebUI",
            "ml_endpoints": [],
            "auth_required_paths": [
                {"endpoint": f"http://127.0.0.1:{port}/api/chat",
                 "auth_type": "unknown", "status_code": 401, "detail": "auth"},
            ],
            "spa_catch_all": True,
            "capabilities": ["chat"],
            "evidence": [],
        }
        agent = AIInfraAgent(timeout=3)
        result = await agent.scan(f"http://127.0.0.1:{port}", ai_stack=fp)
        names = [t.attack_name for t in result.threats]
        assert not any("Kubernetes" in n for n in names)
        assert not any("Model Pull" in n for n in names)
    finally:
        srv.shutdown()


class MarketingBrandHandler(BaseHTTPRequestHandler):
    PAGE = (
        "<!DOCTYPE html><html><head><title>Open WebUI — The best AI interface</title>"
        "<meta name='description' content='Chat with AI models online'>"
        "</head><body><h1>Open WebUI</h1><p>Download our AI assistant.</p>"
        "</body></html>"
    )

    def do_GET(self):  # noqa: N802
        data = self.PAGE.encode()
        self.send_response(200 if self.path in ("/", "/index.html") else 404)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        data = b"Not Found"
        self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


@pytest.mark.asyncio
async def test_brand_only_marketing_site_not_ai_powered():
    port = _free_port()
    srv = _run_server(MarketingBrandHandler, port)
    try:
        agent = AIFingerprintAgent(timeout=3, run_behavioral_probes=False)
        result = await agent.fingerprint(f"http://127.0.0.1:{port}", verbose=False)
        assert result["has_live_surface"] is False
        assert result["is_ai_powered"] is False
        assert result["ai_brand_only"] is True
        assert not result["ml_endpoints"]
        assert not result["auth_required_paths"]
        assert result["posterior"] >= 0.0
    finally:
        srv.shutdown()
