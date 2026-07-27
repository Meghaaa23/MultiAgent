"""
Universal AI app detection: brand/catalog signals, generic OpenAI-compatible
surfaces, auth-gated probes, and app-identity promotion.
LibreChat is one regression fixture — not the only supported product.
"""
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from multiagent.agents.ai_agents.ai_fingerprint import (
    AIFingerprintAgent,
    FRAMEWORK_PROBE_PATHS,
    FRAMEWORK_SIGNATURES,
    framework_title_brands,
)
from multiagent.agents.ai_agents.ai_vulnerability_test import (
    AIVulnerabilityTester,
    FRAMEWORK_INJECTION_PATHS,
)
from multiagent.agents.webappscanner.app_identity import detect_app_identity


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _run_server(handler_class, port: int):
    srv = HTTPServer(("127.0.0.1", port), handler_class)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


class SpaLibreChatHandler(BaseHTTPRequestHandler):
    """LibreChat-like SPA: HTML title brand + auth-gated JSON APIs."""

    SHELL = (
        "<!DOCTYPE html><html><head><title>LibreChat</title>"
        "<meta name='description' content='LibreChat AI assistant'>"
        "</head><body><div id='root'>LibreChat</div>"
        "<script src='/assets/index.js'></script></body></html>"
    )

    AUTH_PATHS = {
        "/api/ask", "/api/messages", "/api/convos",
        "/api/models", "/api/endpoints", "/api/agents",
    }

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
            body = b'window.__LIBRECHAT__=true; fetch("/api/ask");'
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path in self.AUTH_PATHS:
            self._json(401, {"message": "Unauthorized"})
            return
        self._html()

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        path = self.path.split("?")[0]
        if path in self.AUTH_PATHS:
            self._json(401, {"message": "Unauthorized"})
            return
        self._html()

    def log_message(self, *args):
        pass


class GenericOpenAICompatHandler(BaseHTTPRequestHandler):
    """Custom AI app with no known brand — only OpenAI-compatible API."""

    SHELL = (
        "<!DOCTYPE html><html><head><title>Acme Support Assistant</title>"
        "</head><body><div id='app'>Ask our AI assistant</div></body></html>"
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
        if path == "/v1/models":
            self._json(200, {
                "object": "list",
                "data": [{"id": "gpt-4o-mini", "object": "model"}],
            })
            return
        if path in ("/openapi.json", "/v1/openapi.json"):
            self._json(200, {
                "openapi": "3.0.0",
                "paths": {
                    "/v1/chat/completions": {"post": {"summary": "chat"}},
                    "/v1/models": {"get": {"summary": "models"}},
                },
            })
            return
        self._html()

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        path = self.path.split("?")[0]
        if path in ("/v1/chat/completions", "/api/chat/completions"):
            self._json(200, {
                "id": "chatcmpl-1",
                "object": "chat.completion",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "hello"},
                    "finish_reason": "stop",
                }],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            })
            return
        self._html()

    def log_message(self, *args):
        pass


@pytest.mark.asyncio
async def test_app_identity_librechat_title():
    html = "<html><head><title>LibreChat</title></head><body></body></html>"
    identity = await detect_app_identity(
        "http://localhost:3080", html, {}, wappalyzer_technologies=[],
    )
    assert identity.name == "LibreChat"
    assert identity.confidence in ("high", "medium")


@pytest.mark.asyncio
async def test_app_identity_generic_ai_product_title():
    html = "<html><head><title>Acme Support Assistant</title></head></html>"
    identity = await detect_app_identity(
        "http://x", html, {}, wappalyzer_technologies=[],
    )
    assert identity.name
    assert "assistant" in identity.name.lower() or identity.name == "Acme Support Assistant"
    assert identity.confidence in ("high", "medium")


@pytest.mark.asyncio
async def test_app_identity_not_cleared_without_cms():
    """Regression: for/else used to wipe title identity when Wappalyzer had no CMS."""
    html = "<html><head><title>LibreChat - Chat</title></head></html>"
    identity = await detect_app_identity(
        "http://x", html, {},
        wappalyzer_technologies=[{"name": "React", "category": "JavaScript frameworks"}],
    )
    assert identity.name == "LibreChat"


def test_framework_catalog_is_broader_than_librechat():
    brands = framework_title_brands()
    for name in ("LibreChat", "Open WebUI", "Flowise", "Langflow", "Ollama", "Dify"):
        assert name in FRAMEWORK_SIGNATURES
        assert name.lower() in brands or any(v == name for v in brands.values())
    assert "LibreChat" in FRAMEWORK_PROBE_PATHS
    assert "librechat" in FRAMEWORK_INJECTION_PATHS


def test_html_brand_librechat():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    _, ev, _ = agent._analyse_html(
        "<html><head><title>LibreChat</title></head><body>LibreChat</body></html>",
        "http://localhost:3080", {},
    )
    assert any(e.key == "html_brand_signal" and e.framework == "LibreChat" for e in ev)
    assert any(e.key == "page_title_ai" for e in ev)


def test_auth_gated_schema_counts_as_endpoint():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    auth = []
    r = agent._evaluate_probe_response(
        "http://x/api/endpoints", "/api/endpoints", "schema",
        401, {"Content-Type": "application/json"},
        '{"message":"Unauthorized"}', auth,
    )
    assert r["endpoints"] == ["http://x/api/endpoints"]
    assert any(e.key == "ml_endpoint_401_403" for e in r["evidence"])
    assert len(auth) == 1


def test_vuln_framework_fallback_librechat():
    t = AIVulnerabilityTester(enable_embeddings=False, max_requests=5)
    paths = t._build_endpoint_list(
        [], [], "http://localhost:3080", {"framework": "LibreChat"},
    )
    assert paths == [
        "http://localhost:3080/api/ask",
        "http://localhost:3080/api/messages",
    ]


def test_identify_framework_from_title():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    html = "<html><head><title>LibreChat</title></head><body></body></html>"
    result = agent._identify_framework(html, "", {}, [], [])
    assert result["framework"] == "LibreChat"
    assert result["framework_confidence"] > 0


@pytest.mark.asyncio
async def test_fingerprint_librechat_spa():
    port = _free_port()
    srv = _run_server(SpaLibreChatHandler, port)
    try:
        agent = AIFingerprintAgent(timeout=3, run_behavioral_probes=False)
        result = await agent.fingerprint(f"http://127.0.0.1:{port}", verbose=False)
        assert result["is_ai_powered"] is True
        assert result["framework"] == "LibreChat"
        assert result["evidence_score"] >= 12
        auth_eps = [a["endpoint"] for a in result["auth_required_paths"]]
        all_eps = result["ml_endpoints"] + auth_eps
        assert any("/api/" in e for e in all_eps)
        assert any(
            p in e
            for e in all_eps
            for p in ("/api/ask", "/api/messages", "/api/convos", "/api/endpoints")
        )
    finally:
        srv.shutdown()


@pytest.mark.asyncio
async def test_fingerprint_generic_openai_compatible():
    """No catalogued brand — detection must still fire from API/OpenAPI signals."""
    port = _free_port()
    srv = _run_server(GenericOpenAICompatHandler, port)
    try:
        agent = AIFingerprintAgent(timeout=3, run_behavioral_probes=False)
        result = await agent.fingerprint(f"http://127.0.0.1:{port}", verbose=False)
        assert result["is_ai_powered"] is True
        assert result["evidence_score"] >= 12
        assert result["ml_endpoints"] or result.get("openapi_schema")
        fw = result.get("framework") or ""
        assert fw in ("", "OpenAI-compatible", "vLLM") or result["ml_endpoints"]
    finally:
        srv.shutdown()
