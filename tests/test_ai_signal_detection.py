"""
Product-agnostic AI detection: behavioural probes, inference endpoints,
OpenAPI / response-shape signals — never hardcoded application brand names.
"""
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from multiagent.agents.ai_agents.ai_fingerprint import (
    AIFingerprintAgent,
    FRAMEWORK_SIGNATURES,
    LIVE_SURFACE_EVIDENCE_KEYS,
    _is_inference_path,
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


class AuthGatedChatHandler(BaseHTTPRequestHandler):
    """Generic SPA shell + auth-gated chat API (no product brand required)."""

    SHELL = (
        "<!DOCTYPE html><html><head><title>Support Portal</title>"
        "</head><body><div id='root'>chat</div></body></html>"
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
        if path in ("/api/chat", "/api/ask", "/api/messages", "/v1/chat/completions"):
            self._json(401, {"message": "Unauthorized"})
            return
        if path in ("/api/models", "/v1/models"):
            self._json(401, {"message": "Unauthorized"})
            return
        self._html()

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        path = self.path.split("?")[0]
        if path in ("/api/chat", "/api/ask", "/api/messages",
                    "/v1/chat/completions", "/api/chat/completions"):
            self._json(401, {"message": "Unauthorized"})
            return
        self._html()

    def log_message(self, *args):
        pass


class OpenAICompatHandler(BaseHTTPRequestHandler):
    """Custom AI API with OpenAI-compatible JSON — no product name in UI."""

    SHELL = (
        "<!DOCTYPE html><html><head><title>Portal</title></head>"
        "<body>app</body></html>"
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
                "data": [{"id": "demo-model", "object": "model"}],
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


class BrandOnlyShellHandler(BaseHTTPRequestHandler):
    """HTML mentions a product string but exposes no AI API surface."""

    SHELL = (
        "<!DOCTYPE html><html><head><title>LibreChat</title></head>"
        "<body>LibreChat marketing page</body></html>"
    )

    def do_GET(self):  # noqa: N802
        data = self.SHELL.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):  # noqa: N802
        self.do_GET()

    def log_message(self, *args):
        pass


def test_no_product_framework_catalog():
    # Protocol label only — never application brand keys.
    assert list(FRAMEWORK_SIGNATURES.keys()) == ["OpenAI-compatible"]
    assert "title_hints" not in FRAMEWORK_SIGNATURES["OpenAI-compatible"]
    assert "js_strings" not in FRAMEWORK_SIGNATURES["OpenAI-compatible"]


def test_inference_path_helper():
    assert _is_inference_path("/api/chat")
    assert _is_inference_path("/v1/chat/completions")
    assert _is_inference_path("/api/ask")
    assert not _is_inference_path("/api/models")
    assert not _is_inference_path("/health")


def test_live_surface_keys_exclude_passive_brand():
    assert "page_title_ai" not in LIVE_SURFACE_EVIDENCE_KEYS
    assert "js_ai_sdk" not in LIVE_SURFACE_EVIDENCE_KEYS
    assert "behavior_llm_response" in LIVE_SURFACE_EVIDENCE_KEYS
    assert "ml_endpoint_401_403" in LIVE_SURFACE_EVIDENCE_KEYS


def test_title_alone_does_not_identify_framework():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    html = "<html><head><title>LibreChat</title></head><body>LibreChat</body></html>"
    result = agent._identify_framework(html, "", {}, [], [])
    assert result.get("framework") in ("", None)
    _, ev, _ = agent._analyse_html(html, "http://x", {})
    assert not any(e.key == "html_brand_signal" for e in ev)


@pytest.mark.asyncio
async def test_app_identity_generic_ai_cue_not_brand_map():
    html = "<html><head><title>Acme Support Assistant</title></head></html>"
    identity = await detect_app_identity("http://x", html, {}, wappalyzer_technologies=[])
    assert identity.name
    assert "assistant" in identity.name.lower() or "Acme" in (identity.name or "")


@pytest.mark.asyncio
async def test_fingerprint_auth_gated_chat_is_ai():
    port = _free_port()
    srv = _run_server(AuthGatedChatHandler, port)
    try:
        agent = AIFingerprintAgent(timeout=3, run_behavioral_probes=False)
        result = await agent.fingerprint(f"http://127.0.0.1:{port}", verbose=False)
        assert result["is_ai_powered"] is True
        auth_eps = [a["endpoint"] for a in result["auth_required_paths"]]
        all_eps = result["ml_endpoints"] + auth_eps
        assert any(_is_inference_path(e) or "/chat" in e or "/ask" in e or "/messages" in e
                   for e in all_eps)
    finally:
        srv.shutdown()


@pytest.mark.asyncio
async def test_fingerprint_openai_compatible_is_ai():
    port = _free_port()
    srv = _run_server(OpenAICompatHandler, port)
    try:
        agent = AIFingerprintAgent(timeout=3, run_behavioral_probes=False)
        result = await agent.fingerprint(f"http://127.0.0.1:{port}", verbose=False)
        assert result["is_ai_powered"] is True
        assert result["ml_endpoints"] or result.get("openapi_schema")
    finally:
        srv.shutdown()


@pytest.mark.asyncio
async def test_brand_string_alone_is_not_ai():
    """Marketing page with a product name must not escalate without live surface."""
    port = _free_port()
    srv = _run_server(BrandOnlyShellHandler, port)
    try:
        agent = AIFingerprintAgent(timeout=3, run_behavioral_probes=False)
        result = await agent.fingerprint(f"http://127.0.0.1:{port}", verbose=False)
        assert result["is_ai_powered"] is False
    finally:
        srv.shutdown()
