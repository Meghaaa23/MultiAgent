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
    """Simulates Langflow-style UI with JS-declared API paths."""

    SHELL = (
        "<!DOCTYPE html><html><head><title>Langflow</title></head>"
        "<body>langflow<script src='/assets/index.js'></script></body></html>"
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
        if path.startswith("/assets/"):
            body = (
                b'fetch("/api/v1/flows"); fetch("/api/v1/run"); '
                b'fetch("/api/v1/components");'
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
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
# Unit: HTML / SPA helpers
# ---------------------------------------------------------------------------

def test_html_generic_ai_title():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    js_urls, ev, links, title = agent._analyse_html(
        "<html><head><title>AI Chat Assistant</title></head></html>",
        "http://localhost:3001", {},
    )
    assert title == "AI Chat Assistant"
    assert any(e.key == "page_title_ai" for e in ev)


def test_meta_ai_tag_ignores_url_and_domain_noise():
    from multiagent.agents.ai_agents.ai_fingerprint import _is_meaningful_ai_meta_content

    assert not _is_meaningful_ai_meta_content("https://wink.ai")
    assert not _is_meaningful_ai_meta_content("https://wink.ai/logo-big.png")
    assert not _is_meaningful_ai_meta_content("https://remini.ai/og.png")
    assert _is_meaningful_ai_meta_content(
        "Wink AI video & image enhancer sharpens blurry clips"
    )
    assert _is_meaningful_ai_meta_content(
        "wink ai, wink app, ai video editor, video enhancer"
    )

    agent = AIFingerprintAgent(run_behavioral_probes=False)
    html_doc = """
    <html><head>
      <title>Wink: AI Video and Image Enhancer &amp; Editor</title>
      <meta content="https://wink.ai">
      <meta content="https://wink.ai/logo-big.png">
      <meta content="Wink AI video enhancer sharpens blurry clips">
      <meta content="wink ai, ai video editor">
    </head><body></body></html>
    """
    _, ev, _, title = agent._analyse_html(html_doc, "https://wink.ai", {})
    assert "&" in title and "&amp;" not in title
    meta = [e for e in ev if e.key == "meta_ai_tag"]
    details = " ".join(e.detail for e in meta)
    assert "logo-big.png" not in details
    assert "https://wink.ai\"" not in details and not any(
        e.detail.strip().endswith("https://wink.ai") for e in meta
    )
    assert any("video enhancer" in e.detail.lower() or "video editor" in e.detail.lower()
               for e in meta)


def test_html_no_product_brand_matching():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    _, ev, _, title = agent._analyse_html(
        "<html><head><title>Flowise - Build Agents</title></head></html>",
        "http://x", {},
    )
    assert title.startswith("Flowise")
    assert not any(e.key == "html_brand_signal" for e in ev)


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


def test_discovery_extracts_js_routes_without_catalog():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    paths = agent._extract_api_paths_from_js(
        'const WEBUI_NAME="x"; fetch("/api/chat"); fetch("/api/models");'
    )
    assert "/api/chat" in paths
    assert "/api/models" in paths


def test_discovery_extracts_base_url_template_and_concat_paths():
    """SPA bundles often build URLs as `${BASE_URL}/api/...` (LibreChat-style)."""
    from multiagent.agents.ai_agents.ai_fingerprint import _is_inference_path

    agent = AIFingerprintAgent(run_behavioral_probes=False)
    js = r"""
        const BASE_URL = "";
        request.get(`${BASE_URL}/api/messages/${conversationId}`);
        request.post(`${BASE_URL}/api/ask/${endpoint}`, body);
        fetch(`${baseUrl}/v1/chat/completions`);
        const url = BASE_URL + "/api/agents";
        axios.post(API_URL + "/api/chat", payload);
        new EventSource(`${BASE_URL}/api/stream`);
    """
    paths = agent._extract_api_paths_from_js(js)
    assert "/api/messages" in paths
    assert "/api/ask" in paths
    assert "/v1/chat/completions" in paths
    assert "/api/agents" in paths  # discovered; probe gate is separate
    assert "/api/chat" in paths
    assert "/api/stream" in paths
    assert all(
        _is_inference_path(p)
        for p in (
            "/api/messages",
            "/api/ask",
            "/v1/chat/completions",
            "/api/chat",
        )
    )
    # Must not invent catalog endpoints that were never in the bundle.
    assert "/api/tags" not in paths
    assert "/ollama/api/generate" not in paths


def test_discovery_extracts_escaped_and_split_api_paths():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    escaped = r'const root="\/api\/messages"; const chat="\/api\/agents\/chat\/active";'
    paths = agent._extract_api_paths_from_js(escaped)
    assert "/api/messages" in paths
    assert "/api/agents/chat/active" in paths

    split = r'const p="/api/"+"messages"; const q="/api"+"/ask";'
    split_paths = agent._extract_api_paths_from_js(split)
    assert "/api/messages" in split_paths
    assert "/api/ask" in split_paths


def test_js_chunk_url_extraction_follows_vite_assets():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    js = r'''
        import("./assets/data-provider.AbCdEf.js");
        const deps=["assets/Messages.xyz.js","assets/index.BSLuV95c.js"];
    '''
    chunks = agent._extract_js_chunk_urls(js, "http://localhost:3080")
    assert any("data-provider.AbCdEf.js" in c for c in chunks)
    assert any("Messages.xyz.js" in c for c in chunks)


def test_js_chunk_priority_skips_vendor_ui_and_prefers_api():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    assert agent._js_chunk_priority(
        "http://localhost:3080/assets/mermaid.CpNRA-E5.js"
    ) < 0
    assert agent._js_chunk_priority(
        "http://localhost:3080/assets/codemirror-core.DCeggAsc.js"
    ) < 0
    http_pri = agent._js_chunk_priority(
        "http://localhost:3080/assets/http-client.D1qXypdn.js"
    )
    vendor_pri = agent._js_chunk_priority(
        "http://localhost:3080/assets/vendor.DGyZakcu.js"
    )
    index_pri = agent._js_chunk_priority(
        "http://localhost:3080/assets/index.BSLuV95c.js"
    )
    assert http_pri > vendor_pri
    assert index_pri > http_pri


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
        {"framework": "OpenAI-compatible"},
        catch_all=True,
    )
    assert "/api/v1/namespaces" not in paths
    assert "/api/v1/pods" not in paths
    assert "/api/v1/prediction" in paths


# ---------------------------------------------------------------------------
# Unit: vuln tester universal fallbacks
# ---------------------------------------------------------------------------

def test_vuln_uses_discovered_paths_only():
    t = AIVulnerabilityTester(enable_embeddings=False, max_requests=5)
    eps = t._build_endpoint_list(
        [],
        [],
        "http://localhost:3100",
        {"discovered_paths": ["/api/v1/prediction", "/api/v1/run", "/health"]},
    )
    path_list = [e[len("http://localhost:3100"):] for e in eps]
    assert "/api/v1/prediction" in path_list
    assert "/api/v1/run" in path_list
    # Catalog spray must not invent paths the app never exposed.
    assert "/v1/chat/completions" not in path_list


def test_normalize_derives_live_surface_from_endpoints():
    t = AIVulnerabilityTester(enable_embeddings=False, max_requests=5)
    fp = t._normalize_ai_fingerprint({
        "framework": "OpenAI-compatible",
        "ml_endpoints": ["http://localhost:3001/api/chat"],
    })
    assert fp["has_live_surface"] is True
    assert fp["is_ai_powered"] is True


def test_normalize_brand_only_clears_ai_flag():
    t = AIVulnerabilityTester(enable_embeddings=False, max_requests=5)
    fp = t._normalize_ai_fingerprint({
        "framework": "",
        "is_ai_powered": True,
        "ml_endpoints": [],
        "auth_required_paths": [],
    })
    assert fp["has_live_surface"] is False
    assert fp["is_ai_powered"] is False


@pytest.mark.asyncio
async def test_vuln_tester_skips_brand_only_framework():
    t = AIVulnerabilityTester(enable_embeddings=False, max_requests=5)
    result = await t.test_all(
        {
            "framework": "",
            "is_ai_powered": True,
            "ml_endpoints": [],
            "auth_required_paths": [],
        },
        "http://localhost:3100",
        verbose=False,
    )
    assert result["confirmed_ai_vulns"] == []
    assert result["potential_ai_vulns"] == []
    assert result["requests_sent"] == 0


@pytest.mark.asyncio
async def test_vuln_tester_auth_gated_still_reported():
    t = AIVulnerabilityTester(enable_embeddings=False, max_requests=5)
    result = await t.test_all(
        {
            "framework": "OpenAI-compatible",
            "ml_endpoints": [],
            "auth_required_paths": [
                {"endpoint": "http://localhost:3001/api/chat",
                 "auth_type": "bearer", "status_code": 401, "detail": "auth"},
            ],
        },
        "http://localhost:3001",
        verbose=False,
    )
    assert result["confirmed_ai_vulns"] == []
    assert len(result["potential_ai_vulns"]) == 1
    assert "auth-gated" in result["potential_ai_vulns"][0]["type"]


def test_app_detect_from_inference_paths():
    assert detect_application_type(
        {"framework": "", "ml_endpoints": ["http://x/api/tags", "http://x/api/generate"]}
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
        assert result["detection"] == "confirmed"
        assert result["confidence"] == "high"
        # Protocol label only — never a product brand.
        assert result["framework"] in (
            "", "OpenAI-compatible", "chat_api",
        )
        assert result["framework"] not in (
            "Open WebUI", "LibreChat", "Flowise", "Langflow",
        )
        assert result["ml_endpoints"] or result["auth_required_paths"]
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
        assert result["detection"] == "confirmed"
        assert "Langflow" not in (result["framework"], *result.get("frameworks_detected", []))
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
            "framework": "OpenAI-compatible",
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
        assert result["detection"] in ("possible", "probable")
        assert not result["ml_endpoints"]
        assert not result["auth_required_paths"]
        assert "brand" in result.get("evidence_classes", {})
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# Regression: status-code-only must not confirm AI (Canva / LibreChat)
# ---------------------------------------------------------------------------

class CanvaStyleMarketingHandler(BaseHTTPRequestHandler):
    """Non-AI marketing site: AI-heavy copy + robots spray + 405/403 noise."""

    PAGE = (
        "<!DOCTYPE html><html><head>"
        "<title>Canva — AI Design Magic</title>"
        "<meta name='description' content='Create with AI generative design'>"
        "</head><body><h1>AI-powered design for everyone</h1>"
        "<a href='/create/'>Create</a><a href='/features/'>Features</a>"
        "</body></html>"
    )
    ROBOTS = (
        "User-agent: *\n"
        "Disallow: /create/\n"
        "Disallow: /features/\n"
        "Disallow: /da_dk/funktioner/\n"
        "Disallow: /admin\n"
        "Disallow: /_print/export\n"
        "Sitemap: http://127.0.0.1:{port}/sitemap.xml\n"
    )
    SITEMAP = (
        '<?xml version="1.0"?><urlset>'
        "<url><loc>http://127.0.0.1:{port}/create/</loc></url>"
        "<url><loc>http://127.0.0.1:{port}/features/</loc></url>"
        "<url><loc>http://127.0.0.1:{port}/da_dk/funktioner/</loc></url>"
        "</urlset>"
    )

    def _send(self, status: int, body: bytes, ctype: str):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        port = self.server.server_address[1]
        if path == "/robots.txt":
            body = self.ROBOTS.format(port=port).encode()
            return self._send(200, body, "text/plain")
        if path == "/sitemap.xml":
            body = self.SITEMAP.format(port=port).encode()
            return self._send(200, body, "application/xml")
        if path in ("/create/", "/features/", "/da_dk/funktioner/",
                    "/admin", "/_print/export"):
            return self._send(403, b'{"error":"forbidden"}', "application/json")
        if path in ("/", "/index.html"):
            return self._send(200, self.PAGE.encode(), "text/html")
        return self._send(404, b"not found", "text/plain")

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        path = self.path.split("?")[0]
        if path in ("/create/", "/features/", "/da_dk/funktioner/",
                    "/admin", "/_print/export"):
            return self._send(405, b"Method Not Allowed", "text/plain")
        return self._send(404, b"not found", "text/plain")

    def log_message(self, *args):
        pass


class LibreChatStyleHandler(BaseHTTPRequestHandler):
    """Auth-gated inference surfaces must still confirm."""

    PAGE = (
        "<!DOCTYPE html><html><head><title>Chat</title></head>"
        "<body><div id='root'></div>"
        "<script src='/assets/index.js'></script></body></html>"
    )

    def _json(self, status: int, obj: dict):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _html(self):
        data = self.PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path.startswith("/assets/"):
            body = (
                b'fetch("/api/chat"); fetch("/api/messages"); '
                b'fetch("/v1/chat/completions");'
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path in ("/api/chat", "/api/messages", "/v1/chat/completions"):
            self._json(401, {"detail": "Unauthorized"})
            return
        self._html()

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        path = self.path.split("?")[0]
        if path in ("/api/chat", "/api/messages", "/v1/chat/completions"):
            self._json(401, {"detail": "Unauthorized"})
            return
        self._html()

    def log_message(self, *args):
        pass


@pytest.mark.asyncio
async def test_marketing_site_status_codes_do_not_confirm_ai():
    """Canva/Picsart regression: 405/403 on non-inference paths + AI copy
    must never produce has_live_surface / confirmed / ml_endpoints.
    """
    port = _free_port()
    srv = _run_server(CanvaStyleMarketingHandler, port)
    try:
        agent = AIFingerprintAgent(timeout=3, run_behavioral_probes=False)
        result = await agent.fingerprint(f"http://127.0.0.1:{port}", verbose=False)
        assert result["has_live_surface"] is False
        assert result["is_ai_powered"] is False
        assert result["detection"] in ("possible", "probable")
        assert result["detection"] != "confirmed"
        assert result["ml_endpoints"] == []
        # Junk robots/marketing paths must not emit AI hint evidence.
        keys = {e.get("key") for e in (result.get("evidence_items") or [])
                if isinstance(e, dict)}
        assert "ml_endpoint_405" not in keys
        assert "ml_endpoint_401_403" not in keys
        assert "robots_ai_path" not in keys
        assert "sitemap_ai_path" not in keys
        # Brand/meta only → brand-only marketing site.
        assert result["ai_brand_only"] is True
    finally:
        srv.shutdown()


class LibreChatChunkedBundleHandler(BaseHTTPRequestHandler):
    """Entry bundle has no API strings; Vite chunk holds escaped LibreChat paths."""

    PAGE = (
        "<!DOCTYPE html><html><head><title>LibreChat</title>"
        '<meta name="description" content="LibreChat - An open source chat '
        'application with support for multiple AI models"/>'
        "</head><body><div id='root'></div>"
        '<script type="module" src="./assets/index.BSLuV95c.js"></script>'
        "</body></html>"
    )
    ENTRY = b'import("./assets/data-provider.AbCd.js");'
    CHUNK = (
        b'const BASE_URL="";'
        b'const messagesRoot=`${BASE_URL}/api/messages`;'
        b'const active=()=>`${BASE_URL}/api/agents/chat/active`;'
        b'const esc="\\/api\\/ask";'
    )

    def _send(self, status: int, body: bytes, ctype: str):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path.endswith("/assets/index.BSLuV95c.js"):
            return self._send(200, self.ENTRY, "application/javascript")
        if path.endswith("/assets/data-provider.AbCd.js"):
            return self._send(200, self.CHUNK, "application/javascript")
        if path in (
            "/api/messages",
            "/api/agents/chat/active",
            "/api/ask",
            "/__scanner_canary_nonexistent_check_xyz789_do_not_create_this_route",
        ):
            if "canary" in path:
                return self._send(200, self.PAGE.encode(), "text/html")
            return self._send(401, b'{"detail":"Unauthorized"}', "application/json")
        return self._send(200, self.PAGE.encode(), "text/html")

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        path = self.path.split("?")[0]
        if path in ("/api/messages", "/api/agents/chat/active", "/api/ask"):
            return self._send(401, b'{"detail":"Unauthorized"}', "application/json")
        return self._send(404, b"not found", "text/plain")

    def log_message(self, *args):
        pass


@pytest.mark.asyncio
async def test_auth_gated_inference_still_confirms():
    """LibreChat regression: 401 on inference paths must still confirm AI."""
    port = _free_port()
    srv = _run_server(LibreChatStyleHandler, port)
    try:
        agent = AIFingerprintAgent(timeout=3, run_behavioral_probes=False)
        result = await agent.fingerprint(f"http://127.0.0.1:{port}", verbose=False)
        assert result["has_live_surface"] is True
        assert result["is_ai_powered"] is True
        assert result["detection"] == "confirmed"
        auth_eps = [a["endpoint"] for a in (result.get("auth_required_paths") or [])]
        all_eps = list(result.get("ml_endpoints") or []) + auth_eps
        assert any(
            any(seg in e for seg in ("/api/chat", "/api/messages", "/v1/chat/completions"))
            for e in all_eps
        )
    finally:
        srv.shutdown()


@pytest.mark.asyncio
async def test_follows_vite_chunk_for_librechat_api_paths():
    """Entry index.js may not contain routes; follow import() chunks."""
    port = _free_port()
    srv = _run_server(LibreChatChunkedBundleHandler, port)
    try:
        agent = AIFingerprintAgent(timeout=3, run_behavioral_probes=False)
        result = await agent.fingerprint(f"http://127.0.0.1:{port}", verbose=False)
        paths = result.get("discovered_paths") or []
        assert "/api/messages" in paths
        assert any("/api/agents/chat" in p for p in paths)
        assert "/api/ask" in paths
        assert result["has_live_surface"] is True
        assert result["is_ai_powered"] is True
    finally:
        srv.shutdown()


class LibreChatCrowdedChunkHandler(LibreChatChunkedBundleHandler):
    """API chunk buried behind mermaid/vendor noise in the import graph."""

    ENTRY = (
        b'import("./assets/mermaid.BIG.js");'
        b'import("./assets/vendor.BIG.js");'
        b'import("./assets/codemirror-core.BIG.js");'
        b'import("./assets/http-client.OK.js");'
        b'import("./assets/data-provider.OK.js");'
    )

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path.endswith("/assets/index.BSLuV95c.js"):
            return self._send(200, self.ENTRY, "application/javascript")
        if path.endswith("/assets/data-provider.OK.js"):
            return self._send(200, self.CHUNK, "application/javascript")
        if path.endswith(".js"):
            # Vendor noise — must not block discovery of data-provider.
            return self._send(200, b'console.log("vendor");', "application/javascript")
        return super().do_GET()


@pytest.mark.asyncio
async def test_skips_vendor_chunks_to_reach_api_routes():
    port = _free_port()
    srv = _run_server(LibreChatCrowdedChunkHandler, port)
    try:
        agent = AIFingerprintAgent(
            timeout=3, run_behavioral_probes=False, max_js_bundles=4,
        )
        result = await agent.fingerprint(f"http://127.0.0.1:{port}", verbose=False)
        paths = result.get("discovered_paths") or []
        assert "/api/messages" in paths
        assert result["has_live_surface"] is True
    finally:
        srv.shutdown()


def test_cross_origin_app_js_allowed_trackers_rejected():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    page = "https://qwen.ai"
    cdn = "https://g.alicdn.com/qwenweb/qwen-ai-fe/0.0.69/js/main.js"
    tracker = "https://www.googletagmanager.com/gtag/js"
    assert agent._looks_js_asset_url(cdn, page, allow_cross_origin=True) is True
    assert agent._looks_js_asset_url(cdn, page, allow_cross_origin=False) is False
    assert agent._looks_js_asset_url(tracker, page, allow_cross_origin=True) is False


def test_extract_api_bases_and_absolute_urls_from_js():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    js = r'''
        const CHAT = "https://chat.qwen.ai";
        fetch("https://chat.qwen.ai/api/agents/chat");
        const skip = "https://g.alicdn.com/qwenweb/x.js";
        const docs = "https://pre-docs.qwenlm.ai/guide";
        const xmlns = "http://www.w3.org/2000/svg";
        const react = "https://reactjs.org/docs/error-decoder.html";
    '''
    bases = agent._extract_api_bases_from_js(js)
    assert "https://chat.qwen.ai" in bases
    assert not any("alicdn.com" in b for b in bases)
    assert not any("docs" in b for b in bases)
    paths = agent._extract_api_paths_from_js(js)
    assert "https://chat.qwen.ai/api/agents/chat" in paths
    assert not any("w3.org" in p for p in paths)
    assert not any("reactjs.org" in p for p in paths)


@pytest.mark.asyncio
async def test_cdn_js_absolute_api_url_is_probed():
    """qwen.ai-style: page loads CDN JS that references an absolute API URL."""
    api_port = _free_port()
    cdn_port = _free_port()
    page_port = _free_port()

    class ApiHandler(BaseHTTPRequestHandler):
        def _send(self, code: int, body: bytes, ctype: str):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            if self.path.startswith("/api/agents/chat"):
                return self._send(401, b'{"detail":"auth"}', "application/json")
            return self._send(404, b"no", "text/plain")

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            return self.do_GET()

        def log_message(self, *args):
            pass

    class CdnHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = (
                f'fetch("http://127.0.0.1:{api_port}/api/agents/chat");'
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    class PageHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            page = (
                "<!DOCTYPE html><html><head><title>Qwen</title>"
                '<meta name="description" content="Qwen Studio chatbot AI models"/>'
                "</head><body>"
                f'<script src="http://127.0.0.1:{cdn_port}/qwenweb/js/main.js"></script>'
                "</body></html>"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)

        def log_message(self, *args):
            pass

    api_srv = _run_server(ApiHandler, api_port)
    cdn_srv = _run_server(CdnHandler, cdn_port)
    page_srv = _run_server(PageHandler, page_port)
    try:
        agent = AIFingerprintAgent(
            timeout=3, run_behavioral_probes=False, max_js_bundles=4,
        )
        result = await agent.fingerprint(
            f"http://127.0.0.1:{page_port}", verbose=False,
        )
        assert result["has_live_surface"] is True
        assert result["is_ai_powered"] is True
        eps = " ".join(result.get("ml_endpoints") or [])
        assert f"127.0.0.1:{api_port}/api/agents/chat" in eps
        allowed = result.get("allowed_api_hosts") or []
        assert f"127.0.0.1:{api_port}" in allowed
    finally:
        api_srv.shutdown()
        cdn_srv.shutdown()
        page_srv.shutdown()


def test_vuln_scope_allows_fingerprint_related_hosts():
    t = AIVulnerabilityTester(enable_embeddings=False, max_requests=5)
    fp = {
        "allowed_api_hosts": ["www.qwencloud.com", "chat.qwen.ai"],
        "ml_endpoints": ["https://www.qwencloud.com/try-ai/chat"],
    }
    hosts = t._build_scope_hosts("https://qwen.ai", fp)
    assert "qwen.ai" in hosts
    assert "www.qwencloud.com" in hosts
    assert "chat.qwen.ai" in hosts
    t._scope_hosts = hosts
    t._scope_host = "qwen.ai"
    assert t._in_scope("https://www.qwencloud.com/try-ai/chat") is True
    assert t._in_scope("https://evil.example/api/chat") is False
    # Foreign ml_endpoints without allowlist must not expand scope.
    hosts2 = t._build_scope_hosts(
        "https://qwen.ai",
        {"ml_endpoints": ["https://evil.example/api/chat"]},
    )
    assert "evil.example" not in hosts2


@pytest.mark.asyncio
async def test_infra_probes_allowlisted_cross_origin_url():
    """Infra must hit the related host URL, not rewrite onto the page origin."""
    api_port = _free_port()
    page_port = _free_port()
    hit = {"urls": []}

    class ApiHandler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            hit["urls"].append(self.path)
            body = b'{"detail":"auth"}'
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            return self.do_POST()

        def log_message(self, *args):
            pass

    class PageHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = b"<html><title>Qwen</title></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    api_srv = _run_server(ApiHandler, api_port)
    page_srv = _run_server(PageHandler, page_port)
    try:
        cross = f"http://127.0.0.1:{api_port}/try-ai/chat"
        fp = {
            "ml_endpoints": [cross],
            "allowed_api_hosts": [f"127.0.0.1:{api_port}"],
            "auth_required_paths": [],
            "spa_catch_all": False,
            "capabilities": [],
            "evidence": [],
        }
        agent = AIInfraAgent(timeout=3)
        result = await agent.scan(f"http://127.0.0.1:{page_port}", ai_stack=fp)
        assert "/try-ai/chat" in hit["urls"]
        assert any(cross in e for e in (result.auth_protected_endpoints or []))
        # Must not invent the path on the page origin as exposed.
        assert not any(
            f"127.0.0.1:{page_port}/try-ai/chat" in e
            for e in (result.exposed_endpoints or [])
        )
    finally:
        api_srv.shutdown()
        page_srv.shutdown()


def test_normalize_ignores_non_inference_endpoints():
    t = AIVulnerabilityTester(enable_embeddings=False, max_requests=5)
    fp = t._normalize_ai_fingerprint({
        "is_ai_powered": True,
        "ml_endpoints": ["http://x/admin", "http://x/features/"],
        "auth_required_paths": [
            {"endpoint": "http://x/admin", "auth_type": "unknown",
             "status_code": 401, "detail": "auth"},
        ],
        "evidence_classes": {"passive_hint": ["robots_ai_path"], "brand": ["page_title_ai"]},
    })
    assert fp["has_live_surface"] is False
    assert fp["is_ai_powered"] is False


@pytest.mark.asyncio
async def test_robots_junk_path_not_hint_evidence():
    """Disallow: /404 must not become robots_ai_path; /api/chat may."""
    from multiagent.agents.ai_agents.ai_fingerprint import _is_inference_path

    agent = AIFingerprintAgent(run_behavioral_probes=False)
    body = (
        "User-agent: *\n"
        "Disallow: /404\n"
        "Disallow: /features/\n"
        "Disallow: /api/chat\n"
    )
    agent._fetch = lambda url, **kw: (
        200, {}, body if str(url).endswith("robots.txt") else ""
    )
    result = await agent._fetch_robots_sitemap("http://x", False)
    keys = [e.key for e in result["evidence"]]
    assert keys == ["robots_ai_path"]
    assert any("/api/chat" in e.detail for e in result["evidence"])
    assert not any("/404" in e.detail for e in result["evidence"])
    assert not any("/features" in e.detail for e in result["evidence"])
    assert "/404" in result["paths"]
    assert "/features/" in result["paths"] or "/features" in result["paths"]
    assert "/api/chat" in result["paths"]
    assert _is_inference_path("/api/chat")


def test_js_path_evidence_requires_inference_shape():
    from multiagent.agents.ai_agents.ai_fingerprint import _is_inference_path

    agent = AIFingerprintAgent(run_behavioral_probes=False)
    paths = agent._extract_api_paths_from_js(
        'fetch("/pricing"); fetch("/features/"); fetch("/about");'
    )
    assert paths
    assert not any(_is_inference_path(p) for p in paths)

    mixed = agent._extract_api_paths_from_js(
        'fetch("/pricing"); fetch("/api/chat"); fetch("/v1/chat/completions");'
    )
    assert any(_is_inference_path(p) for p in mixed)
    assert "/api/chat" in mixed


def test_inference_path_segment_not_substring():
    """Shape gate: segment match only — no endpoint catalog, no substring FPs."""
    from multiagent.agents.ai_agents.ai_fingerprint import (
        _is_inference_path,
        _looks_non_api_document,
    )

    # App-discovered inference handlers (must keep working).
    assert _is_inference_path("/api/chat")
    assert _is_inference_path("/api/messages")
    assert _is_inference_path("/v1/chat/completions")
    assert _is_inference_path("/api/v1/run")
    assert _is_inference_path("/api/v1/prediction")
    assert _is_inference_path("/ollama/api/generate")

    # Marketing / SEO substrings must not count (Picsart-style).
    assert not _is_inference_path("/llms.txt")
    assert not _is_inference_path("/compare-models/kling-vs-runway/")
    assert not _is_inference_path("/compare-models/runway-gen-4-vs-veo-3/")
    assert not _is_inference_path("/ai-models/runway-gen-4/")
    assert not _is_inference_path("/fonts/grunge/")
    assert not _is_inference_path("/features/")
    assert not _is_inference_path("/create/")

    assert _looks_non_api_document("/llms.txt")
    assert _looks_non_api_document("/sitemap.xml")
    assert not _looks_non_api_document("/api/chat")


def test_chunked_transfer_alone_does_not_confirm():
    """Bare Transfer-Encoding: chunked must not create live-surface / confirm."""
    from multiagent.agents.ai_agents.ai_evidence_scoring import (
        Detection,
        classify_evidence,
        EvidenceClass,
        score_evidence,
    )

    assert classify_evidence("sse_chunked_transfer") == EvidenceClass.PASSIVE_HINT
    result = score_evidence([
        "sse_chunked_transfer",
        "robots_ai_path",
        "page_title_ai",
    ])
    assert result.detection != Detection.CONFIRMED
    assert result.has_live_surface is False
    assert result.is_ai is False

    agent = AIFingerprintAgent(run_behavioral_probes=False)
    r = agent._evaluate_probe_response(
        "http://x/llms.txt", "/llms.txt", "schema",
        200,
        {"Content-Type": "text/plain", "Transfer-Encoding": "chunked"},
        "User-Agent rules for LLMs",
        [],
    )
    keys = [e.key for e in r.get("evidence", [])]
    assert "sse_chunked_transfer" not in keys
    assert r.get("endpoints", []) == []


@pytest.mark.asyncio
async def test_picsart_style_marketing_not_confirmed():
    """Chunked /llms.txt + runway sitemap noise must not confirm AI."""
    port = _free_port()

    class PicsartStyleHandler(BaseHTTPRequestHandler):
        PAGE = (
            "<!DOCTYPE html><html><head>"
            "<title>Picsart: The AI Creative Platform</title>"
            "<meta name='description' content='generative AI tools'>"
            "</head><body><div aria-label='AI Image menu'>x</div></body></html>"
        )

        def _send(self, status, body, ctype):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Transfer-Encoding", "chunked")
            # Avoid real chunk framing complexity — body as Content-Length instead
            # when not using chunk encoder; header alone is what we used to mis-key on.
            data = body if isinstance(body, bytes) else body.encode()
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802
            path = self.path.split("?")[0]
            if path == "/robots.txt":
                body = (
                    "User-agent: *\n"
                    "Disallow: /llms.txt\n"
                    "Sitemap: http://127.0.0.1:%d/sitemap.xml\n" % self.server.server_address[1]
                )
                return self._send(200, body, "text/plain")
            if path == "/sitemap.xml":
                p = self.server.server_address[1]
                body = (
                    '<?xml version="1.0"?><urlset>'
                    f"<url><loc>http://127.0.0.1:{p}/compare-models/kling-vs-runway/</loc></url>"
                    f"<url><loc>http://127.0.0.1:{p}/fonts/grunge/</loc></url>"
                    f"<url><loc>http://127.0.0.1:{p}/llms.txt</loc></url>"
                    "</urlset>"
                )
                return self._send(200, body, "application/xml")
            if path == "/llms.txt":
                return self._send(200, "# LLMs\n", "text/plain")
            if path in ("/", "/index.html"):
                return self._send(200, self.PAGE, "text/html")
            return self._send(404, "no", "text/plain")

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            return self._send(404, "no", "text/plain")

        def log_message(self, *args):
            pass

    srv = _run_server(PicsartStyleHandler, port)
    try:
        agent = AIFingerprintAgent(timeout=3, run_behavioral_probes=False)
        result = await agent.fingerprint(f"http://127.0.0.1:{port}", verbose=False)
        assert result["has_live_surface"] is False
        assert result["is_ai_powered"] is False
        assert result["detection"] != "confirmed"
        assert result["ml_endpoints"] == []
        keys = {e.get("key") for e in (result.get("evidence_items") or [])
                if isinstance(e, dict)}
        assert "sse_chunked_transfer" not in keys
        assert "robots_ai_path" not in keys  # /llms.txt not inference-shaped
    finally:
        srv.shutdown()
