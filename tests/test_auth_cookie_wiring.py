"""Prove auth credentials are sent on the wire across scan HTTP helpers."""
import asyncio
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from multiagent.agents.auth_support import (
    playwright_cookies_from_header,
    request_auth_headers,
)
from multiagent.agents.ai_agents.ai_fingerprint import AIFingerprintAgent
from multiagent.agents.ai_agents.ai_vulnerability_test import AIVulnerabilityTester
from multiagent.agents.webappscanner.vulnerability_tester import (
    SignalCollector,
    VulnerabilityTester,
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


class CookieEchoHandler(BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):  # noqa: N802
        CookieEchoHandler.seen.append({
            "path": self.path,
            "cookie": self.headers.get("Cookie", ""),
            "authorization": self.headers.get("Authorization", ""),
            "method": "GET",
        })
        body = b'{"object":"list","data":[{"id":"gpt-test"}]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        CookieEchoHandler.seen.append({
            "path": self.path,
            "cookie": self.headers.get("Cookie", ""),
            "authorization": self.headers.get("Authorization", ""),
            "method": "POST",
        })
        body = b'{"choices":[{"message":{"content":"ok"}}]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def echo_server():
    CookieEchoHandler.seen = []
    port = _free_port()
    srv = _run_server(CookieEchoHandler, port)
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def test_request_auth_headers_cookie_and_bearer():
    assert request_auth_headers("session=abc") == {"Cookie": "session=abc"}
    assert request_auth_headers("Bearer tok123") == {"Authorization": "Bearer tok123"}
    assert request_auth_headers("") == {}


def test_playwright_cookie_parser():
    cookies = playwright_cookies_from_header(
        "session=abc; Path=/; token=xyz", "http://localhost:3080/app"
    )
    names = {c["name"]: c["value"] for c in cookies}
    assert names["session"] == "abc"
    assert names["token"] == "xyz"
    assert "Path" not in names
    assert playwright_cookies_from_header("Bearer x", "http://localhost:3080") == []


def test_ai_fingerprint_sends_cookie(echo_server):
    CookieEchoHandler.seen = []
    agent = AIFingerprintAgent(timeout=3, run_behavioral_probes=False)
    agent.auth_cookie = "session=fp-cookie"
    status, _, _ = agent._fetch(echo_server + "/api/chat")
    assert status == 200
    assert any(h["cookie"] == "session=fp-cookie" for h in CookieEchoHandler.seen)


def test_ai_vuln_http_post_sends_cookie(echo_server):
    CookieEchoHandler.seen = []
    t = AIVulnerabilityTester(timeout=3, enable_embeddings=False, max_requests=5)
    t.auth_cookie = "session=vuln-cookie"
    status, _, _ = t._http_post(echo_server + "/api/chat", {"messages": []})
    assert status == 200
    assert any(
        h["method"] == "POST" and h["cookie"] == "session=vuln-cookie"
        for h in CookieEchoHandler.seen
    )


def test_ai_vuln_http_post_sends_bearer(echo_server):
    CookieEchoHandler.seen = []
    t = AIVulnerabilityTester(timeout=3, enable_embeddings=False, max_requests=5)
    t.auth_cookie = "Bearer tok-xyz"
    status, _, _ = t._http_post(echo_server + "/v1/chat/completions", {"messages": []})
    assert status == 200
    assert any(h["authorization"] == "Bearer tok-xyz" for h in CookieEchoHandler.seen)


def test_web_vuln_and_signal_collector_send_cookie(echo_server):
    CookieEchoHandler.seen = []
    vt = VulnerabilityTester(timeout=3, auth_cookie="session=web-cookie")
    status, _, _ = vt._fetch_full(echo_server + "/.env")
    assert status == 200
    sc = SignalCollector(timeout=3, auth_cookie="session=sig-cookie")
    sc._fetch(echo_server + "/robots.txt")
    cookies = {h["cookie"] for h in CookieEchoHandler.seen}
    assert "session=web-cookie" in cookies
    assert "session=sig-cookie" in cookies


@pytest.mark.asyncio
async def test_auth_gated_endpoints_tested_when_cookie_present():
    t = AIVulnerabilityTester(timeout=3, enable_embeddings=False, max_requests=5)
    t.auth_cookie = "session=abc"
    # Build a fake fingerprint with only auth-gated chat endpoint.
    fp = {
        "is_ai_powered": True,
        "has_live_surface": True,
        "ml_endpoints": [],
        "auth_required_paths": [
            {"endpoint": "http://127.0.0.1:9/api/chat",
             "auth_type": "unknown", "status_code": 401, "detail": "auth"},
        ],
        "evidence_classes": {"live_surface": ["ml_endpoint_401_403"]},
    }
    # _run will try to POST (connection fails) but must NOT only emit auth-gated Potential.
    confirmed, potential, _ = await t._run(fp, "http://127.0.0.1:9", False, verbose=False)
    auth_gated_only = [
        p for p in potential
        if p.get("evidence", {}).get("outcome") == "auth_required"
    ]
    assert auth_gated_only == []
