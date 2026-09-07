"""
Tests for the XSS reflection-context analyzer and the corrected reflected-XSS
verdict: reflection alone is never "Confirmed" without execution proof.
"""
import asyncio
import socket
import threading
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

import pytest

from multiagent.agents.webappscanner.xss_analysis import classify_reflection
from multiagent.agents.webappscanner.attack_verification_agent import (
    AttackVerificationAgent, VulnStatus,
)


class TestClassifyReflection:
    def test_executable_raw(self):
        payload = "<script>alert(1)</script>"
        assert classify_reflection(f"<div>{payload}</div>", payload) == "executable"

    def test_encoded_is_not_executable(self):
        payload = "<script>alert(1)</script>"
        body = "<div>&lt;script&gt;alert(1)&lt;/script&gt;</div>"
        assert classify_reflection(body, payload) == "encoded"

    def test_absent(self):
        assert classify_reflection("nothing here", "<script>alert(1)</script>") == "absent"

    def test_inert_textarea_context(self):
        payload = "<script>alert(1)</script>"
        body = f"<textarea>{payload}"
        assert classify_reflection(body, payload) != "executable"


class _RawReflectHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        val = q.get("q", [""])[0]
        body = f"<html><body>Search: {val}</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _EncodeHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        import html
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        val = html.escape(q.get("q", [""])[0])
        body = f"<html><body>Search: {val}</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve(handler):
    with socket.socket() as s:
        s.bind(("", 0))
        port = s.getsockname()[1]
    srv = HTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}"


@pytest.fixture(scope="module")
def raw_url():
    return _serve(_RawReflectHandler)


@pytest.fixture(scope="module")
def encoded_url():
    return _serve(_EncodeHandler)


class TestReflectedXssVerdict:
    def test_raw_reflection_is_potential_not_confirmed(self, raw_url):
        agent = AttackVerificationAgent(openai_client=None, llm_model="none")
        url = f"{raw_url}/?q=hello"
        parsed = urllib.parse.urlparse(url)
        finding = asyncio.run(agent._test_reflected_xss(url, "q", parsed))
        assert finding is not None
        assert finding.status == VulnStatus.POTENTIAL
        assert finding.status != VulnStatus.CONFIRMED
        assert finding.evidence.execution_confirmed is False

    def test_encoded_reflection_is_not_reported(self, encoded_url):
        agent = AttackVerificationAgent(openai_client=None, llm_model="none")
        url = f"{encoded_url}/?q=hello"
        parsed = urllib.parse.urlparse(url)
        finding = asyncio.run(agent._test_reflected_xss(url, "q", parsed))
        assert finding is None
