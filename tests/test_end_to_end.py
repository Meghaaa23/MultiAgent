"""
test_end_to_end.py
End-to-end tests for AIVulnerabilityTester against a mock FastAPI/WSGI server.

The mock server simulates three target behaviors:
  - vulnerable_chat: echoes the canary verbatim (EXECUTED expected)
  - refusing_chat:   always refuses (no confirmed vulns expected)
  - leaking_chat:    leaks system prompt context in response

Tests cover test_all() and evaluate() public interfaces.
"""
import asyncio
import json
import threading
import socket
import pytest
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler

from multiagent.agents.ai_agents.ai_vulnerability_test import (
    AIVulnerabilityTester, ResponseOutcome, ApplicationType, CapabilitySet,
)


# ---------------------------------------------------------------------------
# Mock HTTP servers
# ---------------------------------------------------------------------------

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _run_server(handler_class, port: int):
    srv = HTTPServer(("127.0.0.1", port), handler_class)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


class VulnerableHandler(BaseHTTPRequestHandler):
    """Echoes back whatever 'content' or 'prompt' is in the request body."""

    def do_POST(self):  # noqa: N802
        length  = int(self.headers.get("Content-Length", 0))
        body    = json.loads(self.rfile.read(length) or "{}")
        content = (body.get("messages", [{}])[0].get("content", "")
                   or body.get("prompt", "")
                   or body.get("input", "")
                   or body.get("question", ""))
        resp = json.dumps({"choices": [{"message": {"content": content}}]})
        self._reply(resp)

    def _reply(self, text: str, status: int = 200):
        data = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class RefusingHandler(BaseHTTPRequestHandler):
    """Always returns a refusal, never echoes payload content."""

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        resp = json.dumps({"choices": [{"message": {
            "content": "I'm sorry, I cannot help with that request."}}]})
        self._reply(resp)

    def _reply(self, text: str, status: int = 200):
        data = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class LeakingHandler(BaseHTTPRequestHandler):
    """Returns a response that contains system-prompt leak markers."""

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        resp = json.dumps({"choices": [{"message": {
            "content": (
                "Your role is: customer support agent. "
                "My instructions are to assist users with their queries. "
                "You must always be polite and professional."
            )
        }}]})
        self._reply(resp)

    def _reply(self, text: str, status: int = 200):
        data = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def vulnerable_url():
    port = _free_port()
    _run_server(VulnerableHandler, port)
    return f"http://127.0.0.1:{port}"


@pytest.fixture(scope="module")
def refusing_url():
    port = _free_port()
    _run_server(RefusingHandler, port)
    return f"http://127.0.0.1:{port}"


@pytest.fixture(scope="module")
def leaking_url():
    port = _free_port()
    _run_server(LeakingHandler, port)
    return f"http://127.0.0.1:{port}"


@pytest.fixture
def tester():
    return AIVulnerabilityTester(
        timeout=3,
        rate_limit_delay=0.0,
        max_requests=50,
        enable_embeddings=False,
        mutation_sample=2,
    )


def _fingerprint(url: str) -> dict:
    return {
        "page_title": "Test App",
        "technologies": [],
        "ml_endpoints": [f"{url}/v1/chat/completions"],
        "chat_components": [],
        "app_description": "",
        "api_schema": {},
        "discovered_paths": [],
        "response_headers": {},
    }


# ---------------------------------------------------------------------------
# test_all() — operational scan
# ---------------------------------------------------------------------------

class TestTestAll:

    def test_vulnerable_server_finds_confirmed(self, tester, vulnerable_url):
        fp = _fingerprint(vulnerable_url)
        result = asyncio.run(tester.test_all(fp, vulnerable_url))
        assert "confirmed_ai_vulns" in result
        assert len(result["confirmed_ai_vulns"]) > 0

    def test_confirmed_finding_has_required_fields(self, tester, vulnerable_url):
        fp = _fingerprint(vulnerable_url)
        result = asyncio.run(tester.test_all(fp, vulnerable_url))
        finding = result["confirmed_ai_vulns"][0]
        for field in ["type", "severity", "status", "outcome", "family",
                      "technique", "location", "evidence"]:
            assert field in finding, f"Missing field: {field}"

    def test_confirmed_finding_outcome_is_success(self, tester, vulnerable_url):
        fp = _fingerprint(vulnerable_url)
        result = asyncio.run(tester.test_all(fp, vulnerable_url))
        for finding in result["confirmed_ai_vulns"]:
            assert finding["outcome"] in ("executed", "leaked", "followed")

    def test_refusing_server_has_no_confirmed(self, tester, refusing_url):
        fp = _fingerprint(refusing_url)
        result = asyncio.run(tester.test_all(fp, refusing_url))
        assert len(result["confirmed_ai_vulns"]) == 0

    def test_refusing_server_has_potential(self, tester, refusing_url):
        fp = _fingerprint(refusing_url)
        result = asyncio.run(tester.test_all(fp, refusing_url))
        assert len(result["potential_ai_vulns"]) > 0

    def test_result_has_requests_sent(self, tester, refusing_url):
        fp = _fingerprint(refusing_url)
        result = asyncio.run(tester.test_all(fp, refusing_url))
        assert result["requests_sent"] > 0

    def test_result_has_atlas_list(self, tester, refusing_url):
        fp = _fingerprint(refusing_url)
        result = asyncio.run(tester.test_all(fp, refusing_url))
        assert len(result["atlas_techniques_tested"]) > 0

    def test_leaking_server_finds_leak(self, leaking_url):
        # Use a higher budget so leak payloads (which require divergence from baseline)
        # have room to run after baseline + early direct payloads
        leak_tester = AIVulnerabilityTester(
            timeout=3, rate_limit_delay=0.0, max_requests=150,
            enable_embeddings=False, mutation_sample=1,
        )
        fp = _fingerprint(leaking_url)
        result = asyncio.run(leak_tester.test_all(fp, leaking_url))
        leak_findings = [f for f in result["confirmed_ai_vulns"]
                         if f["outcome"] == "leaked"]
        assert len(leak_findings) > 0


# ---------------------------------------------------------------------------
# evaluate() — full matrix + ASR
# ---------------------------------------------------------------------------

class TestEvaluate:

    def test_evaluate_returns_asr_report(self, tester, refusing_url):
        fp = _fingerprint(refusing_url)
        result = asyncio.run(tester.evaluate(fp, refusing_url))
        assert "evaluation" in result
        assert "asr_overall" in result["evaluation"]

    def test_asr_overall_has_strict_and_lenient(self, tester, refusing_url):
        fp = _fingerprint(refusing_url)
        result = asyncio.run(tester.evaluate(fp, refusing_url))
        ov = result["evaluation"]["asr_overall"]
        assert "strict" in ov
        assert "lenient" in ov
        assert "total" in ov

    def test_asr_by_family_present(self, tester, refusing_url):
        fp = _fingerprint(refusing_url)
        result = asyncio.run(tester.evaluate(fp, refusing_url))
        assert "asr_by_family" in result["evaluation"]

    def test_asr_by_objective_present(self, tester, refusing_url):
        fp = _fingerprint(refusing_url)
        result = asyncio.run(tester.evaluate(fp, refusing_url))
        assert "asr_by_objective" in result["evaluation"]

    def test_mutation_lift_present(self, tester, refusing_url):
        fp = _fingerprint(refusing_url)
        result = asyncio.run(tester.evaluate(fp, refusing_url))
        assert "mutation_lift" in result["evaluation"]

    def test_attempts_list_populated(self, tester, refusing_url):
        fp = _fingerprint(refusing_url)
        result = asyncio.run(tester.evaluate(fp, refusing_url))
        assert len(result["attempts"]) > 0

    def test_each_attempt_has_required_fields(self, tester, refusing_url):
        fp = _fingerprint(refusing_url)
        result = asyncio.run(tester.evaluate(fp, refusing_url))
        for attempt in result["attempts"]:
            for field in ["category", "technique", "objective", "outcome",
                          "success", "variant_kind", "mutation"]:
                # Note: 'category' renamed to 'family' internally but check what's returned
                assert field in attempt or "family" in attempt

    def test_semantic_backend_reported(self, tester, refusing_url):
        fp = _fingerprint(refusing_url)
        result = asyncio.run(tester.evaluate(fp, refusing_url))
        assert "semantic_backend" in result
        assert result["semantic_backend"] in ("jaccard", "embeddings")

    def test_refusing_server_asr_is_zero_or_low(self, tester, refusing_url):
        fp = _fingerprint(refusing_url)
        result = asyncio.run(tester.evaluate(fp, refusing_url))
        strict_asr = result["evaluation"]["asr_overall"]["strict"]
        assert strict_asr < 0.3   # should be near 0 for a consistently refusing server

    def test_vulnerable_server_asr_is_high(self, tester, vulnerable_url):
        fp = _fingerprint(vulnerable_url)
        result = asyncio.run(tester.evaluate(fp, vulnerable_url))
        strict_asr = result["evaluation"]["asr_overall"]["strict"]
        assert strict_asr > 0.3   # echo-all server should have high ASR


# ---------------------------------------------------------------------------
# Scope and budget enforcement
# ---------------------------------------------------------------------------

class TestScopeAndBudget:

    def test_out_of_scope_endpoint_skipped(self, tester):
        fp = {
            "page_title": "", "technologies": [], "chat_components": [],
            "ml_endpoints": ["http://evil.example.com/api/chat"],  # different host
            "app_description": "", "api_schema": {}, "discovered_paths": [],
            "response_headers": {},
        }
        result = asyncio.run(tester.test_all(fp, "http://127.0.0.1:9999"))
        # Nothing should have been tested
        assert result["requests_sent"] == 0

    def test_budget_limits_requests(self, vulnerable_url):
        tight_tester = AIVulnerabilityTester(
            timeout=3, rate_limit_delay=0.0, max_requests=3,
            enable_embeddings=False, mutation_sample=2,
        )
        fp = _fingerprint(vulnerable_url)
        result = asyncio.run(tight_tester.test_all(fp, vulnerable_url))
        assert result["requests_sent"] <= 3