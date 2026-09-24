"""Behavioral (table-free) AI confirmation.

Detection must be driven by how an endpoint *behaves* — following a natural-
language instruction, being input-dependent — not by matching response shape
or model-name tables. These tests drive the shape-adaptive behavioral probe
against a fake backend by monkeypatching the agent's blocking _fetch.
"""
import asyncio
import json
import pytest

from multiagent.agents.ai_agents.ai_fingerprint import AIFingerprintAgent


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _make_agent(handler):
    """handler(url, method, data_dict) -> (status, headers, body_str)."""
    agent = AIFingerprintAgent()

    def fake_fetch(url, max_bytes=8192, method="GET", data=None):
        parsed = {}
        if data:
            try:
                parsed = json.loads(data.decode())
            except Exception:
                parsed = {}
        return handler(url, method, parsed)

    agent._fetch = fake_fetch
    return agent


def _user_content(payload: dict) -> str:
    msgs = payload.get("messages")
    if isinstance(msgs, list) and msgs:
        return msgs[-1].get("content", "")
    for k in ("prompt", "input", "query", "question", "text", "message"):
        if isinstance(payload.get(k), str):
            return payload[k]
    return ""


class TestInstructionFollowing:
    def test_instruction_follower_is_confirmed(self):
        """A backend that returns just the requested canary is confirmed AI."""
        def handler(url, method, data):
            content = _user_content(data)
            if "Repeat the following token" in content:
                token = content.rsplit(":", 1)[-1].strip()
                return 200, {"Content-Type": "application/json"}, json.dumps(
                    {"choices": [{"message": {"content": token}}]})
            return 200, {"Content-Type": "application/json"}, json.dumps(
                {"choices": [{"message": {"content": "Hello, how can I help?"}}]})

        agent = _make_agent(handler)
        res = _run(agent._behavioral_probes(["http://x/api/chat"], verbose=False))
        keys = {e.key for e in res["evidence"]}
        assert "behavior_instruction_followed" in keys

    def test_echo_endpoint_is_not_confirmed(self):
        """An endpoint that echoes the whole request also returns the canary,
        but it carries the instruction wrapper too, so it is NOT confirmed."""
        def handler(url, method, data):
            content = _user_content(data)
            # Echo the user content verbatim (canary included, but so is the
            # instruction phrase).
            return 200, {"Content-Type": "application/json"}, json.dumps(
                {"choices": [{"message": {"content": content}}]})

        agent = _make_agent(handler)
        res = _run(agent._behavioral_probes(["http://x/api/echo"], verbose=False))
        keys = {e.key for e in res["evidence"]}
        assert "behavior_instruction_followed" not in keys


class TestModelReportEchoGuard:
    def test_model_name_echoed_from_request_is_not_a_selfreport(self):
        """The probe never sends a model name; an echo backend therefore has
        no model string to reflect, so no self-report is recorded."""
        def handler(url, method, data):
            # Pure echo: reflect exactly what we received.
            return 200, {"Content-Type": "application/json"}, json.dumps(
                {"choices": [{"message": {"content": _user_content(data)}}]})

        agent = _make_agent(handler)
        res = _run(agent._behavioral_probes(["http://x/api/chat"], verbose=False))
        assert res.get("model_reported", "") == ""
        keys = {e.key for e in res["evidence"]}
        assert "behavior_model_reported" not in keys

    def test_genuine_model_selfreport_is_recorded(self):
        def handler(url, method, data):
            content = _user_content(data)
            if "What model or system are you" in content:
                return 200, {"Content-Type": "application/json"}, json.dumps(
                    {"choices": [{"message": {"content": "I am GPT-4, an AI model."}}]})
            return 200, {"Content-Type": "application/json"}, json.dumps(
                {"choices": [{"message": {"content": "Hi!"}}]})

        agent = _make_agent(handler)
        res = _run(agent._behavioral_probes(["http://x/api/chat"], verbose=False))
        assert res.get("model_reported", "")
