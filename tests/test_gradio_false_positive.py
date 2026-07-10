"""
Zapier-like marketing SPA must not be labeled Gradio with a CVE flood.
"""
from multiagent.agents.ai_agents.ai_fingerprint import (
    AIFingerprintAgent,
    _looks_like_gradio_config,
)
from multiagent.agents.webappscanner.action_agent import ActionAgent
from multiagent.agents.webappscanner.vulnerability_tester import _server_header_is_leaky


def test_generic_components_json_is_not_gradio():
    assert not _looks_like_gradio_config(
        '{"components":[],"dependencies":[],"models":[]}', "/config"
    )
    assert not _looks_like_gradio_config(
        '{"version":"1.0","components":[],"gradio":false}', "/config"
    )
    assert _looks_like_gradio_config(
        '{"version":"4.0","api_prefix":"/gradio_api","root":"/","dev_mode":false,'
        '"components":[],"dependencies":[]}',
        "/config",
    )
    assert _looks_like_gradio_config('{"gradio_api":{}}', "/info")
    assert _looks_like_gradio_config('{"ok":true}', "/gradio_api/info")


def test_identify_framework_ignores_config_in_html():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    # HTML that mentions /config everywhere must NOT become Gradio.
    result = agent._identify_framework(
        html='<html><script>fetch("/config"); const x="/info";</script></html>',
        js="",
        headers={"server": "Vercel"},
        known_endpoints=[],
        existing_evidence=[],
    )
    assert result.get("framework") != "Gradio"


def test_identify_framework_gradio_from_verified_endpoint():
    agent = AIFingerprintAgent(run_behavioral_probes=False)
    result = agent._identify_framework(
        html="<html><title>My App</title></html>",
        js="window.__gradio_mode__ = 'app';",
        headers={},
        known_endpoints=["http://x/gradio_api/info"],
        existing_evidence=[],
    )
    assert result.get("framework") == "Gradio"


def test_vercel_server_not_leaky():
    assert not _server_header_is_leaky("Vercel")
    assert not _server_header_is_leaky("cloudflare")
    assert _server_header_is_leaky("uvicorn")


def test_open_redirect_poc_uses_location_header():
    action = ActionAgent()._action_open_redirect(
        "https://zapier.com/google-sso/start",
        "next",
        evidence={
            "request": "GET https://zapier.com/google-sso/start?next=https://evil.com",
            "response_status": 301,
            "response_headers": {"Location": "https://evil.com"},
        },
    )
    assert action["evidence_captured"] is True
    assert "https://evil.com" in action["attack_poc"]
    assert "NO EVIDENCE CAPTURED" not in action["attack_poc"]
