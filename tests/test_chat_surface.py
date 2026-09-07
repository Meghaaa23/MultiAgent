"""
test_chat_surface.py — chat-surface discovery + three-way ownership classification.
"""
import pytest

from multiagent.agents.ai_agents.chat_surface import (
    classify_chat_surfaces, extract_script_and_iframe_srcs, summarize_ownership,
    OWNERSHIP_APPLICATION_OWNED, OWNERSHIP_THIRD_PARTY_WIDGET, OWNERSHIP_HUMAN_OPERATED,
)
from multiagent.agents.ai_agents.ai_fingerprint import should_run_ai_tests


def _owners(components):
    return {c["ownership"] for c in components}


# ---------------------------------------------------------------------------
# Third-party human-operated support widgets
# ---------------------------------------------------------------------------

class TestHumanOperatedVendors:

    def test_intercom_script_is_human_operated(self):
        html = '<html><body><script src="https://widget.intercom.io/widget/abc123"></script></body></html>'
        comps = classify_chat_surfaces(html, "shop.example.com")
        assert any(c["vendor"] == "Intercom" and c["ownership"] == OWNERSHIP_HUMAN_OPERATED
                   for c in comps)

    def test_zendesk_inline_marker_is_human_operated(self):
        html = '<html><head><script>window.zESettings={};zE("messenger","open");</script></head></html>'
        comps = classify_chat_surfaces(html, "help.example.com")
        assert any(c["vendor"] == "Zendesk" and c["ownership"] == OWNERSHIP_HUMAN_OPERATED
                   for c in comps)

    def test_tawk_is_human_operated(self):
        html = '<script src="https://embed.tawk.to/abc/default"></script>'
        comps = classify_chat_surfaces(html, "example.com")
        assert any(c["ownership"] == OWNERSHIP_HUMAN_OPERATED for c in comps)


# ---------------------------------------------------------------------------
# Third-party AI widgets
# ---------------------------------------------------------------------------

class TestThirdPartyAIWidgets:

    def test_botpress_is_third_party_widget(self):
        html = '<script src="https://cdn.botpress.cloud/webchat/v1/inject.js"></script>'
        comps = classify_chat_surfaces(html, "store.example.com")
        assert any(c["vendor"] == "Botpress" and c["ownership"] == OWNERSHIP_THIRD_PARTY_WIDGET
                   for c in comps)

    def test_chatbase_is_third_party_widget(self):
        html = '<script>window.chatbase=window.chatbase||function(){};</script>'
        comps = classify_chat_surfaces(html, "store.example.com")
        assert any(c["ownership"] == OWNERSHIP_THIRD_PARTY_WIDGET for c in comps)


# ---------------------------------------------------------------------------
# Human-operator textual signals (vendor-agnostic)
# ---------------------------------------------------------------------------

class TestHumanOperatorText:

    def test_agent_reply_phrase_is_human_operated(self):
        html = '<div class="chat">Leave a message and we will get back to you. Average response time: 3 minutes.</div>'
        comps = classify_chat_surfaces(html, "example.com")
        assert any(c["ownership"] == OWNERSHIP_HUMAN_OPERATED and c["vendor"] == "unknown"
                   for c in comps)

    def test_no_text_signal_no_human_component(self):
        html = "<div>Welcome to our marketing site</div>"
        comps = classify_chat_surfaces(html, "example.com")
        assert OWNERSHIP_HUMAN_OPERATED not in _owners(comps)


# ---------------------------------------------------------------------------
# Application-owned AI chatbots
# ---------------------------------------------------------------------------

class TestApplicationOwned:

    def test_same_origin_framework_and_endpoint_is_app_owned(self):
        html = '<div class="chat-window"><div data-message-role="assistant">Hi</div></div>'
        comps = classify_chat_surfaces(
            html, "ai.example.com",
            app_framework="LibreChat",
            ml_endpoints=["https://ai.example.com/api/chat"],
        )
        app = [c for c in comps if c["ownership"] == OWNERSHIP_APPLICATION_OWNED]
        assert app and app[0]["confidence"] == "high"

    def test_ai_dom_plus_same_origin_endpoint_is_app_owned(self):
        html = '<div data-role="assistant">answer</div>'
        comps = classify_chat_surfaces(
            html, "ai.example.com",
            ml_endpoints=["https://ai.example.com/v1/chat/completions"],
        )
        assert OWNERSHIP_APPLICATION_OWNED in _owners(comps)

    def test_third_party_chat_endpoint_not_app_owned(self):
        # A chat endpoint on a *different* origin must not be counted as app-owned.
        html = '<div data-role="assistant">answer</div>'
        comps = classify_chat_surfaces(
            html, "ai.example.com",
            ml_endpoints=["https://other-vendor.com/v1/chat/completions"],
        )
        assert OWNERSHIP_APPLICATION_OWNED not in _owners(comps)

    def test_marketing_page_has_no_components(self):
        html = "<html><body><h1>Buy our product</h1></body></html>"
        comps = classify_chat_surfaces(html, "example.com")
        assert comps == []


# ---------------------------------------------------------------------------
# Mixed page + helpers
# ---------------------------------------------------------------------------

class TestMixedAndHelpers:

    def test_app_owned_and_human_widget_coexist(self):
        html = (
            '<div class="chat-window"><div data-message-role="assistant">Hi</div></div>'
            '<script src="https://widget.intercom.io/widget/x"></script>'
        )
        comps = classify_chat_surfaces(
            html, "ai.example.com",
            app_framework="Open WebUI",
            ml_endpoints=["https://ai.example.com/api/chat"],
        )
        owners = _owners(comps)
        assert OWNERSHIP_APPLICATION_OWNED in owners
        assert OWNERSHIP_HUMAN_OPERATED in owners

    def test_extract_script_and_iframe_srcs(self):
        html = ('<script src="/a.js"></script>'
                '<iframe src="https://cdn.example.com/widget.html"></iframe>')
        srcs = extract_script_and_iframe_srcs(html)
        assert "/a.js" in srcs
        assert "https://cdn.example.com/widget.html" in srcs

    def test_summarize_ownership_counts(self):
        comps = [
            {"ownership": OWNERSHIP_APPLICATION_OWNED},
            {"ownership": OWNERSHIP_HUMAN_OPERATED},
            {"ownership": OWNERSHIP_HUMAN_OPERATED},
        ]
        summary = summarize_ownership(comps)
        assert summary[OWNERSHIP_APPLICATION_OWNED] == 1
        assert summary[OWNERSHIP_HUMAN_OPERATED] == 2
        assert summary[OWNERSHIP_THIRD_PARTY_WIDGET] == 0


# ---------------------------------------------------------------------------
# Evidence gate
# ---------------------------------------------------------------------------

class TestEvidenceGate:

    def test_not_ai_powered_gate_closed(self):
        assert should_run_ai_tests({"is_ai_powered": False}) is False

    def test_live_model_confirmed_opens_gate(self):
        assert should_run_ai_tests({
            "is_ai_powered": True, "model_backed_confirmed": True}) is True

    def test_app_owned_chat_opens_gate(self):
        assert should_run_ai_tests({
            "is_ai_powered": True,
            "chat_components": [{"ownership": OWNERSHIP_APPLICATION_OWNED}],
        }) is True

    def test_passive_signals_only_keeps_gate_closed(self):
        # is_ai_powered by score, but no live confirmation, no app-owned chat,
        # no concrete endpoints -> must NOT escalate.
        assert should_run_ai_tests({
            "is_ai_powered": True, "confidence": "medium",
            "model_backed_confirmed": False, "ml_endpoints": [],
            "chat_components": [{"ownership": OWNERSHIP_HUMAN_OPERATED}],
        }) is False

    def test_concrete_endpoints_high_confidence_opens_gate(self):
        assert should_run_ai_tests({
            "is_ai_powered": True, "confidence": "high",
            "ml_endpoints": ["https://x/api/chat"],
        }) is True

    def test_third_party_widget_alone_does_not_open_gate(self):
        # A third-party AI widget is out of scope for testing the target's own model.
        assert should_run_ai_tests({
            "is_ai_powered": True, "confidence": "low",
            "model_backed_confirmed": False, "ml_endpoints": [],
            "chat_components": [{"ownership": OWNERSHIP_THIRD_PARTY_WIDGET}],
        }) is False
