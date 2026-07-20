"""Tests for chatbot UI detection helpers (static HTML path)."""
from multiagent.agents.ai_agents.chatbot_ui_probe import (
    detect_chatbot_from_html,
    widgets_to_chat_components,
    ui_result_to_findings,
    ChatbotUIProbeResult,
    ChatWidget,
)


def test_detect_intercom_marker():
    html = '<script src="https://widget.intercom.io/widget/abc"></script>'
    widgets = detect_chatbot_from_html(html, "https://example.com")
    assert any(w.provider == "Intercom" for w in widgets)


def test_detect_chat_textarea():
    html = '''
    <div data-message-role="assistant">Hi</div>
    <textarea placeholder="Type a message"></textarea>
    <button>Send</button>
    '''
    widgets = detect_chatbot_from_html(html)
    assert any(w.input_selector == "textarea" for w in widgets)
    assert any(w.confidence >= 0.5 for w in widgets)


def test_widgets_to_chat_components_shape():
    widgets = [
        ChatWidget(
            input_selector="textarea",
            send_selector='button[aria-label*="send" i]',
            provider="LibreChat",
            confidence=0.8,
            source="dom",
            detail="test",
            url="http://x",
        )
    ]
    comps = widgets_to_chat_components(widgets)
    assert comps[0]["type"] == "chatbot_ui"
    assert comps[0]["input_selector"] == "textarea"


def test_ui_result_confirmed_finding():
    result = ChatbotUIProbeResult(
        detected=True,
        injected=True,
        confirmed=True,
        outcome="executed",
        canary="YURA_TEST",
        response_snippet="YURA_TEST",
        widgets=[ChatWidget(input_selector="textarea", provider="X")],
    )
    confirmed, potential = ui_result_to_findings(result, "http://localhost:3080")
    assert len(confirmed) == 1
    assert "chatbot UI" in confirmed[0]["type"]
    assert potential == []


def test_ui_result_detected_only_is_potential():
    result = ChatbotUIProbeResult(
        detected=True,
        injected=False,
        widgets=[ChatWidget(provider="Intercom", confidence=0.55, source="static_html")],
        error="no_input_selector",
    )
    confirmed, potential = ui_result_to_findings(result, "https://example.com")
    assert confirmed == []
    assert len(potential) == 1
    assert potential[0]["evidence"]["outcome"] == "ui_detected"


def test_plain_marketing_page_no_widget():
    html = "<html><title>AI Writing Tool</title><p>Our AI helps you write.</p></html>"
    assert detect_chatbot_from_html(html) == []
