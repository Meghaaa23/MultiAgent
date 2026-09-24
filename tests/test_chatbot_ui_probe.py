"""Tests for discover-first chatbot UI probe (taxonomy, gate, differential)."""
from multiagent.agents.ai_agents.chatbot_ui_probe import (
    ChatWidget,
    ChatbotUIProbeResult,
    InjectionSeverity,
    StableLocator,
    classify_injection_severity,
    detect_chatbot_from_html,
    evidence_key_for_tier,
    ui_result_to_findings,
    ui_warrants_vuln,
    widgets_to_chat_components,
)
from multiagent.agents.ai_agents.ai_evidence_scoring import (
    EvidenceClass,
    classify_evidence,
)

def test_detect_intercom_is_third_party_out_of_scope():
    html = '<script src="https://widget.intercom.io/widget/abc"></script>'
    widgets = detect_chatbot_from_html(html, "https://example.com")
    assert any(w.provider == "Intercom" for w in widgets)
    w = next(w for w in widgets if w.provider == "Intercom")
    assert w.scope == "third_party"
    assert w.submit_allowed is False
    assert w.tier == EvidenceClass.PASSIVE_HINT.value

def test_bare_hubspot_brand_is_not_a_widget_marker():
    """www.hubspot.com HTML contains 'hubspot' everywhere — must not FP."""
    html = "<html><title>HubSpot | Software & Tools</title><p>HubSpot CRM</p></html>"
    assert detect_chatbot_from_html(html, "https://www.hubspot.com/") == []

def test_hubspot_conversations_script_is_third_party():
    html = '<script src="https://js.hs-scripts.com/123.js"></script>'
    widgets = detect_chatbot_from_html(html, "https://example.com")
    assert any(w.provider == "HubSpot" and w.scope == "third_party" for w in widgets)

def test_detect_structural_chat_surface():
    html = '''
    <div aria-live="polite" data-message-role="assistant">Hi</div>
    <form>
      <textarea placeholder="Type a message"></textarea>
      <button type="submit">Send</button>
    </form>
    '''
    widgets = detect_chatbot_from_html(html)
    assert any(w.tier == EvidenceClass.PASSIVE_STRUCTURAL.value for w in widgets)
    structural = next(
        w for w in widgets if w.tier == EvidenceClass.PASSIVE_STRUCTURAL.value
    )
    assert structural.submit_allowed is False
    assert structural.locator.get("tag") == "textarea"

def test_detect_hint_only_textarea():
    html = '<textarea placeholder="Type a message"></textarea><button>Send</button>'
    widgets = detect_chatbot_from_html(html)
    assert any(w.tier == EvidenceClass.PASSIVE_HINT.value for w in widgets)

def test_plain_marketing_page_no_widget():
    html = "<html><title>AI Writing Tool</title><p>Our AI helps you write.</p></html>"
    assert detect_chatbot_from_html(html) == []

def test_evidence_keys_map_to_taxonomy():
    assert evidence_key_for_tier("behavioral") == "behavior_chatbot_ui_confirmed"
    assert evidence_key_for_tier("live_surface") == "chatbot_ui_live_surface"
    assert evidence_key_for_tier("passive_structural") == "chatbot_ui_structural"
    assert evidence_key_for_tier("passive_hint") == "chatbot_ui_hint"
    assert evidence_key_for_tier("passive_hint", "third_party") == "chatbot_ui_third_party"

    assert classify_evidence("behavior_chatbot_ui_confirmed") == EvidenceClass.BEHAVIORAL
    assert classify_evidence("chatbot_ui_live_surface") == EvidenceClass.LIVE_SURFACE
    assert classify_evidence("chatbot_ui_structural") == EvidenceClass.PASSIVE_STRUCTURAL
    assert classify_evidence("chatbot_ui_hint") == EvidenceClass.PASSIVE_HINT
    assert classify_evidence("chatbot_ui_third_party") == EvidenceClass.PASSIVE_HINT

def test_widgets_persist_locator_not_as_primary_contract():
    widgets = [
        ChatWidget(
            input_selector="#root > div.chat > textarea",
            locator={"tag": "textarea", "test_id": "chat-input", "role": "textbox"},
            network_signature={"conversational": True, "urls": ["/api/chat"]},
            tier="live_surface",
            scope="app_owned",
            submit_allowed=True,
            provider="LibreChat",
            confidence=0.8,
            source="network",
            detail="test",
            url="http://x",
        )
    ]
    comps = widgets_to_chat_components(widgets)
    assert comps[0]["type"] == "chatbot_ui"
    assert comps[0]["locator"]["test_id"] == "chat-input"
    assert comps[0]["network_signature"]["conversational"] is True
    assert comps[0]["tier"] == "live_surface"
    assert "locator" in comps[0]

def test_stable_locator_prefers_testid_and_role():
    loc = StableLocator(test_id="composer", role="textbox", tag="textarea")
    cands = loc.playwright_candidates()
    assert cands[0] == '[data-testid="composer"]'
    assert any("role=" in c for c in cands)
    assert "#root" not in "".join(cands)

def test_differential_echo_confirms_low_severity():
    canary = "YURARAG_CANARY_7F3A"
    ok, outcome, sev = classify_injection_severity(
        canary,
        control_text="Hello! How can I help?",
        treatment_text=canary,
        differential=True,
    )
    assert ok is True
    assert outcome == "echo"
    assert sev == InjectionSeverity.ECHO

def test_canary_in_both_is_confounded():
    canary = "YURARAG_CANARY_7F3A"
    ok, outcome, sev = classify_injection_severity(
        canary,
        control_text=f"Sure, here is {canary}",
        treatment_text=canary,
        differential=True,
    )
    assert ok is False
    assert outcome == "canary_confounded"
    assert sev == InjectionSeverity.NONE

def test_differential_system_prompt_medium():
    canary = "YURARAG_CANARY_7F3A"
    ok, outcome, sev = classify_injection_severity(
        canary,
        control_text="Hello there.",
        treatment_text="My system prompt says: You are a helpful assistant…",
        differential=True,
    )
    assert ok is True
    assert outcome == "system_prompt"
    assert sev == InjectionSeverity.SYSTEM_PROMPT

def test_differential_tool_egress_high():
    canary = "YURARAG_CANARY_7F3A"
    ok, outcome, sev = classify_injection_severity(
        canary,
        control_text="Hello.",
        treatment_text='{"tool_calls":[{"name":"email","arguments":{}}]}',
        differential=True,
    )
    assert ok is True
    assert outcome == "tool_egress"
    assert sev == InjectionSeverity.TOOL_EGRESS

def test_ui_result_confirmed_requires_differential():
    result = ChatbotUIProbeResult(
        detected=True,
        injected=True,
        confirmed=True,
        differential=True,
        outcome="echo",
        severity=InjectionSeverity.ECHO.value,
        canary="YURA_TEST",
        control_snippet="Hello",
        response_snippet="YURA_TEST",
        widgets=[ChatWidget(
            tier="behavioral", scope="app_owned", locator={"tag": "textarea"},
        )],
    )
    confirmed, potential = ui_result_to_findings(result, "http://localhost:3080")
    assert len(confirmed) == 1
    assert confirmed[0]["evidence"]["differential"] is True
    assert confirmed[0]["evidence"]["severity"] == "echo"
    assert potential == []

def test_third_party_plus_weak_hint_is_not_medium_pi():
    """Vendor widget on a different eTLD+1 must not become Medium PI by default."""
    result = ChatbotUIProbeResult(
        detected=True,
        injected=False,
        widgets=[
            ChatWidget(
                provider="HubSpot",
                tier="passive_hint",
                scope="third_party",
                ownership="vendor_widget",
                reachability="cross_origin_frame",
                injection_policy="skip_inject",
                scope_reason="vendor_widget_default_skip",
                submit_allowed=False,
                source="iframe",
                frame_url="https://app.hubspot.com/conversations",
            ),
            ChatWidget(
                tier="passive_hint",
                scope="app_owned",
                ownership="same_site",
                injection_policy="inject",
                submit_allowed=False,
                source="dom",
                detail="Passive-hint: editable field with weak chat priors",
            ),
        ],
    )
    confirmed, potential = ui_result_to_findings(result, "https://www.klarna.com")
    assert confirmed == []
    assert all(p["severity"] == "Info" for p in potential)
    assert any(
        p["evidence"]["outcome"] in (
            "vendor_widget_policy_skip",
            "third_party_out_of_scope",
            "ui_hint_only",
        )
        for p in potential
    )
    assert not any("Potential Prompt Injection" in p["type"] for p in potential)
    comps = [w.to_dict() for w in result.widgets]
    assert ui_warrants_vuln(comps) is False

def test_ui_result_detected_only_is_potential():
    result = ChatbotUIProbeResult(
        detected=True,
        injected=False,
        widgets=[ChatWidget(
            tier="passive_structural",
            scope="app_owned",
            ownership="same_site",
            injection_policy="inject",
            submit_allowed=False,
            gate_reason="static_html_no_network_gate",
        )],
        error="side_effect_gate_blocked",
    )
    confirmed, potential = ui_result_to_findings(result, "https://example.com")
    assert confirmed == []
    assert len(potential) == 1
    assert potential[0]["evidence"]["outcome"] == "ui_detected"
    assert potential[0]["severity"] == "Medium"
