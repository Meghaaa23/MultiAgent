"""Tests for shared AI escalation phase gating and finding merge."""
from multiagent.agents.ai_agents.ai_scan_phase import (
    should_escalate_ai,
    infra_threats_as_findings,
)


def test_should_escalate_requires_ai_flag():
    assert not should_escalate_ai(None)
    assert not should_escalate_ai({})
    assert not should_escalate_ai({"is_ai_powered": False, "confidence": "high"})


def test_should_escalate_high_confidence():
    assert should_escalate_ai({
        "is_ai_powered": True,
        "confidence": "high",
    })
    assert should_escalate_ai({
        "is_ai_powered": True,
        "confidence": "very_high",
    })


def test_should_escalate_concrete_endpoints_even_if_medium():
    assert should_escalate_ai({
        "is_ai_powered": True,
        "confidence": "medium",
        "ml_endpoints": ["http://x/api/chat"],
    })
    assert should_escalate_ai({
        "is_ai_powered": True,
        "confidence": "low",
        "framework": "Ollama",
    })


def test_should_not_escalate_weak_signals():
    assert not should_escalate_ai({
        "is_ai_powered": True,
        "confidence": "low",
        "ml_endpoints": [],
        "framework": "",
    })


def test_infra_threats_as_findings():
    class T:
        attack_name = "Unauthenticated Inference Endpoint"
        severity = "Medium"
        status = "Confirmed"
        evidence = {"endpoint": "http://x/api/chat"}
        description = "open chat"
        atlas_technique = "AML.T0051"
        mitigation = "add auth"
        stride_category = "Spoofing"

    class R:
        threats = [T()]
        target_url = "http://x"

    findings = infra_threats_as_findings(R())
    assert len(findings) == 1
    assert findings[0]["category"] == "ai_infrastructure"
    assert findings[0]["status"] == "Confirmed"
    assert findings[0]["location"] == "http://x/api/chat"
