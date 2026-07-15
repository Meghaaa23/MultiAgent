"""Tests for ResponseAdaptivePolicy — outcome-conditioned technique selection."""
from multiagent.agents.ai_agents.payloads import (
    AdaptiveAction,
    ResponseAdaptivePolicy,
    ResponseOutcome,
    STATIC_PAYLOADS,
)


def test_seeds_direct_echo_first():
    policy = ResponseAdaptivePolicy(STATIC_PAYLOADS)
    first = policy.next()
    assert first.action == AdaptiveAction.TRY_PAYLOAD
    assert first.payload is not None
    assert first.payload["technique"] == "instruction_reset"


def test_refusal_promotes_jailbreak_techniques():
    policy = ResponseAdaptivePolicy(STATIC_PAYLOADS)
    first = policy.next()
    tech = first.payload["technique"]
    policy.record(tech, ResponseOutcome.REFUSED)
    nxt = policy.next()
    assert nxt.payload is not None
    assert nxt.payload["technique"] == "persona_override_dan"


def test_success_stops_in_scan_mode():
    policy = ResponseAdaptivePolicy(STATIC_PAYLOADS, full_matrix=False)
    first = policy.next()
    decision = policy.record(first.payload["technique"], ResponseOutcome.EXECUTED)
    assert decision is not None
    assert decision.action == AdaptiveAction.STOP


def test_success_continues_in_full_matrix():
    policy = ResponseAdaptivePolicy(STATIC_PAYLOADS, full_matrix=True, max_steps=100)
    first = policy.next()
    decision = policy.record(first.payload["technique"], ResponseOutcome.EXECUTED)
    assert decision is None
    nxt = policy.next()
    assert nxt.action == AdaptiveAction.TRY_PAYLOAD
    assert nxt.payload["technique"] != first.payload["technique"]


def test_partial_requests_mutations():
    policy = ResponseAdaptivePolicy(STATIC_PAYLOADS)
    first = policy.next()
    decision = policy.record(first.payload["technique"], ResponseOutcome.PARTIAL)
    assert decision is not None
    assert decision.action == AdaptiveAction.TRY_MUTATIONS


def test_ignored_promotes_direct_overrides():
    policy = ResponseAdaptivePolicy(STATIC_PAYLOADS)
    first = policy.next()
    policy.record(first.payload["technique"], ResponseOutcome.IGNORED)
    nxt = policy.next()
    assert nxt.payload is not None
    assert nxt.payload["technique"] == "priority_claim"


def test_queue_exhaustion_stops():
    tiny = [p for p in STATIC_PAYLOADS if p["technique"] == "instruction_reset"]
    policy = ResponseAdaptivePolicy(tiny, max_steps=5)
    assert policy.next().action == AdaptiveAction.TRY_PAYLOAD
    policy.record("instruction_reset", ResponseOutcome.IGNORED)
    # priority_claim not in tiny catalog — jumps that are missing are skipped
    assert policy.next().action == AdaptiveAction.STOP
