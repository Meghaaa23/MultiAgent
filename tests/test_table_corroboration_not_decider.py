"""Principle: hardcoded lookup tables corroborate an AI detection, they never
decide it on their own.

The AI fingerprinter emits two behavioral-context signals that are produced by
matching a *hardcoded table* against probe output:

  * behavior_model_reported  ← MODEL_NAME_PATTERNS  (enumerated model names)
  * behavior_llm_response     ← LLM_RESPONSE_SIGNALS (assistant phrasings)

Neither may set is_ai on its own. Only table-free behavior (non-determinism),
protocol structure (streaming header, model-shaped 200 body), or genuine live
interaction (chatbot_ui) may confirm AI. A table match combined with one of
those real deciders is fine and should raise confidence to CONFIRMED.
"""
from multiagent.agents.ai_agents.ai_evidence_scoring import (
    Detection,
    EvidenceClass,
    classify_evidence,
    score_evidence,
)

def test_model_name_table_match_alone_does_not_confirm_ai():
    r = score_evidence(["behavior_model_reported"])
    assert r.is_ai is False
    assert r.has_live_surface is False
    assert r.detection == Detection.PROBABLE

def test_llm_phrasing_table_match_alone_does_not_confirm_ai():
    r = score_evidence(["behavior_llm_response"])
    assert r.is_ai is False
    assert r.has_live_surface is False
    assert r.detection == Detection.POSSIBLE

def test_both_table_matches_together_still_do_not_confirm():
    r = score_evidence(["behavior_model_reported", "behavior_llm_response"])
    assert r.is_ai is False

def test_nondeterminism_confirms_ai():
    r = score_evidence(["behavior_nondeterministic"])
    assert r.is_ai is True
    assert r.detection == Detection.CONFIRMED

def test_streaming_protocol_confirms_ai():
    r = score_evidence(["behavior_streaming"])
    assert r.is_ai is True

def test_model_shaped_200_body_confirms_ai():
    r = score_evidence(["chat_endpoint_200"])
    assert r.is_ai is True

def test_table_match_corroborates_a_real_decider():
    r = score_evidence(["behavior_nondeterministic", "behavior_model_reported"])
    assert r.is_ai is True
    assert r.detection == Detection.CONFIRMED

def test_table_keys_are_not_behavioral_class():
    assert classify_evidence("behavior_model_reported") == EvidenceClass.PASSIVE_STRUCTURAL
    assert classify_evidence("behavior_llm_response") == EvidenceClass.PASSIVE_HINT
    assert classify_evidence("behavior_nondeterministic") == EvidenceClass.BEHAVIORAL
    assert classify_evidence("behavior_streaming") == EvidenceClass.BEHAVIORAL

def test_brand_and_js_sdk_tables_do_not_confirm():
    assert score_evidence(["js_ai_sdk"]).is_ai is False
    assert score_evidence(["page_title_ai"]).is_ai is False
    assert score_evidence(["framework_identified"]).is_ai is False
