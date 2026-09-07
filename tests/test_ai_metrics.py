"""
test_ai_metrics.py — evaluation metrics for AI-surface discovery + prompt injection.

The testbed directory name contains a hyphen, so it is imported by path.
"""
import os
import sys
import pytest

_TESTBED = os.path.join(os.path.dirname(__file__), "..", "multiagent", "multiagent-testbed")
sys.path.insert(0, os.path.abspath(_TESTBED))

import ai_metrics as m  # noqa: E402


# ---------------------------------------------------------------------------
# AI-surface detection
# ---------------------------------------------------------------------------

class TestDetectAISurface:

    def test_is_ai_powered_flag(self):
        assert m.detected_ai_surface({"scan_summary": {"is_ai_powered": True}}) is True

    def test_app_owned_chat_counts(self):
        r = {"scan_summary": {"chat_surface_summary": {"application_owned": 1}}}
        assert m.detected_ai_surface(r) is True

    def test_ml_endpoint_counts(self):
        r = {"scan_summary": {"ml_endpoints": ["http://x/api/chat"]}}
        assert m.detected_ai_surface(r) is True

    def test_human_operated_only_is_not_ai_surface(self):
        r = {"scan_summary": {"is_ai_powered": False,
                              "chat_surface_summary": {"human_operated": 1}}}
        assert m.detected_ai_surface(r) is False

    def test_nothing_detected(self):
        assert m.detected_ai_surface({"scan_summary": {}}) is False


# ---------------------------------------------------------------------------
# AI-surface P/R aggregation
# ---------------------------------------------------------------------------

class TestAISurfaceAggregate:

    def test_confusion_and_metrics(self):
        entries = [
            {"outcome": "tp"}, {"outcome": "tp"}, {"outcome": "fp"},
            {"outcome": "fn"}, {"outcome": "tn"}, {"outcome": "tn"},
        ]
        agg = m.aggregate_ai_surface(entries)
        assert agg["tp"] == 2 and agg["fp"] == 1 and agg["fn"] == 1 and agg["tn"] == 2
        assert agg["precision"] == round(2 / 3, 3)
        assert agg["recall"] == round(2 / 3, 3)
        assert agg["accuracy"] == round(4 / 6, 3)

    def test_score_target_outcomes(self):
        pos_label = {"is_ai_app": True}
        neg_label = {"is_ai_app": False}
        ai_res    = {"scan_summary": {"is_ai_powered": True}}
        plain_res = {"scan_summary": {"is_ai_powered": False}}
        assert m.score_ai_surface_target(pos_label, ai_res)["outcome"] == "tp"
        assert m.score_ai_surface_target(neg_label, ai_res)["outcome"] == "fp"
        assert m.score_ai_surface_target(pos_label, plain_res)["outcome"] == "fn"
        assert m.score_ai_surface_target(neg_label, plain_res)["outcome"] == "tn"


# ---------------------------------------------------------------------------
# Ownership classification accuracy
# ---------------------------------------------------------------------------

class TestOwnershipAccuracy:

    def test_correct_when_expected_detected(self):
        pairs = [{
            "label":  {"expected_ownership": ["application_owned"]},
            "result": {"scan_summary": {"chat_surface_summary": {"application_owned": 1}}},
        }]
        out = m.ownership_classification_accuracy(pairs)
        assert out["targets_considered"] == 1
        assert out["accuracy"] == 1.0

    def test_wrong_when_expected_missing(self):
        pairs = [{
            "label":  {"expected_ownership": ["application_owned"]},
            "result": {"scan_summary": {"chat_surface_summary": {"human_operated": 1}}},
        }]
        out = m.ownership_classification_accuracy(pairs)
        assert out["accuracy"] == 0.0

    def test_unlabelled_ownership_ignored(self):
        pairs = [{"label": {"expected_ownership": []}, "result": {}}]
        out = m.ownership_classification_accuracy(pairs)
        assert out["targets_considered"] == 0


# ---------------------------------------------------------------------------
# Prompt injection metrics
# ---------------------------------------------------------------------------

class TestPromptInjection:

    def test_is_prompt_injection_finding(self):
        assert m.is_prompt_injection_finding(
            {"type": "Indirect Prompt Injection - x", "status": "Confirmed"})
        assert m.is_prompt_injection_finding(
            {"type": "LLM prompt injection", "owasp": "LLM01:2025"})
        assert not m.is_prompt_injection_finding(
            {"type": "Reflected XSS", "status": "Confirmed"})

    def test_confirmed_filter(self):
        findings = [
            {"type": "Prompt Injection", "status": "Confirmed"},
            {"type": "Prompt Injection", "status": "Potential"},
            {"type": "SQL Injection", "status": "Confirmed"},
        ]
        assert len(m.confirmed_prompt_injections(findings)) == 1

    def test_aggregate_precision_recall_fp_rate(self):
        pairs = [
            # expected + confirmed  -> TP target
            {"label": {"prompt_injection_expected": True},
             "result": {"findings": [{"type": "Prompt Injection", "status": "Confirmed"}]}},
            # NOT expected + confirmed -> FP target
            {"label": {"prompt_injection_expected": False},
             "result": {"findings": [{"type": "Prompt Injection", "status": "Confirmed"}]}},
            # expected + none confirmed -> FN (lowers recall)
            {"label": {"prompt_injection_expected": True},
             "result": {"findings": [{"type": "Prompt Injection", "status": "Potential"}]}},
            # not expected + none -> true negative
            {"label": {"prompt_injection_expected": False}, "result": {"findings": []}},
        ]
        agg = m.aggregate_prompt_injection(pairs)
        assert agg["total_confirmations"] == 2
        assert agg["flagged_targets"] == 2
        assert agg["tp_targets"] == 1 and agg["fp_targets"] == 1
        assert agg["expected_targets"] == 2
        assert agg["precision"] == 0.5
        assert agg["false_positive_rate"] == 0.5
        assert agg["recall"] == 0.5


# ---------------------------------------------------------------------------
# Conventional-scan gap
# ---------------------------------------------------------------------------

class TestConventionalGap:

    def test_missed_paths(self):
        r = {"scan_summary": {
            "ml_endpoints": ["http://x/api/chat", "http://x/v1/completions"],
            "discovered_paths": ["/api/chat", "/login"],
        }}
        missed = m.ai_surfaces_missed_by_conventional(r)
        assert "/v1/completions" in missed
        assert "/api/chat" not in missed

    def test_aggregate_gap(self):
        results = [
            {"target_id": 1, "scan_summary": {
                "ml_endpoints": ["http://x/api/chat", "http://x/v1/embeddings"],
                "discovered_paths": ["/api/chat"]}},
            {"target_id": 2, "scan_summary": {
                "ml_endpoints": ["http://y/api/generate"],
                "discovered_paths": []}},
        ]
        agg = m.aggregate_conventional_gap(results)
        assert agg["total_ai_surfaces_missed_by_conventional"] == 2
        assert agg["targets_with_gap"] == 2
