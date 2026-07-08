"""
test_application_detection_edge_ca.py
Adversarial / collision edge cases for detect_application_type().
File name matches what's visible in the screenshot (truncated to 'edge_ca').
"""
import pytest
from multiagent.agents.ai_agents.ai_vulnerability_test import detect_application_type, ApplicationType


def _fp(**kwargs):
    base = {"page_title": "", "technologies": [], "ml_endpoints": [],
            "app_description": ""}
    base.update(kwargs)
    return base


class TestApplicationDetectionCollisions:

    def test_higher_hit_count_wins_over_lower(self):
        # medical: health, patient, clinical = 3 hits
        # financial: balance = 1 hit
        fp = _fp(technologies=["health", "patient", "clinical", "balance"])
        assert detect_application_type(fp) == ApplicationType.MEDICAL

    def test_exact_tie_returns_one_of_the_tied_types(self):
        # 1 RAG hit vs 1 code hit — result is non-deterministic but must be one of them
        fp = _fp(technologies=["vector", "copilot"])
        result = detect_application_type(fp)
        assert result in (ApplicationType.RAG, ApplicationType.CODE_ASSISTANT)

    def test_all_blank_fields_generic(self):
        fp = {"page_title": "   ", "technologies": [""], "ml_endpoints": [""],
              "app_description": ""}
        # blank / whitespace signals → GENERIC
        result = detect_application_type(fp)
        assert result == ApplicationType.GENERIC

    def test_keyword_as_substring_matches(self):
        # "search" is a RAG keyword; "websearch" contains "search"
        fp = _fp(technologies=["websearch"])
        # substring match — RAG should win
        assert detect_application_type(fp) == ApplicationType.RAG

    def test_multiple_fields_combine_hits(self):
        # title: ticket (CS=1), technologies: refund (CS=1), endpoints: helpdesk (CS=1)
        fp = _fp(page_title="ticket", technologies=["refund"],
                 ml_endpoints=["helpdesk"])
        assert detect_application_type(fp) == ApplicationType.CUSTOMER_SUPPORT

    def test_financial_keywords_in_description(self):
        fp = _fp(app_description="bank account transaction invest portfolio")
        assert detect_application_type(fp) == ApplicationType.FINANCIAL

    def test_does_not_raise_on_non_string_technologies(self):
        # Defensive: technologies list might contain non-strings in the wild
        fp = _fp(technologies=[None, 123, "vector"])
        # Should not raise; vector should still count
        try:
            result = detect_application_type(fp)
        except Exception as exc:
            pytest.fail(f"Raised unexpectedly: {exc}")