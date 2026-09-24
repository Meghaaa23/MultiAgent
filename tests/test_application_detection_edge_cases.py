"""Adversarial / collision cases for feature-based application typing."""
import pytest
from multiagent.agents.ai_agents.ai_vulnerability_test import detect_application_type, ApplicationType

def _fp(**kwargs):
    base = {"page_title": "", "technologies": [], "ml_endpoints": [],
            "app_description": "", "api_schema": {}, "discovered_paths": []}
    base.update(kwargs)
    return base

class TestApplicationDetectionCollisions:

    def test_higher_feature_score_wins(self):
        fp = _fp(app_description="patient clinical diagnosis",
                 technologies=["balance"])
        assert detect_application_type(fp) == ApplicationType.MEDICAL

    def test_exact_tie_returns_one_of_the_tied_types(self):
        fp = _fp(ml_endpoints=["/api/vector", "/api/lint"])
        result = detect_application_type(fp)
        assert result in (ApplicationType.RAG, ApplicationType.CODE_ASSISTANT)

    def test_all_blank_fields_generic(self):
        fp = {"page_title": "   ", "technologies": [""], "ml_endpoints": [""],
              "app_description": ""}
        result = detect_application_type(fp)
        assert result == ApplicationType.GENERIC

    def test_feature_substring_in_path(self):
        fp = _fp(ml_endpoints=["/api/websearch"])
        assert detect_application_type(fp) == ApplicationType.RAG

    def test_multiple_fields_combine_hits(self):
        fp = _fp(page_title="ticket", technologies=["refund"],
                 ml_endpoints=["/helpdesk"])
        assert detect_application_type(fp) == ApplicationType.CUSTOMER_SUPPORT

    def test_financial_keywords_in_description(self):
        fp = _fp(app_description="transaction invest portfolio trade")
        assert detect_application_type(fp) == ApplicationType.FINANCIAL

    def test_does_not_raise_on_non_string_technologies(self):
        fp = _fp(technologies=[None, 123, "vector"], ml_endpoints=["/api/retrieve"])
        try:
            result = detect_application_type(fp)
        except Exception as exc:
            pytest.fail(f"Raised unexpectedly: {exc}")
        assert result == ApplicationType.RAG
