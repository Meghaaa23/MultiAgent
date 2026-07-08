"""
test_application_detection.py
Tests for detect_application_type() — heuristic keyword-based inference.
"""
import pytest
from multiagent.agents.ai_agents.ai_vulnerability_test import detect_application_type, ApplicationType


def _fp(**kwargs):
    base = {"page_title": "", "technologies": [], "ml_endpoints": [],
            "app_description": ""}
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# Happy-path: each app type detected from its primary signals
# ---------------------------------------------------------------------------

class TestApplicationDetectionHappyPath:

    def test_customer_support_from_title(self):
        fp = _fp(page_title="Zendesk Support Helpdesk")
        assert detect_application_type(fp) == ApplicationType.CUSTOMER_SUPPORT

    def test_customer_support_from_technologies(self):
        fp = _fp(technologies=["zendesk", "ticket", "crm"])
        assert detect_application_type(fp) == ApplicationType.CUSTOMER_SUPPORT

    def test_rag_from_title(self):
        fp = _fp(page_title="RAG Knowledge Base Assistant")
        assert detect_application_type(fp) == ApplicationType.RAG

    def test_rag_from_technologies(self):
        fp = _fp(technologies=["pinecone", "embedding", "vector"])
        assert detect_application_type(fp) == ApplicationType.RAG

    def test_code_assistant_from_title(self):
        fp = _fp(page_title="GitHub Copilot IDE Assistant")
        assert detect_application_type(fp) == ApplicationType.CODE_ASSISTANT

    def test_code_assistant_from_technologies(self):
        fp = _fp(technologies=["copilot", "repository", "diff"])
        assert detect_application_type(fp) == ApplicationType.CODE_ASSISTANT

    def test_email_assistant_from_title(self):
        fp = _fp(page_title="Gmail Email Compose Assistant")
        assert detect_application_type(fp) == ApplicationType.EMAIL_ASSISTANT

    def test_medical_from_description(self):
        fp = _fp(app_description="clinical diagnosis patient symptom checker")
        assert detect_application_type(fp) == ApplicationType.MEDICAL

    def test_financial_from_technologies(self):
        fp = _fp(technologies=["portfolio", "trade", "bank"])
        assert detect_application_type(fp) == ApplicationType.FINANCIAL

    def test_generic_no_signals(self, empty_fingerprint):
        assert detect_application_type(empty_fingerprint) == ApplicationType.GENERIC

    def test_signals_from_endpoints(self):
        fp = _fp(ml_endpoints=["/api/ticket/create", "/api/refund/request"])
        assert detect_application_type(fp) == ApplicationType.CUSTOMER_SUPPORT


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestApplicationDetectionEdgeCases:

    def test_case_insensitive_matching(self):
        fp = _fp(page_title="ZENDESK SUPPORT TICKET SYSTEM")
        assert detect_application_type(fp) == ApplicationType.CUSTOMER_SUPPORT

    def test_ties_resolved_by_hit_count(self):
        # RAG gets 3 hits, email gets 1 — RAG should win
        fp = _fp(technologies=["vector", "embedding", "pinecone", "email"])
        assert detect_application_type(fp) == ApplicationType.RAG

    def test_single_ambiguous_keyword_returns_generic_or_any(self):
        # "search" matches RAG; only 1 hit but should not be GENERIC
        fp = _fp(technologies=["search"])
        result = detect_application_type(fp)
        assert result != ApplicationType.GENERIC

    def test_empty_strings_return_generic(self):
        fp = {"page_title": "", "technologies": [], "ml_endpoints": [],
              "app_description": ""}
        assert detect_application_type(fp) == ApplicationType.GENERIC

    def test_missing_keys_dont_crash(self):
        # Minimal fingerprint — should not raise
        result = detect_application_type({})
        assert result == ApplicationType.GENERIC

    def test_description_field_contributes(self):
        fp = _fp(app_description="patient ehr fhir clinical prescription")
        assert detect_application_type(fp) == ApplicationType.MEDICAL