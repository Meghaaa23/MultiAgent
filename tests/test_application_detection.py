"""
test_application_type from observed paths / schema / feature copy.
Product brand names are not a detection signal.
"""
import pytest
from multiagent.agents.ai_agents.ai_vulnerability_test import detect_application_type, ApplicationType

def _fp(**kwargs):
    base = {"page_title": "", "technologies": [], "ml_endpoints": [],
            "app_description": "", "api_schema": {}, "discovered_paths": []}
    base.update(kwargs)
    return base

class TestApplicationDetectionHappyPath:

    def test_customer_support_from_title_features(self):
        fp = _fp(page_title="Support Helpdesk")
        assert detect_application_type(fp) == ApplicationType.CUSTOMER_SUPPORT

    def test_customer_support_from_ticket_path(self):
        fp = _fp(ml_endpoints=["/api/ticket/create", "/api/refund/request"])
        assert detect_application_type(fp) == ApplicationType.CUSTOMER_SUPPORT

    def test_rag_from_title(self):
        fp = _fp(page_title="RAG Knowledge Base Assistant")
        assert detect_application_type(fp) == ApplicationType.RAG

    def test_rag_from_retrieve_path(self):
        fp = _fp(ml_endpoints=["/api/retrieve"], discovered_paths=["/api/embed"])
        assert detect_application_type(fp) == ApplicationType.RAG

    def test_code_assistant_from_title(self):
        fp = _fp(page_title="IDE lint and diff assistant")
        assert detect_application_type(fp) == ApplicationType.CODE_ASSISTANT

    def test_code_assistant_from_paths(self):
        fp = _fp(ml_endpoints=["/api/repository/diff", "/api/lint"])
        assert detect_application_type(fp) == ApplicationType.CODE_ASSISTANT

    def test_email_assistant_from_title(self):
        fp = _fp(page_title="Inbox compose draft assistant")
        assert detect_application_type(fp) == ApplicationType.EMAIL_ASSISTANT

    def test_medical_from_description(self):
        fp = _fp(app_description="clinical diagnosis patient symptom checker")
        assert detect_application_type(fp) == ApplicationType.MEDICAL

    def test_financial_from_surface_copy(self):
        fp = _fp(app_description="portfolio trade invest dashboard")
        assert detect_application_type(fp) == ApplicationType.FINANCIAL

    def test_generic_no_signals(self, empty_fingerprint):
        assert detect_application_type(empty_fingerprint) == ApplicationType.GENERIC

    def test_signals_from_endpoints(self):
        fp = _fp(ml_endpoints=["/api/ticket/create", "/api/refund/request"])
        assert detect_application_type(fp) == ApplicationType.CUSTOMER_SUPPORT

    def test_product_name_alone_is_not_a_type(self):
        fp = _fp(page_title="Zendesk", technologies=["pinecone", "ollama"])
        assert detect_application_type(fp) == ApplicationType.GENERIC


class TestApplicationDetectionEdgeCases:

    def test_case_insensitive_matching(self):
        fp = _fp(page_title="SUPPORT HELPDESK TICKET SYSTEM")
        assert detect_application_type(fp) == ApplicationType.CUSTOMER_SUPPORT

    def test_path_beats_weak_text(self):
        fp = _fp(
            page_title="email notice",
            ml_endpoints=["/api/retrieve", "/api/embed"],
        )
        assert detect_application_type(fp) == ApplicationType.RAG

    def test_single_ambiguous_keyword_returns_generic(self):
        fp = _fp(technologies=["search"])
        assert detect_application_type(fp) == ApplicationType.GENERIC

    def test_empty_strings_return_generic(self):
        fp = {"page_title": "", "technologies": [], "ml_endpoints": [],
              "app_description": ""}
        assert detect_application_type(fp) == ApplicationType.GENERIC

    def test_missing_keys_dont_crash(self):
        result = detect_application_type({})
        assert result == ApplicationType.GENERIC

    def test_description_field_contributes(self):
        fp = _fp(app_description="patient ehr fhir clinical prescription")
        assert detect_application_type(fp) == ApplicationType.MEDICAL
