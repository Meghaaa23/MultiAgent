"""
test_capability_detection.py
Tests for detect_capabilities() and CapabilitySet.
"""
import pytest
from multiagent.agents.ai_agents.ai_vulnerability_test import (
    detect_capabilities, AppCapability, CapabilitySet,
)

def _fp(**kwargs):
    base = {
        "page_title": "", "technologies": [], "ml_endpoints": [],
        "app_description": "", "api_schema": {}, "discovered_paths": [],
        "response_headers": {},
    }
    base.update(kwargs)
    return base

class TestCapabilityFromSchema:

    def test_retrieval_tool_in_schema(self):
        fp = _fp(api_schema={"tools": [{"name": "retrieve", "description": "vector search"}]})
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.RETRIEVAL)

    def test_web_search_tool_in_schema(self):
        fp = _fp(api_schema={"tools": [{"name": "serpapi_search", "description": "search the web"}]})
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.WEB_SEARCH)

    def test_email_tool_in_schema(self):
        fp = _fp(api_schema={"functions": [{"name": "send_email", "description": "gmail compose"}]})
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.EMAIL_SEND)

    def test_code_tool_in_schema(self):
        fp = _fp(api_schema={"tools": [{"name": "sandbox", "description": "run code in e2b sandbox"}]})
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.CODE_EXECUTION)

    def test_schema_confidence_is_highest(self):
        fp = _fp(api_schema={"tools": [{"name": "retrieve", "description": "rag retrieval"}]})
        cs = detect_capabilities(fp)
        assert cs.confidence.get(AppCapability.RETRIEVAL, 0) >= 0.90

    def test_plugins_key_also_checked(self):
        fp = _fp(api_schema={"plugins": [{"name": "gmail_plugin", "description": "send emails"}]})
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.EMAIL_SEND)

class TestCapabilityFromEndpoints:
    """Endpoint-path capability inference requires a CONFIRMED live surface and
    reads only ml_endpoints (AI-classified). A capability-shaped substring in a
    path that was never confirmed live — or the raw, never-probed
    discovered_paths bag — must not fabricate a capability."""

    def test_retrieve_path(self):
        fp = _fp(ml_endpoints=["/api/retrieve"], has_live_surface=True)
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.RETRIEVAL)

    def test_tool_execute_path(self):
        fp = _fp(ml_endpoints=["/api/tool/execute"], has_live_surface=True)
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.TOOL_CALLING)

    def test_memory_path(self):
        fp = _fp(ml_endpoints=["/api/memory/store"], has_live_surface=True)
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.MEMORY)

    def test_code_exec_path(self):
        fp = _fp(ml_endpoints=["/api/code/exec"], has_live_surface=True)
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.CODE_EXECUTION)

    def test_send_email_path(self):
        fp = _fp(ml_endpoints=["/api/email/send"], has_live_surface=True)
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.EMAIL_SEND)

    def test_agent_orchestrat_path(self):
        fp = _fp(ml_endpoints=["/api/agent/orchestrat"], has_live_surface=True)
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.MULTI_AGENT)

    def test_endpoint_confidence_is_0_70(self):
        fp = _fp(ml_endpoints=["/api/retrieve"], has_live_surface=True)
        cs = detect_capabilities(fp)
        conf = cs.confidence.get(AppCapability.RETRIEVAL, 0)
        assert 0.65 <= conf <= 0.75

    def test_endpoint_path_requires_confirmed_live_surface(self):
        fp = _fp(ml_endpoints=["/api/retrieve"], has_live_surface=False)
        cs = detect_capabilities(fp)
        assert not cs.has(AppCapability.RETRIEVAL)

    def test_discovered_paths_are_not_a_capability_source(self):
        fp = _fp(
            ml_endpoints=["/api/retrieve"],
            discovered_paths=["/api/memory/store"],
            has_live_surface=True,
        )
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.RETRIEVAL)
        assert not cs.has(AppCapability.MEMORY)

class TestCapabilityFromObservedFeatures:

    def test_vector_retrieval_copy_gives_retrieval(self):
        fp = _fp(app_description="vector retrieval")
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.RETRIEVAL)

    def test_function_call_copy_gives_tool(self):
        fp = _fp(app_description="function_call tool_choice")
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.TOOL_CALLING)

    def test_orchestrator_copy_gives_multi_agent(self):
        fp = _fp(app_description="multi_agent orchestrator")
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.MULTI_AGENT)

    def test_product_name_alone_is_not_a_capability(self):
        fp = _fp(technologies=["pinecone", "langchain", "autogen", "redis", "sendgrid"])
        cs = detect_capabilities(fp)
        assert not cs.has(AppCapability.RETRIEVAL)
        assert not cs.has(AppCapability.MEMORY)
        assert not cs.has(AppCapability.EMAIL_SEND)
        assert not cs.has(AppCapability.MULTI_AGENT)

    def test_compose_copy_gives_email(self):
        fp = _fp(app_description="send email compose")
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.EMAIL_SEND)

    def test_web_search_copy(self):
        fp = _fp(app_description="web search browsing")
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.WEB_SEARCH)

    def test_feature_copy_confidence_is_0_50(self):
        fp = _fp(app_description="vector retrieval")
        cs = detect_capabilities(fp)
        conf = cs.confidence.get(AppCapability.RETRIEVAL, 0)
        assert 0.45 <= conf <= 0.55

    def test_brand_header_is_not_a_capability(self):
        fp = _fp(response_headers={"X-Powered-By": "langchain"})
        cs = detect_capabilities(fp)
        assert not cs.has(AppCapability.RETRIEVAL)

class TestCapabilityConfidencePrecedence:

    def test_schema_overrides_weak_copy(self):
        fp = _fp(
            app_description="vector",
            api_schema={"tools": [{"name": "retrieve", "description": "rag"}]},
        )
        cs = detect_capabilities(fp)
        assert cs.confidence.get(AppCapability.RETRIEVAL, 0) >= 0.90

    def test_endpoint_overrides_weak_copy(self):
        fp = _fp(
            app_description="vector",
            ml_endpoints=["/api/retrieve"],
            has_live_surface=True,
        )
        cs = detect_capabilities(fp)
        assert cs.confidence.get(AppCapability.RETRIEVAL, 0) >= 0.65

class TestCapabilitySet:

    def test_has_returns_true_for_present(self):
        cs = CapabilitySet(capabilities=[AppCapability.RETRIEVAL])
        assert cs.has(AppCapability.RETRIEVAL)

    def test_has_returns_false_for_absent(self):
        cs = CapabilitySet(capabilities=[AppCapability.RETRIEVAL])
        assert not cs.has(AppCapability.MEMORY)

    def test_empty_capset_has_nothing(self):
        cs = CapabilitySet()
        for cap in AppCapability:
            assert not cs.has(cap)

    def test_repr_lists_cap_values(self):
        cs = CapabilitySet(capabilities=[AppCapability.RETRIEVAL, AppCapability.MEMORY])
        r = repr(cs)
        assert "retrieval" in r
        assert "memory" in r

    def test_no_capabilities_empty_fingerprint(self, empty_fingerprint):
        cs = detect_capabilities(empty_fingerprint)
        assert cs.capabilities == []