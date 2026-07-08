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


# ---------------------------------------------------------------------------
# Source 1: explicit tool/function schemas (confidence 0.95)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Source 2: endpoint path patterns (confidence 0.70)
# ---------------------------------------------------------------------------

class TestCapabilityFromEndpoints:

    def test_retrieve_path(self):
        fp = _fp(ml_endpoints=["/api/retrieve"])
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.RETRIEVAL)

    def test_tool_execute_path(self):
        fp = _fp(ml_endpoints=["/api/tool/execute"])
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.TOOL_CALLING)

    def test_memory_path(self):
        fp = _fp(discovered_paths=["/api/memory/store"])
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.MEMORY)

    def test_code_exec_path(self):
        fp = _fp(discovered_paths=["/api/code/exec"])
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.CODE_EXECUTION)

    def test_send_email_path(self):
        fp = _fp(discovered_paths=["/api/email/send"])
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.EMAIL_SEND)

    def test_agent_orchestrat_path(self):
        fp = _fp(discovered_paths=["/api/agent/orchestrat"])
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.MULTI_AGENT)

    def test_endpoint_confidence_is_0_70(self):
        fp = _fp(ml_endpoints=["/api/retrieve"])
        cs = detect_capabilities(fp)
        conf = cs.confidence.get(AppCapability.RETRIEVAL, 0)
        # schema not present, so confidence should be ~0.70 (not bumped higher)
        assert 0.65 <= conf <= 0.75

    def test_both_ml_endpoints_and_discovered_paths_checked(self):
        fp = _fp(ml_endpoints=["/api/retrieve"], discovered_paths=["/api/memory/store"])
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.RETRIEVAL)
        assert cs.has(AppCapability.MEMORY)


# ---------------------------------------------------------------------------
# Source 3: technology keyword signals (confidence 0.50)
# ---------------------------------------------------------------------------

class TestCapabilityFromTechSignals:

    def test_pinecone_gives_retrieval(self):
        fp = _fp(technologies=["pinecone"])
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.RETRIEVAL)

    def test_langchain_gives_retrieval_and_tool(self):
        fp = _fp(technologies=["langchain"])
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.RETRIEVAL)
        assert cs.has(AppCapability.TOOL_CALLING)

    def test_autogen_gives_multi_agent(self):
        fp = _fp(technologies=["autogen"])
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.MULTI_AGENT)

    def test_redis_gives_memory(self):
        fp = _fp(technologies=["redis"])
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.MEMORY)

    def test_sendgrid_gives_email(self):
        fp = _fp(technologies=["sendgrid"])
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.EMAIL_SEND)

    def test_tavily_gives_web_search(self):
        fp = _fp(technologies=["tavily"])
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.WEB_SEARCH)

    def test_tech_confidence_is_0_50(self):
        fp = _fp(technologies=["pinecone"])
        cs = detect_capabilities(fp)
        conf = cs.confidence.get(AppCapability.RETRIEVAL, 0)
        assert 0.45 <= conf <= 0.55

    def test_response_headers_checked(self):
        fp = _fp(response_headers={"X-Powered-By": "langchain"})
        cs = detect_capabilities(fp)
        assert cs.has(AppCapability.RETRIEVAL)


# ---------------------------------------------------------------------------
# Higher-confidence source wins
# ---------------------------------------------------------------------------

class TestCapabilityConfidencePrecedence:

    def test_schema_overrides_tech_keyword(self):
        fp = _fp(
            technologies=["pinecone"],  # 0.50
            api_schema={"tools": [{"name": "retrieve", "description": "rag"}]},  # 0.95
        )
        cs = detect_capabilities(fp)
        assert cs.confidence.get(AppCapability.RETRIEVAL, 0) >= 0.90

    def test_endpoint_overrides_tech_keyword(self):
        fp = _fp(
            technologies=["pinecone"],       # 0.50
            ml_endpoints=["/api/retrieve"],  # 0.70
        )
        cs = detect_capabilities(fp)
        assert cs.confidence.get(AppCapability.RETRIEVAL, 0) >= 0.65


# ---------------------------------------------------------------------------
# CapabilitySet dataclass
# ---------------------------------------------------------------------------

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