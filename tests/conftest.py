"""
conftest.py  —  shared fixtures for all ai_vulnerability_tester tests.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from multiagent.agents.ai_agents.ai_vulnerability_test import (
    SemanticScorer, CapabilitySet, AppCapability,
    ApplicationType, InjectionFamily, Objective, ResponseOutcome,
    STATIC_PAYLOADS, CANARY_PREFIX,
)

@pytest.fixture(scope="session")
def scorer():
    """Jaccard-only scorer — no heavy embedding dependency in CI."""
    return SemanticScorer(enable_embeddings=False)

@pytest.fixture
def canary():
    return "YURA_TESTCANARY"

@pytest.fixture
def baseline():
    return "The answer is four."

@pytest.fixture
def empty_fingerprint():
    return {
        "page_title": "", "technologies": [], "ml_endpoints": [],
        "app_description": "", "api_schema": {}, "discovered_paths": [],
        "response_headers": {},
    }

@pytest.fixture
def rag_fingerprint():
    return {
        "page_title": "RAG Knowledge Assistant",
        "technologies": ["vector", "retrieval"],
        "ml_endpoints": ["/api/retrieve", "/api/chat/completions"],
        "app_description": "vector retrieval chatbot",
        "api_schema": {"tools": [{"name": "retrieve", "description": "vector search"}]},
        "discovered_paths": ["/api/retrieve"],
        "response_headers": {},
    }

@pytest.fixture
def cs_fingerprint():
    return {
        "page_title": "Customer Support Helpdesk",
        "technologies": ["ticket", "helpdesk"],
        "ml_endpoints": ["/api/chat"],
        "app_description": "support ticket assistant",
        "api_schema": {},
        "discovered_paths": [],
        "response_headers": {},
    }

@pytest.fixture
def agentic_fingerprint():
    return {
        "page_title": "AutoGen Multi-Agent Workflow",
        "technologies": ["orchestrator", "multi_agent"],
        "ml_endpoints": ["/api/agent/run", "/api/tool/execute"],
        "app_description": "multi-agent orchestrator",
        "api_schema": {"tools": [
            {"name": "web_search", "description": "search the internet"},
            {"name": "code_exec", "description": "run python code in sandbox"},
        ]},
        "discovered_paths": ["/api/memory/store", "/api/agent/orchestrat"],
        "response_headers": {},
    }