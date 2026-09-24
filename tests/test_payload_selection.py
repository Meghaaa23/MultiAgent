"""
test_payload_selection.py
Tests for STATIC_PAYLOADS corpus integrity and build_application_payloads().
"""
import pytest
from multiagent.agents.ai_agents.ai_vulnerability_test import (
    STATIC_PAYLOADS, InjectionFamily, Objective, ApplicationType,
    AppCapability, CapabilitySet, build_application_payloads,
    TECHNIQUE_FAMILY,
)

class TestStaticCorpusIntegrity:

    def test_no_indirect_payloads_in_static(self):
        """INDIRECT family should be zero in static corpus — only via IndirectInjectionProbe."""
        indirect = [p for p in STATIC_PAYLOADS if p["family"] == InjectionFamily.INDIRECT]
        assert len(indirect) == 0, \
            f"Found INDIRECT payloads in static corpus: {[p['technique'] for p in indirect]}"

    def test_agentic_family_has_at_least_9_techniques(self):
        agentic = [p for p in STATIC_PAYLOADS if p["family"] == InjectionFamily.AGENTIC]
        assert len(agentic) >= 9

    def test_agentic_covers_all_pipeline_nodes(self):
        agentic = [p for p in STATIC_PAYLOADS if p["family"] == InjectionFamily.AGENTIC]
        objectives = {p["objective"] for p in agentic}
        assert Objective.CALL_TOOL in objectives
        assert Objective.HIJACK_PLANNER in objectives
        assert Objective.INJECT_OBSERVATION in objectives
        assert Objective.POISON_MEMORY in objectives
        assert Objective.EXFIL_SCRATCHPAD in objectives

    def test_all_techniques_unique(self):
        techniques = [p["technique"] for p in STATIC_PAYLOADS]
        assert len(techniques) == len(set(techniques)), "Duplicate technique slugs found"

    def test_all_payloads_have_required_fields(self):
        required = {"family", "technique", "objective", "template",
                    "owasp", "atlas", "difficulty", "complexity"}
        for p in STATIC_PAYLOADS:
            missing = required - set(p.keys())
            assert not missing, f"Payload {p.get('technique')} missing: {missing}"

    def test_difficulty_values_are_valid(self):
        valid = {"low", "medium", "high"}
        for p in STATIC_PAYLOADS:
            assert p["difficulty"] in valid, \
                f"Invalid difficulty '{p['difficulty']}' in {p['technique']}"

    def test_complexity_is_int_1_to_5(self):
        for p in STATIC_PAYLOADS:
            assert isinstance(p["complexity"], int)
            assert 1 <= p["complexity"] <= 5, \
                f"Complexity out of range in {p['technique']}: {p['complexity']}"

    def test_canary_placeholder_in_all_templates(self):
        for p in STATIC_PAYLOADS:
            assert "{CANARY}" in p["template"], \
                f"Missing {{CANARY}} in {p['technique']}"

    def test_objectives_are_objective_enum(self):
        for p in STATIC_PAYLOADS:
            assert isinstance(p["objective"], Objective), \
                f"Non-enum objective in {p['technique']}"

    def test_families_are_injection_family_enum(self):
        for p in STATIC_PAYLOADS:
            assert isinstance(p["family"], InjectionFamily)

    def test_technique_family_index_populated(self):
        for p in STATIC_PAYLOADS:
            assert p["technique"] in TECHNIQUE_FAMILY

    def test_markup_framing_payloads_are_direct(self):
        html = next((p for p in STATIC_PAYLOADS if p["technique"] == "html_comment_framing"), None)
        md   = next((p for p in STATIC_PAYLOADS if p["technique"] == "markdown_link_framing"), None)
        assert html is not None, "html_comment_framing not found"
        assert md   is not None, "markdown_link_framing not found"
        assert html["family"] == InjectionFamily.DIRECT
        assert md["family"]   == InjectionFamily.DIRECT

    def test_objective_diversity(self):
        objectives = {p["objective"] for p in STATIC_PAYLOADS}
        assert len(objectives) >= 8

    def test_all_difficulties_represented(self):
        difficulties = {p["difficulty"] for p in STATIC_PAYLOADS}
        assert {"low", "medium", "high"} == difficulties

class TestBuildApplicationPayloadsCapability:

    def test_retrieval_cap_yields_rag_payloads(self):
        cs = CapabilitySet(capabilities=[AppCapability.RETRIEVAL])
        payloads = build_application_payloads(ApplicationType.GENERIC, cs)
        assert any("rag" in p["technique"] or "retrieval" in p["technique"]
                   or p["objective"] == Objective.LEAK_RAG_CHUNK
                   for p in payloads)

    def test_tool_calling_cap_yields_tool_payloads(self):
        cs = CapabilitySet(capabilities=[AppCapability.TOOL_CALLING])
        payloads = build_application_payloads(ApplicationType.GENERIC, cs)
        assert any(p["objective"] == Objective.CALL_TOOL or "tool" in p["technique"]
                   for p in payloads)

    def test_memory_cap_yields_memory_payloads(self):
        cs = CapabilitySet(capabilities=[AppCapability.MEMORY])
        payloads = build_application_payloads(ApplicationType.GENERIC, cs)
        assert any(p["objective"] in (Objective.POISON_MEMORY, Objective.REVEAL_MEMORY)
                   for p in payloads)

    def test_code_execution_cap_yields_code_payloads(self):
        cs = CapabilitySet(capabilities=[AppCapability.CODE_EXECUTION])
        payloads = build_application_payloads(ApplicationType.GENERIC, cs)
        assert any(p["objective"] == Objective.EXEC_CODE for p in payloads)

    def test_email_cap_yields_email_payloads(self):
        cs = CapabilitySet(capabilities=[AppCapability.EMAIL_SEND])
        payloads = build_application_payloads(ApplicationType.GENERIC, cs)
        assert any(p["objective"] == Objective.SEND_EMAIL for p in payloads)

    def test_multi_agent_cap_yields_agentic_payloads(self):
        cs = CapabilitySet(capabilities=[AppCapability.MULTI_AGENT])
        payloads = build_application_payloads(ApplicationType.GENERIC, cs)
        assert any(p["family"] == InjectionFamily.AGENTIC for p in payloads)

    def test_multiple_caps_combine(self):
        cs = CapabilitySet(capabilities=[AppCapability.RETRIEVAL, AppCapability.MEMORY])
        payloads = build_application_payloads(ApplicationType.GENERIC, cs)
        objs = {p["objective"] for p in payloads}
        assert Objective.LEAK_RAG_CHUNK in objs or Objective.IGNORE_POLICY in objs
        assert Objective.POISON_MEMORY in objs or Objective.REVEAL_MEMORY in objs

    def test_cap_payloads_registered_in_technique_family(self):
        cs = CapabilitySet(capabilities=[AppCapability.RETRIEVAL])
        payloads = build_application_payloads(ApplicationType.GENERIC, cs)
        for p in payloads:
            assert p["technique"] in TECHNIQUE_FAMILY

class TestBuildApplicationPayloadsFallback:

    def test_customer_support_fallback(self):
        payloads = build_application_payloads(ApplicationType.CUSTOMER_SUPPORT, CapabilitySet())
        assert len(payloads) > 0
        assert any(p["objective"] in (Objective.IGNORE_POLICY, Objective.LEAK_TICKET)
                   for p in payloads)

    def test_rag_fallback(self):
        payloads = build_application_payloads(ApplicationType.RAG, CapabilitySet())
        assert any(p["objective"] == Objective.LEAK_RAG_CHUNK for p in payloads)

    def test_code_assistant_fallback(self):
        payloads = build_application_payloads(ApplicationType.CODE_ASSISTANT, CapabilitySet())
        assert any(p["objective"] == Objective.EXEC_CODE for p in payloads)

    def test_email_assistant_fallback(self):
        payloads = build_application_payloads(ApplicationType.EMAIL_ASSISTANT, CapabilitySet())
        assert any(p["objective"] == Objective.SEND_EMAIL for p in payloads)

    def test_financial_fallback(self):
        payloads = build_application_payloads(ApplicationType.FINANCIAL, CapabilitySet())
        assert any(p["objective"] == Objective.FINANCIAL_ACTION for p in payloads)

    def test_generic_with_no_caps_returns_empty(self):
        payloads = build_application_payloads(ApplicationType.GENERIC, CapabilitySet())
        assert payloads == []

    def test_none_capabilities_uses_fallback(self):
        payloads = build_application_payloads(ApplicationType.RAG, None)
        assert len(payloads) > 0

    def test_cap_path_takes_priority_over_fallback(self):
        cs = CapabilitySet(capabilities=[AppCapability.RETRIEVAL])
        payloads_cap = build_application_payloads(ApplicationType.CUSTOMER_SUPPORT, cs)
        payloads_no  = build_application_payloads(ApplicationType.CUSTOMER_SUPPORT, CapabilitySet())
        cap_objs = {p["objective"] for p in payloads_cap}
        assert Objective.LEAK_RAG_CHUNK in cap_objs or Objective.IGNORE_POLICY in cap_objs