"""Security header + Server disclosure report integrity."""
import asyncio
from multiagent.agents.webappscanner.action_agent import ActionAgent
from multiagent.agents.webappscanner.vulnerability_tester import (
    DEPRECATED_SECURITY_HEADERS,
    _hsts_applicable,
    _should_report_missing_header,
    _server_header_is_leaky,
)
from multiagent.agents.webappscanner.attack_verification_agent import (
    AttackVerificationAgent,
    VulnStatus,
)


def test_hsts_skipped_on_http_localhost():
    assert _hsts_applicable("http://localhost:3119") is False
    assert _hsts_applicable("https://localhost:3119") is False
    assert _hsts_applicable("https://app.example.com") is True
    assert _should_report_missing_header(
        "Strict-Transport-Security", "http://localhost:3119"
    ) is False
    assert _should_report_missing_header(
        "X-XSS-Protection", "https://app.example.com"
    ) is False
    assert _should_report_missing_header(
        "Content-Security-Policy", "http://localhost:3119"
    ) is True
    assert "X-XSS-Protection" in DEPRECATED_SECURITY_HEADERS


def test_server_header_evidence_fallback_from_finding():
    """§3b must show Captured value when shared headers were not passed."""
    agent = ActionAgent.__new__(ActionAgent)
    out = agent._action_info_disclosure_header(
        "Information Disclosure: server header",
        "http://localhost:3119",
        ["apache"],
        response_headers={},  # ThreatModelingAgent used to omit these
        evidence={
            "confirmation_method": "header",
            "response_headers": {"server": "Apache/2.4.58 (Ubuntu)"},
        },
        details="server: Apache/2.4.58 (Ubuntu)",
    )
    assert out is not None
    assert out["evidence_captured"] is True
    assert "NO EVIDENCE CAPTURED" not in out["attack_poc"]
    assert "Apache/2.4.58" in out["attack_poc"]
    assert "ServerTokens Prod" in out["fix_snippet"]
    assert "Header unset Server" in out["fix_snippet"]


def test_server_header_suppressed_without_any_evidence():
    agent = ActionAgent.__new__(ActionAgent)
    out = agent._action_info_disclosure_header(
        "Information Disclosure: server header",
        "http://localhost:3119",
        ["apache"],
        response_headers={},
        evidence={},
        details="",
    )
    assert out is None


def test_non_leaky_server_suppressed():
    assert _server_header_is_leaky("Apache") is False
    assert _server_header_is_leaky("Apache/2.4.58 (Ubuntu)") is True
    agent = ActionAgent.__new__(ActionAgent)
    out = agent._action_info_disclosure_header(
        "Information Disclosure: server header",
        "http://localhost:3119",
        ["apache"],
        response_headers={"server": "Apache"},
        evidence={},
    )
    assert out is None


def test_reconcile_downgrades_unconfirmed_server_finding():
    confirmed = [{
        "type": "Information Disclosure: server header",
        "status": "Confirmed",
        "severity": "Low",
        "location": "http://localhost:3119",
        "details": "",
        "evidence": {},
    }]
    potential = []
    actions = []  # ActionAgent suppressed — no evidence
    confirmed2, potential2 = ActionAgent.reconcile_server_header_evidence(
        confirmed, potential, actions, {}
    )
    assert confirmed2 == []
    assert len(potential2) == 1
    assert potential2[0]["status"] == "Potential"


def test_reconcile_keeps_evidenced_server_finding():
    confirmed = [{
        "type": "Information Disclosure: server header",
        "status": "Confirmed",
        "severity": "Low",
        "location": "http://localhost:3119",
        "details": "server: Apache/2.4.58",
        "evidence": {"response_headers": {"server": "Apache/2.4.58"}},
    }]
    actions = [{
        "finding_type": "Information Disclosure: server header",
        "evidence_captured": True,
        "severity": "Low",
        "location": "http://localhost:3119",
        "attack_poc": "Captured: Server: Apache/2.4.58",
        "poc_type": "curl",
        "fix_snippet": "ServerTokens Prod",
        "fix_language": "apache",
        "fix_context": "httpd.conf",
        "effort_minutes": 5,
    }]
    confirmed2, potential2 = ActionAgent.reconcile_server_header_evidence(
        confirmed, [], actions, {"server": "Apache/2.4.58"}
    )
    assert len(confirmed2) == 1
    assert potential2 == []


def test_av_case_insensitive_missing_headers_and_no_hsts_on_localhost():
    agent = AttackVerificationAgent(openai_client=None, llm_model="test")

    async def _run():
        return await agent._check_security_headers(
            "http://localhost:3119",
            shared_headers={
                # lowercase keys as produced by WebScannerAgent._sync_headers
                "server": "Apache/2.4.58 (Ubuntu)",
                "content-type": "text/html",
            },
        )

    findings = asyncio.run(_run())
    types = [f.vuln_type for f in findings]
    assert "Missing Security Header: Content-Security-Policy" in types
    assert "Missing Security Header: X-Content-Type-Options" in types
    assert "Missing Security Header: Strict-Transport-Security" not in types
    assert any("server" in f.vuln_type.lower() for f in findings)
    server = next(f for f in findings if "server" in f.vuln_type.lower())
    assert server.status == VulnStatus.CONFIRMED
    assert "Apache/2.4.58" in str(server.evidence.response_headers)


def test_process_all_recovers_server_from_finding_evidence():
    """ThreatModelingAgent path: process_all without shared headers still works."""
    findings = [{
        "type": "Information Disclosure: server header",
        "status": "Confirmed",
        "severity": "Low",
        "location": "http://localhost:3119",
        "details": "server: Apache/2.4.58 (Ubuntu)",
        "evidence": {
            "confirmation_method": "header",
            "response_headers": {"Server": "Apache/2.4.58 (Ubuntu)"},
        },
    }]
    actions = ActionAgent().process_all(
        findings,
        "http://localhost:3119",
        {"technologies": ["Apache/2.4.58"], "stack_summary": "Apache/2.4.58"},
        response_headers=None,
    )
    assert len(actions) == 1
    assert actions[0]["evidence_captured"] is True
    assert "Apache/2.4.58" in actions[0]["attack_poc"]
    assert "NO EVIDENCE CAPTURED" not in actions[0]["attack_poc"]


def test_apache_http_server_dict_yields_apache_fix_snippets():
    """Wappalyzer-style 'Apache HTTP Server' must map to apache Header fixes."""
    agent = ActionAgent()
    stack = {
        "technologies": [{
            "name": "Apache HTTP Server",
            "version": "2.4.58",
            "category": "Server",
            "confidence": 0.95,
        }],
        "stack_summary": "Apache HTTP Server 2.4.58",
        "server": "Apache HTTP Server 2.4.58",
    }
    keywords = agent._infer_stack_keywords(stack)
    assert "apache" in keywords
    assert agent._best_stack_for_header(keywords) == "apache"

    findings = [
        {
            "type": "Missing Security Header: Content-Security-Policy",
            "status": "Confirmed",
            "severity": "Medium",
            "location": "http://localhost:3119",
            "evidence": {"response_status": 200, "confirmation_method": "header"},
        },
        {
            "type": "Information Disclosure: server header",
            "status": "Confirmed",
            "severity": "Low",
            "location": "http://localhost:3119",
            "details": "server: Apache/2.4.58 (Ubuntu)",
            "evidence": {
                "confirmation_method": "header",
                "response_headers": {"server": "Apache/2.4.58 (Ubuntu)"},
            },
        },
    ]
    actions = agent.process_all(
        findings,
        "http://localhost:3119",
        stack,
        response_headers={
            "server": "Apache/2.4.58 (Ubuntu)",
            "content-type": "text/html",
        },
    )
    by_type = {a["finding_type"]: a for a in actions}
    csp = by_type["Missing Security Header: Content-Security-Policy"]
    assert csp["fix_language"] == "apache"
    assert "Header always set Content-Security-Policy" in csp["fix_snippet"]
    assert csp["fix_context"] == "httpd.conf or .htaccess"

    server = by_type["Information Disclosure: server header"]
    assert server["fix_language"] == "apache"
    assert "ServerTokens Prod" in server["fix_snippet"]
    assert server["fix_context"] == "httpd.conf"
