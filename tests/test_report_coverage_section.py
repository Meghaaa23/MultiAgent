"""Section 7 surfaces all crawl data (URLs, forms, nav graph, test attempts) in
the report, the log-style detail the competitors print."""
import os
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "multiagent"))

from multiagent.agents.threat_modeling_agent import _build_section_7_coverage


def _sr():
    return {
        "tasks_generated": 40, "tasks_executed": 38,
        "eval_metrics": {"nav_states": 59, "nav_edges": 120, "nav_unique_urls": 85,
                         "interstate_flows": 2, "interstate_unescaped": 1,
                         "xss_attempted": 7, "xss_confirmed": 1, "xss_potential": 0,
                         "prompt_injection_attempted": 3, "prompt_injection_confirmed": 1,
                         "prompt_injection_potential": 0},
        "coverage_assessment": {"coverage_percent": 72.0, "assessed_count": 18,
                                "discovered_count": 25},
        "discovered_urls": [f"http://h/p{i}" for i in range(200)],
        "discovered_forms": [{"action": "http://h/search", "method": "get",
                              "fields": ["q"]}],
        "endpoints_discovered": [{"url": "http://h/api/x", "interesting": True,
                                  "category": "api"}],
    }


def test_section_includes_crawl_and_graph():
    out = _build_section_7_coverage(_sr())
    assert "SCAN COVERAGE" in out
    assert "40 task(s) generated" in out
    assert "59 state(s)" in out and "85 unique URL(s)" in out
    assert "Inter-state flows: 2" in out


def test_section_lists_urls_forms_attempts():
    out = _build_section_7_coverage(_sr())
    assert "Discovered URLs (200)" in out
    assert "and 50 more" in out                      # capped at 150
    assert "[GET] http://h/search" in out
    assert "Prompt injection: 3 / 1 / 0" in out
    assert "XSS: 7 / 1 / 0" in out
    assert "http://h/api/x" in out


def test_section_handles_empty_scan():
    out = _build_section_7_coverage({})
    assert "SCAN COVERAGE" in out
    assert "Discovered URLs (0)" in out


def test_section_none_is_safe():
    out = _build_section_7_coverage(None)
    assert "SCAN COVERAGE" in out
