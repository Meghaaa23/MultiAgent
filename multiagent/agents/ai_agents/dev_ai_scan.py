#!/usr/bin/env python3
"""
dev_ai_scan.py — local harness for AI scanning.

Modes
-----
  (default)     AI-only: fingerprint → infra → vuln → AVID
                (fast iteration; skips traditional web vulns)

  --with-web    Full single-phase scan via WebScannerAgent:
                  page capture → tech fingerprint → endpoint discovery
                  → AI fingerprint
                  → IF AI detected: AVID + AI vuln + AI infra
                  → ALWAYS: crawl + traditional web vulns + verify + merge

Production path is the same as --with-web (ThreatModelingAgent → WebScannerAgent).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(name)s — %(message)s")

# Allow running from multiagent/agents/ai_agents/
_HERE = os.path.dirname(os.path.abspath(__file__))
_AGENTS = os.path.dirname(_HERE)
_ROOT = os.path.dirname(_AGENTS)
for p in (_HERE, _AGENTS, _ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)


def get_openai_client():
    from openai import AzureOpenAI
    return AzureOpenAI(
        api_key=os.getenv("AZURE_OPENAI_API_KEY"),
        api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01"),
        azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    )


async def run_ai_only(target_url: str, agent: str, verbose: bool) -> None:
    from ai_fingerprint import AIFingerprintAgent
    from Ai_Infra_agent import AIInfraAgent
    from ai_vulnerability_test import AIVulnerabilityTester
    from avid_lookup_agent import AVIDLookupAgent
    from ai_scan_phase import run_ai_escalation_phase, should_escalate_ai

    fp_agent = AIFingerprintAgent(timeout=8)
    ai_fingerprint = await fp_agent.fingerprint(
        target_url=target_url,
        discovered_endpoints=[],
        page_html="",
        response_headers={},
        verbose=True,
    )

    print("\n========== RAW FINGERPRINT ==========")
    for k, v in ai_fingerprint.items():
        if isinstance(v, list):
            print(f"{k}: {len(v)} items")
        elif isinstance(v, dict):
            print(f"{k}: {len(v)} keys")
        else:
            print(f"{k}: {v}")

    print(f"\n  AI detected : {ai_fingerprint['is_ai_powered']} [{ai_fingerprint['confidence']}]")
    print(f"  Escalate    : {should_escalate_ai(ai_fingerprint)}")
    print(f"  ML endpoints: {ai_fingerprint['ml_endpoints']}")
    print("\nEvidence:")
    for item in ai_fingerprint.get("evidence_items") or []:
        print(f"  +{item['weight']:2d} {item['key']:<30} {item['detail']}")

    if agent == "fingerprint":
        return

    client = None
    try:
        client = get_openai_client()
    except Exception as exc:
        logging.warning("OpenAI client unavailable (%s) — infra/vuln may be limited", exc)

    llm_model = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")

    if agent == "all":
        # Same escalation policy as production WebScannerAgent.
        phase = await run_ai_escalation_phase(
            target_url=target_url,
            ai_fingerprint=ai_fingerprint,
            avid_lookup=AVIDLookupAgent(timeout=15),
            ai_vuln_tester=AIVulnerabilityTester(timeout=10, openai_client=client),
            ai_infra_agent=AIInfraAgent(openai_client=client, llm_model=llm_model, timeout=15),
            verbose=True,
        )
        if not phase["escalated"]:
            print("\n  AI escalation skipped (not AI-powered / weak signals).")
            return
        infra = phase.get("ai_infra_result")
        vuln = phase.get("ai_vuln_results") or {}
        avid = phase.get("avid_results") or {}
        print(f"\n  Infra threats: {len(getattr(infra, 'threats', []) or [])}")
        print(f"  Confirmed AI vulns: {len(vuln.get('confirmed_ai_vulns', []))}")
        print(f"  Potential AI vulns: {len(vuln.get('potential_ai_vulns', []))}")
        print(f"  AVID findings: {avid.get('total_found', 0)}")
        return

    # Individual agent selection (dev debugging).
    if agent == "infra":
        infra_agent = AIInfraAgent(openai_client=client, llm_model=llm_model, timeout=15)
        infra_result = await infra_agent.scan(target_url=target_url, ai_stack=ai_fingerprint)
        print(f"\n  Infra threats: {len(infra_result.threats)}")
        for t in infra_result.threats:
            print(f"  [{t.severity}] {t.attack_name} — {t.stride_category}")
        print(f"\n  Summary: {infra_result.summary}")

    if agent == "vuln":
        vuln_agent = AIVulnerabilityTester(timeout=10, openai_client=client)
        vuln_result = await vuln_agent.test_all(
            ai_fingerprint=ai_fingerprint, target_url=target_url, verbose=verbose,
        )
        print(f"\n  Confirmed: {len(vuln_result['confirmed_ai_vulns'])}")
        print(f"  Potential: {len(vuln_result['potential_ai_vulns'])}")

    if agent == "avid":
        avid_agent = AVIDLookupAgent(timeout=15)
        avid_result = await avid_agent.lookup(
            ai_fingerprint=ai_fingerprint,
            ml_stack=ai_fingerprint.get("ml_libraries", []),
            verbose=verbose,
        )
        print(f"\n  AVID findings: {avid_result['total_found']}")


async def run_with_web(target_url: str, verbose: bool, max_time: int) -> None:
    """Full single-phase scan: web vulns always + AI escalation if detected."""
    # Package import: multiagent/ must be on sys.path (set in main).
    from agents.webappscanner.web_scanner_agent import WebScannerAgent

    client = get_openai_client()
    llm_model = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
    scanner = WebScannerAgent(openai_client=client, llm_model=llm_model)
    result = await scanner.scan_application(
        target_url=target_url,
        max_time_minutes=max_time,
        verbose=True,
    )

    print("\n========== UNIFIED SCAN SUMMARY ==========")
    print(f"  Target        : {result.get('target_url')}")
    print(f"  Duration      : {result.get('scan_duration')}s")
    print(f"  AI powered    : {result.get('is_ai_powered')}")
    print(f"  Confirmed     : {result.get('confirmed_count')}")
    print(f"  Potential     : {result.get('potential_count')}")
    print(f"  Web+AI findings: {len(result.get('vulnerabilities') or [])}")
    if result.get("is_ai_powered"):
        fp = result.get("ai_fingerprint") or {}
        print(f"  Framework     : {fp.get('framework') or '(unknown)'}")
        print(f"  AVID findings : {len(result.get('avid_findings') or [])}")
        infra = result.get("ai_infrastructure") or {}
        print(f"  Infra threats : {infra.get('threat_count', 0)}")
    else:
        print("  AI escalation : skipped (traditional web scan only)")


async def main():
    parser = argparse.ArgumentParser(
        description="AI scan harness. Use --with-web for full web+AI single-phase scan.",
    )
    parser.add_argument("target", help="Live target URL")
    parser.add_argument(
        "--agent",
        choices=["fingerprint", "infra", "vuln", "avid", "all"],
        default="all",
        help="AI-only mode: which AI agent(s) to run (ignored with --with-web)",
    )
    parser.add_argument(
        "--with-web",
        action="store_true",
        help="Run full WebScannerAgent pipeline (web vulns + conditional AI escalation)",
    )
    parser.add_argument("--max-time", type=int, default=10, help="Web scan budget (minutes)")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    target_url = args.target.rstrip("/")
    if args.with_web:
        await run_with_web(target_url, verbose=args.verbose, max_time=args.max_time)
    else:
        await run_ai_only(target_url, agent=args.agent, verbose=args.verbose)


if __name__ == "__main__":
    asyncio.run(main())
