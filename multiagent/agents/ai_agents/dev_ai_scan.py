#!/usr/bin/env python3
"""
dev_ai_scan.py — local harness to test AI agents individually.

Production scans go through WebScannerAgent (webappscanner), which already
calls these same AI agents inline when AI is detected.

This file is only for fast, AI-only iteration (no traditional web vulns).
"""

import asyncio
import argparse
import logging
import os

from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(name)s — %(message)s")

from ai_fingerprint import AIFingerprintAgent
from Ai_Infra_agent import AIInfraAgent
from ai_vulnerability_test import AIVulnerabilityTester
from avid_lookup_agent import AVIDLookupAgent
from openai import AzureOpenAI


def get_openai_client():
    return AzureOpenAI(
        api_key=os.getenv("AZURE_OPENAI_API_KEY"),
        api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01"),
        azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    )


async def main():
    parser = argparse.ArgumentParser(
        description="AI-only agent harness (use frontend /scan or WebScannerAgent for full web+AI).",
    )
    parser.add_argument("target", help="Live target URL")
    parser.add_argument(
        "--agent",
        choices=["fingerprint", "infra", "vuln", "avid", "all"],
        default="all",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    target_url = args.target.rstrip("/")

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
    print(f"  ML endpoints: {ai_fingerprint['ml_endpoints']}")
    print("\nEvidence:")
    for item in ai_fingerprint.get("evidence_items") or []:
        print(f"  +{item['weight']:2d} {item['key']:<30} {item['detail']}")

    if args.agent == "fingerprint":
        return

    client = None
    try:
        client = get_openai_client()
    except Exception as exc:
        logging.warning("OpenAI client unavailable (%s)", exc)

    llm_model = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")

    if args.agent in ("infra", "all"):
        infra_agent = AIInfraAgent(openai_client=client, llm_model=llm_model, timeout=15)
        infra_result = await infra_agent.scan(
            target_url=target_url,
            ai_stack=ai_fingerprint,
        )
        print(f"\n  Infra threats: {len(infra_result.threats)}")
        for t in infra_result.threats:
            print(f"  [{t.severity}] {t.attack_name} — {t.stride_category}")
        print(f"\n  Summary: {infra_result.summary}")

    if args.agent in ("vuln", "all"):
        vuln_agent = AIVulnerabilityTester(timeout=10, openai_client=client)
        vuln_result = await vuln_agent.test_all(
            ai_fingerprint=ai_fingerprint,
            target_url=target_url,
            verbose=args.verbose,
        )
        print(f"\n  Confirmed: {len(vuln_result['confirmed_ai_vulns'])}")
        print(f"  Potential: {len(vuln_result['potential_ai_vulns'])}")

    if args.agent in ("avid", "all"):
        ml_stack = ai_fingerprint.get("ml_libraries", [])
        avid_agent = AVIDLookupAgent(timeout=15)
        avid_result = await avid_agent.lookup(
            ai_fingerprint=ai_fingerprint,
            ml_stack=ml_stack,
            verbose=args.verbose,
        )
        print(f"\n  AVID findings: {avid_result['total_found']}")


if __name__ == "__main__":
    asyncio.run(main())
