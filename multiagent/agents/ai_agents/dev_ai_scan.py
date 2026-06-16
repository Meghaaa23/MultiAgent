# dev_ai_scan.py

import asyncio, argparse, json, os, logging
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(name)s — %(message)s")

from ai_fingerprint import AIFingerprintAgent
from Ai_Infra_agent       import AIInfraAgent
from ai_vulnerability_test       import AIVulnerabilityTester
from avid_lookup_agent    import AVIDLookupAgent
from openai import AzureOpenAI

def get_openai_client():
    return AzureOpenAI(
        api_key        = os.getenv("AZURE_OPENAI_API_KEY"),
        api_version    = os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01"),
        azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT"),
    )

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Live target URL ")
    parser.add_argument("--agent", choices=["fingerprint","infra","vuln","avid","all"], default="all")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    target_url = args.target.rstrip("/")


    fp_agent = AIFingerprintAgent(timeout=8)
    ai_fingerprint = await fp_agent.fingerprint(
        target_url           = target_url,
        discovered_endpoints = [],   
        page_html            = "",   
        response_headers     = {},   
        verbose              = True,
    )

    print(f"\n  AI detected : {ai_fingerprint['is_ai_powered']} [{ai_fingerprint['confidence']}]")
    print(f"  ML endpoints: {ai_fingerprint['ml_endpoints']}")
    print(f"  Evidence    : {ai_fingerprint['evidence']}")

    if args.agent == "fingerprint":
        return

   
    if args.agent in ("infra", "all"):
        infra_agent = AIInfraAgent(openai_client=get_openai_client(), timeout=15)
        infra_result = await infra_agent.scan(
            target_url = target_url,
            ai_stack   = ai_fingerprint,  
        )
        print(f"\n  Infra threats: {len(infra_result.threats)}")
        for t in infra_result.threats:
            print(f"  [{t.severity}] {t.attack_name} — {t.stride_category}")
        print(f"\n  Summary: {infra_result.summary}")

    
    if args.agent in ("vuln", "all"):
        vuln_agent = AIVulnerabilityTester(timeout=10)
        vuln_result = await vuln_agent.test_all(
            ai_fingerprint = ai_fingerprint,
            target_url     = target_url,
            verbose        = args.verbose,
        )
        print(f"\n  Confirmed: {len(vuln_result['confirmed_ai_vulns'])}")
        print(f"  Potential: {len(vuln_result['potential_ai_vulns'])}")

  
    if args.agent in ("avid", "all"):
        ml_stack = ai_fingerprint.get("ml_libraries", [])
        avid_agent = AVIDLookupAgent(timeout=15)
        avid_result = await avid_agent.lookup(
            ai_fingerprint = ai_fingerprint,
            ml_stack       = ml_stack,
            verbose        = args.verbose,
        )
        print(f"\n  AVID findings: {avid_result['total_found']}")

if __name__ == "__main__":
    asyncio.run(main())