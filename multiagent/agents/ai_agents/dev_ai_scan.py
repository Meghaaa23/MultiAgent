# dev_ai_scan.py

import asyncio, argparse, json, os, logging
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(name)s — %(message)s")

from ai_fingerprint import AIFingerprintAgent
from Ai_Infra_agent       import AIInfraAgent
from ai_vulnerability_test       import AIVulnerabilityTester
from avid_lookup_agent    import AVIDLookupAgent
from chatbot_ui_probe     import (
    ChatbotUIProbe,
    widgets_to_chat_components,
)
from chatbot_ui_scope     import ScopePolicy
from openai import AzureOpenAI

def get_openai_client():
    return AzureOpenAI(
        api_key        = os.getenv("AZURE_OPENAI_API_KEY"),
        api_version    = os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01"),
        azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT"),
    )


async def _enrich_chatbot_ui(ai_fingerprint: dict, target_url: str,
                             auth_cookie: str, verbose: bool,
                             scope_policy=None) -> dict:
    """Detect on-page chatbot widgets (Playwright) and merge into fingerprint."""
    probe = ChatbotUIProbe(scope_policy=scope_policy or ScopePolicy())
    result = await probe.detect(
        target_url,
        html="",
        auth_cookie=auth_cookie,
        verbose=verbose,
    )
    if not result.widgets:
        return ai_fingerprint

    components = widgets_to_chat_components(result.widgets)
    existing = list(ai_fingerprint.get("chat_components") or [])
    # Prefer Playwright selectors; keep unique provider hints.
    merged = components + [
        c for c in existing
        if c.get("source") == "static_html"
        and c.get("provider")
        and not any(x.get("provider") == c.get("provider") for x in components)
    ]
    ai_fingerprint["chat_components"] = merged
    print(f"\n  Chatbot UI widgets: {len(merged)}")
    for w in merged[:5]:
        print(
            f"    - tier={w.get('tier') or '?'} ownership={w.get('ownership') or w.get('scope') or '?'} "
            f"policy={w.get('injection_policy') or '-'} "
            f"submit={w.get('submit_allowed')} provider={w.get('provider') or '-'} "
            f"via={w.get('source')}"
        )
    # Merge UI taxonomy evidence into fingerprint evidence list when present.
    evidence = list(ai_fingerprint.get("evidence_items") or [])
    existing_keys = {e.get("key") for e in evidence if isinstance(e, dict)}
    for w in merged:
        key = {
            "behavioral": "behavior_chatbot_ui_confirmed",
            "live_surface": "chatbot_ui_live_surface",
            "passive_structural": "chatbot_ui_structural",
            "passive_hint": "chatbot_ui_hint",
        }.get(w.get("tier") or "", "chatbot_ui_hint")
        if w.get("ownership") == "vendor_widget" or w.get("scope") == "third_party":
            key = "chatbot_ui_third_party"
        if key in existing_keys:
            continue
        evidence.append({
            "key": key,
            "detail": w.get("detail") or key,
            "source": "chatbot_ui",
            "weight": {"behavior_chatbot_ui_confirmed": 5,
                       "chatbot_ui_live_surface": 4,
                       "chatbot_ui_structural": 3}.get(key, 2),
            "evidence_class": {
                "behavior_chatbot_ui_confirmed": "behavioral",
                "chatbot_ui_live_surface": "live_surface",
                "chatbot_ui_structural": "passive_structural",
            }.get(key, "passive_hint"),
        })
        existing_keys.add(key)
    ai_fingerprint["evidence_items"] = evidence
    return ai_fingerprint


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Live target URL ")
    parser.add_argument("--agent", choices=["fingerprint","infra","vuln","avid","all"], default="all")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument(
        "--cookie",
        default="",
        help="Session cookie (session=...) or Bearer token (Bearer ...) supplied up front",
    )
    parser.add_argument(
        "--skip-chatbot-ui",
        action="store_true",
        help="Skip browser chatbot UI detection/injection",
    )
    parser.add_argument(
        "--include-thirdparty",
        action="store_true",
        help=(
            "Authorize active injection into known vendor chat widgets on a "
            "different eTLD+1 (Intercom/Drift/HubSpot-as-vendor/…). Default skips them."
        ),
    )
    parser.add_argument(
        "--authorize-external",
        action="store_true",
        help=(
            "Authorize active injection into non-vendor surfaces on a different "
            "registrable domain than the target (explicit client authorization)."
        ),
    )
    args = parser.parse_args()

    target_url = args.target.rstrip("/")
    auth_cookie = args.cookie or ""
    scope_policy = ScopePolicy(
        include_thirdparty=bool(args.include_thirdparty),
        authorize_external=bool(args.authorize_external),
    )

    fp_agent = AIFingerprintAgent(timeout=8)
    ai_fingerprint = await fp_agent.fingerprint(
        target_url           = target_url,
        discovered_endpoints = [],
        page_html            = "",
        response_headers     = {},
        verbose              = True,
        auth_cookie          = auth_cookie,
    )

    if not args.skip_chatbot_ui:
        ai_fingerprint = await _enrich_chatbot_ui(
            ai_fingerprint, target_url, auth_cookie, verbose=True,
            scope_policy=scope_policy,
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
    print(f"  Live surface: {ai_fingerprint.get('has_live_surface')}")
    print(f"  Brand only  : {ai_fingerprint.get('ai_brand_only')}")
    print(f"  Auth cookie : {'yes' if auth_cookie else 'no'}")
    print(f"  Chat UI     : {len(ai_fingerprint.get('chat_components') or [])} widget(s)")
    print(f"  Allowed hosts: {ai_fingerprint.get('allowed_api_hosts') or []}")
    print(f"  ML endpoints: {ai_fingerprint['ml_endpoints']}")
    print("\nEvidence:")

    for item in ai_fingerprint["evidence_items"]:
        print(
            f"  +{item['weight']:2d} "
            f"{item['key']:<30} "
            f"{item['detail']}"
        )

    if args.agent == "fingerprint":
        return

    has_live = bool(ai_fingerprint.get("has_live_surface"))
    try:
        from chatbot_ui_probe import ui_warrants_vuln
    except ImportError:
        from multiagent.agents.ai_agents.chatbot_ui_probe import ui_warrants_vuln
    has_ui = ui_warrants_vuln(ai_fingerprint.get("chat_components") or [])
    if not has_live and not has_ui and args.agent in ("infra", "vuln", "all"):
        print(
            "\n  No live AI surface / injectable chatbot UI — skipping infra / vuln "
            "escalation (vendor widgets default to policy-skip; weak DOM hints do "
            "not escalate; use --include-thirdparty / --authorize-external when "
            "explicitly authorized, or --agent avid for brand-only AVID)."
        )
        if args.agent != "avid":
            return

    if args.agent in ("infra", "all"):
        if not has_live:
            print("\n  No API live surface — skipping infra (chatbot UI alone does not imply exposed infra).")
        else:
            infra_agent = AIInfraAgent(openai_client=get_openai_client(), timeout=15)
            infra_agent.auth_cookie = auth_cookie
            infra_result = await infra_agent.scan(
                target_url = target_url,
                ai_stack   = ai_fingerprint,
            )
            print(f"\n  Infra threats: {len(infra_result.threats)}")
            for t in infra_result.threats:
                print(f"  [{t.severity}] {t.attack_name} — {t.stride_category}")
            print(f"\n  Summary: {infra_result.summary}")
            if infra_result.exposed_endpoints:
                ai_fingerprint = AIVulnerabilityTester.merge_exposed_endpoints(
                    ai_fingerprint, infra_result.exposed_endpoints)
                print(f"  Merged exposed endpoints: {infra_result.exposed_endpoints}")

    if args.agent in ("vuln", "all"):
        if not has_live and not has_ui:
            print("\n  Skipping vuln — nothing to inject against.")
        else:
            vuln_agent = AIVulnerabilityTester(timeout=10, scope_policy=scope_policy)
            vuln_result = await vuln_agent.test_all(
                ai_fingerprint=ai_fingerprint,
                target_url=target_url,
                verbose=args.verbose,
                auth_cookie=auth_cookie,
            )
            print(f"\n  Confirmed: {len(vuln_result.get('confirmed_ai_vulns') or [])}")
            print(f"  Potential: {len(vuln_result.get('potential_ai_vulns') or [])}")
            print(f"  Authenticated requests: {vuln_result.get('authenticated')}")
            for finding in (vuln_result.get("confirmed_ai_vulns") or [])[:5]:
                print(f"  [CONFIRMED] {finding.get('type')} @ {finding.get('location')}")
            for finding in (vuln_result.get("potential_ai_vulns") or [])[:5]:
                print(f"  [POTENTIAL] {finding.get('type')} @ {finding.get('location')}")

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
