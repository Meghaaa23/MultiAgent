"""
Shared AI escalation phase used by WebScannerAgent (production) and
dev_ai_scan.py (local harness).

Policy (professor / product rule):
  - Traditional web scanning always runs.
  - AI-specific tests (AVID, prompt-injection, infra) escalate ONLY when
    the fingerprint confirms an AI-powered application.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_CONFIDENCE_RANK = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "very_high": 4,
}


def should_escalate_ai(ai_fingerprint: Optional[Dict]) -> bool:
    """Return True when AI-specific agents should run after fingerprinting.

    Requires fingerprint.is_ai_powered plus either high confidence or at
    least one concrete ML endpoint / AI header signal.
    """
    if not ai_fingerprint:
        return False
    if not ai_fingerprint.get("is_ai_powered"):
        return False
    confidence = str(ai_fingerprint.get("confidence") or "none").lower()
    has_concrete = bool(
        ai_fingerprint.get("ml_endpoints")
        or ai_fingerprint.get("ai_headers")
        or ai_fingerprint.get("auth_required_paths")
        or ai_fingerprint.get("framework")
    )
    return _CONFIDENCE_RANK.get(confidence, 0) >= 3 or has_concrete


def infra_threats_as_findings(ai_infra_result: Any) -> List[Dict]:
    """Normalize AIInfraAgent threats into the web-scanner finding shape."""
    if not ai_infra_result or not getattr(ai_infra_result, "threats", None):
        return []
    out: List[Dict] = []
    for t in ai_infra_result.threats:
        status = getattr(t, "status", "Potential") or "Potential"
        if status == "Surface":
            status = "Potential"
        out.append({
            "type":       getattr(t, "attack_name", "AI Infrastructure Finding"),
            "severity":   getattr(t, "severity", "Medium"),
            "status":     status if status in ("Confirmed", "Potential") else "Potential",
            "location":   (getattr(t, "evidence", None) or {}).get("endpoint")
                          if isinstance(getattr(t, "evidence", None), dict)
                          else getattr(ai_infra_result, "target_url", ""),
            "details":    getattr(t, "description", ""),
            "category":   "ai_infrastructure",
            "atlas":      getattr(t, "atlas_technique", ""),
            "remediation": getattr(t, "mitigation", ""),
            "evidence":   getattr(t, "evidence", {}),
            "stride":     getattr(t, "stride_category", ""),
        })
    return out


async def run_ai_escalation_phase(
    *,
    target_url: str,
    ai_fingerprint: Dict,
    avid_lookup,
    ai_vuln_tester,
    ai_infra_agent,
    verbose: bool = False,
) -> Dict[str, Any]:
    """Run AVID + AI vuln + AI infra when escalation is warranted.

    Returns a dict with keys:
      escalated, avid_results, ai_vuln_results, ai_infra_result, findings
    """
    result: Dict[str, Any] = {
        "escalated": False,
        "avid_results": None,
        "ai_vuln_results": None,
        "ai_infra_result": None,
        "findings": [],
    }

    if not should_escalate_ai(ai_fingerprint):
        if verbose:
            raw = bool(ai_fingerprint.get("is_ai_powered"))
            conf = ai_fingerprint.get("confidence", "none")
            if raw:
                print(f"  Weak AI signals (confidence: {conf}) — skipping AI escalation\n")
            else:
                print("  No AI/ML components detected — AI-specific tests skipped\n")
        return result

    result["escalated"] = True
    if verbose:
        print(f"  AI-powered app detected [{ai_fingerprint.get('confidence')} confidence]")
        print(f"     Framework   : {ai_fingerprint.get('framework') or '(unknown)'}")
        print(f"     ML endpoints: {(ai_fingerprint.get('ml_endpoints') or [])[:3]}\n")

    # --- AVID ---
    try:
        if verbose:
            print("  Querying AVID database for AI vulnerabilities...")
        ml_stack = list(ai_fingerprint.get("ml_libraries") or [])
        for ep in (ai_fingerprint.get("ml_endpoints") or [])[:3]:
            ml_stack.append(str(ep).rstrip("/").split("/")[-1])
        avid_results = await avid_lookup.lookup(
            ai_fingerprint=ai_fingerprint, ml_stack=ml_stack, verbose=verbose,
        )
        result["avid_results"] = avid_results
        if verbose:
            print(f"   AVID: {avid_results.get('total_found', 0)} findings "
                  f"({len(avid_results.get('backdoor_relevant', []))} backdoor-relevant)\n")
    except Exception as exc:
        logger.warning("AVID lookup failed: %s", exc)

    # --- Prompt-injection / AI vuln tests ---
    try:
        if verbose:
            print("  Running AI-specific vulnerability tests...")
        ai_vuln_results = await ai_vuln_tester.test_all(
            ai_fingerprint=ai_fingerprint, target_url=target_url, verbose=verbose,
        )
        result["ai_vuln_results"] = ai_vuln_results
        for f in ai_vuln_results.get("confirmed_ai_vulns", []) or []:
            f.setdefault("category", "ai_vulnerability")
            result["findings"].append(f)
        for f in ai_vuln_results.get("potential_ai_vulns", []) or []:
            f.setdefault("category", "ai_vulnerability")
            result["findings"].append(f)
        if verbose:
            c = len(ai_vuln_results.get("confirmed_ai_vulns", []) or [])
            p = len(ai_vuln_results.get("potential_ai_vulns", []) or [])
            s = len(ai_vuln_results.get("strategic_recommendations", []) or [])
            print(f"   AI vulns: {c} confirmed, {p} potential")
            print(f"   Strategic recommendations: {s} ATLAS-based\n")
    except Exception as exc:
        logger.warning("AI vulnerability tests failed: %s", exc)

    # --- AI infrastructure ---
    try:
        if verbose:
            print("  AI Infrastructure Build Attack Analysis...")
        ai_infra_result = await ai_infra_agent.scan(
            target_url=target_url, ai_stack=ai_fingerprint,
        )
        result["ai_infra_result"] = ai_infra_result
        result["findings"].extend(infra_threats_as_findings(ai_infra_result))
        if verbose:
            n = len(getattr(ai_infra_result, "threats", []) or [])
            print(f"   AI Infra threats: {n} total\n")
    except Exception as exc:
        logger.warning("AIInfraAgent failed: %s", exc)

    return result
