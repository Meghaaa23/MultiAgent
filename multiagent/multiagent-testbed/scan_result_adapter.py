#!/usr/bin/env python3
"""
scan_result_adapter.py — bridges WebScannerAgent.scan_application()'s real
output shape to the run-result shape metrics.py consumes.

This exists because the two shapes genuinely don't match and reconciling
them was left as an open item when metrics.py was written:
  - metrics.py wants a flat `ai_surfaces: [{url, tier, auth_gated}, ...]`
  - the scanner's actual output has no such list. The closest things are:
      ai_fingerprint.evidence_items  — [{endpoint, evidence_class, weight, ...}]
        (per-URL, tier-bearing — this is the real source of ai_surfaces)
      ai_fingerprint.classified_endpoints — [{url, type, risk, auth_required}]
        (a DIFFERENT taxonomy: functional type/risk, not EvidenceClass tier —
        not used for `tier` here, only cross-referenced for auth_required)
      ai_fingerprint.auth_required_paths — [{endpoint, auth_type, status_code}]
      eval_metrics — aggregate COUNTS, not a list
        (used for injection.attempted/confirmed/potential)

Rather than changing the scanner's core return shape (used by report
rendering, regression_eval.py, and main.py's API response — much larger
blast radius) or changing metrics.py's field names (would make it diverge
from SCHEMA.md's documented ai_endpoints_true tier vocabulary), this is a
pure, additive translation layer. Nothing it reads is mutated.

Usage:
    from scan_result_adapter import to_metrics_run
    run = to_metrics_run(scan_result_dict, target="flowise")
    json.dump(run, open("runs/flowise_r1.json", "w"))

    scan_result_adapter.py --selftest
"""

from __future__ import annotations

import argparse
import json
import sys


def _dedupe_evidence_items(evidence_items: list[dict]) -> dict[str, dict]:
    """One entry per endpoint, keeping the highest-weight evidence for it.

    evidence_items is already sorted by weight descending (see
    AIFingerprintReport.to_dict()), so first-seen-per-endpoint wins without
    needing to re-sort here — but re-sorting defensively costs nothing and
    doesn't assume that ordering is preserved through JSON round-trips.
    """
    ranked = sorted(evidence_items or [], key=lambda e: e.get("weight", 0), reverse=True)
    out: dict[str, dict] = {}
    for e in ranked:
        ep = (e.get("endpoint") or "").strip()
        if not ep or ep in out:
            continue
        out[ep] = e
    return out


def _auth_gated_urls(ai_fp: dict) -> set[str]:
    urls = {a.get("endpoint", "") for a in (ai_fp.get("auth_required_paths") or [])}
    urls |= {
        c.get("url", "") for c in (ai_fp.get("classified_endpoints") or [])
        if c.get("auth_required")
    }
    urls.discard("")
    return urls


def to_metrics_run(scan_result: dict, target: str) -> dict:
    """Translate one scan_application() output dict into metrics.py's run shape."""
    ai_fp = scan_result.get("ai_fingerprint") or {}
    eval_metrics = scan_result.get("eval_metrics") or {}
    coverage_assessment = scan_result.get("coverage_assessment") or {}
    endpoints_discovered = scan_result.get("endpoints_discovered") or []

    by_endpoint = _dedupe_evidence_items(ai_fp.get("evidence_items") or [])
    gated = _auth_gated_urls(ai_fp)

    ai_surfaces = [
        {
            "url": url,
            "tier": item.get("evidence_class") or None,
            "auth_gated": url in gated,
            "reachable": url not in gated,
        }
        for url, item in by_endpoint.items()
    ]

    # Endpoints present in ml_endpoints but with no matching evidence_item
    # (shouldn't normally happen, but ml_endpoints and evidence_items are
    # populated by different code paths — don't silently drop a claimed
    # surface just because it lacks a tier).
    seen = set(by_endpoint)
    for url in (ai_fp.get("ml_endpoints") or []):
        if url and url not in seen:
            ai_surfaces.append({
                "url": url, "tier": None,
                "auth_gated": url in gated, "reachable": url not in gated,
            })
            seen.add(url)

    paths_excluded = sum(
        1 for e in endpoints_discovered
        if e.get("excluded") or e.get("exclude_reason")
    )
    auth_gated_count = int(coverage_assessment.get("auth_gated_count") or 0)
    auth_state = coverage_assessment.get("note") or (
        f"{auth_gated_count} auth-gated endpoint(s) not assessed"
        if auth_gated_count else ""
    )

    return {
        "target": target,
        "url": scan_result.get("target_url", ""),
        "commit_sha": None,
        "run_index": None,
        "wall_time_s": scan_result.get("scan_duration"),
        "ai_surfaces": ai_surfaces,
        "findings": scan_result.get("vulnerabilities") or [],
        "endpoints": endpoints_discovered,
        "coverage": {
            "auth_state": auth_state,
            "paths_excluded": paths_excluded,
            "functional_endpoints": coverage_assessment.get("assessed_count"),
            "coverage_percent": coverage_assessment.get("coverage_percent"),
        },
        "injection": {
            "attempted": int(eval_metrics.get("prompt_injection_attempted") or 0),
            "confirmed": int(eval_metrics.get("prompt_injection_confirmed") or 0),
            "potential": int(eval_metrics.get("prompt_injection_potential") or 0),
        },
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in", dest="infile", help="raw scan_application() JSON output")
    ap.add_argument("--target", help="ground-truth target id, e.g. flowise")
    ap.add_argument("--out", help="write adapted run JSON here (default: stdout)")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)

    if a.selftest:
        return selftest()

    if not (a.infile and a.target):
        ap.error("supply --in and --target, or --selftest")

    with open(a.infile) as fh:
        scan_result = json.load(fh)
    run = to_metrics_run(scan_result, a.target)
    js = json.dumps(run, indent=2, sort_keys=True)
    if a.out:
        with open(a.out, "w") as fh:
            fh.write(js)
        print(f"wrote {a.out}")
    else:
        print(js)
    return 0


def selftest():
    """Synthetic scan_application()-shaped input, built from the real field
    names/nesting confirmed in web_scanner_agent.py and
    AIFingerprintReport.to_dict() — not a guessed shape."""
    fails = []

    def check(name, got, want):
        if got != want:
            fails.append(f"{name}: got {got!r} want {want!r}")

    scan_result = {
        "target_url": "http://localhost:3100",
        "scan_duration": 123.4,
        "endpoints_discovered": [
            {"url": "http://localhost:3100/api/prediction/abc", "interesting": True},
            {"url": "http://localhost:3100/api/admin", "excluded": True,
             "exclude_reason": "SPA/soft-404 shell — not a real endpoint"},
        ],
        "coverage_assessment": {
            "assessed_count": 2, "auth_gated_count": 1,
            "coverage_percent": 50.0, "note": "1 auth-gated endpoint not assessed",
        },
        "eval_metrics": {
            "prompt_injection_attempted": 3,
            "prompt_injection_confirmed": 0,
            "prompt_injection_potential": 1,
        },
        "vulnerabilities": [
            {"type": "Missing CSP", "location": "http://localhost:3100/",
             "status": "Confirmed", "evidence": {"confidence": "High"}},
        ],
        "ai_fingerprint": {
            "ml_endpoints": ["http://localhost:3100/api/prediction/abc"],
            "evidence_items": [
                {"key": "ml_endpoint_200", "detail": "live prediction endpoint",
                 "weight": 4, "evidence_class": "live_surface", "source": "probe",
                 "endpoint": "http://localhost:3100/api/prediction/abc", "framework": ""},
                {"key": "framework_identified", "detail": "Flowise header",
                 "weight": 1, "evidence_class": "brand", "source": "header",
                 "endpoint": "", "framework": "Flowise"},
            ],
            "auth_required_paths": [
                {"endpoint": "http://localhost:3100/api/admin",
                 "auth_type": "session", "status_code": 401, "detail": ""},
            ],
            "classified_endpoints": [],
        },
    }

    run = to_metrics_run(scan_result, target="flowise")
    check("target", run["target"], "flowise")
    check("wall_time_s", run["wall_time_s"], 123.4)
    check("n_surfaces", len(run["ai_surfaces"]), 1)
    check("surface_url", run["ai_surfaces"][0]["url"],
          "http://localhost:3100/api/prediction/abc")
    check("surface_tier", run["ai_surfaces"][0]["tier"], "live_surface")
    check("surface_not_gated", run["ai_surfaces"][0]["auth_gated"], False)
    check("paths_excluded", run["coverage"]["paths_excluded"], 1)
    check("auth_state_declared", bool(run["coverage"]["auth_state"]), True)
    check("injection_attempted", run["injection"]["attempted"], 3)
    check("n_findings", len(run["findings"]), 1)

    # a brand-only evidence item (no endpoint) must not become a fake AI surface
    check("no_brand_leak", any(s["tier"] == "brand" for s in run["ai_surfaces"]), False)

    # cross-check against metrics.py using the real adapter output end-to-end
    try:
        import metrics
        gt = {
            "target": "flowise",
            "ai_surface": {
                "has_ai_surface": "yes",
                "ai_auth_gated": False,
                "ai_endpoints_true": [
                    {"url": "http://localhost:3100/api/prediction/abc",
                     "tier": "live_surface", "routes_without_config": True},
                ],
            },
        }
        graded = metrics.grade_target(gt, [run])
        check("e2e.recall", graded["recall_strict"], 1.0)
        check("e2e.overclaim", graded["overclaim_rate"], 0.0)
    except ImportError:
        print("(metrics.py not importable from this cwd — skipped e2e check)")

    if fails:
        print("SELFTEST FAILED")
        for f in fails:
            print("  " + f)
        return 1
    print("selftest: adapter OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
