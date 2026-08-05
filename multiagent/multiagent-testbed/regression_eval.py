#!/usr/bin/env python3
"""
regression_eval.py — Ground-truth regression harness (precision-first).

Operating point (stated, durable):
  - Optimize precision; report recall honestly under black-box unauth scope.
  - Auth-gated surfaces → not_assessed (never FN).
  - must_not_report hits → hard FP (fail).
  - required expected findings missed → FN (fail under --strict).

Usage:
  # Score a saved /scan/ JSON against a ground-truth file
  python3 regression_eval.py --fixture results/dvwa_scan.json --truth ground_truth/dvwa.json

  # Score golden fixtures (must PASS) + negative FP fixtures (must FAIL)
  python3 regression_eval.py --fixtures-dir fixtures/golden
  python3 regression_eval.py --fixtures-dir fixtures/negative --expect-fail

  # Live scan (requires scanner + target up)
  python3 regression_eval.py --live dvwa --url http://localhost:3142

  # CI gate: exit 1 on must_not violations or required FNs
  python3 regression_eval.py --fixtures-dir fixtures/golden --strict
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = Path(__file__).parent
TRUTH_DIR = SCRIPT_DIR / "ground_truth"
FIXTURES_DIR = SCRIPT_DIR / "fixtures"
RESULTS_DIR = SCRIPT_DIR / "results"
RESULTS_DIR.mkdir(exist_ok=True)

SCANNER_BASE_URL = "http://localhost:8000"
SCANNER_TIMEOUT = 300

# ---------------------------------------------------------------------------
# Type normalisation
# ---------------------------------------------------------------------------

_NORM_MAP = [
    ("sql injection (time-based", "sqli-timing"),
    ("sql injection", "sqli"),
    ("sqli", "sqli"),
    ("cross-site scripting", "xss"),
    ("stored/reflected xss", "xss"),
    ("reflected xss", "xss"),
    ("xss", "xss"),
    ("missing csrf", "csrf"),
    ("csrf", "csrf"),
    ("cors misconfiguration", "cors"),
    ("cors", "cors"),
    ("missing security header: content-security-policy", "missing_header"),
    ("missing security header: x-content-type-options", "missing_header"),
    ("missing security header: x-frame-options", "missing_header"),
    ("missing security header", "missing_header"),
    ("content-security-policy", "missing_header"),
    ("x-content-type-options", "missing_header"),
    ("information disclosure: server", "server_header"),
    ("server header", "server_header"),
    ("clickjacking", "clickjacking"),
    ("unauthenticated admin", "unauthenticated-access"),
    ("unauthenticated", "unauthenticated-access"),
    ("sensitive file exposed", "unauthenticated-access"),
    ("admin configuration", "unauthenticated-access"),
    ("open redirect", "open-redirect"),
    ("authenticated_scan", "authenticated_scan"),
    ("authenticated scan", "authenticated_scan"),
]


def normalise_type(scanner_type: str) -> str:
    lower = (scanner_type or "").lower().strip()
    for fragment, canonical in _NORM_MAP:
        if fragment in lower:
            return canonical
    return lower


def _sev_rank(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 0}.get(
        (sev or "").lower(), 0
    )


# ---------------------------------------------------------------------------
# Finding / must_not matchers
# ---------------------------------------------------------------------------

def _finding_text(f: Dict) -> str:
    return " ".join(
        str(f.get(k, "") or "")
        for k in ("type", "details", "location", "poc", "impact")
    ).lower()


def _evidence(f: Dict) -> Dict:
    ev = f.get("evidence") or {}
    return ev if isinstance(ev, dict) else {}


def finding_matches_expected(finding: Dict, spec: Dict) -> bool:
    """Does this scanner finding satisfy an expected_findings entry?"""
    ftype = finding.get("type", "")
    canon = normalise_type(ftype)
    want = normalise_type(spec.get("type", ""))

    if want and canon != want and want not in (ftype or "").lower():
        # Allow header name specs under missing_header
        if want not in ("missing_header",) and canon not in (want,):
            return False

    name = (spec.get("name") or "").lower()
    if name:
        blob = _finding_text(finding)
        if name not in blob and name not in (ftype or "").lower():
            return False

    path = spec.get("path") or ""
    if path and path not in (finding.get("location") or ""):
        return False

    max_sev = spec.get("max_severity")
    if max_sev and _sev_rank(finding.get("severity", "")) > _sev_rank(max_sev):
        return False

    min_sev = spec.get("min_severity")
    if min_sev and _sev_rank(finding.get("severity", "")) < _sev_rank(min_sev):
        return False

    return True


def finding_hits_must_not(finding: Dict, rule: Dict, scan: Dict) -> bool:
    """True when a finding (or scan metadata) violates a must_not_report rule."""
    match = (rule.get("match") or "").lower()
    rtype = normalise_type(rule.get("type", ""))
    ftype = finding.get("type", "") if finding else ""
    fcanon = normalise_type(ftype)

    # CVE rules may inspect verified_cves / findings without a finding type match
    if rtype == "cve" or (rule.get("type") or "").lower() == "cve":
        cve_id = rule.get("id") or ""
        if not cve_id:
            return False
        for c in scan.get("verified_cves") or []:
            cid = c.get("id") or c.get("cve_id") or ""
            if cve_id in str(cid):
                return True
        if finding and cve_id.lower() in _finding_text(finding):
            return True
        # Also flag when CVE appears only as a "finding type"
        if finding and cve_id in ftype:
            return True
        return False

    if rtype == "authenticated_scan":
        if scan.get("authenticated_scan") is True:
            return True
        report = (scan.get("report") or "").lower()
        if "[authenticated scan]" in report:
            return True
        return False

    if not finding:
        return False

    # Type gate
    if rtype and fcanon != rtype and rtype not in (ftype or "").lower():
        if not (
            rtype in ("xss", "sqli", "sqli-timing", "cors", "csrf")
            and fcanon == rtype
        ):
            return False

    path = rule.get("path") or ""
    if path and path not in (finding.get("location") or ""):
        return False

    if match == "evidence_status_0":
        ev = _evidence(finding)
        return ev.get("response_status") in (0, "0", None) and (
            fcanon in ("sqli-timing", "sqli")
            or "time-based" in (ftype or "").lower()
        )

    if match == "confirmed_without_js_execution":
        if (finding.get("status") or "").lower() != "confirmed":
            return False
        if fcanon != "xss" and "xss" not in (ftype or "").lower():
            return False
        method = (_evidence(finding).get("confirmation_method") or "").lower()
        return method != "js_execution"

    if match == "high_without_acac":
        if fcanon != "cors" and "cors" not in (ftype or "").lower():
            return False
        if (finding.get("severity") or "").lower() != "high":
            return False
        ev = _evidence(finding)
        headers = ev.get("response_headers") or {}
        if not isinstance(headers, dict):
            headers = {}
        headers_l = {str(k).lower(): str(v or "") for k, v in headers.items()}
        acac = (
            str(ev.get("access_control_allow_credentials") or "")
            or headers_l.get("access-control-allow-credentials", "")
        ).lower()
        return acac != "true"

    # Default: type (+ optional path) match is enough to forbid
    return True


def is_out_of_scope(finding: Dict, truth: Dict) -> bool:
    canon = normalise_type(finding.get("type", ""))
    oos = {normalise_type(t) for t in (truth.get("out_of_scope_types") or [])}
    return canon in oos


# ---------------------------------------------------------------------------
# Score one target
# ---------------------------------------------------------------------------

def score_scan(truth: Dict, scan: Dict) -> Dict[str, Any]:
    """
    Diff scanner JSON against ground truth.

    Returns TP/FP/FN tallies, must_not violations, not_assessed count,
    and precision/recall under black-box unauth scope.
    """
    findings = list(scan.get("vulnerabilities") or scan.get("findings") or [])
    endpoints = list(scan.get("endpoints_discovered") or scan.get("endpoints") or [])
    not_assessed_scan = list(scan.get("not_assessed_endpoints") or [])

    expected = list(truth.get("expected_findings") or [])
    must_not = list(truth.get("must_not_report") or [])
    auth_gated = list(truth.get("endpoints_auth_gated") or [])

    # --- must_not violations ---
    violations: List[Dict] = []
    for rule in must_not:
        # Scan-level rules (no finding)
        if finding_hits_must_not({}, rule, scan) and normalise_type(
            rule.get("type", "")
        ) in ("cve", "authenticated_scan"):
            # CVE: only count once at scan level
            if normalise_type(rule.get("type", "")) == "cve":
                if finding_hits_must_not({}, rule, scan):
                    violations.append({"rule": rule, "finding": None})
            elif finding_hits_must_not({}, rule, scan):
                violations.append({"rule": rule, "finding": None})
            continue
        for f in findings:
            if finding_hits_must_not(f, rule, scan):
                violations.append({"rule": rule, "finding": f})
                break  # one hit per rule is enough

    # --- expected matching ---
    tp: List[Dict] = []
    fn_required: List[Dict] = []
    fn_optional: List[Dict] = []
    matched_finding_idxs: set = set()

    for spec in expected:
        hit_idx = None
        for i, f in enumerate(findings):
            if i in matched_finding_idxs:
                continue
            if finding_matches_expected(f, spec):
                hit_idx = i
                break
        if hit_idx is not None:
            matched_finding_idxs.add(hit_idx)
            tp.append({"spec": spec, "finding": findings[hit_idx]})
        else:
            if spec.get("required", True):
                fn_required.append(spec)
            else:
                fn_optional.append(spec)

    # --- unexpected findings (FP candidates) ---
    fps: List[Dict] = []
    for i, f in enumerate(findings):
        if i in matched_finding_idxs:
            continue
        if is_out_of_scope(f, truth):
            continue
        # Already counted as must_not?
        if any(
            finding_hits_must_not(f, v["rule"], scan)
            for v in violations
            if v.get("finding") is f or v.get("finding") is None
        ):
            # still count as FP via violations
            continue
        # Allowed: stride clickjacking when headers missing (informational)
        canon = normalise_type(f.get("type", ""))
        if canon in ("clickjacking",):
            continue
        fps.append(f)

    # must_not violations count as FP
    fp_count = len(fps) + len(violations)
    tp_count = len(tp)
    fn_count = len(fn_required)  # optional FNs excluded from hard recall

    prec = tp_count / (tp_count + fp_count) if (tp_count + fp_count) else 1.0
    # Recall over required expected only
    req_total = tp_count + fn_count
    # Recompute TP that were required
    tp_required = sum(1 for t in tp if t["spec"].get("required", True))
    recall = tp_required / (tp_required + fn_count) if (tp_required + fn_count) else 1.0

    # --- not_assessed ---
    # Prefer scanner-emitted list; else infer from truth auth_gated ∩ discovered
    not_assessed: List[Dict] = list(not_assessed_scan)
    if not not_assessed:
        for ep in endpoints:
            url = ep.get("url") or ep.get("path") or ""
            if ep.get("auth_required") or ep.get("access_controlled") or ep.get(
                "redirects_to_auth"
            ):
                not_assessed.append(
                    {"url": url, "reason": "auth_required", "status": ep.get("status")}
                )
        # Also count truth auth_gated paths as expected not_assessed slots
        for path in auth_gated:
            if not any(path in (n.get("url") or "") for n in not_assessed):
                not_assessed.append(
                    {"url": path, "reason": "auth_gated_label", "status": None}
                )

    return {
        "target": truth.get("target"),
        "scope": truth.get("scope"),
        "tp": tp_count,
        "fp": fp_count,
        "fn": fn_count,
        "fn_optional": len(fn_optional),
        "precision": round(prec, 3),
        "recall": round(recall, 3),
        "must_not_violations": [
            {
                "reason": v["rule"].get("reason"),
                "type": v["rule"].get("type"),
                "match": v["rule"].get("match"),
                "finding_type": (v["finding"] or {}).get("type") if v["finding"] else None,
                "location": (v["finding"] or {}).get("location") if v["finding"] else None,
            }
            for v in violations
        ],
        "tp_detail": [
            {"id": t["spec"].get("id"), "type": t["finding"].get("type")} for t in tp
        ],
        "fn_required": [s.get("id") or s.get("type") for s in fn_required],
        "fn_optional": [s.get("id") or s.get("type") for s in fn_optional],
        "fp_unexpected": [
            {"type": f.get("type"), "location": f.get("location")} for f in fps
        ],
        "not_assessed_count": len(not_assessed),
        "not_assessed": not_assessed[:30],
        "findings_total": len(findings),
        "pass": len(violations) == 0 and fn_count == 0,
    }


def load_truth(name_or_path: str) -> Dict:
    p = Path(name_or_path)
    if not p.exists():
        p = TRUTH_DIR / name_or_path
    if not p.exists() and not str(name_or_path).endswith(".json"):
        p = TRUTH_DIR / f"{name_or_path}.json"
    with open(p) as f:
        return json.load(f)


def load_scan_fixture(path: Path) -> Dict:
    with open(path) as f:
        data = json.load(f)
    # Accept raw /scan/ response or a wrapped {scan, truth} fixture
    if "scan" in data and "vulnerabilities" not in data:
        return data["scan"]
    return data


def resolve_truth_for_fixture(fixture_path: Path, scan: Dict) -> Optional[Dict]:
    """Pick ground truth by fixture name or URL alias."""
    stem = fixture_path.stem.lower()
    for truth_path in sorted(TRUTH_DIR.glob("*.json")):
        truth = json.loads(truth_path.read_text())
        if truth.get("target", "").lower() in stem:
            return truth
        url = (scan.get("target_url") or "").rstrip("/")
        for alias in truth.get("url_aliases") or []:
            if url.startswith(alias.rstrip("/")):
                return truth
    return None


def run_live_scan(url: str) -> Dict:
    payload = json.dumps(
        {"target_url": url, "session_id": f"regression-{int(datetime.now().timestamp())}"}
    ).encode()
    req = urllib.request.Request(
        SCANNER_BASE_URL + "/scan/",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=SCANNER_TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def print_score(score: Dict) -> None:
    status = "PASS" if score.get("pass") else "FAIL"
    print(
        f"  [{status}] {score.get('target')}: "
        f"P={score['precision']:.3f} R={score['recall']:.3f} "
        f"TP={score['tp']} FP={score['fp']} FN={score['fn']} "
        f"(optional_fn={score['fn_optional']}, "
        f"not_assessed={score['not_assessed_count']})"
    )
    if score.get("must_not_violations"):
        print("    must_not violations:")
        for v in score["must_not_violations"]:
            print(f"      - {v.get('type')} @ {v.get('location')}: {v.get('reason')}")
    if score.get("fn_required"):
        print(f"    required FN: {', '.join(score['fn_required'])}")
    if score.get("fp_unexpected"):
        print("    unexpected FP:")
        for f in score["fp_unexpected"][:5]:
            print(f"      - {f.get('type')} @ {f.get('location')}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Ground-truth regression harness")
    parser.add_argument("--fixture", type=str, help="Path to a /scan/ JSON fixture")
    parser.add_argument("--truth", type=str, help="Ground-truth JSON (or target name)")
    parser.add_argument(
        "--fixtures-dir",
        type=str,
        default=None,
        help="Score all *.json fixtures in directory",
    )
    parser.add_argument("--live", type=str, help="Target name for live scan")
    parser.add_argument("--url", type=str, help="URL override for --live")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 on must_not violations or required FNs",
    )
    parser.add_argument(
        "--expect-fail",
        action="store_true",
        help="Invert gate: every scored target must FAIL (negative FP fixtures)",
    )
    args = parser.parse_args(argv)

    scores: List[Dict] = []

    if args.fixtures_dir or (not args.fixture and not args.live):
        d = Path(args.fixtures_dir) if args.fixtures_dir else FIXTURES_DIR
        if not d.exists():
            print(f"No fixtures dir at {d}")
            return 2
        for path in sorted(d.glob("*.json")):
            scan = load_scan_fixture(path)
            truth = (
                load_truth(args.truth)
                if args.truth
                else resolve_truth_for_fixture(path, scan)
            )
            if not truth:
                print(f"  SKIP {path.name}: no matching ground truth")
                continue
            s = score_scan(truth, scan)
            s["fixture"] = str(path)
            scores.append(s)
            print_score(s)
    elif args.fixture:
        scan = load_scan_fixture(Path(args.fixture))
        truth = load_truth(args.truth) if args.truth else resolve_truth_for_fixture(
            Path(args.fixture), scan
        )
        if not truth:
            print("No ground truth resolved"); return 2
        s = score_scan(truth, scan)
        scores.append(s)
        print_score(s)
    elif args.live:
        truth = load_truth(args.live)
        url = args.url or (truth.get("url_aliases") or [None])[0]
        if not url:
            print("Need --url"); return 2
        print(f"  Live scan {url} …")
        scan = run_live_scan(url)
        out = RESULTS_DIR / f"live_{truth['target']}_{datetime.now():%Y%m%d_%H%M%S}.json"
        out.write_text(json.dumps(scan, indent=2))
        print(f"  Saved {out}")
        s = score_scan(truth, scan)
        scores.append(s)
        print_score(s)
    else:
        parser.print_help()
        return 2

    if not scores:
        return 2

    tp = sum(s["tp"] for s in scores)
    fp = sum(s["fp"] for s in scores)
    fn = sum(s["fn"] for s in scores)
    prec = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    print("\n  GLOBAL:")
    print(f"    Precision={prec:.3f}  Recall={recall:.3f}  TP={tp} FP={fp} FN={fn}")
    print(
        f"    not_assessed={sum(s['not_assessed_count'] for s in scores)}  "
        f"must_not_violations={sum(len(s['must_not_violations']) for s in scores)}"
    )

    report_path = RESULTS_DIR / f"regression_{datetime.now():%Y%m%d_%H%M%S}.json"
    report_path.write_text(
        json.dumps(
            {
                "run_at": datetime.now().isoformat(),
                "operating_point": "precision_first_blackbox_unauth",
                "aggregate": {
                    "precision": round(prec, 3),
                    "recall": round(recall, 3),
                    "tp": tp,
                    "fp": fp,
                    "fn": fn,
                },
                "per_target": scores,
            },
            indent=2,
        )
    )
    print(f"  Report: {report_path}")

    if args.expect_fail:
        # Negative corpus: each fixture must surface a must_not / FP failure
        bad = [s for s in scores if s.get("pass")]
        if bad:
            print(f"\n  EXPECT-FAIL gate: {len(bad)} fixture(s) unexpectedly PASSED")
            return 1
        return 0
    if args.strict:
        failed = [s for s in scores if not s.get("pass")]
        return 1 if failed else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
