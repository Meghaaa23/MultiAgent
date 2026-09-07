#!/usr/bin/env python3
"""
accuracy_eval.py — Measure scanner accuracy against testbed ground truth.

Usage:
  # Scan all reachable targets and evaluate
  python3 accuracy_eval.py --all

  # Evaluate a specific group
  python3 accuracy_eval.py --group intentionally-vulnerable

  # Evaluate single target
  python3 accuracy_eval.py --target 1

  # Load existing suite result instead of scanning
  python3 accuracy_eval.py --suite-file results/suite_20260530_183620.json

  # Scan and save raw suite for later re-evaluation
  python3 accuracy_eval.py --all --save-suite
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

SCANNER_BASE_URL = "http://localhost:8000"
SCANNER_TIMEOUT  = 300

SCRIPT_DIR   = Path(__file__).parent
TARGETS_FILE = SCRIPT_DIR / "targets.json"
RESULTS_DIR  = SCRIPT_DIR / "results"
RESULTS_DIR.mkdir(exist_ok=True)

sys.path.insert(0, str(SCRIPT_DIR))
import ai_metrics  # noqa: E402  (AI-specific discovery / prompt-injection metrics)

# ---------------------------------------------------------------------------
# Normalise vulnerability type strings → canonical known_vuln key
# ---------------------------------------------------------------------------

_NORM_MAP = [
    # (substring_in_scanner_type,          canonical_key)
    ("reflected xss",                       "xss"),
    ("stored/reflected xss",                "xss"),
    ("stored xss",                          "xss"),
    ("xss",                                 "xss"),
    ("sql injection",                       "sqli"),
    ("sqli",                                "sqli"),
    ("nosql injection",                     "nosqli"),
    ("nosqli",                              "nosqli"),
    ("csrf",                                "csrf"),
    ("missing csrf",                        "csrf"),
    ("open redirect",                       "open-redirect"),
    ("server-side request forgery",         "ssrf"),
    ("ssrf",                                "ssrf"),
    ("remote code execution",               "rce"),
    ("rce",                                 "rce"),
    ("command injection",                   "cmdi"),
    ("cmdi",                                "cmdi"),
    ("insecure direct object",              "idor"),
    ("idor",                                "idor"),
    ("local file inclusion",                "lfi"),
    ("lfi",                                 "lfi"),
    ("remote file inclusion",               "rfi"),
    ("rfi",                                 "rfi"),
    ("xml external entity",                 "xxe"),
    ("xxe",                                 "xxe"),
    ("server-side template injection",      "ssti"),
    ("ssti",                                "ssti"),
    ("path traversal",                      "path-traversal"),
    ("directory traversal",                 "path-traversal"),
    ("broken auth",                         "broken-auth"),
    ("auth bypass",                         "auth-bypass"),
    ("authentication bypass",               "auth-bypass"),
    ("oauth",                               "oauth-misconfig"),
    ("token forg",                          "token-forgery"),
    ("graphql",                             "graphql-injection"),
    ("prototype pollution",                 "prototype-pollution"),
    ("deserialization",                     "deserialization"),
    ("jwt",                                 "jwt"),
    ("log4shell",                           "log4shell"),
    ("ognl",                                "ognl-injection"),
    ("hardcoded secret",                    "hardcoded-secrets"),
    ("sensitive data",                      "sensitive-data"),
    ("sensitive-data",                      "sensitive-data"),
    ("unauthenticated",                     "unauthenticated-access"),
    ("default cred",                        "default-creds"),
    ("container escape",                    "container-escape"),
    ("privilege escalation",                "privilege-escalation"),
    ("misconfigured bucket",                "misconfigured-bucket"),
    ("mass assignment",                     "mass-assignment"),
    ("broken object",                       "bola"),
    ("bola",                                "bola"),
    ("excessive data",                      "excessive-data-exposure"),
    ("model theft",                         "model-theft"),
    ("prompt injection",                    "prompt-injection"),
    ("model poisoning",                     "model-poisoning"),
    ("token exposure",                      "token-exposure"),
    ("webhook ssrf",                        "webhook-ssrf"),
    ("repo traversal",                      "repo-traversal"),
    ("token leak",                          "token-leak"),
    ("file upload",                         "fileupload"),
    ("fileupload",                          "fileupload"),
    ("webdav",                              "webdav-abuse"),
    ("clickjacking",                        "clickjacking"),
    ("http header injection",               "http-header-injection"),
    ("regex",                               "regex-dos"),
    ("anon",                                "anon-access"),
    ("plugin rce",                          "plugin-rce"),
    ("groovy",                              "groovy-script-exec"),
    ("credential exposure",                 "credential-exposure"),
    ("message injection",                   "message-injection"),
    ("introspection",                       "introspection-abuse"),
]


def normalise_vuln_type(scanner_type: str) -> str:
    """Map a scanner-reported vuln type string to a canonical known_vuln key."""
    lower = scanner_type.lower()
    for fragment, canonical in _NORM_MAP:
        if fragment in lower:
            return canonical
    return lower.strip()


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def score_target(known_vulns: list, findings: list) -> dict:
    """
    Compare scanner findings against ground-truth known_vulns.

    Returns a dict with:
        detected_types  — set of canonical vuln types the scanner found
        tp_types        — intersection with known_vulns
        fp_types        — scanner found but NOT in known_vulns
        fn_types        — known but NOT found
        precision       — TP / (TP + FP)
        recall          — TP / (TP + FN)
        f1
    """
    known_set    = set(known_vulns)
    detected_set = {normalise_vuln_type(f.get("type", "")) for f in findings}
    detected_set.discard("")

    tp = known_set & detected_set
    fp = detected_set - known_set
    fn = known_set  - detected_set

    prec   = len(tp) / len(detected_set) if detected_set else 0.0
    recall = len(tp) / len(known_set)    if known_set    else 1.0
    f1     = (2 * prec * recall / (prec + recall)) if (prec + recall) > 0 else 0.0

    return {
        "known_types":    sorted(known_set),
        "detected_types": sorted(detected_set),
        "tp_types":       sorted(tp),
        "fp_types":       sorted(fp),
        "fn_types":       sorted(fn),
        "tp": len(tp), "fp": len(fp), "fn": len(fn),
        "precision": round(prec,   3),
        "recall":    round(recall, 3),
        "f1":        round(f1,     3),
    }


def aggregate_metrics(per_target: list) -> dict:
    """Micro-average precision/recall/F1 over all scored targets."""
    tp = sum(t["tp"] for t in per_target)
    fp = sum(t["fp"] for t in per_target)
    fn = sum(t["fn"] for t in per_target)

    prec   = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1     = (2 * prec * recall / (prec + recall)) if (prec + recall) > 0 else 0.0

    return {
        "total_tp": tp, "total_fp": fp, "total_fn": fn,
        "micro_precision": round(prec,   3),
        "micro_recall":    round(recall, 3),
        "micro_f1":        round(f1,     3),
    }


# ---------------------------------------------------------------------------
# Scan helpers (reused from test_harness)
# ---------------------------------------------------------------------------

TARGETS_OVERRIDE = None  # set from --targets-file


def load_targets(group=None, target_id=None):
    path = TARGETS_OVERRIDE or TARGETS_FILE
    with open(path) as f:
        manifest = json.load(f)
    targets = manifest["targets"]
    if target_id:
        targets = [t for t in targets if t["id"] == target_id]
    if group:
        targets = [t for t in targets if t["group"] == group]
    return targets


def is_reachable(url, timeout=5):
    try:
        req = urllib.request.urlopen(url, timeout=timeout)
        return req.status < 500
    except Exception:
        return False


def run_scan(target):
    tid  = target["id"]
    name = target["name"]
    url  = target["url"]
    print(f"\n  [{tid:02d}] {name} @ {url}")

    if not is_reachable(url):
        print("       SKIP — unreachable")
        return {"target_id": tid, "target_name": name, "url": url,
                "group": target["group"], "known_vulns": target.get("known_vulns", []),
                "status": "unreachable", "findings": []}

    try:
        urllib.request.urlopen(SCANNER_BASE_URL + "/health", timeout=5)
    except Exception:
        print(f"       SKIP — scanner offline at {SCANNER_BASE_URL}")
        return {"target_id": tid, "status": "scanner_offline", "findings": []}

    session_id = f"accuracy-{tid}-{int(time.time())}"
    payload    = json.dumps({"target_url": url, "session_id": session_id}).encode()
    start      = time.time()

    try:
        req = urllib.request.Request(
            SCANNER_BASE_URL + "/scan/",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=SCANNER_TIMEOUT) as resp:
            elapsed   = round(time.time() - start, 1)
            scan_resp = json.loads(resp.read().decode())

        # /scan/ returns vulnerabilities at top level
        findings = scan_resp.get("vulnerabilities") or []
        if not findings:
            sd = scan_resp.get("scan_results") or scan_resp.get("data") or {}
            findings = (sd.get("vulnerabilities") or sd.get("findings") or []) if isinstance(sd, dict) else sd

        summary = scan_resp.get("scan_summary", {})
        print(f"       done in {elapsed}s  |  raw findings={len(findings)}"
              f"  |  scanner_count={summary.get('vulnerabilities_found', '?')}")

        return {
            "target_id": tid, "target_name": name, "url": url,
            "group": target["group"], "known_vulns": target.get("known_vulns", []),
            "session_id": session_id, "scan_time_s": elapsed,
            "status": "done", "findings": findings,
            "scan_summary": summary,
        }

    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:300]
        print(f"       ERROR HTTP {e.code} — {body}")
        return {"target_id": tid, "target_name": name, "url": url,
                "group": target["group"], "known_vulns": target.get("known_vulns", []),
                "status": f"http_{e.code}", "findings": [], "error": body}
    except Exception as e:
        print(f"       ERROR — {e}")
        return {"target_id": tid, "target_name": name, "url": url,
                "group": target["group"], "known_vulns": target.get("known_vulns", []),
                "status": "error", "findings": [], "error": str(e)}


# ---------------------------------------------------------------------------
# Report printer
# ---------------------------------------------------------------------------

def print_report(eval_results: list, agg: dict, suite_id: str):
    print("\n" + "=" * 72)
    print(f"  ACCURACY REPORT  [{suite_id}]")
    print("=" * 72)

    header = f"  {'ID':<4} {'Target':<30} {'Prec':>6} {'Rec':>6} {'F1':>6}  TP/FP/FN  status"
    print(header)
    print("  " + "-" * 68)

    for r in eval_results:
        s    = r["score"]
        st   = r["status"]
        name = r.get("target_name", f"target_{r.get('target_id','?')}")
        if st not in ("done",):
            print(f"  {r['target_id']:<4} {name:<30}   {'—':>5}  {'—':>5}  {'—':>5}  —/—/—    {st}")
        else:
            print(f"  {r['target_id']:<4} {name:<30}  "
                  f"{s['precision']:>6.3f} {s['recall']:>6.3f} {s['f1']:>6.3f}  "
                  f"{s['tp']}/{s['fp']}/{s['fn']}   {st}")

    print("  " + "-" * 68)
    print(f"\n  MICRO-AVERAGED (over {len([r for r in eval_results if r['status']=='done'])} scanned targets):")
    print(f"    Precision : {agg['micro_precision']:.3f}")
    print(f"    Recall    : {agg['micro_recall']:.3f}")
    print(f"    F1        : {agg['micro_f1']:.3f}")
    print(f"    TP={agg['total_tp']}  FP={agg['total_fp']}  FN={agg['total_fn']}")

    # Breakdown by group
    from collections import defaultdict
    groups = defaultdict(list)
    for r in eval_results:
        if r["status"] == "done":
            groups[r["group"]].append(r["score"])

    if groups:
        print("\n  BY GROUP:")
        for grp, scores in sorted(groups.items()):
            tp = sum(s["tp"] for s in scores)
            fp = sum(s["fp"] for s in scores)
            fn = sum(s["fn"] for s in scores)
            p  = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rc = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * p * rc / (p + rc)) if (p + rc) > 0 else 0.0
            print(f"    {grp:<30}  P={p:.3f}  R={rc:.3f}  F1={f1:.3f}  ({len(scores)} targets)")

    print("=" * 72 + "\n")

    # Detail: FN (what we missed) for done targets
    missed = [(r["target_name"], r["score"]["fn_types"])
              for r in eval_results if r["status"] == "done" and r["score"]["fn_types"]]
    if missed:
        print("  MISSED VULNERABILITIES (false negatives):")
        for name, fns in missed:
            print(f"    {name}: {', '.join(fns)}")
        print()

    # Detail: FP (what we over-reported)
    false_pos = [(r["target_name"], r["score"]["fp_types"])
                 for r in eval_results if r["status"] == "done" and r["score"]["fp_types"]]
    if false_pos:
        print("  OVER-REPORTED (false positives):")
        for name, fps in false_pos:
            print(f"    {name}: {', '.join(fps)}")
        print()


# ---------------------------------------------------------------------------
# AI-specific evaluation (surface discovery + prompt injection)
# ---------------------------------------------------------------------------

def evaluate_ai(raw_results: list, target_map: dict) -> dict:
    """Compute the abstract's AI-specific metrics for targets carrying labels."""
    surface_entries = []
    pairs           = []
    labelled        = 0
    done_results    = []

    for r in raw_results:
        tid   = r.get("target_id")
        label = (target_map.get(tid, {}) or {}).get("ai_surface")
        if label is None:
            continue
        labelled += 1
        if r.get("status") == "done":
            done_results.append(r)
            surface_entries.append(ai_metrics.score_ai_surface_target(label, r))
            pairs.append({"label": label, "result": r})

    if not labelled:
        return {}

    return {
        "labelled_targets":  labelled,
        "scored_targets":    len(pairs),
        "ai_surface":        ai_metrics.aggregate_ai_surface(surface_entries),
        "ownership":         ai_metrics.ownership_classification_accuracy(pairs),
        "prompt_injection":  ai_metrics.aggregate_prompt_injection(pairs),
        "conventional_gap":  ai_metrics.aggregate_conventional_gap(done_results),
    }


def print_ai_report(ai_eval: dict):
    if not ai_eval:
        return
    s  = ai_eval["ai_surface"]
    pi = ai_eval["prompt_injection"]
    ow = ai_eval["ownership"]
    cg = ai_eval["conventional_gap"]

    print("=" * 72)
    print("  AI-SPECIFIC EVALUATION")
    print("=" * 72)
    print(f"  Labelled targets scored: {ai_eval['scored_targets']}/{ai_eval['labelled_targets']}")
    print("\n  AI-surface discovery (app level):")
    print(f"    Precision : {s['precision']:.3f}   Recall : {s['recall']:.3f}   F1 : {s['f1']:.3f}")
    print(f"    TP={s['tp']}  FP={s['fp']}  FN={s['fn']}  TN={s['tn']}   Accuracy={s['accuracy']:.3f}")
    print("\n  Chat-ownership classification:")
    print(f"    Accuracy  : {ow['accuracy']:.3f} over {ow['targets_considered']} labelled surfaces")
    print(f"    Per-class recall: {ow['per_class_recall']}")
    print("\n  Prompt injection:")
    print(f"    Confirmations : {pi['total_confirmations']}  across {pi['flagged_targets']} target(s)")
    print(f"    Precision : {pi['precision']:.3f}   Recall : {pi['recall']:.3f}   "
          f"FP-rate : {pi['false_positive_rate']:.3f}")
    print(f"    (expected={pi['expected_targets']} tp={pi['tp_targets']} fp={pi['fp_targets']})")
    print("\n  AI surfaces missed by a conventional scan:")
    print(f"    {cg['total_ai_surfaces_missed_by_conventional']} surface(s) across "
          f"{cg['targets_with_gap']} target(s)")
    print("=" * 72 + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Scanner accuracy evaluator")
    parser.add_argument("--all",        action="store_true", help="Scan all targets")
    parser.add_argument("--target",     type=int,            help="Scan single target by ID")
    parser.add_argument("--group",      type=str,            help="Scan targets in group")
    parser.add_argument("--suite-file", type=str,            help="Load existing suite JSON instead of scanning")
    parser.add_argument("--save-suite", action="store_true", help="Save raw scan suite alongside accuracy report")
    parser.add_argument("--targets-file", type=str,          help="Override targets manifest (e.g. targets_ai.json)")
    args = parser.parse_args()

    global TARGETS_OVERRIDE
    if args.targets_file:
        tf = Path(args.targets_file)
        TARGETS_OVERRIDE = tf if tf.is_absolute() else (SCRIPT_DIR / tf)

    suite_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    # ── Load from existing suite or run new scans ──────────────────────────
    if args.suite_file:
        path = Path(args.suite_file)
        if not path.is_absolute():
            path = SCRIPT_DIR / path
        with open(path) as f:
            suite = json.load(f)
        raw_results = suite["results"]
        # Re-attach known_vulns from targets.json in case they were missing
        target_map = {t["id"]: t for t in load_targets()}
        for r in raw_results:
            if not r.get("known_vulns") and r.get("target_id") in target_map:
                r["known_vulns"] = target_map[r["target_id"]].get("known_vulns", [])
        suite_id = suite.get("suite_id", suite_id)
    else:
        if args.all:
            targets = load_targets()
        elif args.target:
            targets = load_targets(target_id=args.target)
            if not targets:
                print(f"No target with ID {args.target}"); return
        elif args.group:
            targets = load_targets(group=args.group)
            if not targets:
                print(f"No targets in group '{args.group}'"); return
        else:
            parser.print_help(); return

        print(f"\n  Scanning {len(targets)} target(s) — suite {suite_id}")
        raw_results = [run_scan(t) for t in targets]

        if args.save_suite:
            suite_path = RESULTS_DIR / f"suite_{suite_id}.json"
            suite_path.write_text(json.dumps({
                "suite_id": suite_id, "run_at": datetime.now().isoformat(),
                "total_targets": len(raw_results),
                "successful_scans": sum(1 for r in raw_results if r["status"] == "done"),
                "total_findings": sum(len(r.get("findings", [])) for r in raw_results),
                "results": raw_results,
            }, indent=2))
            print(f"  Suite saved: {suite_path}")

    # ── Score each result ──────────────────────────────────────────────────
    eval_results = []
    scored = []
    for r in raw_results:
        known   = r.get("known_vulns", [])
        findings = r.get("findings", [])
        score   = score_target(known, findings)
        entry   = {**r, "score": score}
        eval_results.append(entry)
        if r.get("status") == "done":
            scored.append(score)

    agg = aggregate_metrics(scored)

    print_report(eval_results, agg, suite_id)

    # ── AI-specific evaluation (surface discovery + prompt injection) ───────
    target_map = {t["id"]: t for t in load_targets()}
    ai_eval    = evaluate_ai(raw_results, target_map)
    print_ai_report(ai_eval)

    # ── Save accuracy report ───────────────────────────────────────────────
    report = {
        "suite_id":   suite_id,
        "run_at":     datetime.now().isoformat(),
        "aggregate":  agg,
        "ai_evaluation": ai_eval,
        "per_target": eval_results,
    }
    report_path = RESULTS_DIR / f"accuracy_{suite_id}.json"
    report_path.write_text(json.dumps(report, indent=2))
    print(f"  Accuracy report saved: {report_path}")


if __name__ == "__main__":
    main()
