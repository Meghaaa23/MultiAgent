#!/usr/bin/env python3
"""
metrics.py — executable definitions for the six YuraRAG evaluation metrics.

The point of this file is that the metric definitions are MECHANICAL. Once a
number comes out of here it is not re-interpretable. If you find yourself
wanting to argue that a case "sort of counts", change the POLICY block below,
re-run everything, and note the change in the paper. Do not argue it in prose.

Usage:
    metrics.py --gt ground_truth/librechat_local.json --runs runs/librechat_local_*.json
    metrics.py --gt-dir ground_truth/ --runs-dir runs/ --out table2_input.json
    metrics.py --selftest

Ground-truth schema (ground_truth/<target>.json) — see SCHEMA.md for the full
shape; the fields this script reads are all nested under "ai_surface":
    {
      "target": "librechat_local",
      "ai_surface": {
        "has_ai_surface": "yes" | "no" | "partial" | "unverifiable",
        "ai_auth_gated": true,
        "chat_ui_present": true,
        "injection_authorized": true,
        "soft_404_behavior": "catch_all_spa" | "proper_404",
        "stack_true": {"framework": "...", "language": "..."},
        "ai_endpoints_true": [
          {"url": "http://localhost:3080/api/agents/chat",
           "tier": "live_surface",
           "routes_without_config": true}
        ]
      }
    }
  ai_endpoints_true entries may also be bare strings (pre-migration files);
  they are upgraded to {"url": s, "tier": None, "routes_without_config": True}.

Scan-result schema (runs/<target>_r<N>.json): see SCAN_KEYS below. Produced
from a real scan_application() output dict via scan_result_adapter.py — see
that file, not this one, for the mapping from the scanner's actual fields
(endpoints_discovered, eval_metrics, ai_fingerprint.evidence_items, ...) to
this shape.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from itertools import combinations
from urllib.parse import urlsplit

# --------------------------------------------------------------------------
# POLICY  — every judgement call in the evaluation lives here and nowhere else.
# --------------------------------------------------------------------------

# Which has_ai_surface labels are graded by which metric.
# 'unverifiable' has no AI ground truth, so it is excluded from the four
# ground-truth-dependent metrics (recall, precision, tier accuracy, coverage
# honesty) — but overclaim rate and determinism are internal-consistency
# measures that need no ground truth at all, and grade every target,
# including 'unverifiable' ones. Splitting the exclusion per-metric (rather
# than dropping the target everywhere) keeps denominators consistent across
# the table instead of silently shrinking sample size for metrics that never
# needed the exclusion.
GRADED_FOR_AI_GROUND_TRUTH = {"yes", "no", "partial"}
GRADED_FOR_INTERNAL_CONSISTENCY = {"yes", "no", "partial", "unverifiable"}

# URL matching. 'path' ignores scheme/host/port (target host is fixed per run,
# and port drift between testbed restarts should not read as a miss).
DEFAULT_MATCH_MODE = "path"

# A finding counts as an overclaim if it asserts confirmation while carrying
# no evidence. These are the field values that mean "asserted confirmed".
CONFIRMED_VERIFIED_VALUES = {"yes", "confirmed", True}

# Tiers in the falsifiability taxonomy — MUST match EvidenceClass in
# multiagent/agents/ai_agents/ai_evidence_scoring.py exactly (underscored,
# not hyphenated: "live_surface" not "live-surface"). tier_accuracy is
# meaningless if this drifts from what the scanner actually emits.
KNOWN_TIERS = {"behavioral", "live_surface", "passive_structural",
               "passive_hint", "brand"}

SCAN_KEYS = ("target", "ai_surfaces", "findings", "coverage")


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def canon(url: str, mode: str = DEFAULT_MATCH_MODE) -> str:
    """Canonicalise a URL for set comparison.

    Without this, half your 'misses' are trailing slashes and query strings.
    """
    if not url:
        return ""
    parts = urlsplit(url.strip())
    path = (parts.path or "/").rstrip("/") or "/"
    if mode == "path":
        return path.lower()
    return f"{parts.netloc.lower()}{path.lower()}"


def _norm_true_endpoints(raw) -> list[dict]:
    out = []
    for e in raw or []:
        if isinstance(e, str):
            out.append({"url": e, "tier": None, "routes_without_config": True})
        else:
            out.append({
                "url": e.get("url", ""),
                "tier": e.get("tier"),
                "routes_without_config": e.get("routes_without_config", True),
            })
    return out


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


def _finding_key(f: dict) -> tuple:
    """Identity of a finding for determinism purposes: what it is and where.

    Deliberately excludes severity and prose so that wording drift between
    runs does not read as nondeterminism.
    """
    return (str(f.get("type", "")).strip().lower(),
            canon(f.get("location") or f.get("url") or ""))


def _is_confirmed(f: dict) -> bool:
    v = f.get("verified", f.get("status"))
    if isinstance(v, str):
        v = v.strip().lower()
    return v in CONFIRMED_VERIFIED_VALUES


def _has_evidence(f: dict) -> bool:
    if "evidence_present" in f:
        return bool(f["evidence_present"])
    ev = f.get("evidence")
    # bool(ev) alone is correct for str/list/None; a plain str(ev).strip()
    # check would be WRONG for the real scanner's evidence dicts, since
    # str({}) == "{}" is truthy even though the dict is empty.
    return bool(ev)


# --------------------------------------------------------------------------
# per-target grading
# --------------------------------------------------------------------------

def grade_target(gt: dict, runs: list[dict], match_mode: str = DEFAULT_MATCH_MODE) -> dict:
    """Grade one target from its ground truth and >=1 scan results.

    Ground-truth-dependent metrics are computed against runs[0] (the primary
    run). Determinism is computed across all runs supplied.
    """
    if not runs:
        raise ValueError(f"{gt.get('target')}: no runs supplied")

    ai_gt = gt.get("ai_surface") or {}
    label = ai_gt.get("has_ai_surface")
    graded_gt = label in GRADED_FOR_AI_GROUND_TRUTH
    primary = runs[0]

    true_eps = _norm_true_endpoints(ai_gt.get("ai_endpoints_true"))
    true_all = {canon(e["url"], match_mode): e for e in true_eps}
    true_reachable = {k: e for k, e in true_all.items()
                      if e.get("routes_without_config", True)}

    claimed = {}
    for s in primary.get("ai_surfaces") or []:
        claimed[canon(s.get("url", ""), match_mode)] = s
    claimed.pop("", None)

    res = {
        "target": gt.get("target"),
        "has_ai_surface": label,
        "ai_auth_gated": bool(ai_gt.get("ai_auth_gated")),
        "graded_ai_ground_truth": graded_gt,
        "n_runs": len(runs),
    }

    # ---- 1/2. AI surface recall & precision -------------------------------
    if graded_gt:
        tp_strict = set(true_all) & set(claimed)
        tp_reach = set(true_reachable) & set(claimed)
        fp = set(claimed) - set(true_all)

        # Recall is undefined when there is nothing to find (all 'no' targets,
        # and any 'yes'/'partial' target whose true list is empty). Skipped,
        # not scored zero — scoring it zero would silently drag macro-recall
        # down by the size of your no-AI stratum.
        res["recall_strict"] = (len(tp_strict) / len(true_all)) if true_all else None
        res["recall_reachable"] = (len(tp_reach) / len(true_reachable)) if true_reachable else None

        # Precision IS defined with an empty true list: everything claimed on a
        # no-AI target is a false positive. This is the headline number for the
        # no-AI stratum.
        res["precision"] = (len(tp_strict) / len(claimed)) if claimed else None

        res["_counts"] = {
            "tp_strict": len(tp_strict),
            "tp_reachable": len(tp_reach),
            "fp": len(fp),
            "true_all": len(true_all),
            "true_reachable": len(true_reachable),
            "claimed": len(claimed),
        }
        res["false_positive_endpoints"] = sorted(fp)
        res["missed_endpoints"] = sorted(set(true_all) - set(claimed))
    else:
        for k in ("recall_strict", "recall_reachable", "precision"):
            res[k] = None
        res["_counts"] = None
        res["skip_reason"] = f"has_ai_surface={label!r} — no AI ground truth to grade against"

    # ---- 3. Tier accuracy -------------------------------------------------
    # Only over endpoints that were both truly present and discovered, and for
    # which ground truth records a tier. Undiscovered endpoints are a recall
    # failure, not a tier failure; double-counting them would conflate the two.
    if graded_gt:
        tier_pairs = []
        for k in sorted(set(true_all) & set(claimed)):
            t_true = true_all[k].get("tier")
            if t_true is None:
                continue
            tier_pairs.append((t_true, claimed[k].get("tier")))
        res["tier_accuracy"] = (
            sum(1 for a, b in tier_pairs if a == b) / len(tier_pairs)
        ) if tier_pairs else None
        res["tier_confusions"] = [
            {"expected": a, "got": b} for a, b in tier_pairs if a != b
        ]
    else:
        res["tier_accuracy"] = None
        res["tier_confusions"] = []

    # ---- 4. Coverage honesty ---------------------------------------------
    # Scored only where there is something to be honest ABOUT: an auth-gated
    # (or config-gated) true AI surface. Pass requires all three:
    #   (a) the surface was discovered at all,
    #   (b) it was marked unreachable/auth-gated rather than silently dropped,
    #   (c) coverage.auth_state was declared in the report,
    # and requires the absence of:
    #   (d) any confirmed injection finding it could not have earned.
    if graded_gt and ai_gt.get("ai_auth_gated") and true_all:
        cov = primary.get("coverage") or {}
        inj = primary.get("injection") or {}
        discovered_any = bool(set(true_all) & set(claimed))
        gated_marked = any(
            (s.get("auth_gated") is True) or (s.get("reachable") is False)
            for k, s in claimed.items() if k in true_all
        )
        declared = bool(str(cov.get("auth_state") or "").strip())
        false_clear = int(inj.get("confirmed") or 0) > 0
        checks = {
            "discovered_any": discovered_any,
            "gated_marked": gated_marked,
            "auth_state_declared": declared,
            "no_false_injection_claim": not false_clear,
        }
        res["coverage_honesty"] = 1.0 if all(checks.values()) else 0.0
        res["coverage_honesty_checks"] = checks
    else:
        res["coverage_honesty"] = None
        res["coverage_honesty_checks"] = None

    # 'partial' targets get a separate, narrower credit: did the scanner say
    # WHY the surface was unusable (provider key / admin config / plugin not
    # installed)? Reported alongside coverage honesty, never folded into it —
    # a yes/no target has no opportunity to earn it and averaging across
    # strata would be a lie.
    if label == "partial":
        cov = primary.get("coverage") or {}
        blob = " ".join(str(v) for v in cov.values()).lower()
        res["config_gate_declared"] = any(
            t in blob for t in ("provider", "api key", "api_key",
                                "not configured", "unconfigured", "admin",
                                "not installed", "not provisioned")
        )
    else:
        res["config_gate_declared"] = None

    # ---- 5. Overclaim rate ------------------------------------------------
    # Ground-truth independent: graded on every target including unverifiable.
    confirmed = [f for f in (primary.get("findings") or []) if _is_confirmed(f)]
    overclaims = [f for f in confirmed if not _has_evidence(f)]
    res["overclaim_rate"] = (len(overclaims) / len(confirmed)) if confirmed else None
    res["n_confirmed_findings"] = len(confirmed)
    res["n_overclaims"] = len(overclaims)
    res["overclaim_examples"] = [_finding_key(f) for f in overclaims][:5]

    # ---- 6. Determinism ---------------------------------------------------
    # Ground-truth independent. Mean pairwise Jaccard over all run pairs.
    if len(runs) >= 2:
        f_sets = [{_finding_key(f) for f in (r.get("findings") or [])} for r in runs]
        a_sets = [{canon(s.get("url", ""), match_mode)
                   for s in (r.get("ai_surfaces") or [])} for r in runs]
        f_pairs = [_jaccard(a, b) for a, b in combinations(f_sets, 2)]
        a_pairs = [_jaccard(a, b) for a, b in combinations(a_sets, 2)]
        res["determinism_findings"] = sum(f_pairs) / len(f_pairs)
        res["determinism_ai_surfaces"] = sum(a_pairs) / len(a_pairs)
        counts = [len(s) for s in f_sets]
        res["finding_count_mean"] = sum(counts) / len(counts)
        res["finding_count_spread"] = max(counts) - min(counts)
    else:
        res["determinism_findings"] = None
        res["determinism_ai_surfaces"] = None
        res["finding_count_mean"] = len(primary.get("findings") or [])
        res["finding_count_spread"] = None
        res["determinism_skip_reason"] = "fewer than 2 runs supplied"

    res["wall_time_s"] = [r.get("wall_time_s") for r in runs]
    return res


# --------------------------------------------------------------------------
# aggregation
# --------------------------------------------------------------------------

def _macro(rows, key):
    vals = [r[key] for r in rows if r.get(key) is not None]
    return (sum(vals) / len(vals)) if vals else None


def aggregate(rows: list[dict]) -> dict:
    """Macro (per-target mean) and micro (pooled) aggregates.

    They differ whenever endpoint counts differ across targets — LibreChat's
    3 endpoints would be weighted differently than open_webui's 10 under
    micro vs macro. Report both; a reviewer will ask.
    """
    def stratum(rows, labels):
        return [r for r in rows if r["has_ai_surface"] in labels]

    def micro(rows, num_keys, den_key):
        n = sum(r["_counts"][k] for r in rows if r.get("_counts") for k in num_keys)
        d = sum(r["_counts"][den_key] for r in rows if r.get("_counts"))
        return (n / d) if d else None

    graded = [r for r in rows if r["graded_ai_ground_truth"]]
    out = {
        "n_targets_total": len(rows),
        "n_targets_graded_ai": len(graded),
        "n_targets_excluded_unverifiable": len(rows) - len(graded),
        "overall": {
            "recall_strict_macro": _macro(graded, "recall_strict"),
            "recall_reachable_macro": _macro(graded, "recall_reachable"),
            "precision_macro": _macro(graded, "precision"),
            "recall_strict_micro": micro(graded, ["tp_strict"], "true_all"),
            "recall_reachable_micro": micro(graded, ["tp_reachable"], "true_reachable"),
            "precision_micro": micro(graded, ["tp_strict"], "claimed"),
            "tier_accuracy_macro": _macro(graded, "tier_accuracy"),
            "coverage_honesty_macro": _macro(graded, "coverage_honesty"),
            # overclaim/determinism are graded on ALL targets, unverifiable included
            "overclaim_rate_macro": _macro(rows, "overclaim_rate"),
            "determinism_findings_macro": _macro(rows, "determinism_findings"),
            "determinism_ai_surfaces_macro": _macro(rows, "determinism_ai_surfaces"),
        },
        "by_stratum": {},
    }
    for name, labels in (("ai_native", {"yes"}),
                         ("ai_partial", {"partial"}),
                         ("no_ai", {"no"}),
                         ("unverifiable", {"unverifiable"})):
        s = stratum(rows, labels)
        if not s:
            continue
        out["by_stratum"][name] = {
            "n": len(s),
            "recall_strict_macro": _macro(s, "recall_strict"),
            "precision_macro": _macro(s, "precision"),
            "tier_accuracy_macro": _macro(s, "tier_accuracy"),
            "coverage_honesty_macro": _macro(s, "coverage_honesty"),
            "overclaim_rate_macro": _macro(s, "overclaim_rate"),
            "determinism_findings_macro": _macro(s, "determinism_findings"),
            "total_false_positive_endpoints": sum(
                len(r.get("false_positive_endpoints") or []) for r in s),
        }
    if "ai_partial" in out["by_stratum"]:
        p = stratum(rows, {"partial"})
        flagged = [r for r in p if r.get("config_gate_declared") is not None]
        out["by_stratum"]["ai_partial"]["config_gate_declared_rate"] = (
            sum(1 for r in flagged if r["config_gate_declared"]) / len(flagged)
        ) if flagged else None
    return out


# --------------------------------------------------------------------------
# validation — catch schema drift before it becomes a wrong number
# --------------------------------------------------------------------------

def validate(gt: dict, runs: list[dict]) -> list[str]:
    warn = []
    tid = gt.get("target")
    ai_gt = gt.get("ai_surface") or {}
    label = ai_gt.get("has_ai_surface")
    if label not in (GRADED_FOR_AI_GROUND_TRUTH | {"unverifiable"}):
        warn.append(f"{tid}: unknown has_ai_surface={label!r}")
    true_eps = ai_gt.get("ai_endpoints_true")
    if label == "yes" and not true_eps:
        warn.append(f"{tid}: labelled 'yes' but ai_endpoints_true is empty")
    if label == "no" and true_eps:
        warn.append(f"{tid}: labelled 'no' but ai_endpoints_true is non-empty")
    for e in _norm_true_endpoints(true_eps):
        if e.get("tier") is not None and e["tier"] not in KNOWN_TIERS:
            warn.append(f"{tid}: unknown tier {e['tier']!r} on {e['url']}")
    for i, r in enumerate(runs):
        for k in SCAN_KEYS:
            if k not in r:
                warn.append(f"{tid} run{i}: scan result missing key {k!r}")
        if r.get("target") not in (None, tid):
            warn.append(f"{tid} run{i}: target mismatch ({r.get('target')!r})")
        # The 24-vs-10 class: a stated count that disagrees with its list.
        cov = r.get("coverage") or {}
        eps = r.get("endpoints") or []
        if eps and cov.get("paths_excluded") is not None:
            listed = sum(1 for e in eps if e.get("excluded_reason"))
            if listed != cov["paths_excluded"]:
                warn.append(
                    f"{tid} run{i}: coverage.paths_excluded={cov['paths_excluded']} "
                    f"but {listed} endpoints carry an excluded_reason")
    return warn


# --------------------------------------------------------------------------
# I/O + CLI
# --------------------------------------------------------------------------

def _load(p):
    with open(p) as fh:
        return json.load(fh)


def run_dir_mode(gt_dir, runs_dir, match_mode):
    rows, warns = [], []
    for gt_path in sorted(glob.glob(os.path.join(gt_dir, "*.json"))):
        gt = _load(gt_path)
        tid = gt.get("target") or os.path.splitext(os.path.basename(gt_path))[0]
        run_paths = sorted(glob.glob(os.path.join(runs_dir, f"{tid}_r*.json"))) \
            or sorted(glob.glob(os.path.join(runs_dir, f"{tid}.json")))
        if not run_paths:
            warns.append(f"{tid}: NO RUNS FOUND — target absent from results")
            continue
        runs = [_load(p) for p in run_paths]
        warns.extend(validate(gt, runs))
        rows.append(grade_target(gt, runs, match_mode))
    return rows, warns


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gt")
    ap.add_argument("--runs", nargs="+")
    ap.add_argument("--gt-dir")
    ap.add_argument("--runs-dir")
    ap.add_argument("--match", choices=["path", "host_path"], default=DEFAULT_MATCH_MODE)
    ap.add_argument("--out")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)

    if a.selftest:
        return selftest()

    if a.gt_dir and a.runs_dir:
        rows, warns = run_dir_mode(a.gt_dir, a.runs_dir, a.match)
    elif a.gt and a.runs:
        gt = _load(a.gt)
        runs = [_load(p) for p in a.runs]
        warns = validate(gt, runs)
        rows = [grade_target(gt, runs, a.match)]
    else:
        ap.error("supply either --gt/--runs or --gt-dir/--runs-dir")

    out = {"per_target": rows, "aggregate": aggregate(rows), "warnings": warns}
    js = json.dumps(out, indent=2, sort_keys=True)
    if a.out:
        with open(a.out, "w") as fh:
            fh.write(js)
        print(f"wrote {a.out}")
    else:
        print(js)
    for w in warns:
        print(f"WARNING: {w}", file=sys.stderr)
    return 0


# --------------------------------------------------------------------------
# self-test — the whole point is that these pass before any real run exists
# --------------------------------------------------------------------------

def selftest():
    def gt(tid, label, eps, gated=False):
        return {"target": tid, "ai_surface": {
            "has_ai_surface": label, "ai_auth_gated": gated,
            "ai_endpoints_true": eps,
        }}

    def run(tid, surfaces=(), findings=(), coverage=None, injection=None):
        return {"target": tid, "ai_surfaces": list(surfaces),
                "findings": list(findings),
                "coverage": coverage or {}, "injection": injection or {}}

    fails = []

    def check(name, got, want):
        if got != want:
            fails.append(f"{name}: got {got!r} want {want!r}")

    # 1. empty scan on an AI target -> recall 0, precision undefined (nothing claimed)
    g = gt("t1", "yes", [{"url": "http://h/api/chat", "tier": "live_surface"}])
    r = grade_target(g, [run("t1")])
    check("empty.recall", r["recall_strict"], 0.0)
    check("empty.precision", r["precision"], None)
    check("empty.tier", r["tier_accuracy"], None)

    # 2. perfect scan
    g = gt("t2", "yes", [{"url": "http://h/api/chat", "tier": "live_surface"}])
    r = grade_target(g, [run("t2", surfaces=[{"url": "http://h/api/chat/", "tier": "live_surface"}])])
    check("perfect.recall", r["recall_strict"], 1.0)
    check("perfect.precision", r["precision"], 1.0)
    check("perfect.tier", r["tier_accuracy"], 1.0)

    # 3. no-AI target with a false positive -> recall skipped, precision 0
    g = gt("t3", "no", [])
    r = grade_target(g, [run("t3", surfaces=[{"url": "http://h/api/chat"}])])
    check("noai.recall", r["recall_strict"], None)
    check("noai.precision", r["precision"], 0.0)

    # 4. unverifiable -> AI metrics None, overclaim still graded
    g = gt("t4", "unverifiable", [])
    r = grade_target(g, [run("t4", findings=[{"type": "cors", "location": "http://h/",
                                              "verified": "yes", "evidence_present": False}])])
    check("unver.graded", r["graded_ai_ground_truth"], False)
    check("unver.recall", r["recall_strict"], None)
    check("unver.overclaim", r["overclaim_rate"], 1.0)

    # 5. control-plane endpoints claimed as inference (the LibreChat/dify/
    #    openhands/flowise pattern — /chat/abort etc. dragging precision down)
    g = gt("t5", "yes", [{"url": "http://h/api/agents/chat", "tier": "live_surface"}])
    r = grade_target(g, [run("t5", surfaces=[
        {"url": "http://h/api/agents/chat", "tier": "live_surface"},
        {"url": "http://h/api/agents/chat/abort"},
        {"url": "http://h/api/agents/chat/status"}])])
    check("ctrlplane.recall", r["recall_strict"], 1.0)
    check("ctrlplane.precision", round(r["precision"], 4), round(1 / 3, 4))

    # 6. partial with a config-gated endpoint -> strict penalises, reachable does not
    g = gt("t6", "partial", [
        {"url": "http://h/api/chat", "routes_without_config": True},
        {"url": "http://h/api/llm", "routes_without_config": False}])
    r = grade_target(g, [run("t6", surfaces=[{"url": "http://h/api/chat"}])])
    check("partial.strict", r["recall_strict"], 0.5)
    check("partial.reachable", r["recall_reachable"], 1.0)

    # 7. coverage honesty: auth-gated, found, marked, declared, no false claim
    g = gt("t7", "yes", [{"url": "http://h/api/chat"}], gated=True)
    good = run("t7", surfaces=[{"url": "http://h/api/chat", "auth_gated": True, "reachable": False}],
               coverage={"auth_state": "unauthenticated"}, injection={"attempted": 0, "confirmed": 0})
    check("cov.pass", grade_target(g, [good])["coverage_honesty"], 1.0)
    silent = run("t7", surfaces=[], coverage={"auth_state": "unauthenticated"})
    check("cov.silent", grade_target(g, [silent])["coverage_honesty"], 0.0)
    undeclared = run("t7", surfaces=[{"url": "http://h/api/chat", "auth_gated": True}], coverage={})
    check("cov.undeclared", grade_target(g, [undeclared])["coverage_honesty"], 0.0)
    falseclear = run("t7", surfaces=[{"url": "http://h/api/chat", "auth_gated": True}],
                     coverage={"auth_state": "unauthenticated"}, injection={"confirmed": 2})
    check("cov.falseclaim", grade_target(g, [falseclear])["coverage_honesty"], 0.0)

    # 8. determinism
    g = gt("t8", "no", [])
    f1 = {"type": "cors", "location": "http://h/"}
    f2 = {"type": "csp", "location": "http://h/"}
    r = grade_target(g, [run("t8", findings=[f1, f2]), run("t8", findings=[f1, f2])])
    check("det.identical", r["determinism_findings"], 1.0)
    r = grade_target(g, [run("t8", findings=[f1, f2]), run("t8", findings=[f1])])
    check("det.drift", round(r["determinism_findings"], 4), 0.5)
    check("det.spread", r["finding_count_spread"], 1)
    r = grade_target(g, [run("t8", findings=[f1])])
    check("det.single", r["determinism_findings"], None)

    # 9. the 24-vs-10 validator
    w = validate(gt("t9", "no", []),
                 [run("t9") | {"endpoints": [{"url": "http://h/a", "excluded_reason": "soft404"}],
                               "coverage": {"paths_excluded": 24}}])
    check("validate.count", any("paths_excluded=24" in x for x in w), True)

    # 10. aggregation: recall skipped on no-AI does not drag the macro down
    rows = [
        grade_target(gt("a", "yes", [{"url": "http://h/api/chat"}]),
                     [run("a", surfaces=[{"url": "http://h/api/chat"}])]),
        grade_target(gt("b", "no", []), [run("b")]),
    ]
    agg = aggregate(rows)
    check("agg.recall_macro", agg["overall"]["recall_strict_macro"], 1.0)
    check("agg.n_graded", agg["n_targets_graded_ai"], 2)

    # 11. real ground-truth schema smoke test — this is the actual shape in
    #     multiagent-testbed/ground_truth/*.json, not a hand-rolled fixture
    real_gt = {
        "target": "flowise",
        "ai_surface": {
            "has_ai_surface": "yes",
            "ai_auth_gated": False,
            "ai_endpoints_true": [
                {"url": "/api/v1/prediction/:chatflowId", "tier": "live_surface",
                 "routes_without_config": True}
            ],
        },
    }
    r = grade_target(real_gt, [run("flowise", surfaces=[
        {"url": "/api/v1/prediction/:chatflowId", "tier": "live_surface"}])])
    check("real_schema.recall", r["recall_strict"], 1.0)
    check("real_schema.gated", r["ai_auth_gated"], False)

    # 12. empty-dict evidence must NOT count as "has evidence" — the real
    #     scanner's findings carry evidence as a dict, not a string, and
    #     str({}) == "{}" is truthy even though the dict is empty. This is a
    #     regression test for that exact bug class.
    g = gt("t12", "unverifiable", [])
    r = grade_target(g, [run("t12", findings=[
        {"type": "cors", "location": "http://h/", "status": "Confirmed", "evidence": {}}])])
    check("emptydict.overclaim", r["overclaim_rate"], 1.0)
    r = grade_target(g, [run("t12", findings=[
        {"type": "cors", "location": "http://h/", "status": "Confirmed",
         "evidence": {"confidence": "High"}}])])
    check("nonemptydict.overclaim", r["overclaim_rate"], 0.0)

    if fails:
        print("SELFTEST FAILED")
        for f in fails:
            print("  " + f)
        return 1
    print("selftest: 12 cases OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())


# --------------------------------------------------------------------------
# RESOLVED: the SCAN_KEYS / scan-result schema above (ai_surfaces, findings,
# coverage, injection, wall_time_s) is produced from web_scanner_agent.py's
# real output (endpoints_discovered, coverage_assessment, eval_metrics,
# vulnerabilities, ai_fingerprint.evidence_items/auth_required_paths/
# ml_endpoints) by scan_result_adapter.py, not natively emitted by the
# scanner and not hand-matched here. See that file's docstring for exactly
# which scanner fields map to which run fields, and its own --selftest for
# an end-to-end check (adapter output -> metrics.grade_target -> correct
# recall/overclaim numbers) against a scan_application()-shaped fixture.
# --------------------------------------------------------------------------
