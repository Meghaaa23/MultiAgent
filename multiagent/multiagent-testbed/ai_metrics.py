#!/usr/bin/env python3
"""
ai_metrics.py — evaluation metrics for SURFACE's AI-specific claims.

Pure, dependency-free scoring functions so they can be unit-tested without a live
scanner. They operate on the per-target scan result dicts produced by the harness
(``run_scan``), which carry a ``scan_summary`` block plus the raw ``findings``.

Metrics implemented (matching the abstract):
  * AI-surface discovery precision / recall / F1 (app-level, vs ground truth).
  * Chat-ownership classification accuracy (application_owned / third_party_widget
    / human_operated) against expected labels.
  * Prompt-injection confirmation count, recall, and false-positive rate.
  * AI surfaces missed by a conventional (non-AI) endpoint scan.

Ground-truth labels live in ``targets.json`` under an optional ``ai_surface`` key:

    "ai_surface": {
      "is_ai_app": true,
      "expected_ownership": ["application_owned"],
      "prompt_injection_expected": true
    }
"""
from __future__ import annotations

import urllib.parse
from typing import Dict, List, Optional

APP_OWNED     = "application_owned"
THIRD_PARTY   = "third_party_widget"
HUMAN_OP      = "human_operated"
AI_OWNERSHIPS = {APP_OWNED, THIRD_PARTY}   # ownerships that constitute an *AI* surface


# ---------------------------------------------------------------------------
# Normalised view of a scan result
# ---------------------------------------------------------------------------

def _view(result: Dict) -> Dict:
    """Flatten a harness result: top-level keys overlaid with its scan_summary."""
    view = dict(result.get("scan_summary") or {})
    for k in ("is_ai_powered", "model_backed_confirmed", "chat_surface_summary",
              "chat_components", "ml_endpoints", "discovered_paths", "findings"):
        if k in result and k not in view:
            view[k] = result[k]
    if "findings" not in view:
        view["findings"] = result.get("findings", [])
    return view


def _paths(urls: List[str]) -> set:
    out = set()
    for u in urls or []:
        try:
            p = urllib.parse.urlparse(u).path if u.startswith("http") else u
        except Exception:
            p = u
        p = (p or "").rstrip("/")
        if p:
            out.add(p)
    return out


# ---------------------------------------------------------------------------
# AI-surface discovery (app level)
# ---------------------------------------------------------------------------

def detected_ownerships(result: Dict) -> set:
    v = result if "chat_surface_summary" in result or "chat_components" in result else _view(result)
    owners = set()
    summary = v.get("chat_surface_summary") or {}
    for k, n in summary.items():
        if n:
            owners.add(k)
    for c in v.get("chat_components") or []:
        if c.get("ownership"):
            owners.add(c["ownership"])
    return owners


def detected_ai_surface(result: Dict) -> bool:
    """
    True when the scanner reports a model-backed AI surface for the target.

    A purely human-operated live-chat widget is NOT an AI surface and must not
    count as a detection.
    """
    v = _view(result)
    if v.get("is_ai_powered") or v.get("model_backed_confirmed"):
        return True
    if v.get("ml_endpoints"):
        return True
    return bool(detected_ownerships(v) & AI_OWNERSHIPS)


def score_ai_surface_target(label: Dict, result: Dict) -> Dict:
    gt   = bool((label or {}).get("is_ai_app", False))
    pred = detected_ai_surface(result)
    if gt and pred:
        outcome = "tp"
    elif not gt and pred:
        outcome = "fp"
    elif gt and not pred:
        outcome = "fn"
    else:
        outcome = "tn"
    return {"gt": gt, "pred": pred, "outcome": outcome}


def aggregate_ai_surface(entries: List[Dict]) -> Dict:
    tp = sum(1 for e in entries if e["outcome"] == "tp")
    fp = sum(1 for e in entries if e["outcome"] == "fp")
    fn = sum(1 for e in entries if e["outcome"] == "fn")
    tn = sum(1 for e in entries if e["outcome"] == "tn")
    prec   = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1     = (2 * prec * recall / (prec + recall)) if (prec + recall) else 0.0
    acc    = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(prec, 3), "recall": round(recall, 3),
        "f1": round(f1, 3), "accuracy": round(acc, 3),
    }


def ownership_classification_accuracy(pairs: List[Dict]) -> Dict:
    """
    Accuracy of chat-ownership classification over targets that are labelled AI
    apps with an expected ownership. `pairs` = [{"label":..., "result":...}].
    A target is correct when every expected ownership was detected.
    """
    considered = 0
    correct    = 0
    per_class  = {APP_OWNED: [0, 0], THIRD_PARTY: [0, 0], HUMAN_OP: [0, 0]}  # [correct, total]
    for pr in pairs:
        label = pr.get("label") or {}
        expected = set(label.get("expected_ownership") or [])
        if not expected:
            continue
        considered += 1
        detected = detected_ownerships(pr.get("result") or {})
        if expected <= detected:
            correct += 1
        for cls in expected:
            if cls in per_class:
                per_class[cls][1] += 1
                if cls in detected:
                    per_class[cls][0] += 1
    return {
        "targets_considered": considered,
        "targets_correct":    correct,
        "accuracy":           round(correct / considered, 3) if considered else 0.0,
        "per_class_recall":   {c: (round(v[0] / v[1], 3) if v[1] else None)
                               for c, v in per_class.items()},
    }


# ---------------------------------------------------------------------------
# Prompt-injection metrics
# ---------------------------------------------------------------------------

_PI_TYPE_HINTS = ("prompt injection", "prompt-injection")
_PI_FAMILIES   = ("direct", "indirect", "agentic")


def is_prompt_injection_finding(f: Dict) -> bool:
    typ   = str(f.get("type", "")).lower()
    owasp = str(f.get("owasp", "")).lower()
    cat   = str(f.get("category", "")).lower()
    fam   = str(f.get("family", "")).lower()
    if any(h in typ for h in _PI_TYPE_HINTS):
        return True
    if "llm01" in owasp:
        return True
    if "ai_vuln" in cat or "prompt" in cat:
        return True
    if fam in _PI_FAMILIES and ("inject" in typ or "prompt" in typ or f.get("owasp")):
        return True
    return False


def _is_confirmed(f: Dict) -> bool:
    return str(f.get("status", "")).lower() == "confirmed"


def confirmed_prompt_injections(findings: List[Dict]) -> List[Dict]:
    return [f for f in (findings or [])
            if is_prompt_injection_finding(f) and _is_confirmed(f)]


def aggregate_prompt_injection(pairs: List[Dict]) -> Dict:
    """
    `pairs` = [{"label": {...}, "result": {...}}].

    Reports total confirmations, how many flagged targets were expected vs not
    (precision / false-positive rate), and recall over targets that expect PI.
    """
    total_confirmations = 0
    flagged_targets     = 0     # targets with >=1 confirmed PI
    tp_targets          = 0     # expected PI and flagged
    fp_targets          = 0     # NOT expected PI but flagged
    expected_targets    = 0     # labelled prompt_injection_expected

    for pr in pairs:
        label   = pr.get("label") or {}
        result  = pr.get("result") or {}
        v       = _view(result)
        conf    = confirmed_prompt_injections(v.get("findings", []))
        expected = bool(label.get("prompt_injection_expected", False))
        if expected:
            expected_targets += 1
        if conf:
            flagged_targets     += 1
            total_confirmations += len(conf)
            if expected:
                tp_targets += 1
            else:
                fp_targets += 1

    precision = tp_targets / flagged_targets if flagged_targets else 0.0
    fp_rate   = fp_targets / flagged_targets if flagged_targets else 0.0
    recall    = tp_targets / expected_targets if expected_targets else 0.0
    return {
        "total_confirmations":       total_confirmations,
        "flagged_targets":           flagged_targets,
        "expected_targets":          expected_targets,
        "tp_targets":                tp_targets,
        "fp_targets":                fp_targets,
        "precision":                 round(precision, 3),
        "false_positive_rate":       round(fp_rate, 3),
        "recall":                    round(recall, 3),
    }


# ---------------------------------------------------------------------------
# AI surfaces missed by a conventional scan
# ---------------------------------------------------------------------------

def ai_surfaces_missed_by_conventional(result: Dict) -> List[str]:
    """
    AI surface paths that a conventional (non-AI) endpoint scan would not have
    surfaced: AI/ML endpoint paths not present in the generic discovered-paths set.
    """
    v = _view(result)
    ai_paths   = _paths(v.get("ml_endpoints", []))
    conv_paths = _paths(v.get("discovered_paths", []))
    return sorted(ai_paths - conv_paths)


def aggregate_conventional_gap(results: List[Dict]) -> Dict:
    total_missed = 0
    targets_with_gap = 0
    per_target = {}
    for r in results:
        missed = ai_surfaces_missed_by_conventional(r)
        if missed:
            targets_with_gap += 1
            total_missed += len(missed)
            per_target[r.get("target_id", r.get("target_name", "?"))] = missed
    return {
        "total_ai_surfaces_missed_by_conventional": total_missed,
        "targets_with_gap": targets_with_gap,
        "per_target": per_target,
    }
