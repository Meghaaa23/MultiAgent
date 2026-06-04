# agents/threat_modeling_agent.py

import os
import re
import json
import openai
import pymongo
import hashlib
import logging
import traceback
from typing import Dict, List, Optional
from datetime import datetime

from .webappscanner.action_agent import ActionAgent

from .redis_manager import cache_result, get_cached_result
from .vector_search import VectorSearch
from .webappscanner.web_scanner_agent import WebScannerAgent
from langchain_community.vectorstores import MongoDBAtlasVectorSearch
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain.docstore.document import Document

from utils.threat_prompts import (
    QUESTION_DECOMPOSITION_PROMPT,
    STRIDE_ANALYSIS_PROMPT,
    SYNTHESIS_PROMPT,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Post-processors
# ---------------------------------------------------------------------------

_VALID_OWASP = {
    "A01", "A02", "A03", "A04", "A05",
    "A06", "A07", "A08", "A09", "A10",
    "A01:2021", "A02:2021", "A03:2021", "A04:2021", "A05:2021",
    "A06:2021", "A07:2021", "A08:2021", "A09:2021", "A10:2021",
}


def _sanitize_report(report_text: str) -> str:
    if not report_text:
        return report_text
    lines             = report_text.split("\n")
    cleaned_lines     = []
    seen_owasp_lines  = set()
    in_compliance     = False
    compliance_ended  = False
    table_row_count   = 0

    for line in lines:
        if " 7." in line or " 7 " in line or "COMPLIANCE" in line.upper():
            in_compliance = True
            cleaned_lines.append(line)
            continue
        if in_compliance and compliance_ended:
            continue
        m = re.search(r'\bA(\d{2,3})\b', line)
        if m and int(m.group(1)) > 10:
            continue
        norm = re.sub(r'\s+', ' ', line.strip().lower())
        if "broken xss protection" in norm:
            if norm in seen_owasp_lines:
                continue
            seen_owasp_lines.add(norm)
        if in_compliance and line.strip().startswith("|"):
            table_row_count += 1
            if table_row_count > 30:
                compliance_ended = True
                continue
        elif in_compliance and table_row_count > 0 and not line.strip().startswith("|"):
            if line.strip():
                compliance_ended = True
                continue
        cleaned_lines.append(line)

    final_lines = []
    for line in "\n".join(cleaned_lines).split("\n"):
        m = re.search(r'\bA(\d{2,3})\b', line)
        if m and int(m.group(1)) > 10:
            continue
        final_lines.append(line)
    return "\n".join(final_lines)


def _truncate_at_section(report_text: str, max_section: int = 7) -> str:
    section_pattern = re.compile(r'^## \d+\.', re.MULTILINE)
    matches         = list(section_pattern.finditer(report_text))
    if not matches:
        return report_text
    sec7_start = None
    for m in matches:
        sn = re.match(r'^## (\d+)', m.group())
        if sn and int(sn.group(1)) == max_section:
            sec7_start = m.start()
            break
    if sec7_start is None:
        return report_text
    for m in matches:
        sn = re.match(r'^## (\d+)', m.group())
        if sn and int(sn.group(1)) > max_section:
            return report_text[:m.start()].rstrip()
    return report_text


def _format_confirmed_stack(stack: Dict) -> str:
    confirmed  = stack.get("technologies", [])
    unverified = stack.get("unverified_hints", [])
    if not confirmed:
        note = (
            f" Hints detected but NOT confirmed: {', '.join(unverified)}"
            if unverified else ""
        )
        return f"Unknown (no technology confirmed from HTTP evidence).{note}"
    evidence_map = stack.get("confirmed_by", {})
    parts = [
        f"{t} [{evidence_map.get(t, 'confirmed')}]" for t in confirmed
    ]
    result = ", ".join(parts)
    if unverified:
        result += f"\nEXCLUDED (unconfirmed): {', '.join(unverified)}"
    return result


_CWE_TO_OWASP = {
    "CWE-79":   ("A03:2021", "Injection"),
    "CWE-89":   ("A03:2021", "Injection"),
    "CWE-538":  ("A05:2021", "Security Misconfiguration"),
    "CWE-200":  ("A05:2021", "Security Misconfiguration"),
    "CWE-693":  ("A05:2021", "Security Misconfiguration"),
    "CWE-352":  ("A01:2021", "Broken Access Control"),
    "CWE-601":  ("A01:2021", "Broken Access Control"),
    "CWE-22":   ("A01:2021", "Broken Access Control"),
    "CWE-942":  ("A05:2021", "Security Misconfiguration"),
    "CWE-1021": ("A04:2021", "Insecure Design"),
    "CWE-284":  ("A01:2021", "Broken Access Control"),
    "CWE-77":   ("A03:2021", "Injection"),
    "CWE-434":  ("A04:2021", "Insecure Design"),
    "CWE-770":  ("A05:2021", "Security Misconfiguration"),
}


# ---------------------------------------------------------------------------
# Python-generated report
# ---------------------------------------------------------------------------

def _build_section_1(confirmed_vulns, potential_vulns, target_url, scan_results):
    n_confirmed = len(confirmed_vulns)
    n_potential = len(set(v.get("type", "") for v in potential_vulns))
    duration    = (scan_results or {}).get("scan_duration", 0)

    # Weighted risk score: severity base × confirmation-method multiplier
    # Only confirmed vulns drive the primary risk; potential vulns contribute a fraction
    _sev_base = {"Critical": 40, "High": 20, "Medium": 10, "Low": 5, "Info": 1}
    _method_mult = {
        "js_execution":  1.5,   # alert() fired — highest confidence
        "timing":        1.4,   # time-delay confirmed
        "dom_reflection": 1.2,  # DOM injection confirmed via Playwright
        "http_body":     1.0,   # payload in raw HTTP response
        "pattern":       0.8,   # regex error pattern
        "header":        0.5,   # passive header check
    }
    exploit_score = 0.0
    for v in confirmed_vulns:
        method = v.get("evidence", {}).get("confirmation_method", "http_body")
        base   = _sev_base.get(v.get("severity", "Low"), 5)
        mult   = _method_mult.get(method, 1.0)
        exploit_score += base * mult
    # Potential vulns add a smaller fractional weight (unconfirmed)
    for v in potential_vulns:
        base = _sev_base.get(v.get("severity", "Low"), 5)
        exploit_score += base * 0.3

    risk = (
        "Critical"   if exploit_score >= 40 else
        "High"       if exploit_score >= 20 else
        "Medium"     if exploit_score >= 8  else
        "Low-Medium" if exploit_score >  0  else "Low"
    )

    authenticated = (scan_results or {}).get("authenticated_scan", False)

    actions = [
        v.get("remediation", "")[:100]
        for v in (confirmed_vulns + potential_vulns)[:3]
        if v.get("remediation")
    ] or ["No immediate action required — continue monitoring."]

    actions_text = " ".join(f"({i+1}) {a}" for i, a in enumerate(actions[:3]))
    auth_note = " [Authenticated scan]" if authenticated else " [Unauthenticated — post-login surfaces not tested]"
    summary = (
        f"Active scan of `{target_url}` completed in {duration:.0f}s{auth_note}. "
        f"Identified {n_confirmed} confirmed and {n_potential} potential "
        f"vulnerability type(s). Overall risk level: **{risk}** (score: {exploit_score:.0f})"
    )
    if n_confirmed == 0 and n_potential == 0:
        summary += (
            " — no exploitable surfaces found. "
            "Consider providing a session cookie for authenticated scanning."
        )
    else:
        summary += f". Top actions: {actions_text}"

    return f" 1. EXECUTIVE SUMMARY\n{summary}"


def _build_section_2(stack, endpoints, cves):
    """
    Build Section 2 — Technology Stack & Attack Surface.
    FIX: Added missing return statement and improved stack fallback logic.
    """
    lines = [" 2. TECHNOLOGY STACK & ATTACK SURFACE",
             " Technology Stack"]

    noise_words = {"content", "unknown", "none", "null", "n/a", "signals",
                   "content signals", "true", "false"}

    # Filter confirmed technologies
    confirmed = [
        t for t in (stack.get("technologies") or [])
        if t
        and len(str(t).strip()) > 2
        and "signal" not in str(t).lower()
        and str(t).strip().lower() not in noise_words
    ]

    if confirmed:
        lines.extend(f"- {t}" for t in confirmed)
    else:
        # Fallback 1: stack_summary field
        summary = stack.get("stack_summary", "")
        noise_summary = {
            "unknown",
            "unknown (no technology confirmed from http evidence)",
            "",
        }
        if summary and summary.strip().lower() not in noise_summary:
            lines.append(f"- {summary}")
        else:
            # Fallback 2: individual stack fields (server, language, framework etc.)
            added = False
            for field in ("server", "language", "framework", "frontend", "cms", "cdn"):
                val = stack.get(field)
                if val and str(val).strip().lower() not in noise_words:
                    lines.append(f"- {val}")
                    added = True

            if not added:
                lines.append(
                    "Unknown — target is behind a CDN/WAF that strips identifying headers. "
                    "See Information Disclosure findings in Section 3 for detected headers."
                )

    unverified = stack.get("unverified_hints", [])
    if unverified:
        lines.append(f"\n*Unconfirmed hints (excluded): {', '.join(unverified[:5])}*")

    # Discovered endpoints
    lines.append("\n Discovered Endpoints")
    interesting = [e for e in (endpoints or []) if e.get("interesting")]
    if interesting:
        for ep in interesting[:15]:
            auth = " [AUTH REQUIRED]" if ep.get("auth_required") else ""
            lines.append(
                f"- [{ep.get('status','?')}] {ep.get('method','GET')} "
                f"{ep.get('url','')} [{ep.get('source','')}]{auth}"
            )
    else:
        lines.append("None discovered.")

    # Verified CVEs
    lines.append("\n Verified CVEs (NVD/OSV)")
    if cves:
        for cve in cves[:5]:
            lines.append(
                f"- *{cve.get('cve_id','?')}* [{cve.get('severity','?')}] "
                f"CVSS {cve.get('cvss_score','N/A')} — "
                f"{cve.get('description','')[:150]}"
            )
    else:
        lines.append("None found for this stack in NVD/OSV.")

    return "\n".join(lines)


_CONFIDENCE_LABEL = {
    "js_execution":   "HIGH  (JavaScript executed)",
    "timing":         "HIGH  (timing-confirmed)",
    "dom_reflection": "HIGH  (DOM reflection confirmed)",
    "http_body":      "MEDIUM (HTTP body reflection)",
    "pattern":        "MEDIUM (error pattern match)",
    "header":         "LOW   (passive header check)",
}


def _build_section_3(confirmed_vulns):
    lines = [" 3. CONFIRMED VULNERABILITIES"]
    if not confirmed_vulns:
        lines.append("No confirmed vulnerabilities identified from active scanning.")
        return "\n".join(lines)
    seen = set()
    for v in confirmed_vulns:
        key = (v.get("type", ""), v.get("location", ""))
        if key in seen:
            continue
        seen.add(key)
        ev     = v.get("evidence", {})
        method = ev.get("confirmation_method", "http_body")
        conf   = _CONFIDENCE_LABEL.get(method, "MEDIUM (code confirmed)")
        lines += [
            "",
            f"*Severity*: {v.get('severity','?')} | {v.get('type','?')}",
            f"- *Confidence*: {conf}",
            f"- *Location*: `{v.get('location','?')}`",
            f"- *Evidence*: `{ev.get('request','?')}` "
            f"(HTTP {ev.get('response_status','?')}, "
            f"confirmed by {method})",
            f"- *Impact*: {v.get('impact','')}",
            f"- *Fix*: {v.get('remediation','')}",
            f"- *CWE*: {v.get('cwe','')}",
        ]
    return "\n".join(lines)


def render_section_3b(action_results: list) -> str:
    if not action_results:
        return ""
    lines = [
        "\n 3b. ACTION AGENT — ATTACK PoCs & FIX SNIPPETS",
        "> Stack-specific fix code and proof-of-concept for each confirmed finding.\n",
    ]
    for a in action_results:
        e = a.get("effort_minutes", 0)
        effort = f"{e} min" if e < 60 else f"{e//60}h {e%60}min"
        poc_lang = {"curl": "bash", "html": "html", "command": "bash"}.get(
            a.get("poc_type", ""), "text"
        )
        lines += [
            f" [{a['severity']}] {a['finding_type']}",
            f"*Location:* `{a['location']}` | *Estimated fix effort:* {effort}\n",
            f"*Attack PoC ({a.get('poc_type', '')}):*",
            f"```{poc_lang}",
            a["attack_poc"],
            "```\n",
            f"*Fix ({a['fix_context']}):*",
            f"```{a['fix_language']}",
            a["fix_snippet"],
            "```\n",
            "---\n",
        ]
    return "\n".join(lines)


def _build_section_4(potential_vulns):
    lines = [" 4. POTENTIAL VULNERABILITIES"]
    if not potential_vulns:
        lines.append(
            "No potential vulnerabilities identified. "
            "All tested surfaces returned clean results."
        )
        return "\n".join(lines)
    seen = set()
    for i, v in enumerate(potential_vulns, 1):
        key = v.get("type", "")
        if key in seen:
            continue
        seen.add(key)
        ev     = v.get("evidence", {})
        method = ev.get("confirmation_method", "code analysis")
        snippet = ev.get("response_body_snippet", "")
        lines += [
            "",
            f" [{i}] {v.get('type','?')}",
            f"- *Severity*: {v.get('severity','Low')} | *Confidence*: LOW (unconfirmed — manual verification required)",
            f"- *Location*: {v.get('location','?')}",
            f"- *Why Potential*: Requires manual confirmation — {v.get('details','')}",
            f"- *Detection Method*: {method}",
        ]
        if snippet:
            lines.append(f"- *Evidence Snippet*: `{snippet[:120]}`")
        if v.get("cwe"):
            lines.append(f"- *CWE*: {v.get('cwe')}")
    return "\n".join(l for l in lines if l is not None)


def _build_section_5(stride_threats):
    lines = [
        " 5. ARCHITECTURAL THREAT MODEL (STRIDE)",
        " Architectural Risk — not a confirmed finding",
        "",
    ]
    if not stride_threats:
        lines += [
            "No architectural threats identified from scanner evidence.",
            "",
            "Note: STRIDE threats are only reported when supporting evidence",
            "was found during active scanning.",
        ]
        return "\n".join(lines)
    for t in stride_threats:
        status = "Evidence-confirmed" if t.get("confirmed") else "Evidence-based (potential)"
        lines += [
            f" {t.get('category','?')}: {t.get('threat','?')}",
            f"- *Status*: {status}",
            f"- *Evidence*: {t.get('evidence','?')}",
            f"- *Likelihood*: {t.get('likelihood','?')}",
            f"- *Impact*: {t.get('impact','?')}",
            f"- *Mitigation*: {t.get('mitigation','?')}",
            "",
        ]
    return "\n".join(lines)


def _build_section_6(confirmed_vulns, potential_vulns):
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    groups: Dict[str, List[str]] = {s: [] for s in severity_order}
    seen: set = set()

    for v in confirmed_vulns:
        key = (v.get("type", ""), v.get("location", ""))
        if key in seen:
            continue
        seen.add(key)
        sev = v.get("severity", "Low")
        groups.get(sev, groups["Low"]).append(
            f"- *{v.get('type','?')}* **\n"
            f"  Location: {v.get('location','?')}\n"
            f"  Fix: {v.get('remediation','')[:120]}"
        )

    for v in potential_vulns:
        key = (v.get("type", ""), v.get("location", ""))
        if key in seen:
            continue
        seen.add(key)
        sev = v.get("severity", "Low")
        groups.get(sev, groups["Low"]).append(
            f"- *{v.get('type','?')}* *(Potential — manual verification needed)*\n"
            f"  Location: {v.get('location','?')}\n"
            f"  Note: {v.get('details','')[:120]}"
        )

    lines = [" 6. PRIORITISED REMEDIATION ROADMAP", " Grouped by Severity"]
    any_finding = False
    for sev in severity_order:
        if groups[sev]:
            any_finding = True
            lines.append(f"\n {sev}")
            lines.extend(groups[sev])
    if not any_finding:
        lines.append("No findings requiring remediation.")
    return "\n".join(lines)


def _build_section_7(confirmed_vulns):
    header = (
        " 7. COMPLIANCE MAPPING\n"
        " OWASP Top 10 and CWE Mapping for Confirmed Findings Only\n\n"
        "| Finding | OWASP Category | CWE | Recommended Fix |\n"
        "|---------|---------------|-----|-----------------|\n"
    )
    if not confirmed_vulns:
        return (
            header +
            "| No confirmed vulnerabilities | N/A | N/A | No remediation required. |"
        )

    rows = []
    seen: set = set()
    for v in confirmed_vulns:
        key = (v.get("type", ""), v.get("location", ""))
        if key in seen:
            continue
        seen.add(key)
        cwe_raw  = v.get("cwe", "")
        cwe_list = [c.strip() for c in re.split(r"[,;/]", cwe_raw) if c.strip()][:2]
        cwe_str  = ", ".join(cwe_list) or "N/A"
        owasp_code, owasp_name = "A05:2021", "Security Misconfiguration"
        for cwe in cwe_list:
            if cwe in _CWE_TO_OWASP:
                owasp_code, owasp_name = _CWE_TO_OWASP[cwe]
                break
        fix = v.get("remediation", "")[:100]
        rows.append(
            f"| {v.get('type','?')} | {owasp_code} — {owasp_name} "
            f"| {cwe_str} | {fix} |"
        )
    return header + "\n".join(rows)


# ---------------------------------------------------------------------------
# Section 8 — AI Backdoor Analysis
# FIX 1: AVID CVEs filtered to detected ML stack only
# FIX 2: Detection Indicators added to all fallback recommendations
# ---------------------------------------------------------------------------

def _build_section_8_ai_backdoor(scan_results: Dict) -> str:
    ai_fp     = scan_results.get("ai_fingerprint", {})
    strategic = scan_results.get("strategic_recommendations", [])
    ai_vulns  = [
        f for f in scan_results.get("vulnerabilities", [])
        if f.get("category") == "ai_vulnerability"
    ]

    if not ai_fp or not ai_fp.get("is_ai_powered"):
        return ""

    # -----------------------------------------------------------------------
    # FIX 1: Filter AVID CVEs to only those relevant to the detected stack.
    # Previously all backdoor-relevant CVEs were shown regardless of target,
    # causing BentoML/InvokeAI/Langflow CVEs to appear on unrelated targets.
    # Now we only show CVEs whose title/description mentions a detected library
    # or technology from the stack.
    # -----------------------------------------------------------------------
    avid_raw = scan_results.get("avid_backdoor_relevant", [])

    ml_libraries   = ai_fp.get("ml_libraries", [])
    detected_stack = [
        t.lower() for t in
        (scan_results.get("stack") or {}).get("technologies", [])
    ]
    relevant_terms = [t.lower() for t in ml_libraries] + detected_stack

    if relevant_terms:
        avid = [
            cve for cve in avid_raw
            if any(
                term in (
                    cve.get("title", "") + " " + cve.get("description", "")
                ).lower()
                for term in relevant_terms
            )
        ]
    else:
        # No stack detected — show nothing rather than generic CVEs
        avid = []

    lines = [
        " 8. AI/ML BACKDOOR VULNERABILITY ANALYSIS",
        "",
        f"> *AI/ML components detected in this application* "
        f"[confidence: {ai_fp.get('confidence', 'medium')}]",
        "> Traditional web vulnerability scanning has been supplemented with "
        "AI-specific backdoor analysis per NIST AI 100-2 E2025 and MITRE ATLAS.",
        "",
    ]

    # 8.1 Detected AI Components
    lines.append(" 8.1 Detected AI/ML Components")
    lines.append("")

    if ai_fp.get("ml_endpoints"):
        lines.append("*ML Inference Endpoints:*")
        for ep in ai_fp["ml_endpoints"][:5]:
            lines.append(f"- `{ep}`")
        lines.append("")

    if ai_fp.get("ml_libraries"):
        libs = ", ".join(ai_fp["ml_libraries"][:6])
        lines.append(f"*Detected ML Libraries:* {libs}")
        lines.append("")

    if ai_fp.get("chat_components"):
        lines.append("*LLM Chat UI Components Detected:* Yes")
        lines.append("")

    if ai_fp.get("model_upload_endpoints"):
        lines.append("* Model File Upload Endpoints (HIGH RISK):*")
        for ep in ai_fp["model_upload_endpoints"][:3]:
            lines.append(f"- `{ep}` — accepts model files (.pkl, .pt, .h5)")
        lines.append(
            "\n> Pickle (.pkl) files execute arbitrary code on load. "
            "This is the primary vector for AML.T0018.002 — Embed Malware."
        )
        lines.append("")

    if ai_fp.get("atlas_techniques"):
        lines.append("*Applicable ATLAS Techniques (from detected signals):*")
        for tech in ai_fp["atlas_techniques"]:
            lines.append(f"- {tech}")
        lines.append("")

    # 8.2 Confirmed AI Vulnerabilities
    lines.append(" 8.2 Confirmed AI/ML Vulnerabilities")
    lines.append("")
    if ai_vulns:
        confirmed_ai = [v for v in ai_vulns if v.get("status") == "Confirmed"]
        potential_ai = [v for v in ai_vulns if v.get("status") == "Potential"]

        for v in confirmed_ai:
            lines += [
                f" [CONFIRMED] {v.get('type','?')}",
                f"- *Severity:* {v.get('severity','?')}",
                f"- *Location:* `{v.get('location','?')}`",
                f"- *ATLAS Technique:* {v.get('atlas', 'N/A')}",
                f"- *CWE:* {v.get('cwe', 'N/A')}",
                f"- *Impact:* {v.get('impact', v.get('details', ''))}",
                f"- *PoC:* `{v.get('poc','N/A')}`",
                f"- *Remediation:* {v.get('remediation','')}",
                "",
            ]
        for v in potential_ai:
            lines += [
                f" [POTENTIAL] {v.get('type','?')}",
                f"- *Severity:* {v.get('severity','?')}",
                f"- *Location:* `{v.get('location','?')}`",
                f"- *ATLAS Technique:* {v.get('atlas', 'N/A')}",
                f"- *Details:* {v.get('details','')}",
                f"- *Remediation:* {v.get('remediation','')}",
                "",
            ]
    else:
        lines.append(
            "No AI-specific vulnerabilities confirmed via active testing. "
            "See Section 8.4 for strategic recommendations on undetectable threats."
        )
        lines.append("")

    # 8.3 AVID CVEs (FIX 1 applied — filtered to detected stack)
    lines.append(" 8.3 AI-Specific CVEs from AVID Database")
    lines.append("")
    if avid:
        lines.append(
            "> Source: [AVID — AI Vulnerability and Incidents Database]"
            "(https://avidml.org/database/)"
        )
        lines.append("")
        lines.append("| CVE ID | Severity | ATLAS Technique | Description |")
        lines.append("|--------|----------|-----------------|-------------|")
        for cve in avid[:8]:
            cve_id = cve.get("cve_id") or cve.get("avid_id", "N/A")
            sev    = cve.get("severity", "?")
            atlas  = cve.get("atlas_technique", "N/A")
            desc   = cve.get("title", cve.get("description", ""))[:80]
            lines.append(f"| {cve_id} | {sev} | {atlas} | {desc} |")
        lines.append("")
        lines.append(
            f"*{len(avid)} AI backdoor-relevant CVEs found. "
            f"Full details at [avidml.org/database](https://avidml.org/database/)*"
        )
        lines.append("")
    else:
        lines.append(
            "No AVID CVEs matched the detected ML stack. "
            "AVID coverage of AI vulnerabilities is still growing."
        )
        lines.append("")

    # 8.4 Strategic Recommendations (FIX 2 — indicators added to all fallback recs)
    lines.append(" 8.4 Strategic Recommendations (ATLAS-Based)")
    lines.append("")
    lines.append(
        "> The following threats **cannot be detected via black-box scanning** because "
        "they occur at training time or in the supply chain — before deployment. "
        "Reported as strategic recommendations based on NIST AI 100-2 E2025, "
        "MITRE ATLAS, and OWASP LLM04:2025."
    )
    lines.append("")

    # Use provided strategic recs or fall back to core ATLAS set
    # FIX 2: All fallback recs now include "indicators" field so the
    # Detection Indicators section renders correctly in the report.
    recs_to_use = strategic if strategic else [
        {
            "atlas_id":    "AML.T0018",
            "title":       "Backdoor ML Model",
            "severity":    "Critical",
            "description": (
                "A backdoored model operates normally under typical conditions "
                "but produces adversary-defined outputs when a hidden trigger is present. "
                "Cannot be detected from outside the system without model file access."
            ),
            "indicators": [
                "Model downloaded from untrusted/unverified repository",
                "No model integrity verification (hash/signature check) in place",
                "Unexpected behavior on specific structured inputs",
                "No model versioning or artifact signing in deployment pipeline",
            ],
            "mitigations": [
                "Verify model integrity via cryptographic hash before deployment",
                "Run modelscan/picklescan on all model files before loading",
                "Download models only from verified, audited sources",
                "Implement Neural Cleanse or STRIP for backdoor detection",
                "Monitor for concept drift — may indicate backdoor activation",
            ],
            "atlas_url": "https://atlas.mitre.org/techniques/AML.T0018",
            "nist_ref":  "NIST AI 100-2 E2025 § 3.1",
            "owasp_ref": "OWASP LLM04:2025 — Scenario #5",
        },
        {
            "atlas_id":    "AML.T0020",
            "title":       "Poison Training Data",
            "severity":    "High",
            "description": (
                "Training data poisoning cannot be detected via black-box scanning. "
                "An attacker with access to the training pipeline could corrupt model "
                "behavior by injecting malicious samples."
            ),
            "indicators": [
                "Unexpected model outputs on specific input patterns",
                "Model accuracy degradation over time",
                "Unusual confidence scores on boundary inputs",
                "Anomalous distribution shift in model predictions",
            ],
            "mitigations": [
                "Validate all training data sources and provenance",
                "Use OWASP CycloneDX or ML-BOM to track training data",
                "Implement anomaly detection on training data distribution",
                "Apply differential privacy during training",
            ],
            "atlas_url": "https://atlas.mitre.org/techniques/AML.T0020",
            "nist_ref":  "NIST AI 100-2 E2025 § 3.2",
            "owasp_ref": "OWASP LLM04:2025 — Data Poisoning",
        },
        {
            "atlas_id":    "AML.T0010",
            "title":       "ML Supply Chain Compromise",
            "severity":    "High",
            "description": (
                "ML models sourced from public repositories (Hugging Face, PyPI, GitHub) "
                "may be compromised via supply chain attacks. Invisible from outside."
            ),
            "indicators": [
                "Model sourced from unverified Hugging Face repository",
                "No SBOM (Software Bill of Materials) for ML artifacts",
                "ML dependencies pinned to vulnerable or unaudited versions",
                "No automated vulnerability scanning in CI/CD pipeline",
            ],
            "mitigations": [
                "Maintain an AI/ML SBOM for all model artifacts",
                "Verify model provenance and publisher reputation",
                "Pin ML dependencies to verified, audited versions",
                "Reference ATLAS case studies: AML.CS0027, AML.CS0030",
            ],
            "atlas_url": "https://atlas.mitre.org/techniques/AML.T0010",
            "nist_ref":  "NIST AI 100-2 E2025 § 4.1",
            "owasp_ref": "OWASP LLM03:2025 — Supply Chain",
        },
        {
            "atlas_id":    "AML.T0043.004",
            "title":       "Insert Backdoor Trigger",
            "severity":    "High",
            "description": (
                "If this application's model contains a backdoor, an attacker can "
                "activate it by sending inputs containing the trigger pattern. "
                "Triggers are typically imperceptible to humans."
            ),
            "indicators": [
                "Sudden confidence spikes on specific structured inputs",
                "Inconsistent model outputs on visually/semantically similar inputs",
                "Model misclassifies inputs containing specific patterns",
                "Unusual latency on specific input types",
            ],
            "mitigations": [
                "Implement STRIP for runtime backdoor detection",
                "Use activation clustering to identify poisoned samples",
                "Apply fine-pruning to remove potential backdoor neurons",
                "Test model with known trigger patterns from research literature",
                "Monitor input distribution for anomalous patterns at inference",
            ],
            "atlas_url": "https://atlas.mitre.org/techniques/AML.T0043.004",
            "nist_ref":  "NIST AI 100-2 E2025 § 3.1.2",
            "owasp_ref": "OWASP LLM04:2025 — Sleeper Agent Backdoor",
        },
    ]

    for rec in recs_to_use:
        lines += [
            f" {rec.get('atlas_id','?')}: {rec.get('title','?')}",
            f"*Severity:* {rec.get('severity','High')} | "
            "*Category:* Strategic Recommendation (Not directly testable)",
            "",
            rec.get("description", ""),
            "",
        ]
        context = rec.get("context")
        if context:
            lines.append(f"*Context:* {context}")
            lines.append("")

        # FIX 2: indicators now render correctly because all fallback recs
        # include the "indicators" key above.
        lines.append("*Detection Indicators (manual investigation):*")
        for indicator in rec.get("indicators", [])[:4]:
            lines.append(f"- {indicator}")
        lines.append("")

        lines.append("*Recommended Mitigations:*")
        for mitigation in rec.get("mitigations", [])[:5]:
            lines.append(f"- {mitigation}")
        lines += [
            "",
            f"*ATLAS Reference:* [{rec.get('atlas_id','')}]({rec.get('atlas_url','')})",
            f"*NIST Reference:* {rec.get('nist_ref','')}",
            f"*OWASP Reference:* {rec.get('owasp_ref','')}",
            "",
            "---",
            "",
        ]

    return "\n".join(lines)


# ===========================================================================
# MAIN CLASS
# ===========================================================================

class ThreatModelingAgent:

    def __init__(self, mongodb_client=None, openai_client=None,
                 vectorstore=None, web_search_function=None):
        self.mongo_client = mongodb_client or pymongo.MongoClient(
            os.getenv("MONGODB_URI"),
            tls=True,
            tlsAllowInvalidCertificates=True
        )
        if openai_client:
            self.openai_client = openai_client
            self.llm_model     = os.getenv("LLAMA_MODEL_NAME", "Qwen-2.5")
        else:
            llama_base_url     = os.getenv("LLAMA_BASE_URL", "http://localhost:8080")
            self.openai_client = openai.OpenAI(
                base_url=f"{llama_base_url}/v1", api_key="not-needed"
            )
            self.llm_model = os.getenv("LLAMA_MODEL_NAME", "Qwen-2.5")

        self.web_search = web_search_function

        self.kb_vector_search = VectorSearch(
            mongodb_client=self.mongo_client,
            collection_name="security_knowledge_base",
        )
        self.user_vectorstore = vectorstore
        self.db               = self.mongo_client["multiagentllm"]
        self.rag_collection   = self.db["RAG"]

        self.web_scanner = WebScannerAgent(
            openai_client=self.openai_client,
            llm_model=self.llm_model,
        )

        print("✓ ThreatModelingAgent initialized (v7 — AI Backdoor Detection)")

    # =========================================================================
    # CACHE
    # =========================================================================

    def _generate_cache_key(self, query: str, include_scan: bool = False) -> str:
        base = query.lower().strip()
        if include_scan:
            base += ":with_scan"
        return f"threat_model:{hashlib.md5(base.encode()).hexdigest()}"

    # =========================================================================
    # QUERY CLASSIFICATION
    # =========================================================================

    def is_security_query(self, query: str, use_llm: bool = True) -> bool:
        if not use_llm:
            return self._keyword_fallback(query)

        prompt = f"""You are a cybersecurity question classifier.

Determine if the following question is related to:
- Cybersecurity / security vulnerabilities / threat modeling
- Security attacks or exploits / authentication or authorization
- Data protection / secure systems / web application security testing
- AI/ML security / backdoor attacks / adversarial machine learning

Question: "{query}"

Answer ONLY with "YES" or "NO".

Examples:
- "What is SSRF?" → YES
- "Scan myapp.com for vulnerabilities" → YES
- "What is an AI backdoor?" → YES
- "How does vulnerability work?" → YES
- "What's the weather?" → NO
- "Write me a poem" → NO

Answer:"""

        try:
            response = self.openai_client.chat.completions.create(
                model=self.llm_model,
                messages=[
                    {"role": "system", "content": "You are a security question classifier."},
                    {"role": "user",   "content": prompt},
                ],
                temperature=0.0, max_tokens=10,
            )
            answer      = response.choices[0].message.content.strip().upper()
            is_security = "YES" in answer
            logger.info(f"Classification: '{query[:60]}' → {answer}")
            return is_security
        except Exception as e:
            logger.warning(f"LLM classification failed: {e}")
            return self._keyword_fallback(query)

    def _keyword_fallback(self, query: str) -> bool:
        security_keywords = [
            "threat", "vulnerability", "vulnerable", "attack", "security",
            "exploit", "breach", "malware", "hack", "risk", "scan", "test",
            "injection", "xss", "csrf", "ssrf", "sql", "rce",
            "authentication", "authorization", "encryption", "firewall",
            "backdoor", "poison", "adversarial", "ai security", "ml security",
        ]
        return any(kw in query.lower() for kw in security_keywords)

    def is_web_scan_request(self, query: str) -> bool:
        """
        Returns True only when a URL is present in the query.
        General security questions without a URL → False → KB-only AutoGen answer.
        """
        query_lower = query.lower()
        has_url = bool(re.search(
            r'https?://'
            r'|www\.'
            r'|localhost'
            r'|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            r'|\.(com|org|net|io|dev|app|local)\b',
            query_lower
        ))
        return has_url

    # =========================================================================
    # MAIN ENTRY POINT
    # =========================================================================

    async def analyze(self, user_query: str, verbose: bool = True,
                      use_cache: bool = True, filenames: List[str] = None,
                      enable_web_scan: bool = False,
                      target_url: str = None,
                      auth_cookie: str = "") -> Dict:

        if verbose:
            print("\n" + "=" * 80)
            print("THREAT MODELING ANALYSIS")
            print("=" * 80)
            print(f"Query: {user_query}")
            if enable_web_scan:
                print(f"Web Scan: ENABLED | Target: {target_url}")
            print("=" * 80 + "\n")

        if not enable_web_scan:
            enable_web_scan = self.is_web_scan_request(user_query)

        if enable_web_scan and not target_url:
            target_url = self._extract_url_from_query(user_query)

        cache_key = self._generate_cache_key(user_query, include_scan=enable_web_scan)

        if use_cache:
            cached = get_cached_result(cache_key)
            if cached:
                result           = json.loads(cached)
                result["cached"] = True
                return result

        # Phase 1: Knowledge Gathering
        if verbose:
            print("PHASE 1: KNOWLEDGE GATHERING")

        decomposition = await self.decompose_query(user_query)
        known_vulns   = await self.search_known_vulnerabilities_web(
            user_query, target_url, verbose=verbose
        )
        research      = await self.research_sub_questions_hybrid(
            decomposition, filenames=filenames, verbose=verbose
        )

        # Phase 2: Active Scanning
        scan_results = None
        if enable_web_scan and target_url:
            if verbose:
                print("PHASE 2: ACTIVE WEB APPLICATION SCANNING")
            scan_results = await self.web_scanner.scan_application(
                target_url=target_url, max_time_minutes=3, verbose=verbose,
                auth_cookie=auth_cookie,
            )

        # Phase 3: Report Generation
        if verbose:
            print("PHASE 3: REPORT GENERATION")

        formatted_research = self.format_research_hybrid(research)
        threat_model       = await self.apply_stride_framework(
            user_query, formatted_research, known_vulns, scan_results
        )
        final_report, report_sections = await self.synthesize_comprehensive_report(
            user_query, threat_model, known_vulns, scan_results, target_url
        )

        result = {
            "query":          user_query,
            "report":         final_report,
            "report_sections": report_sections,
            "reasoning_chain": {
                "decomposition":         decomposition,
                "research_summary":      self._summarize_research_hybrid(research),
                "known_vulnerabilities": known_vulns,
                "scan_results":          self._summarize_scan_results(scan_results),
                "threat_model":          threat_model,
            },
            "timestamp":          datetime.now().isoformat(),
            "cached":             False,
            "web_scan_performed": enable_web_scan and scan_results is not None,
            "target_url":         target_url,
        }

        if use_cache:
            cache_result(cache_key, json.dumps(result), ttl=3600)

        return result

    # =========================================================================
    # URL EXTRACTION
    # =========================================================================

    def _extract_url_from_query(self, query: str) -> Optional[str]:
        url_pattern = (
            r'https?://[^\s]+'
            r'|www\.[^\s]+'
            r'|localhost:\d+'
            r'|[a-zA-Z0-9-]+\.(com|org|net|io|dev|app)[^\s]*'
        )
        match = re.search(url_pattern, query)
        if match:
            url = match.group(0)
            if not url.startswith('http'):
                url = 'http://' + url
            if '#' in url:
                url = url.split('#')[0].rstrip('/')
            return url
        return None

    # =========================================================================
    # VULNERABILITY SEARCH
    # =========================================================================

    async def search_known_vulnerabilities_web(self, query: str,
                                               target_url: Optional[str] = None,
                                               verbose: bool = False) -> List[Dict]:
        known_vulns = []
        if not self.web_search:
            return await self.search_known_vulnerabilities_kb(query, target_url, verbose)

        search_queries = []
        if target_url:
            from urllib.parse import urlparse
            domain   = urlparse(target_url).netloc or target_url
            app_name = domain.split('.')[0]
            search_queries += [
                f"{app_name} CVE vulnerability",
                f"{domain} security advisory",
                f"{app_name} known exploits",
                f"{app_name} CISA KEV",
            ]

        if "CVE" not in query.upper():
            search_queries.append(f"{query} CVE")
        search_queries += [
            f"{query} vulnerability NVD",
            f"{query} exploit database",
        ]

        for sq in search_queries[:4]:
            if verbose:
                print(f"  Searching: {sq[:50]}...")
            try:
                results = await self.web_search(sq)
                if results and isinstance(results, list):
                    for idx, r in enumerate(results[:3]):
                        known_vulns.append({
                            "source":        "Web Search",
                            "url":           r.get("url", ""),
                            "title":         r.get("title", "Unknown"),
                            "snippet":       r.get("snippet", r.get("content", ""))[:500],
                            "search_query":  sq,
                            "rank":          idx + 1,
                            "is_cve":        "CVE-" in r.get("title", "") or
                                             "CVE-" in r.get("snippet", ""),
                            "is_exploit_db": "exploit-db" in r.get("url", "").lower(),
                            "is_nvd":        "nvd.nist.gov" in r.get("url", "").lower(),
                            "is_cisa":       "cisa.gov" in r.get("url", "").lower(),
                        })
            except Exception as e:
                if verbose:
                    print(f"    Search failed: {e}")

        kb_results = await self.search_known_vulnerabilities_kb(
            query, target_url, verbose=False
        )
        known_vulns.extend(kb_results)
        return known_vulns

    async def search_known_vulnerabilities_kb(self, query: str,
                                              target_url: Optional[str] = None,
                                              verbose: bool = False) -> List[Dict]:
        known_vulns    = []
        search_queries = []
        if target_url:
            from urllib.parse import urlparse
            domain = urlparse(target_url).netloc or target_url
            search_queries.append(f"{domain} vulnerabilities")
        search_queries.append(f"{query} security")

        for sq in search_queries[:2]:
            results = await self.kb_vector_search.search(
                query=sq,
                filters={"source": {"$in": ["CISA", "OWASP", "NIST", "MITRE_ATLAS"]}},
                top_k=3,
            )
            for r in results:
                known_vulns.append({
                    "source":  r.get("source", "Unknown"),
                    "title":   r.get("title", ""),
                    "snippet": r.get("content", "")[:500],
                    "is_cve":  False,
                    "is_kb":   True,
                })
        return known_vulns

    # =========================================================================
    # QUERY DECOMPOSITION
    # =========================================================================

    async def decompose_query(self, user_query: str) -> Dict:
        prompt = QUESTION_DECOMPOSITION_PROMPT.format(query=user_query)
        response = self.openai_client.chat.completions.create(
            model=self.llm_model,
            messages=[
                {
                    "role":    "system",
                    "content": (
                        "You are a cybersecurity expert. Respond with valid JSON only. "
                        "The JSON must have exactly these two keys: "
                        "'task_1_system_understanding' and 'task_2_security_analysis'. "
                        "Each must be a list of objects with keys 'question' (string) "
                        "and 'preferred_source' (string or null). Maximum 3 items per list."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
            temperature=0.3, max_tokens=800,
        )
        raw = json.loads(response.choices[0].message.content)

        def normalize_list(items):
            if not isinstance(items, list):
                return []
            result = []
            for item in items:
                if isinstance(item, dict) and 'question' in item:
                    result.append(item)
                elif isinstance(item, str) and item.strip():
                    result.append({"question": item.strip(), "preferred_source": None})
            return result[:3]

        return {
            "task_1_system_understanding": normalize_list(
                raw.get("task_1_system_understanding", [])
            ),
            "task_2_security_analysis": normalize_list(
                raw.get("task_2_security_analysis", [])
            ),
        }

    # =========================================================================
    # HYBRID RESEARCH
    # =========================================================================

    async def research_sub_questions_hybrid(self, decomposition: Dict,
                                            filenames: List[str] = None,
                                            verbose: bool = False) -> Dict:
        research_results = {"task_1": [], "task_2": []}

        def normalize_sq(sq):
            if isinstance(sq, dict):  return sq
            if isinstance(sq, str):   return {"question": sq, "preferred_source": None}
            return {"question": str(sq), "preferred_source": None}

        for task_key, task_label in [
            ("task_1_system_understanding", "task_1"),
            ("task_2_security_analysis",    "task_2"),
        ]:
            for idx, sq_raw in enumerate(decomposition.get(task_key, []), 1):
                sq            = normalize_sq(sq_raw)
                question_text = sq.get("question", "")

                if verbose:
                    print(f"  {task_label}.{idx}: {question_text[:60]}...")

                kb_results, user_results = [], []
                try:
                    sources    = [sq["preferred_source"]] if sq.get("preferred_source") else None
                    kb_results = await self.kb_vector_search.search(
                        query=question_text,
                        filters={"source": {"$in": sources}} if sources else None,
                        top_k=3,
                    )
                except Exception as e:
                    logger.warning(f"KB search failed: {e}")

                try:
                    user_results = await self._search_user_docs(question_text, filenames)
                except Exception as e:
                    logger.warning(f"User doc search failed: {e}")

                if verbose:
                    print(f"    KB: {len(kb_results)} | User: {len(user_results)}")

                research_results[task_label].append({
                    "question":         question_text,
                    "preferred_source": sq.get("preferred_source"),
                    "kb_findings":      kb_results,
                    "user_findings":    user_results,
                })

        return research_results

    async def _search_user_docs(self, query: str, filenames: List[str] = None,
                                top_k: int = 2) -> List[Dict]:
        if not self.user_vectorstore:
            return []
        try:
            mongo_filter = {"filename": {"$in": filenames}} if filenames else {}
            user_docs    = list(self.rag_collection.find(mongo_filter).limit(50))
            if not user_docs:
                return []
            langchain_docs = [
                Document(
                    page_content=doc.get("text", ""),
                    metadata={
                        "filename": doc.get("filename", "Unknown"),
                        "page":     doc.get("page", "Unknown"),
                    },
                )
                for doc in user_docs
            ]
            results = self.user_vectorstore.similarity_search(
                query, k=min(top_k, len(langchain_docs))
            )
            return [
                {
                    "content":     r.page_content,
                    "filename":    r.metadata.get("filename", "Unknown"),
                    "source":      "User Document",
                    "page":        r.metadata.get("page", "Unknown"),
                    "source_type": "user_doc",
                }
                for r in results
            ]
        except Exception as e:
            logger.warning(f"User doc search error: {e}")
            return []

    # =========================================================================
    # RESEARCH FORMATTING
    # =========================================================================

    def format_research_hybrid(self, research: Dict) -> str:
        formatted = " TASK 1 - System Understanding\n\n"
        for item in research["task_1"]:
            formatted += f"*Question:* {item['question']}\n\n"
            if item.get("kb_findings"):
                formatted += "*From Security KB:*\n\n"
                for idx, f in enumerate(item["kb_findings"][:3], 1):
                    formatted += (
                        f"{idx}. [{f.get('source','?')}] "
                        f"{f.get('title', f.get('filename','Untitled'))}\n"
                        f"   {f.get('content','')[:400]}...\n\n"
                    )
            if item.get("user_findings"):
                formatted += "*From Your Uploaded Documents:*\n\n"
                for idx, f in enumerate(item["user_findings"][:2], 1):
                    formatted += (
                        f"{idx}. {f.get('filename','?')} (Page {f.get('page','?')})\n"
                        f"   {f.get('content','')[:400]}...\n\n"
                    )
            formatted += "---\n\n"

        formatted += " TASK 2 - Security Analysis\n\n"
        for item in research["task_2"]:
            formatted += f"*Question:* {item['question']}\n\n"
            if item.get("kb_findings"):
                formatted += "*From Security KB:*\n\n"
                for idx, f in enumerate(item["kb_findings"][:3], 1):
                    formatted += (
                        f"{idx}. [{f.get('source','?')}] "
                        f"{f.get('title', f.get('filename','Untitled'))}\n"
                        f"   {f.get('content','')[:400]}...\n\n"
                    )
            if item.get("user_findings"):
                formatted += "*From Your Uploaded Documents:*\n\n"
                for idx, f in enumerate(item["user_findings"][:2], 1):
                    formatted += (
                        f"{idx}. {f.get('filename','?')} (Page {f.get('page','?')})\n"
                        f"   {f.get('content','')[:400]}...\n\n"
                    )
            formatted += "---\n\n"

        return formatted

    # =========================================================================
    # STRIDE
    # =========================================================================

    async def apply_stride_framework(self, user_query: str,
                                     formatted_research: str,
                                     known_vulns: List[Dict],
                                     scan_results: Optional[Dict]) -> str:
        known_vulns_text = "\n\n KNOWN VULNERABILITIES (Web Search + KB)\n\n"
        for idx, v in enumerate(known_vulns[:10], 1):
            label = (
                "CVE"        if v.get("is_cve")        else
                "Exploit-DB" if v.get("is_exploit_db") else
                "NVD"        if v.get("is_nvd")        else
                "CISA"       if v.get("is_cisa")       else
                v.get("source", "Unknown")
            )
            known_vulns_text += f"{idx}. [{label}] {v.get('title','?')}\n"
            if v.get("url"):
                known_vulns_text += f"   URL: {v['url']}\n"
            known_vulns_text += f"   {v.get('snippet','')[:300]}...\n\n"

        scan_text = ""
        if scan_results:
            stack = scan_results.get("stack") or {}
            scan_text += (
                f"\n\n TECH STACK\n"
                f"   {stack.get('stack_summary','Unknown')}\n\n"
            )
            for cve in scan_results.get("verified_cves", [])[:5]:
                scan_text += (
                    f"*{cve.get('cve_id','?')}* [{cve.get('severity','?')}] "
                    f"CVSS: {cve.get('cvss_score','?')}\n"
                    f"   {cve.get('description','')[:300]}\n\n"
                )

            vulns     = scan_results.get("vulnerabilities", [])
            confirmed = [v for v in vulns if v.get("status") == "Confirmed"]
            potential = [v for v in vulns if v.get("status") == "Potential"]

            if confirmed:
                scan_text += " CONFIRMED VULNERABILITIES\n\n"
                for v in confirmed:
                    scan_text += (
                        f"*{v.get('type','?')}* — {v.get('severity','?')}\n"
                        f"   {v.get('details','')[:200]}\n\n"
                    )
            if potential:
                scan_text += " POTENTIAL VULNERABILITIES\n\n"
                for v in potential:
                    scan_text += (
                        f"*{v.get('type','?')}* — {v.get('severity','?')}\n"
                        f"   {v.get('details','')[:200]}\n\n"
                    )

            stride_threats = scan_results.get("stride_threats", [])
            if stride_threats:
                scan_text += " STRIDE EVIDENCE (from scanner)\n\n"
                for t in stride_threats:
                    label = "CONFIRMED" if t.get("confirmed") else "POTENTIAL"
                    scan_text += (
                        f"*[{label}] {t.get('category','?')}: {t.get('threat','?')}*\n"
                        f"   Evidence: {t.get('evidence','?')}\n\n"
                    )
            else:
                scan_text += (
                    " STRIDE EVIDENCE\n"
                    "No STRIDE threats confirmed by scanner evidence.\n\n"
                )

        prompt = STRIDE_ANALYSIS_PROMPT.format(
            query=user_query,
            research=formatted_research + known_vulns_text + scan_text,
        )

        response = self.openai_client.chat.completions.create(
            model=self.llm_model,
            messages=[
                {
                    "role":    "system",
                    "content": (
                        "You are a cybersecurity threat modeling expert specializing in "
                        "STRIDE analysis. Do NOT invent vulnerabilities. "
                        "Only model threats based on the evidence provided. "
                        "Maximum 4 STRIDE threats."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.2, max_tokens=1500,
        )
        return response.choices[0].message.content

    # =========================================================================
    # REPORT SYNTHESIS
    # =========================================================================

    async def synthesize_comprehensive_report(self, user_query: str,
                                               threat_model: str,
                                               known_vulns: List[Dict],
                                               scan_results: Optional[Dict],
                                               target_url: Optional[str]) -> str:
        confirmed_vulns: List[Dict] = []
        potential_vulns: List[Dict] = []
        stack:     Dict       = {}
        cves:      List[Dict] = []
        endpoints: List[Dict] = []

        if scan_results:
            stack     = scan_results.get("stack") or {}
            cves      = scan_results.get("verified_cves", [])
            endpoints = scan_results.get("endpoints_discovered", [])
            vulns     = scan_results.get("vulnerabilities", [])

            # FIX: if stack is empty, reconstruct from header values
            if not stack.get("technologies") and not stack.get("stack_summary"):
                raw = scan_results.get("stack") or {}
                headers = raw.get("headers", {})
                server  = (raw.get("server") or
                           headers.get("server") or headers.get("Server", ""))
                powered = (raw.get("language") or
                           headers.get("x-powered-by") or
                           headers.get("X-Powered-By", ""))
                cdn     = raw.get("cdn", "")
                techs   = [t for t in [server, powered, cdn] if t and t.strip()]
                if techs:
                    stack = {
                        "technologies":     techs,
                        "stack_summary":    " · ".join(techs[:3]),
                        "unverified_hints": [],
                    }

            seen: set = set()
            for v in vulns:
                key = f"{v.get('type','')}__{v.get('location','')}"
                if key in seen:
                    continue
                seen.add(key)
                if v.get("status") == "Confirmed":
                    confirmed_vulns.append(v)
                elif v.get("status") == "Potential":
                    potential_vulns.append(v)

            # Deduplicate potential by type
            seen_types: set = set()
            deduped_pot     = []
            for v in potential_vulns:
                t = v.get("type", "")
                if t not in seen_types:
                    seen_types.add(t)
                    deduped_pot.append(v)
            potential_vulns = deduped_pot

        interesting_endpoints = [e for e in endpoints if e.get("interesting")]

        # Build context for LLM synthesis prompt
        context_lines = [
            f"TARGET: {target_url or 'N/A'}",
            f"QUERY: {user_query}",
            "",
            "=== TECH STACK ===",
            _format_confirmed_stack(stack),
            "",
            "=== SCAN STATISTICS ===",
            f"Confirmed vulnerabilities : {len(confirmed_vulns)}",
            f"Potential vulnerabilities : {len(potential_vulns)}",
            f"Verified CVEs (NVD/OSV)   : {len(cves)}",
            f"Endpoints discovered      : {len(interesting_endpoints)}",
        ]
        if scan_results:
            context_lines.append(
                f"Scan duration             : {scan_results.get('scan_duration',0)}s"
            )
        context_lines.append("")

        if cves:
            context_lines.append("=== VERIFIED CVEs ===")
            for cve in cves[:8]:
                context_lines.append(
                    f"  {cve.get('cve_id','?')} | {cve.get('severity','?')} | "
                    f"CVSS {cve.get('cvss_score','N/A')} | "
                    f"{cve.get('description','')[:200]}"
                )
            context_lines.append("")
        else:
            context_lines += ["=== VERIFIED CVEs ===", "  None found.", ""]

        if confirmed_vulns:
            context_lines.append(
                f"=== CONFIRMED VULNERABILITIES ({len(confirmed_vulns)}) ==="
            )
            for i, v in enumerate(confirmed_vulns, 1):
                ev = v.get("evidence", {})
                context_lines += [
                    f"[{i}] {v.get('type','?')}",
                    f"  Severity: {v.get('severity','?')}  ← USE THIS EXACTLY",
                    f"  Location: {v.get('location','?')}",
                    f"  CWE: {v.get('cwe','?')}",
                    f"  Fix: {v.get('remediation','')[:200]}",
                ]
            context_lines.append("")

        if potential_vulns:
            context_lines.append(
                f"=== POTENTIAL VULNERABILITIES ({len(potential_vulns)}) ==="
            )
            for i, v in enumerate(potential_vulns, 1):
                context_lines += [
                    f"[{i}] {v.get('type','?')}",
                    f"  Severity: {v.get('severity','?')}",
                    f"  Detail: {v.get('details','')[:200]}",
                ]
            context_lines.append("")

        context_lines += [
            "=== STRIDE ARCHITECTURAL THREAT MODEL ===",
            threat_model[:1500],
            "",
        ]

        if known_vulns:
            context_lines.append("=== INTELLIGENCE FROM WEB SEARCH / KB ===")
            for v in known_vulns[:5]:
                label = (
                    "CVE"        if v.get("is_cve")        else
                    "Exploit-DB" if v.get("is_exploit_db") else
                    v.get("source", "Reference")
                )
                context_lines.append(
                    f"  [{label}] {v.get('title','?')} — "
                    f"{v.get('snippet','')[:150]}"
                )
            context_lines.append("")

        report_context   = "\n".join(context_lines)
        synthesis_prompt = SYNTHESIS_PROMPT.format(report_context=report_context)

        response = self.openai_client.chat.completions.create(
            model=self.llm_model,
            messages=[
                {
                    "role":    "system",
                    "content": (
                        "You are a senior cybersecurity analyst. Follow the rules exactly. "
                        "CRITICAL: OWASP Top 10 has exactly 10 items: A01 through A10. "
                        "NEVER write A11 or higher. "
                        "Section 7 compliance MUST be a table. "
                        "Never invent CVEs or change severity values. "
                        "Stop writing after the section 7 table."
                    ),
                },
                {"role": "user", "content": synthesis_prompt},
            ],
            temperature=0.1, max_tokens=2500,
        )

        raw_report = response.choices[0].message.content
        _sanitize_report(raw_report)

        stride_threats = (scan_results or {}).get("stride_threats", [])
        action_agent   = ActionAgent()
        action_results = action_agent.process_all(
            confirmed_vulns,
            target_url,
            stack
        )

        section_1  = _build_section_1(
            confirmed_vulns, potential_vulns, target_url or "", scan_results
        ) or ""
        section_2  = _build_section_2(
            stack,
            (scan_results or {}).get("endpoints_discovered", []),
            cves,
        ) or ""
        section_3  = _build_section_3(confirmed_vulns)                  or ""
        section_3b = render_section_3b(action_results)                  or ""
        section_4  = _build_section_4(potential_vulns)                  or ""
        section_5  = _build_section_5(stride_threats)                   or ""
        section_6  = _build_section_6(confirmed_vulns, potential_vulns) or ""
        section_7  = _build_section_7(confirmed_vulns)                  or ""

        final = "\n\n".join([
            s for s in [
                section_1, section_2, section_3, section_3b,
                section_4, section_5, section_6, section_7,
            ]
            if s
        ])

        # Section 8: AI Backdoor Analysis
        section_8 = ""
        if scan_results and scan_results.get("is_ai_powered"):
            section_8 = _build_section_8_ai_backdoor(scan_results)
            if section_8:
                final = final + "\n\n" + section_8
                logger.info("✓ Section 8 (AI Backdoor Analysis) added to report")

        # Build structured sections list for interactive UI rendering
        report_sections = []
        _section_defs = [
            ("1",  "Executive Summary",      section_1),
            ("2",  "Tech Stack",             section_2),
            ("3",  "Confirmed Vulns",        section_3),
            ("3b", "PoCs & Fixes",           section_3b),
            ("4",  "Potential Vulns",        section_4),
            ("5",  "STRIDE Model",           section_5),
            ("6",  "Remediation Roadmap",    section_6),
            ("7",  "Compliance Mapping",     section_7),
            ("8",  "AI/ML Analysis",         section_8),
        ]
        for _sid, _title, _content in _section_defs:
            if _content and _content.strip():
                report_sections.append({
                    "id":      _sid,
                    "title":   _title,
                    "content": _content,
                })

        return final, report_sections

    # =========================================================================
    # SUMMARISERS
    # =========================================================================

    def _summarize_research_hybrid(self, research: Dict) -> Dict:
        kb_sources, user_docs = set(), set()
        kb_findings = user_findings = 0
        for item in research["task_1"] + research["task_2"]:
            for f in item.get("kb_findings", []):
                kb_findings += 1
                kb_sources.add(f.get("source", "Unknown"))
            for f in item.get("user_findings", []):
                user_findings += 1
                user_docs.add(f.get("filename", "Unknown"))
        return {
            "kb_findings":    kb_findings,
            "kb_sources":     list(kb_sources),
            "user_findings":  user_findings,
            "user_docs":      list(user_docs),
            "total_findings": kb_findings + user_findings,
        }

    def _summarize_scan_results(self, scan_results: Optional[Dict]) -> Optional[Dict]:
        if not scan_results:
            return None
        vulns     = scan_results.get("vulnerabilities", [])
        endpoints = scan_results.get("endpoints_discovered", [])
        return {
            "stack":                 (scan_results.get("stack") or {}).get(
                                         "stack_summary", "Unknown"),
            "endpoints_found":       len(endpoints),
            "endpoints_interesting": sum(1 for e in endpoints if e.get("interesting")),
            "verified_cves":         len(scan_results.get("verified_cves", [])),
            "confirmed_vulns":       sum(1 for v in vulns if v.get("status") == "Confirmed"),
            "potential_vulns":       sum(1 for v in vulns if v.get("status") == "Potential"),
            "tasks_generated":       scan_results.get("tasks_generated", 0),
            "tasks_executed":        scan_results.get("tasks_executed",  0),
            "forms_discovered":      scan_results.get("forms_discovered", 0),
            "urls_discovered":       scan_results.get("urls_discovered",  0),
            "scan_duration":         scan_results.get("scan_duration",    0),
            "is_ai_powered":         scan_results.get("is_ai_powered", False),
            "avid_findings":         len(scan_results.get("avid_findings", [])),
            "strategic_recommendations": len(
                scan_results.get("strategic_recommendations", [])
            ),
            "vulnerabilities":       vulns,
        }