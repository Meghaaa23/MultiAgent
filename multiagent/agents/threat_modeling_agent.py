import os
import re
import json
import openai
import hashlib
import logging
import traceback
import urllib.parse
from typing import Dict, List, Optional
from datetime import datetime

from .webappscanner.action_agent import ActionAgent
from .redis_manager import cache_result, get_cached_result
from .webappscanner.web_scanner_agent import WebScannerAgent

from utils.threat_prompts import (
    QUESTION_DECOMPOSITION_PROMPT,
    STRIDE_ANALYSIS_PROMPT,
)

logger = logging.getLogger(__name__)

def _tech_display(t) -> str:
    if isinstance(t, dict):
        name = t.get("name", "")
        ver  = t.get("version", "")
        return f"{name} {ver}".strip() if ver else name
    return str(t).split("/")[0].strip()

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
    parts = []
    for t in confirmed:
        if isinstance(t, dict):
            name    = t.get("name", "")
            ver     = t.get("version", "")
            conf    = t.get("confidence", 0)
            display = f"{name} {ver}".strip() if ver else name
            parts.append(f"{display} [conf={conf:.2f}]")
        else:
            parts.append(f"{t} [{evidence_map.get(t, 'confirmed')}]")

    result = ", ".join(parts)
    if unverified:
        result += f"\nEXCLUDED (unconfirmed): {', '.join(unverified)}"
    return result

def _evidence_has_substance(ev: Dict) -> bool:
    """
    True only when the evidence blob contains something a reviewer can verify.
    Empty / placeholder evidence must never ship as Confirmed/HIGH.
    """
    if not isinstance(ev, dict) or not ev:
        return False
    method = str(ev.get("confirmation_method") or "").lower()
    body = (
        ev.get("response_body_snippet")
        or ev.get("body_snippet")
        or ev.get("response_snippet")
        or ev.get("db_error_snippet")
        or ""
    )
    headers = ev.get("response_headers") or ev.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    header_vals = [str(v).strip() for v in headers.values() if str(v).strip()]

    if method in ("header",):
        if header_vals:
            return True
        req = str(ev.get("request") or ev.get("request_line") or "")
        return bool(req) and ev.get("response_status") not in (None, 0, "")

    if method in ("timing",):
        status = ev.get("response_status")
        if status in (None, 0, ""):
            return False
        return ev.get("timing_delta_seconds") is not None

    if method in ("pattern", "http_body", "dom_reflection", "js_execution"):
        return bool(str(body).strip())

    return bool(str(body).strip()) or bool(header_vals)

def _norm_conf_label(val) -> str:
    """Normalize confidence/status labels; tolerate Enum reprs like Confidence.HIGH."""
    if val is None:
        return ""
    if hasattr(val, "value"):
        val = val.value
    s = str(val).strip().lower()
    if "." in s:
        s = s.rsplit(".", 1)[-1]
    return s

def _is_publishable_confirmed(v: Dict) -> bool:
    """
    Publisher gate: only report Confirmed findings with High confidence
    and verified, non-empty evidence. No site/app hardcoding — evidence-driven only.

    XSS Confirmed requires js_execution proof; HTTP/DOM reflection alone is
    demoted to the Potential queue (general rule — not app-specific).
    """
    if not isinstance(v, dict):
        return False
    if _norm_conf_label(v.get("status")) != "confirmed":
        return False
    conf = _norm_conf_label(v.get("confidence"))
    ev = v.get("evidence") or {}
    if not isinstance(ev, dict):
        ev = {}
    ev_conf = _norm_conf_label(ev.get("confidence"))
    if conf not in ("high",) and ev_conf not in ("high",):
        return False
    if ev.get("verified") is False:
        return False
    if not _evidence_has_substance(ev):
        return False
    loc = str(v.get("location") or "")
    details = str(v.get("details") or v.get("description") or "")
    if "<node>" in loc.lower() or "<node>" in details.lower():
        return False
    if loc.strip().lower() in ("", "unknown"):
        return False

    ftype = str(v.get("type") or "")
    method = str(ev.get("confirmation_method") or "").lower()
    if "XSS" in ftype and method not in ("js_execution",):
        return False
    return True

def _is_private_or_local_host(url: str) -> bool:
    """True for localhost / RFC1918 / link-local targets — no CDN/WAF excuse."""
    try:
        host = (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        host = ""
    if not host:
        return False
    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return True
    if host.endswith(".local") or host.endswith(".internal"):
        return True
    import ipaddress
    try:
        ip = ipaddress.ip_address(host)
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local)
    except ValueError:
        return False

def _is_manual_queue_finding(v: Dict) -> bool:
    """Medium+ Potential findings only — Low speculation is dropped."""
    if not isinstance(v, dict):
        return False
    if v.get("status") != "Potential":
        return False
    conf = str(
        v.get("confidence") or (v.get("evidence") or {}).get("confidence") or ""
    ).lower()
    return conf in ("medium", "high")

def _auth_info(scan_results) -> Dict:
    return (scan_results or {}).get("auth") or {"enabled": False}


def _is_authenticated_scan(scan_results) -> bool:
    return (scan_results or {}).get("scan_scope") == "authenticated"


def _authed_wording(text: str, scan_results) -> str:
    """Rewrite pre-auth scope wording when the scan ran with a login session."""
    if not _is_authenticated_scan(scan_results):
        return text
    user = _auth_info(scan_results).get("username") or "operator account"
    for old, new in (
        ("[Black-box unauthenticated]", f"[Authenticated as '{user}']"),
        ("pre-authentication", "authenticated"),
        ("(pre-auth)", "(authenticated)"),
        ("pre-auth surface", "authenticated surface"),
        ("on unauthenticated surfaces", "on the authenticated surface"),
        ("on the unauthenticated surface", "on the authenticated surface"),
        ("unauthenticated only", f"authenticated as '{user}'"),
        ("auth-gated", "access-controlled for this account"),
    ):
        text = text.replace(old, new)
    return text


def _auth_status_line(scan_results) -> str:
    a = _auth_info(scan_results)
    if not a.get("enabled"):
        return ""
    user = a.get("username") or "?"
    if a.get("logged_in"):
        via = []
        if a.get("cookie_names"):
            via.append(f"session cookie(s) {', '.join(a['cookie_names'][:5])}")
        if a.get("auth_header"):
            via.append(f"Authorization header ({a.get('auth_header_source') or 'captured'})")
        line = (f" Authentication: logged in as '{user}' via "
                f"{a.get('login_page_url') or 'login form'}"
                + (f"; session carried by {' and '.join(via)}" if via else "")
                + ".")
        if a.get("relogin_count"):
            line += f" Session expired and was re-established {a['relogin_count']} time(s)."
        if not a.get("expiry_monitored"):
            line += " Session expiry could not be monitored."
        if a.get("error"):
            line += f" Note: {a['error']}."
        return line
    return (f" Authentication: login as '{user}' FAILED ({a.get('error') or 'unknown error'}); "
            "results cover the unauthenticated surface only.")


def _coverage_from_scan(scan_results) -> Dict:
    """
    Black-box unauth coverage signal: how much of the discovered surface
    was actually assessed vs auth-gated / not tested.
    """
    sr = scan_results or {}
    not_assessed = list(sr.get("not_assessed_endpoints") or [])
    endpoints = list(sr.get("endpoints_discovered") or [])
    n_auth_gated = sum(
        1 for e in not_assessed
        if not isinstance(e, dict)
        or (e.get("reason") or "auth_required") == "auth_required"
    )

    assessed = []
    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        if ep.get("static_asset"):
            continue
        if (
            ep.get("access_controlled")
            or ep.get("auth_required")
            or ep.get("redirects_to_auth")
            or ep.get("category") == "discovered_protected"
        ):
            continue
        if ep.get("interesting") or ep.get("auth_endpoint"):
            assessed.append(ep)

    n_assessed = len(assessed)
    dominated = n_auth_gated > 0 and (
        n_auth_gated >= max(n_assessed, 1) or n_assessed <= 1
    )
    return {
        "auth_gated_count": n_auth_gated,
        "assessed_count": n_assessed,
        "auth_wall_dominated": dominated,
    }

def _build_section_1(confirmed_vulns, potential_vulns, target_url, scan_results):
    n_confirmed = len(confirmed_vulns)
    n_potential = len(set(v.get("type", "") for v in potential_vulns))
    duration    = (scan_results or {}).get("scan_duration", 0)
    coverage    = _coverage_from_scan(scan_results)
    n_auth      = coverage["auth_gated_count"]
    dominated   = coverage["auth_wall_dominated"]

    _sev_base = {"Critical": 40, "High": 20, "Medium": 10, "Low": 5, "Info": 1}
    _method_mult = {
        "js_execution":   1.5,
        "timing":         1.4,
        "dom_reflection": 1.2,
        "http_body":      1.0,
        "pattern":        0.8,
        "header":         0.2,
    }
    exploit_score = 0.0
    for v in confirmed_vulns:
        method = v.get("evidence", {}).get("confirmation_method", "http_body")
        base   = _sev_base.get(v.get("severity", "Low"), 5)
        mult   = _method_mult.get(method, 1.0)
        exploit_score += base * mult

    risk = (
        "Critical"   if exploit_score >= 40 else
        "High"       if exploit_score >= 20 else
        "Medium"     if exploit_score >= 8  else
        "Low-Medium" if exploit_score >  0  else "Low"
    )

    actions = [
        v.get("remediation", "")[:200]
        for v in confirmed_vulns[:3]
        if v.get("remediation")
    ] or ["No immediate action required — continue monitoring."]

    actions_text = " ".join(f"({i+1}) {a}" for i, a in enumerate(actions[:3]))

    if dominated:
        risk_clause = (
            f"Overall risk level on assessed pre-authentication surface: {risk} "
            f"(score: {exploit_score:.0f}). "
            f"Assessed surface limited to pre-authentication endpoints; "
            f"{n_auth} functional surface(s) were auth-gated and not tested."
        )
    elif n_auth > 0:
        risk_clause = (
            f"Overall risk level on assessed (pre-auth) surface: {risk} "
            f"(score: {exploit_score:.0f}). "
            f"{n_auth} functional surface(s) were auth-gated and not tested."
        )
    else:
        risk_clause = (
            f"Overall risk level: {risk} (score: {exploit_score:.0f})."
        )

    summary = (
        f"Active scan of `{target_url}` completed in {duration:.0f}s "
        f"[Black-box unauthenticated]. "
        f"Identified {n_confirmed} confirmed and {n_potential} potential "
        f"vulnerability type(s). {risk_clause}"
    )
    if n_confirmed == 0 and n_potential == 0:
        if n_auth > 0:
            summary += (
                " No exploitable issues on the reachable pre-auth surface; "
                "this is not an app-wide clean result."
            )
        else:
            summary += " — no exploitable surfaces found on unauthenticated surfaces."
    else:
        summary += f" Top actions: {actions_text}"
    summary = _authed_wording(summary, scan_results) + _auth_status_line(scan_results)

    return f" 1. EXECUTIVE SUMMARY\n{summary}"

def _tech_matches_cve_query(tech_name: str, cve_query: str) -> bool:
 
    tn = (tech_name or "").strip().lower()
    cq = (cve_query or "").strip().lower()
    if not tn or not cq:
        return False
    return cq == tn or cq.startswith(tn + " ")

def _cves_for_tech(tech_name: str, cves: Optional[List[Dict]]) -> List[Dict]:
    if not cves:
        return []
    matched = [c for c in cves if _tech_matches_cve_query(tech_name, c.get("query", ""))]
    seen_ids: set = set()
    deduped: List[Dict] = []
    for c in matched:
        cid = c.get("cve_id", "")
        if cid and cid in seen_ids:
            continue
        if cid:
            seen_ids.add(cid)
        deduped.append(c)
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
    deduped.sort(key=lambda c: sev_order.get(c.get("severity", "Unknown"), 4))
    return deduped

def _build_section_2(stack, endpoints, cves, target_url: str = "",
                     forms_discovered: int = 0,
                     forms_testing: Optional[Dict] = None,
                     scan_results: Optional[Dict] = None):
    lines = [" 2. TECHNOLOGY STACK & ATTACK SURFACE", " Technology Stack"]

    app_name = (stack or {}).get("app_identity_name") or ""
    try:
        from .webappscanner.app_identity import _is_infra_or_framework_name
    except Exception:
        def _is_infra_or_framework_name(s: str) -> bool:
            return (s or "").strip().lower() in {
                "express", "node", "nginx", "apache", "php", "python",
            }
    if app_name and not _is_infra_or_framework_name(app_name):
        lines.append(f"App identity: {app_name}")
    else:
        lines.append("App identity: not determined")

    technologies = stack.get("technologies") or []
    noise_words  = {"content", "unknown", "none", "null", "n/a",
                    "signals", "content signals", "true", "false"}
    noise_tech = {
        "x-robots-tag", "x-robots-tag: noindex", "noindex",
        "nosniff", "sameorigin",
    }

    def _is_noise_tech(name: str) -> bool:
        n = (name or "").strip().lower()
        if not n or n in noise_words or n in noise_tech:
            return True
        if n.startswith("x-") and ":" in n:
            return True
        return False

    if technologies and isinstance(technologies[0], dict):
        by_cat: Dict[str, list] = {}
        for dt in technologies:
            if _is_noise_tech(dt.get("name", "")):
                continue
            by_cat.setdefault(dt.get("category", "Other"), []).append(dt)

        cat_order     = ["CMS", "Server", "Language", "Framework", "CDN",
                         "Database", "Analytics", "Other"]
        rendered_cats = []
        for cat in cat_order:
            if cat in by_cat:
                rendered_cats.append(cat)
        for cat in by_cat:
            if cat not in rendered_cats:
                rendered_cats.append(cat)

        for cat in rendered_cats:
            for dt in by_cat[cat]:
                name    = dt.get("name", "")
                ver     = dt.get("version", "")
                conf    = dt.get("confidence", 0)
                display = f"{name} {ver}".strip() if ver else name
                try:
                    conf_s = f"{float(conf):.0%}"
                except (TypeError, ValueError):
                    conf_s = str(conf)
                lines.append(f"- {display}  [{cat}, {conf_s} confidence]")

        if not by_cat:
            technologies = []

    elif technologies:
        confirmed = [
            t for t in technologies
            if t
            and len(str(t).strip()) > 2
            and "signal" not in str(t).lower()
            and str(t).strip().lower() not in noise_words
            and not _is_noise_tech(str(t))
        ]
        if confirmed:
            lines.extend(f"- {t}" for t in confirmed)
        else:
            technologies = []

    if not technologies or (
        isinstance(technologies[0], dict)
        and not any(
            not _is_noise_tech(dt.get("name", ""))
            for dt in technologies if isinstance(dt, dict)
        )
    ):
        app_name = stack.get("app_identity_name") or ""
        if app_name:
            lines.append(f"- {app_name}")
        summary      = stack.get("stack_summary", "")
        noise_summary = {"unknown", "unknown (no technology confirmed from http evidence)", ""}
        if summary and summary.strip().lower() not in noise_summary:
            if not app_name or app_name.lower() not in summary.lower():
                lines.append(f"- {summary}")
        else:
            added = bool(app_name)
            for field in ("server", "language", "framework", "frontend", "cms", "cdn"):
                val = stack.get(field)
                if val and str(val).strip().lower() not in noise_words:
                    lines.append(f"- {val}")
                    added = True
            if not added:
                if _is_private_or_local_host(target_url or ""):
                    lines.append(
                        "Unidentified — no Server/X-Powered-By (or equivalent) "
                        "headers confirmed on this local/private target. "
                        "See Section 3 for detected headers and route evidence."
                    )
                else:
                    lines.append(
                        "Unidentified — no confirming Server/X-Powered-By (or "
                        "equivalent) headers observed. See Section 3 for "
                        "detected headers."
                    )

    unverified = stack.get("unverified_hints", [])
    if unverified:
        lines.append(f"\nUnconfirmed hints (excluded): {', '.join(unverified[:5])}")

    lines.append("\n Attack Surface")
    try:
        from .webappscanner.endpoint_discovery_agent import is_static_asset
    except Exception:
        def is_static_asset(url="", content_type=""):
            return False

    interesting = [
        e for e in (endpoints or [])
        if e.get("interesting") and not e.get("static_asset")
        and not e.get("spa_catch_all") and not e.get("excluded")
        and not is_static_asset(e.get("url", ""), e.get("content_type", ""))
        and "SPA" not in str(e.get("verification") or "")
        and "soft-404" not in str(e.get("verification") or "").lower()
    ]
    verified_eps = [
        e for e in interesting
        if e.get("status") not in (None, "", "?")
    ]
    excluded_eps = [
        e for e in (endpoints or [])
        if (e.get("spa_catch_all") or e.get("excluded"))
        and e.get("status") not in (None, "", "?")
    ]
    if verified_eps:
        functional, admin, discovery = [], [], []
        for ep in verified_eps:
            url_lower = (ep.get("url") or "").lower()
            path_lower = ""
            try:
                path_lower = (urllib.parse.urlsplit(url_lower).path or "").lower()
            except Exception:
                path_lower = url_lower
            status = ep.get("status")
            static_path = is_static_asset(url_lower, ep.get("content_type", ""))
            if static_path:
                continue
            if any(x in url_lower for x in ["sitemap", "robots.txt"]):
                discovery.append(ep)
            elif ep.get("admin_panel") or (
                status in (401, 403)
                and any(x in path_lower for x in (
                    "/admin", "/dashboard", "/manage", "/wp-admin", "/console",
                ))
                and "/plugin" not in path_lower
            ):
                admin.append(ep)
            else:
                functional.append(ep)

        for group_label, group in [
            (" Functional Endpoints", functional),
            (" Administrative Endpoints", admin),
            (" Discovery Resources", discovery),
        ]:
            if group:
                lines.append(group_label)
                for ep in group[:15]:
                    if ep.get("redirects_to_auth"):
                        status_disp = "REDIR→AUTH"
                        auth_tag = " [REDIRECTS TO AUTH]"
                    elif ep.get("auth_required"):
                        status_disp = ep.get("status", "?")
                        auth_tag = " [AUTH REQUIRED]"
                    else:
                        status_disp = ep.get("status", "?")
                        auth_tag = ""
                    lines.append(
                        f"- [{status_disp}] {ep.get('method','GET')} "
                        f"{ep.get('url','')} [{ep.get('source','')}]{auth_tag}"
                    )
    else:
        lines.append("None discovered with verified HTTP responses.")

    if excluded_eps:
        lines.append("\n Excluded endpoints (SPA/soft-404 — not attack surface)")
        shown_excluded = excluded_eps[:10]
        for ep in shown_excluded:
            reason = ep.get("exclude_reason") or ep.get("verification") or "SPA catch-all"
            lines.append(
                f"- [{ep.get('status','?')}] {ep.get('method','GET')} "
                f"{ep.get('url','')} — {reason}"
            )
        remaining = len(excluded_eps) - len(shown_excluded)
        if remaining > 0:
            lines.append(f"- ...and {remaining} more (see JSON output for full list)")

    openapi_eps = [
        e for e in (endpoints or [])
        if e.get("source") == "swagger"
        and not e.get("spa_catch_all")
        and not e.get("excluded")
    ]
    docs_ui_eps = [
        e for e in (endpoints or [])
        if e.get("interesting")
        and not e.get("spa_catch_all")
        and not e.get("excluded")
        and any(
            k in ((urllib.parse.urlsplit(e.get("url") or "").path) or "").lower()
            for k in ("/docs", "swagger", "redoc", "documentation")
        )
    ]
    if openapi_eps:
        spec_url = next(
            (e.get("openapi_spec") for e in openapi_eps if e.get("openapi_spec")),
            "",
        )
        hdr = " OpenAPI-enumerated endpoints"
        if spec_url:
            hdr += f" (from `{spec_url}`)"
        lines.append("\n" + hdr)
        seen_oa: set = set()
        shown = 0
        for ep in openapi_eps:
            key = (ep.get("method", "GET"), ep.get("url", ""))
            if key in seen_oa:
                continue
            seen_oa.add(key)
            status_disp = ep.get("status")
            if status_disp in (None, "", "?"):
                status_disp = "spec"
            lines.append(
                f"- [{status_disp}] {ep.get('method','GET')} {ep.get('url','')}"
            )
            shown += 1
            if shown >= 20:
                break
        n_unique = len({(e.get("method"), e.get("url")) for e in openapi_eps})
        if n_unique > shown:
            lines.append(f"- … and {n_unique - shown} more from OpenAPI spec")
    elif docs_ui_eps:
        docs_urls = ", ".join(f"`{e.get('url')}`" for e in docs_ui_eps[:3])
        lines.append(
            f"\n OpenAPI/Swagger: docs UI found ({docs_urls}) but no "
            "machine-readable OpenAPI/Swagger document was retrieved "
            "(HTML shell or missing spec URL)."
        )

    ft = forms_testing if isinstance(forms_testing, dict) else {}
    n_forms = int(forms_discovered or ft.get("discovered") or 0)
    if n_forms or ft:
        tested = int(ft.get("tested") if ft.get("tested") is not None else n_forms)
        with_findings = int(ft.get("with_findings") or 0)
        errored = int(ft.get("errored") or 0)
        outcome = (
            f"{with_findings} produced findings"
            if with_findings
            else "no injection/CSRF findings on exercised forms"
        )
        err_bit = f"; {errored} errored" if errored else ""
        lines.append(
            f"\n Forms discovered: {n_forms} "
            f"(tested: {tested}; {outcome}{err_bit})"
        )
        per_form = ft.get("per_form") or []
        if isinstance(per_form, list) and per_form:
            lines.append(" Form exercises:")
            for rec in per_form[:15]:
                if not isinstance(rec, dict):
                    continue
                fields = rec.get("input_fields") or []
                if isinstance(fields, list):
                    field_s = ",".join(str(x) for x in fields[:8] if x) or "(none)"
                    if len(fields) > 8:
                        field_s += ",…"
                else:
                    field_s = str(fields)
                tests = rec.get("tests_run") or []
                tests_s = ",".join(str(t) for t in tests) if tests else "none"
                note = rec.get("response_note") or rec.get("outcome") or ""
                lines.append(
                    f"- `{rec.get('method', 'GET')} {rec.get('action', '?')}` "
                    f"fields=[{field_s}] tests=[{tests_s}] → {note}"
                )
            if len(per_form) > 15:
                lines.append(f"- … and {len(per_form) - 15} more form(s)")
    elif scan_results is not None:
        lines.append("\n Forms discovered: 0 (none found for active testing)")

    em = (scan_results or {}).get("eval_metrics") if scan_results else None
    if isinstance(em, dict) and em:
        lines.append("\n Evaluation metrics (scan summary):")
        lines.append(
            f"- AI surfaces discovered: {em.get('ai_surfaces_discovered', 0)} "
            f"(unauthenticated: {em.get('ai_surfaces_unauthenticated', 0)})"
        )
        lines.append(
            f"- Prompt injection attempted: {em.get('prompt_injection_attempted', 0)}; "
            f"confirmed: {em.get('prompt_injection_confirmed', 0)}; "
            f"potential: {em.get('prompt_injection_potential', 0)}"
        )
        lines.append(
            f"- XSS attempted: {em.get('xss_attempted', 0)}; "
            f"confirmed: {em.get('xss_confirmed', 0)}; "
            f"potential: {em.get('xss_potential', 0)}"
        )
        lines.append(
            f"- SQLi attempted: {em.get('sqli_attempted', 0)}; "
            f"confirmed: {em.get('sqli_confirmed', 0)}; "
            f"potential: {em.get('sqli_potential', 0)}"
        )
        lines.append(
            f"- CSRF attempted: {em.get('csrf_attempted', 0)}; "
            f"confirmed: {em.get('csrf_confirmed', 0)}; "
            f"potential: {em.get('csrf_potential', 0)}"
        )
        if em.get("nav_states") or em.get("interstate_flows") is not None:
            lines.append(
                f"- Navigation graph: {em.get('nav_states', 0)} states, "
                f"{em.get('nav_edges', 0)} edges, "
                f"{em.get('nav_unique_urls', 0)} unique URLs"
            )
            lines.append(
                f"- Inter-state flows: {em.get('interstate_flows', 0)} "
                f"(unescaped: {em.get('interstate_unescaped', 0)}; "
                f"tokens planted: {em.get('interstate_tokens_planted', 0)})"
            )
        cov = em.get("endpoint_coverage_percent")
        if cov is not None:
            lines.append(f"- Endpoint coverage: {cov}%")
        lines.append(
            f"- Forms: discovered {em.get('forms_discovered', n_forms)}, "
            f"tested {em.get('forms_tested', 0)}"
        )

    return "\n".join(lines)

_CONFIDENCE_LABEL = {
    "js_execution":   "HIGH  (JavaScript executed)",
    "timing":         "HIGH  (timing-confirmed)",
    "dom_reflection": "HIGH  (DOM reflection confirmed)",
    "http_body":      "HIGH  (HTTP body evidence)",
    "pattern":        "HIGH  (error pattern in response body)",
    "header":         "HIGH  (direct header inspection)",
}

def _build_section_3(confirmed_vulns):
    lines = [" 3. CONFIRMED SECURITY MISCONFIGURATIONS & WEAKNESSES"]
    if not confirmed_vulns:
        lines.append("No confirmed vulnerabilities identified from active scanning.")
        return "\n".join(lines)
    seen = set()
    for v in confirmed_vulns:
        key = (v.get("type", ""), v.get("location", ""))
        if key in seen:
            continue
        seen.add(key)
        ev     = v.get("evidence", {}) or {}
        method = ev.get("confirmation_method", "http_body")
        if _evidence_has_substance(ev):
            conf = _CONFIDENCE_LABEL.get(method, "HIGH  (verified evidence)")
        else:
            conf = "LOW   (insufficient evidence — should not publish)"
        body_snip = (
            ev.get("response_body_snippet")
            or ev.get("db_error_snippet")
            or ""
        )
        evid_line = (
            f"`{ev.get('request','?')}` "
            f"(HTTP {ev.get('response_status','?')}, confirmed by {method})"
        )
        if body_snip:
            evid_line += f"\n- Body evidence: `{str(body_snip)[:180]}`"
        lines += [
            "",
            f"Severity: {v.get('severity','?')} | {v.get('type','?')}",
            f"- Confidence: {conf}",
            f"- Location: `{v.get('location','?')}`",
            f"- Evidence: {evid_line}",
            f"- Impact: {v.get('impact','')}",
            f"- Fix: {v.get('remediation','')}",
            f"- CWE: {v.get('cwe','')}",
        ]
    return "\n".join(lines)

def render_section_3b(action_results: list) -> str:
    if not action_results:
        return ""
    lines = ["\n VERIFICATION EVIDENCE & FIX SNIPPETS"]
    for a in action_results:
        e        = a.get("effort_minutes", 0)
        effort   = f"{e} min" if e < 60 else f"{e//60}h {e%60}min"
        poc_lang = {"curl": "bash", "html": "html", "command": "bash"}.get(
            a.get("poc_type", ""), "text"
        )
        lines += [
            f" [{a['severity']}] {a['finding_type']}",
            f"Location: `{a['location']}` | Estimated fix effort: {effort}\n",
            f"Verification Evidence:",
            f"```{poc_lang}",
            a["attack_poc"],
            "```\n",
            f"Fix ({a['fix_context']}):",
            f"```{a['fix_language']}",
            a["fix_snippet"],
            "```\n",
            "---\n",
        ]
    return "\n".join(lines)

def _coverage_denominator_text(scan_results) -> str:
    """Denominator for zero-finding sections — never imply app-wide cleanliness."""
    sr = scan_results or {}
    endpoints = list(sr.get("endpoints_discovered") or [])
    n_functional = 0
    n_excluded = 0
    for ep in endpoints:
        if not isinstance(ep, dict) or ep.get("static_asset"):
            continue
        if ep.get("spa_catch_all") or ep.get("excluded"):
            n_excluded += 1
        elif ep.get("interesting") or ep.get("auth_endpoint"):
            if not (
                ep.get("access_controlled")
                or ep.get("auth_required")
                or ep.get("redirects_to_auth")
                or ep.get("category") == "discovered_protected"
            ):
                n_functional += 1
    n_forms = int(sr.get("forms_discovered") or 0)
    cov = _coverage_from_scan(sr)
    n_auth = cov["auth_gated_count"]
    parts = [
        f"{n_functional} functional endpoint(s)",
        f"{n_forms} form(s)",
        "unauthenticated only",
    ]
    if n_excluded:
        parts.append(f"{n_excluded} candidate path(s) excluded as soft-404")
    if n_auth:
        parts.append(f"{n_auth} auth-gated surface(s) not tested")
    return _authed_wording("Coverage: " + "; ".join(parts) + ".", scan_results)

def _build_section_4(potential_vulns, scan_results=None):
    lines = [" 4. POTENTIAL VULNERABILITIES"]
    if not potential_vulns:
        lines.append(
            "No potential vulnerabilities identified. "
            + _coverage_denominator_text(scan_results)
        )
        return "\n".join(lines)
    seen = set()
    for i, v in enumerate(potential_vulns, 1):
        key = v.get("type", "")
        if key in seen:
            continue
        seen.add(key)
        ev = v.get("evidence") or {}
        if not isinstance(ev, dict):
            ev = {}
        method = ev.get("confirmation_method", "code analysis")
        snippet = ev.get("response_body_snippet", "")
        raw_conf = str(
            v.get("confidence") or ev.get("confidence") or "Medium"
        ).strip().lower()
        conf_label = {
            "high":   "MEDIUM-HIGH (strong indicators — manual verification required)",
            "medium": "MEDIUM (unconfirmed — manual verification required)",
            "low":    "LOW (weak indicators — manual verification required)",
        }.get(raw_conf, "MEDIUM (unconfirmed — manual verification required)")
        lines += [
            "",
            f" [{i}] {v.get('type','?')}",
            f"- Severity: {v.get('severity','Low')} | "
            f"Confidence: {conf_label}",
            f"- Location: {v.get('location','?')}",
            f"- Why Potential: Requires manual confirmation — {v.get('details','')}",
            f"- Detection Method: {method}",
        ]
        if snippet:
            lines.append(f"- Evidence Snippet: `{snippet[:120]}`")
        if v.get("cwe"):
            lines.append(f"- CWE: {v.get('cwe')}")
    return "\n".join(l for l in lines if l is not None)

def _build_section_5(stride_threats, confirmed_vulns=None):
    threats = [
        t for t in (stride_threats or [])
        if isinstance(t, dict) and t.get("confirmed") is True
    ]
    lines = [
        " 5. ARCHITECTURAL THREAT MODEL (STRIDE)",
        " Evidence-confirmed architectural risks only",
    ]
    if not threats:
        lines.append("No evidence-confirmed STRIDE risks from active scanning.")
        return "\n".join(lines)

    clickjacking_finding = None
    for v in (confirmed_vulns or []):
        if not isinstance(v, dict):
            continue
        if "Clickjacking" in (v.get("type") or "") and v.get("status") == "Confirmed":
            clickjacking_finding = v
            break

    for t in threats:
        evidence = t.get("evidence", "") or ""
        if (
            clickjacking_finding
            and "Clickjacking" in (t.get("threat") or "")
        ):
            if "see section 3" not in evidence.lower():
                evidence = (
                    f"See Section 3: {clickjacking_finding.get('type')} — "
                    f"{evidence}"
                )
        lines += [
            "",
            f" {t.get('category','?')}: {t.get('threat','?')}",
            f"- Status: Evidence-confirmed",
            f"- Evidence: {evidence}",
            f"- Likelihood: {t.get('likelihood','?')}",
            f"- Impact: {t.get('impact','?')}",
            f"- Mitigation: {t.get('mitigation','')}",
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
            f"- {v.get('type','?')}\n"
            f"  Location: {v.get('location','?')}\n"
            f"  Fix: {v.get('remediation','')[:120]}"
        )

    lines       = [" 6. PRIORITISED REMEDIATION ROADMAP", " Grouped by Severity"]
    any_finding = False
    for sev in severity_order:
        if groups[sev]:
            any_finding = True
            lines.append(f"\n {sev}")
            lines.extend(groups[sev])
    if not any_finding:
        lines.append("No findings requiring remediation.")
    return "\n".join(lines)

def _build_section_8_ai_negative(scan_results: Dict) -> str:
    """
    When no AI surface is escalated, still emit §8 with a denominator —
    silence is not a negative result under the coverage-honesty invariant.
    """
    brand_only = bool((scan_results or {}).get("ai_brand_only"))
    live = bool((scan_results or {}).get("has_live_surface"))
    if brand_only and not live:
        note = (
            "AI product branding was observed without a confirmed "
            "live chat/inference surface; AI-specific active testing "
            "was not applicable. "
            + _coverage_denominator_text(scan_results)
        )
    else:
        note = _authed_wording(
            "No AI/ML attack surface detected on the unauthenticated "
            "surface; AI-specific analysis not applicable. ",
            scan_results,
        ) + _coverage_denominator_text(scan_results)
    return " 8. AI/ML BACKDOOR VULNERABILITY ANALYSIS\n\n" + note

def _build_section_8_ai_backdoor(scan_results: Dict) -> str:
    ai_fp     = scan_results.get("ai_fingerprint", {})
    strategic = scan_results.get("strategic_recommendations", [])
    ai_vulns  = [
        f for f in scan_results.get("vulnerabilities", [])
        if f.get("category") == "ai_vulnerability"
    ]

    if not ai_fp or not ai_fp.get("is_ai_powered"):
        return ""

    avid_raw     = scan_results.get("avid_backdoor_relevant", [])
    ml_libraries = ai_fp.get("ml_libraries", [])

    _techs         = (scan_results.get("stack") or {}).get("technologies", [])
    detected_stack = [
        (t.get("name", "") if isinstance(t, dict) else str(t).split("/")[0]).lower()
        for t in _techs
    ]
    relevant_terms = [t.lower() for t in ml_libraries] + detected_stack

    avid = (
        [
            cve for cve in avid_raw
            if any(
                term in (cve.get("title", "") + " " + cve.get("description", "")).lower()
                for term in relevant_terms
            )
        ]
        if relevant_terms else []
    )

    lines = [
        " 8. AI/ML BACKDOOR VULNERABILITY ANALYSIS",
        "",
        f"> AI/ML components detected in this application [confidence: {ai_fp.get('confidence', 'medium')}]",
        "> Traditional web vulnerability scanning has been supplemented with "
        "AI-specific backdoor analysis per NIST AI 100-2 E2025 and MITRE ATLAS.",
        "",
    ]

    lines.append(" 8.1 Detected AI/ML Components")
    lines.append("")

    if ai_fp.get("ml_endpoints"):
        lines.append("ML Inference Endpoints:")
        for ep in ai_fp["ml_endpoints"][:5]:
            lines.append(f"- `{ep}`")
        lines.append("")

    if ai_fp.get("ml_libraries"):
        libs = ", ".join(ai_fp["ml_libraries"][:6])
        lines.append(f"Detected ML Libraries: {libs}")
        lines.append("")

    if ai_fp.get("chat_components"):
        lines.append("LLM Chat UI Components Detected: Yes")
        lines.append("")

    if ai_fp.get("model_upload_endpoints"):
        lines.append("Model File Upload Endpoints (HIGH RISK):")
        for ep in ai_fp["model_upload_endpoints"][:3]:
            lines.append(f"- `{ep}` — accepts model files (.pkl, .pt, .h5)")
        lines.append(
            "\n> Pickle (.pkl) files execute arbitrary code on load. "
            "This is the primary vector for AML.T0018.002 — Embed Malware."
        )
        lines.append("")

    if ai_fp.get("atlas_techniques"):
        lines.append("Applicable ATLAS Techniques (from detected signals):")
        for tech in ai_fp["atlas_techniques"]:
            lines.append(f"- {tech}")
        lines.append("")

    lines.append(" 8.2 Confirmed AI/ML Vulnerabilities")
    lines.append("")
    if ai_vulns:
        confirmed_ai = [v for v in ai_vulns if v.get("status") == "Confirmed"]
        potential_ai = [v for v in ai_vulns if v.get("status") == "Potential"]
        collapsed_potential: List[Dict] = []
        auth_gated_bucket: List[Dict] = []
        for v in potential_ai:
            if "auth-gated" in (v.get("type") or "").lower():
                auth_gated_bucket.append(v)
            else:
                collapsed_potential.append(v)
        if auth_gated_bucket:
            primary = auth_gated_bucket[0]
            related = []
            for v in auth_gated_bucket:
                loc = v.get("location")
                if loc and loc not in related:
                    related.append(loc)
                for ep in v.get("related_endpoints") or []:
                    if ep not in related:
                        related.append(ep)
            detail = primary.get("details") or (
                "AI inference/chat endpoint(s) exist but require authentication. "
                "Prompt-injection testing was not attempted without credentials."
            )
            if len(related) > 1 and "Related auth-gated" not in detail:
                detail += (
                    f" Related auth-gated surfaces ({len(related)}): "
                    + ", ".join(related[1:6])
                    + (" …" if len(related) > 6 else "")
                )
            collapsed_potential.insert(0, {
                **primary,
                "location": related[0] if related else primary.get("location"),
                "details": detail,
            })
            potential_ai = collapsed_potential

        for v in confirmed_ai:
            lines += [
                f" [CONFIRMED] {v.get('type','?')}",
                f"- Severity: {v.get('severity','?')}",
                f"- Location: `{v.get('location','?')}`",
                f"- ATLAS Technique: {v.get('atlas', 'N/A')}",
                f"- CWE: {v.get('cwe', 'N/A')}",
                f"- Impact: {v.get('impact', v.get('details', ''))}",
                f"- PoC: `{v.get('poc','N/A')}`",
                f"- Remediation: {v.get('remediation','')}",
                "",
            ]
        for v in potential_ai:
            lines += [
                f" [POTENTIAL] {v.get('type','?')}",
                f"- Severity: {v.get('severity','?')}",
                f"- Location: `{v.get('location','?')}`",
                f"- ATLAS Technique: {v.get('atlas', 'N/A')}",
                f"- Details: {v.get('details','')}",
                f"- Remediation: {v.get('remediation','')}",
                "",
            ]
    else:
        lines.append("No AI-specific vulnerabilities confirmed via active testing.")
        lines.append("")

    lines.append(" 8.3 AI-Specific CVEs from AVID Database")
    lines.append("")
    if avid:
        lines.append("> Source: AVID — AI Vulnerability and Incidents Database (https://avidml.org/database/)")
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
            f"{len(avid)} AI backdoor-relevant CVEs found. "
            f"Full details at https://avidml.org/database/"
        )
        lines.append("")
    else:
        lines.append(
            "No AVID CVEs matched the detected ML stack. "
            "AVID coverage of AI vulnerabilities is still growing."
        )
        lines.append("")

    lines.append(" 8.4 Strategic Recommendations (ATLAS-Based)")
    lines.append("")

    has_ai_surface = bool(
        ai_fp.get("ml_endpoints")
        or ai_fp.get("has_live_surface")
        or ai_fp.get("chat_components")
        or ai_vulns
    )

    if not strategic:
        if has_ai_surface:
            lines.append(
                "AI chat/inference surfaces were identified (see 8.1–8.2). "
                "No additional ATLAS strategic recommendations were generated "
                "beyond those surfaces — keep authentication on chat APIs, "
                "add input/output guardrails, and re-test prompt injection with "
                "credentials when authorized."
            )
        else:
            lines.append(
                "No strategic recommendations generated — "
                "no AI-specific attack surfaces identified during active scanning."
            )
        return "\n".join(lines)

    for rec in strategic:
        lines += [
            f" {rec.get('atlas_id','?')}: {rec.get('title','?')}",
            f"Severity: {rec.get('severity','High')} | "
            f"Category: Strategic Recommendation (Not directly testable)",
            "",
            rec.get("description", ""),
            "",
        ]
        context = rec.get("context")
        if context:
            lines.append(f"Context: {context}")
            lines.append("")

        lines.append("Detection Indicators (manual investigation):")
        for indicator in rec.get("indicators", [])[:4]:
            lines.append(f"- {indicator}")
        lines.append("")

        lines.append("Recommended Mitigations:")
        for mitigation in rec.get("mitigations", [])[:5]:
            lines.append(f"- {mitigation}")
        lines += [
            "",
            f"ATLAS Reference: {rec.get('atlas_id','')} ({rec.get('atlas_url','')})",
            f"NIST Reference: {rec.get('nist_ref','')}",
            f"OWASP Reference: {rec.get('owasp_ref','')}",
            "",
            "---",
            "",
        ]

    return "\n".join(lines)

def _build_section_9_ai_infra(ai_infra_data: dict) -> str:
    lines = [
        "\n---\n",
        "9. AI INFRASTRUCTURE BUILD ATTACK ANALYSIS\n",
        f"> Attack planes scanned: {', '.join(ai_infra_data.get('planes_covered', []))}\n",
        f"> AI Stack: {json.dumps(ai_infra_data.get('ai_stack', {}))}\n\n",
    ]

    by_plane: Dict[str, list] = {}
    for f in ai_infra_data.get("findings", []):
        plane = f.get("layer", "UNKNOWN")
        by_plane.setdefault(plane, []).append(f)

    for plane, findings in by_plane.items():
        lines.append(f" {plane}\n")
        for f in findings:
            lines.append(f"[{f.get('severity','')}] {f.get('name','')}\n")
            lines.append(f"- STRIDE Category: {f.get('category','')}\n")
            lines.append(f"- Description: {f.get('description','')}\n")
            lines.append(f"- Evidence: `{f.get('evidence','')}`\n")
            lines.append(f"- Mitigation: {f.get('mitigation','')}\n")
            atlas = f.get("references", {}).get("atlas", "")
            if atlas:
                lines.append(
                    f"- ATLAS Technique: {atlas} (https://atlas.mitre.org/techniques/{atlas})\n"
                )
            lines.append("\n")

    if ai_infra_data.get("summary"):
        lines.append(" Executive Summary\n")
        lines.append(ai_infra_data["summary"] + "\n")

    return "".join(lines)

class ThreatModelingAgent:

    def __init__(self, openai_client=None, web_search_function=None,
                 llm_model: str = None, **_kwargs):
        if openai_client:
            self.openai_client = openai_client
            self.llm_model = (
                llm_model
                or os.getenv("AZURE_OPENAI_DEPLOYMENT")
                or os.getenv("LLAMA_MODEL_NAME", "Qwen-2.5")
            )
        else:
            llama_base_url     = os.getenv("LLAMA_BASE_URL", "http://localhost:8080")
            self.openai_client = openai.OpenAI(
                base_url=f"{llama_base_url}/v1", api_key="not-needed"
            )
            self.llm_model = llm_model or os.getenv("LLAMA_MODEL_NAME", "Qwen-2.5")

        self.web_search = web_search_function
        try:
            self.web_scanner = WebScannerAgent(
                openai_client=self.openai_client,
                llm_model=self.llm_model,
            )
        except Exception as e:
            logger.warning(f"WebScannerAgent init failed (scans disabled): {e}")
            self.web_scanner = None

        print("ThreatModelingAgent initialized")

    def ensure_web_scanner(self):
        """Create WebScannerAgent on demand if startup init failed."""
        if self.web_scanner is not None:
            return self.web_scanner
        try:
            self.web_scanner = WebScannerAgent(
                openai_client=self.openai_client,
                llm_model=self.llm_model,
            )
            logger.info("WebScannerAgent recovered on demand")
        except Exception as e:
            logger.error(f"WebScannerAgent still unavailable: {e}", exc_info=True)
            self.web_scanner = None
        return self.web_scanner

    def _generate_cache_key(self, query: str, include_scan: bool = False) -> str:
        base = query.lower().strip()
        if include_scan:
            base += ":with_scan"
        return f"threat_model:{hashlib.md5(base.encode()).hexdigest()}"

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
        return bool(re.search(
            r'https?://|www\.|localhost|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            r'|\.(com|org|net|io|dev|app|local)\b',
            query.lower()
        ))

    async def analyze(self, user_query: str, verbose: bool = True,
                      use_cache: bool = True, filenames: List[str] = None,
                      enable_web_scan: bool = False,
                      target_url: str = None,
                      ai_auth_token: Optional[str] = None,
                      auth: Optional[Dict] = None,
                      ) -> Dict:

        if verbose:
            print("\n" + "=" * 80)
            print("THREAT MODELING ANALYSIS")
            print("=" * 80)
            print(f"Query: {user_query}")
            if enable_web_scan:
                print(f"Web Scan: ENABLED | Target: {target_url}"
                      f" | AI Pipeline Auth: {'provided' if ai_auth_token else 'none'}"
                      f" | Login: {auth.get('username') if auth else 'none'}")
            print("=" * 80 + "\n")

        if not enable_web_scan:
            enable_web_scan = self.is_web_scan_request(user_query)
        if enable_web_scan and not target_url:
            target_url = self._extract_url_from_query(user_query)

        cache_key = self._generate_cache_key(
            user_query + (f" :auth={auth.get('username', '')}" if auth else ""),
            include_scan=enable_web_scan,
        )

        if use_cache:
            cached = get_cached_result(cache_key)
            if cached:
                result           = json.loads(cached)
                result["cached"] = True
                return result

        if verbose:
            print("PHASE 1: KNOWLEDGE GATHERING")

        decomposition = await self.decompose_query(user_query)
        known_vulns   = await self.search_known_vulnerabilities_web(
            user_query, target_url, verbose=verbose
        )
        research      = await self.research_sub_questions_hybrid(
            decomposition, filenames=filenames, verbose=verbose
        )

        scan_results = None
        if enable_web_scan and target_url:
            scanner = self.ensure_web_scanner()
            if not scanner:
                raise RuntimeError(
                    "Web scanner is not initialized. Check backend startup logs "
                    "for WebScannerAgent errors (often missing Playwright browsers)."
                )
            if verbose:
                print("PHASE 2: ACTIVE WEB APPLICATION SCANNING")
            scan_results = await scanner.scan_application(
                target_url=target_url, max_time_minutes=15, verbose=verbose,
                ai_auth_token=ai_auth_token, auth=auth,
            )

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
            "query":           user_query,
            "report":          final_report,
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

    async def search_known_vulnerabilities_web(self, query: str,
                                               target_url: Optional[str] = None,
                                               verbose: bool = False) -> List[Dict]:
        known_vulns = []
        if not self.web_search:
            return []

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
                            "is_cve":        "CVE-" in r.get("title", "") or "CVE-" in r.get("snippet", ""),
                            "is_exploit_db": "exploit-db" in r.get("url", "").lower(),
                            "is_nvd":        "nvd.nist.gov" in r.get("url", "").lower(),
                            "is_cisa":       "cisa.gov" in r.get("url", "").lower(),
                        })
            except Exception as e:
                if verbose:
                    print(f"    Search failed: {e}")

        return known_vulns

    async def search_known_vulnerabilities_kb(self, query: str,
                                              target_url: Optional[str] = None,
                                              verbose: bool = False) -> List[Dict]:
        """Knowledge-base vector search removed — use web search instead."""
        return []

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
            "task_1_system_understanding": normalize_list(raw.get("task_1_system_understanding", [])),
            "task_2_security_analysis":    normalize_list(raw.get("task_2_security_analysis", [])),
        }

    async def research_sub_questions_hybrid(self, decomposition: Dict,
                                            filenames: List[str] = None,
                                            verbose: bool = False) -> Dict:
        """Research sub-questions via web search."""
        research_results = {"task_1": [], "task_2": []}

        def normalize_sq(sq):
            if isinstance(sq, dict): return sq
            if isinstance(sq, str):  return {"question": sq, "preferred_source": None}
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

                web_findings = []
                if self.web_search and question_text:
                    try:
                        results = await self.web_search(question_text)
                        for r in (results or [])[:3]:
                            web_findings.append({
                                "content": r.get("snippet", r.get("content", "")),
                                "title":   r.get("title", ""),
                                "source":  "Web Search",
                                "url":     r.get("url", ""),
                            })
                    except Exception as e:
                        logger.warning(f"Web research failed: {e}")

                if verbose:
                    print(f"    Web: {len(web_findings)}")

                research_results[task_label].append({
                    "question":         question_text,
                    "preferred_source": sq.get("preferred_source"),
                    "kb_findings":      web_findings,
                    "user_findings":    [],
                })

        return research_results

    def format_research_hybrid(self, research: Dict) -> str:
        formatted = " TASK 1 - System Understanding\n\n"
        for item in research["task_1"]:
            formatted += f"Question: {item['question']}\n\n"
            if item.get("kb_findings"):
                formatted += "From Security KB:\n\n"
                for idx, f in enumerate(item["kb_findings"][:3], 1):
                    formatted += (
                        f"{idx}. [{f.get('source','?')}] "
                        f"{f.get('title', f.get('filename','Untitled'))}\n"
                        f"   {f.get('content','')[:400]}...\n\n"
                    )
            if item.get("user_findings"):
                formatted += "From Your Uploaded Documents:\n\n"
                for idx, f in enumerate(item["user_findings"][:2], 1):
                    formatted += (
                        f"{idx}. {f.get('filename','?')} (Page {f.get('page','?')})\n"
                        f"   {f.get('content','')[:400]}...\n\n"
                    )
            formatted += "---\n\n"

        formatted += " TASK 2 - Security Analysis\n\n"
        for item in research["task_2"]:
            formatted += f"Question: {item['question']}\n\n"
            if item.get("kb_findings"):
                formatted += "From Security KB:\n\n"
                for idx, f in enumerate(item["kb_findings"][:3], 1):
                    formatted += (
                        f"{idx}. [{f.get('source','?')}] "
                        f"{f.get('title', f.get('filename','Untitled'))}\n"
                        f"   {f.get('content','')[:400]}...\n\n"
                    )
            if item.get("user_findings"):
                formatted += "From Your Uploaded Documents:\n\n"
                for idx, f in enumerate(item["user_findings"][:2], 1):
                    formatted += (
                        f"{idx}. {f.get('filename','?')} (Page {f.get('page','?')})\n"
                        f"   {f.get('content','')[:400]}...\n\n"
                    )
            formatted += "---\n\n"

        return formatted

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
            stack      = scan_results.get("stack") or {}
            scan_text += f"\n\n TECH STACK\n   {stack.get('stack_summary','Unknown')}\n\n"
            verified_cves = scan_results.get("verified_cves") or []
            for cve in verified_cves[:5]:
                scan_text += (
                    f"{cve.get('cve_id','?')} [{cve.get('severity','?')}] "
                    f"CVSS: {cve.get('cvss_score','?')}\n"
                    f"   {cve.get('description','')[:300]}\n\n"
                )

            vulns     = scan_results.get("vulnerabilities", [])
            confirmed = [v for v in vulns if v.get("status") == "Confirmed"]
            potential = [v for v in vulns if v.get("status") == "Potential"]

            if confirmed:
                scan_text += " CONFIRMED VULNERABILITIES\n\n"
                for v in confirmed:
                    scan_text += f"{v.get('type','?')} — {v.get('severity','?')}\n   {v.get('details','')[:200]}\n\n"
            if potential:
                scan_text += " POTENTIAL VULNERABILITIES\n\n"
                for v in potential:
                    scan_text += f"{v.get('type','?')} — {v.get('severity','?')}\n   {v.get('details','')[:200]}\n\n"

            stride_threats = scan_results.get("stride_threats", [])
            if stride_threats:
                scan_text += " STRIDE EVIDENCE (from scanner)\n\n"
                for t in stride_threats:
                    label = "CONFIRMED" if t.get("confirmed") else "POTENTIAL"
                    scan_text += (
                        f"[{label}] {t.get('category','?')}: {t.get('threat','?')}\n"
                        f"   Evidence: {t.get('evidence','?')}\n\n"
                    )
            else:
                scan_text += " STRIDE EVIDENCE\nNo STRIDE threats confirmed by scanner evidence.\n\n"

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
            cves      = scan_results.get("verified_cves") or []
            endpoints = scan_results.get("endpoints_discovered", [])
            vulns     = scan_results.get("vulnerabilities", [])

            if scan_results.get("app_name"):
                stack["app_identity_name"]    = scan_results["app_name"]
                stack["app_identity_version"] = scan_results.get("app_version", "")

            if not stack.get("technologies") and not stack.get("stack_summary"):
                raw     = scan_results.get("stack") or {}
                headers = raw.get("headers", {})
                server  = raw.get("server") or headers.get("server") or headers.get("Server", "")
                powered = raw.get("language") or headers.get("x-powered-by") or headers.get("X-Powered-By", "")
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
                if _is_publishable_confirmed(v):
                    confirmed_vulns.append(v)
                    continue
                ftype = str(v.get("type") or "")
                ev = v.get("evidence") or {}
                method = str(
                    (ev.get("confirmation_method") if isinstance(ev, dict) else "")
                    or ""
                ).lower()
                if (
                    v.get("status") == "Confirmed"
                    and "XSS" in ftype
                    and method not in ("js_execution",)
                ):
                    demoted = dict(v)
                    demoted["status"] = "Potential"
                    demoted["confidence"] = "Medium"
                    if isinstance(demoted.get("evidence"), dict):
                        demoted["evidence"] = dict(demoted["evidence"])
                        demoted["evidence"]["confidence"] = "Medium"
                        demoted["evidence"]["verified"] = False
                    if _is_manual_queue_finding(demoted):
                        potential_vulns.append(demoted)
                    continue
                if _is_manual_queue_finding(v):
                    potential_vulns.append(v)

            seen_types: set = set()
            deduped_pot     = []
            for v in potential_vulns:
                t = v.get("type", "")
                if t not in seen_types:
                    seen_types.add(t)
                    deduped_pot.append(v)
            potential_vulns = deduped_pot

        stride_threats = (scan_results or {}).get("stride_threats", [])
        action_agent   = ActionAgent()
        action_results = action_agent.process_all(confirmed_vulns, target_url, stack)

        section_1   = _build_section_1(confirmed_vulns, potential_vulns, target_url or "", scan_results) or ""
        section_2   = _build_section_2(
            stack,
            (scan_results or {}).get("endpoints_discovered", []),
            cves,
            target_url=target_url or "",
            forms_discovered=int((scan_results or {}).get("forms_discovered") or 0),
            forms_testing=(scan_results or {}).get("forms_testing"),
            scan_results=scan_results,
        ) or ""
        section_3   = _build_section_3(confirmed_vulns)                  or ""
        section_3b  = render_section_3b(action_results)                  or ""
        section_4   = _build_section_4(potential_vulns, scan_results)    or ""
        section_5   = _build_section_5(stride_threats, confirmed_vulns)  or ""
        section_6   = _build_section_6(confirmed_vulns, potential_vulns) or ""

        final = "\n\n".join([
            s for s in [section_1, section_2, section_3, section_3b,
                        section_4, section_5, section_6]
            if s
        ])

        section_8 = ""
        if scan_results is not None:
            if scan_results.get("is_ai_powered"):
                section_8 = _build_section_8_ai_backdoor(scan_results) or ""
            if not section_8:
                section_8 = _build_section_8_ai_negative(scan_results)
            if section_8:
                final = final + "\n\n" + section_8

        section_9 = ""
        ai_infra_data = (scan_results or {}).get("ai_infrastructure")
        if ai_infra_data and ai_infra_data.get("findings"):
            section_9 = _build_section_9_ai_infra(ai_infra_data)
            if section_9:
                final = final + "\n\n" + section_9

        report_sections = []
        for _sid, _title, _content in [
            ("1",  "Executive Summary",   section_1),
            ("2",  "Tech Stack",          section_2),
            ("3",  "Confirmed Vulns",     section_3),
            ("3b", "PoCs & Fixes",        section_3b),
            ("4",  "Potential Vulns",     section_4),
            ("5",  "STRIDE Model",        section_5),
            ("6",  "Remediation Roadmap", section_6),
            ("8",  "AI/ML Analysis",      section_8),
            ("9",  "AI Infra Attacks",    section_9),
        ]:
            if _content and _content.strip():
                report_sections.append({"id": _sid, "title": _title, "content": _content})

        return final, report_sections

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

    @staticmethod
    def _count_or_len(value, default: int = 0) -> int:
        """Accept either a list or a pre-computed int count."""
        if value is None:
            return default
        if isinstance(value, int):
            return value
        try:
            return len(value)
        except TypeError:
            return default

    def _summarize_scan_results(self, scan_results: Optional[Dict]) -> Optional[Dict]:
        if not scan_results:
            return None
        vulns     = scan_results.get("vulnerabilities", []) or []
        if not isinstance(vulns, list):
            vulns = []
        endpoints = scan_results.get("endpoints_discovered", []) or []
        if not isinstance(endpoints, list):
            endpoints = []
        return {
            "stack":                     (scan_results.get("stack") or {}).get("stack_summary", "Unknown"),
            "endpoints_found":           len(endpoints),
            "endpoints_interesting":     sum(
                1 for e in endpoints if isinstance(e, dict) and e.get("interesting")
            ),
            "verified_cves":             self._count_or_len(scan_results.get("verified_cves") or []),
            "confirmed_vulns":           sum(
                1 for v in vulns if isinstance(v, dict) and v.get("status") == "Confirmed"
            ),
            "potential_vulns":           sum(
                1 for v in vulns if isinstance(v, dict) and v.get("status") == "Potential"
            ),
            "tasks_generated":           scan_results.get("tasks_generated", 0),
            "tasks_executed":            scan_results.get("tasks_executed",  0),
            "forms_discovered":          scan_results.get("forms_discovered", 0),
            "urls_discovered":           scan_results.get("urls_discovered",  0),
            "scan_duration":             scan_results.get("scan_duration",    0),
            "is_ai_powered":             scan_results.get("is_ai_powered", False),
            "avid_findings":             self._count_or_len(
                scan_results.get("avid_findings", [])
            ),
            "strategic_recommendations": self._count_or_len(
                scan_results.get("strategic_recommendations", [])
            ),
            "vulnerabilities":           vulns,
        }