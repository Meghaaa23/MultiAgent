import os
import asyncio
import logging
import json
import re
import urllib.request
import urllib.parse
from typing import Dict, List, Optional, Set
from datetime import datetime
from pprint import pprint

from .fingerprint_agent         import TechFingerprintAgent, merge_url_stack_signals
from .pipeline_agent            import CVEVerificationPipeline
from .endpoint_discovery_agent  import EndpointDiscoveryAgent
from .browser_controller        import BrowserController
from .vulnerability_tester      import VulnerabilityTester
from .attack_verification_agent import AttackVerificationAgent, VulnStatus
from ..ai_agents.ai_fingerprint            import AIFingerprintAgent
from ..ai_agents.avid_lookup_agent         import AVIDLookupAgent
from ..ai_agents.ai_vulnerability_test     import AIVulnerabilityTester
from ..ai_agents.Ai_Infra_agent            import AIInfraAgent
from . import auth_session as _auth

logger = logging.getLogger(__name__)

try:
    from .app_identity import detect_app_identity, AppIdentity
    _HAS_APP_IDENTITY = True
except Exception as _e:
    logger.warning(f"app_identity import failed: {_e}")
    _HAS_APP_IDENTITY = False

try:
    from .spa_scanner import SPAScanner as _SPAScanner
    _spa_scanner_instance = _SPAScanner(timeout_ms=15000, max_routes=12)
except Exception as _e:
    logger.warning(f"SPAScanner import failed: {_e}")
    _spa_scanner_instance = None

def _validate_stack(stack, response_headers, body):
    if not stack:
        return {"stack_summary": "Unknown", "technologies": [],
                "unverified_hints": [], "vuln_hints": []}

    raw_tech = stack.get("technologies", [])
    if not isinstance(raw_tech, list) or not raw_tech:
        return stack

    if isinstance(raw_tech[0], dict):
        stack.setdefault("unverified_hints", [])
        stack.setdefault("confirmed_by", {})
        if not stack.get("stack_summary") or stack.get("stack_summary") == "Unknown":
            parts = []
            for dt in raw_tech[:4]:
                ver = dt.get("version", "")
                parts.append(f"{dt['name']} {ver}".strip() if ver else dt["name"])
            stack["stack_summary"] = " · ".join(parts) if parts else "Unknown"
        return stack

    return stack

def _build_evidence_gated_stride(target_url, response_headers,
                                  discovered_params, discovered_forms,
                                  cors_mode, stack,
                                  headers_capture_failed: bool = False) -> List[Dict]:
    """cors_mode: None | "wildcard" | "reflected" | "credentialed" """
    threats = []
    hdrs    = {k.lower(): v for k, v in (response_headers or {}).items()}
    xfo     = hdrs.get("x-frame-options", "")
    csp     = hdrs.get("content-security-policy", "")

    if not headers_capture_failed and not xfo and "frame-ancestors" not in csp.lower():
        threats.append({
            "category":   "Spoofing",
            "threat":     "Clickjacking",
            "evidence":   (
                "Missing Clickjacking Protection "
                "(X-Frame-Options and CSP frame-ancestors absent)"
            ),
            "likelihood": "Medium",
            "impact":     "Medium",
            "mitigation": "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'",
            "confirmed":  True,
        })

    redirect_kws    = {"redirect", "url", "next", "return", "goto", "dest", "to"}
    redirect_params = [p for p in discovered_params if any(k in p.lower() for k in redirect_kws)]
    if redirect_params:
        threats.append({
            "category":   "Tampering",
            "threat":     "Open Redirect",
            "evidence":   f"Redirect params in crawl: {redirect_params}",
            "likelihood": "Medium",
            "impact":     "Medium",
            "mitigation": "Validate redirects against allowlist",
            "confirmed":  False,
        })

    if cors_mode == "credentialed":
        threats.append({
            "category":   "Information Disclosure",
            "threat":     "CORS Misconfiguration",
            "evidence":   "ACAO reflects attacker origin with Allow-Credentials: true",
            "likelihood": "High",
            "impact":     "High",
            "mitigation": "Restrict ACAO to trusted origins; never pair * with credentials",
            "confirmed":  True,
        })
    elif cors_mode == "reflected":
        threats.append({
            "category":   "Information Disclosure",
            "threat":     "CORS Misconfiguration",
            "evidence":   "ACAO reflects attacker-controlled origin (no credentials)",
            "likelihood": "Medium",
            "impact":     "Medium",
            "mitigation": "Restrict ACAO to trusted origins; remove origin reflection",
            "confirmed":  True,
        })

    def _inputs(form):
        return form.get("inputs") or form.get("fields") or []

    return threats

class WebScannerAgent:

    def __init__(self, openai_client, llm_model: str):
        self.openai_client = openai_client
        self.llm_model     = llm_model

        self.fingerprinter  = TechFingerprintAgent(openai_client, llm_model)
        self.cve_pipeline   = CVEVerificationPipeline(nvd_api_key=os.environ.get("NVD_API_KEY", ""))
        self.endpoint_disco = EndpointDiscoveryAgent(timeout=5, max_probe_paths=90)
        self.browser        = BrowserController(openai_client, llm_model)
        self.vuln_tester    = VulnerabilityTester(timeout=10)
        self.verifier       = AttackVerificationAgent(openai_client, llm_model)

        self.ai_fingerprinter = AIFingerprintAgent(timeout=8)
        self.avid_lookup      = AVIDLookupAgent(timeout=15)
        self.ai_vuln_tester   = AIVulnerabilityTester(
            timeout=10,
            llm_model=self.llm_model,
            enable_embeddings=False,
        )
        self.ai_infra_agent   = AIInfraAgent(openai_client=self.openai_client, llm_model=self.llm_model)

        print(" WebScannerAgent initialized ")

    async def scan_application(self, target_url: str,
                               max_time_minutes: Optional[int] = None,
                               verbose: bool = False,
                               ai_auth_token: Optional[str] = None,
                               auth: Optional[Dict] = None) -> Dict:
        """auth (optional): {"username", "password", "login_url","""
        session: Optional[_auth.AuthSession] = None
        if auth and auth.get("username") and auth.get("password"):
            base = _resolve_docker_url(target_url.split("#")[0].rstrip("/"))
            login_url = auth.get("login_url") or ""
            if login_url:
                login_url = _resolve_docker_url(login_url)
            if verbose:
                print(f"\nAuthenticating as {auth['username']!r}...")
            session = await _auth.login(
                target_url=base,
                username=auth["username"],
                password=auth["password"],
                login_url=login_url,
                username_selector=auth.get("username_selector") or "",
                password_selector=auth.get("password_selector") or "",
                success_indicator=auth.get("success_indicator") or "",
                verbose=verbose,
            )
            if session.logged_in:
                _auth.activate(session)
            elif verbose:
                print(f"   ! {session.error} - continuing unauthenticated\n")
        try:
            return await self._scan_application(
                target_url, max_time_minutes=max_time_minutes, verbose=verbose,
                ai_auth_token=ai_auth_token, session=session,
            )
        finally:
            if session is not None:
                _auth.deactivate(session)

    async def _scan_application(self, target_url: str,
                                max_time_minutes: Optional[int] = None,
                                verbose: bool = False,
                                ai_auth_token: Optional[str] = None,
                                session: Optional["_auth.AuthSession"] = None) -> Dict:
        start = datetime.now()
        authed = bool(session and session.logged_in)

        async def _keep_session():
            if authed:
                await session.ensure_alive(verbose=verbose)

        ai_auth_headers = (
            {"Authorization": f"Bearer {ai_auth_token}"} if ai_auth_token else None
        )
        ai_fingerprinter = self.ai_fingerprinter
        ai_infra_agent   = self.ai_infra_agent
        ai_vuln_tester   = self.ai_vuln_tester
        infra_headers = {
            **(session.request_headers() if authed else {}),
            **(ai_auth_headers or {}),
        }
        if infra_headers:
            ai_infra_agent = AIInfraAgent(
                openai_client=self.openai_client, llm_model=self.llm_model,
                auth_headers=infra_headers,
            )
        if ai_auth_headers:
            ai_fingerprinter = AIFingerprintAgent(timeout=8, auth_headers=ai_auth_headers)
            ai_vuln_tester   = AIVulnerabilityTester(
                timeout=10, llm_model=self.llm_model, enable_embeddings=False,
                auth_headers=ai_auth_headers,
            )

        if "#" in target_url:
            target_url = target_url.split("#")[0].rstrip("/")

        target_url = _resolve_docker_url(target_url, verbose=verbose)

        if verbose:
            print(f"\n{'='*70}")
            print(f"Evidence Based Web Application Scan + AI Backdoor Detection")
            print("  Mode   : "
                  + (f"Authenticated (as {session.username!r})" if authed
                     else "Black-box unauthenticated"))
            print(f"  Target : {target_url}")
            print("  Budget : coverage-based (runs until surface saturation; no time limit)")
            print("  Crawl  : Deep (shared "
                  + ("authenticated" if authed else "anonymous") + " session)")
            print(f"  AI Pipeline Auth : {'provided' if ai_auth_headers else 'none (unauthenticated)'}")
            print(f"{'='*70}\n")

        all_forms:       List[Dict] = []
        all_urls:        List[str]  = [target_url]
        html:            str        = ""
        stack:           Dict       = {}
        elements:        List[Dict] = []
        initial_headers: Dict       = {}
        headers_capture_failed: bool = False

        if verbose:
            print(" Technology Fingerprinting...")
        try:
            page            = await self.browser.capture_page(target_url)
            html            = page.get("html", "")
            elements        = page.get("elements", [])
            initial_headers, headers_capture_failed = await self._get_real_headers(
                target_url, verbose=verbose
            )
            stack           = await self.fingerprinter.fingerprint(
                target_url=target_url, page_html=html,
                response_headers=initial_headers, verbose=verbose
            )
            stack = _validate_stack(stack, initial_headers, html) or {
                "stack_summary": "Unknown", "technologies": [],
                "unverified_hints": [], "vuln_hints": [],
            }
        except Exception as e:
            logger.warning(f"Fingerprinting failed: {e}")
            stack = {"stack_summary": "Unknown", "vuln_hints": []}

        if verbose:
            print(f"  Stack: {stack.get('stack_summary','Unknown')}\n")
            if headers_capture_failed:
                print(" Could not capture live response headers for the target — "
                      "header-dependent findings will be marked as evidence-incomplete.\n")

        app_identity = None
        if _HAS_APP_IDENTITY:
            try:
                app_identity = await detect_app_identity(
                    base_url=target_url,
                    html=html or "",
                    response_headers=initial_headers,
                    wappalyzer_technologies=stack.get("technologies", []),
                    verbose=verbose,
                )

                if app_identity and app_identity.name:
                    from .app_identity import _is_infra_or_framework_name
                    product_name = app_identity.name
                    if _is_infra_or_framework_name(product_name):
                        product_name = None
                    if product_name:
                        stack["app_identity_name"]    = product_name
                        stack["app_identity_version"] = app_identity.version or ""
                    stack["app_identity"] = app_identity
                    existing = stack.get("technologies", [])
                    if product_name and existing and isinstance(existing[0], dict):
                        current_summary = stack.get("stack_summary", "")
                        app_str = product_name
                        if app_identity.version:
                            app_str += f" {app_identity.version}"
                        if app_str.lower() not in current_summary.lower():
                            stack["stack_summary"] = (
                                f"{app_str} · {current_summary}"
                                if current_summary and current_summary != "Unknown"
                                else app_str
                            )
                    elif product_name:
                        ver_str    = f" {app_identity.version}" if app_identity.version else ""
                        name_entry = f"{product_name}{ver_str}"
                        merged     = [name_entry] + list(app_identity.technologies or []) + list(existing or [])
                        seen_t: set = set()
                        deduped_t   = []
                        for t in merged:
                            tkey = t.get("name", str(t)).lower() if isinstance(t, dict) else str(t).lower()
                            if tkey not in seen_t:
                                seen_t.add(tkey)
                                deduped_t.append(t)
                        stack["technologies"] = deduped_t
                        if "Unknown" in stack.get("stack_summary", ""):
                            stack["stack_summary"] = product_name
                    if verbose:
                        shown = product_name or "(not determined — stack-only signal)"
                        print(f"   App identity: {shown!r} v{app_identity.version or '?'} [{app_identity.confidence}]\n")
            except Exception as e:
                logger.debug(f"App identity failed: {e}")


        await _keep_session()
        if verbose:
            print("Endpoint Discovery...")
        discovered_endpoints: List[Dict] = []
        try:
            discovered_endpoints = await self.endpoint_disco.discover(
                target_url=target_url, page_html=html, verbose=verbose
            )
            for ep in discovered_endpoints:
                if ep.get("url") and ep.get("interesting") and ep.get("method") == "GET":

                    if ep.get("category") != "discovered_protected":
                        all_urls.append(ep["url"])
            from .vulnerability_tester import synthesize_injectable_urls
            all_urls.extend(synthesize_injectable_urls(
                target_url,
                [ep.get("url", "") for ep in discovered_endpoints if ep.get("url")],
                page_html=html or "",
            ))
            disco_urls = [
                ep.get("url", "") for ep in discovered_endpoints if ep.get("url")
            ]
            disco_urls.append(target_url)
            stack = merge_url_stack_signals(stack, disco_urls)
            if verbose:
                promoted = [
                    t.get("name") for t in (stack.get("technologies") or [])
                    if isinstance(t, dict) and t.get("category") in (
                        "Server", "Language", "Framework"
                    )
                ]
                if promoted:
                    print(f"   Stack after discovery merge: {', '.join(promoted)}")
        except Exception as e:
            logger.warning(f"Endpoint discovery failed: {e}")

        if verbose:
            interesting = sum(1 for e in discovered_endpoints if e.get("interesting"))
            protected   = sum(1 for e in discovered_endpoints if e.get("access_controlled"))
            soft_mode   = getattr(self.endpoint_disco, "_soft_mode", False)
            print(f"   {len(discovered_endpoints)} endpoints "
                  f"({interesting} interesting, {protected} access-controlled)"
                  + (" [soft-404 filter active]" if soft_mode else "") + "\n")


        await _keep_session()
        if verbose:
            print("AI/ML Component Detection...")

        ai_fingerprint  = None
        avid_results    = None
        ai_vuln_results = None
        ai_infra_result = None
        is_ai_powered   = False
        brand_only_ai   = False
        route_confirmed_only_ai = False

        try:
            ai_fingerprint = await ai_fingerprinter.fingerprint(
                target_url           = target_url,
                discovered_endpoints = discovered_endpoints,
                page_html            = html,
                response_headers     = initial_headers,
                verbose              = verbose,
            )

            has_live_surface = bool(ai_fingerprint.get("has_live_surface"))
            has_route_confirmed = bool(ai_fingerprint.get("has_route_confirmed"))
            brand_only_ai = (
                bool(ai_fingerprint.get("ai_brand_only"))
                and not has_live_surface and not has_route_confirmed
            )
            is_ai_powered = bool(
                ai_fingerprint.get("is_ai_powered") and has_live_surface
            )
            route_confirmed_only_ai = has_route_confirmed and not has_live_surface

            if is_ai_powered or route_confirmed_only_ai:
                if verbose:
                    conf = ai_fingerprint.get("confidence", "low")
                    det = ai_fingerprint.get("detection", "not_detected")
                    if is_ai_powered:
                        print(f"  AI-powered app detected [{det}, confidence={conf}]")
                    else:
                        print(f"  AI-shaped endpoint(s) discovered but not confirmed live "
                              f"[{det}, confidence={conf}] — route exists, no model output "
                              f"observed. Running classification only (no injection will be sent).")
                    print(f"     ML endpoints: {ai_fingerprint.get('ml_endpoints',[])[:3]}")
                    print(f"     ML libraries: {ai_fingerprint.get('ml_libraries',[])[:3]}\n")

                if is_ai_powered:
                    if verbose:
                        print("  AI Infrastructure Build Attack Analysis...")
                    try:
                        ai_infra_result = await ai_infra_agent.scan(
                            target_url=target_url, ai_stack=ai_fingerprint,
                        )
                        if ai_infra_result and ai_infra_result.exposed_endpoints:
                            ai_fingerprint = AIVulnerabilityTester.merge_exposed_endpoints(
                                ai_fingerprint, ai_infra_result.exposed_endpoints)
                            if verbose:
                                print(f"     Infra exposed endpoints merged: "
                                      f"{ai_infra_result.exposed_endpoints[:3]}")
                        if verbose and ai_infra_result is not None:
                            print(f"   AI Infra threats: {len(ai_infra_result.threats)} total\n")
                    except Exception as e:
                        logging.warning(f"AIInfraAgent failed: {e}")

                    if verbose:
                        print("  Querying AVID database for AI vulnerabilities...")
                    ml_stack = (
                        ai_fingerprint.get("ml_libraries", []) +
                        [ep.split("/")[-1] for ep in ai_fingerprint.get("ml_endpoints", [])[:3]]
                    )
                    avid_results = await self.avid_lookup.lookup(
                        ai_fingerprint=ai_fingerprint, ml_stack=ml_stack, verbose=verbose,
                    )
                    if verbose:
                        print(f"   AVID: {avid_results.get('total_found',0)} findings "
                              f"({len(avid_results.get('backdoor_relevant',[]))} backdoor-relevant)\n")

                if verbose:
                    print("  Running AI-specific vulnerability tests...")
                ai_vuln_results = await ai_vuln_tester.test_all(
                    ai_fingerprint=ai_fingerprint, target_url=target_url,
                    verbose=verbose,
                )
                if verbose:
                    c = len(ai_vuln_results.get("confirmed_ai_vulns", []))
                    p = len(ai_vuln_results.get("potential_ai_vulns", []))
                    s = len(ai_vuln_results.get("strategic_recommendations", []))
                    print(f"   AI vulns: {c} confirmed, {p} potential")
                    print(f"   Strategic recommendations: {s} ATLAS-based\n")
            elif brand_only_ai:
                if verbose:
                    fw = ai_fingerprint.get("framework") or (
                        (ai_fingerprint.get("frameworks_detected") or ["unknown"])[0]
                    )
                    det = ai_fingerprint.get("detection", "possible")
                    print(f"  AI product brand detected ({fw}) but no live inference surface")
                    print(f"     detection={det} — skipping AI escalation\n")
            else:
                if verbose:
                    print("  No AI/ML components detected — AI-specific tests skipped\n")

        except Exception as e:
            logger.warning(f"AI detection failed: {e}")

        verified_cves = []
        if verbose:
            print(" CVE Lookup — skipped (fingerprint-only mode)\n")

        await _keep_session()
        if verbose:
            print("Deep Browser Crawl (Yura-style shared session)...")

        for el in elements or []:
            if el.get("type") == "form":
                action = el.get("action") or target_url
                all_forms.append({
                    "action": action,
                    "method": el.get("method") or "get",
                    "inputs": el.get("inputs") or el.get("fields") or [],
                    "route":  action,
                })
            elif el.get("type") == "link" and el.get("href"):
                all_urls.append(el["href"])

        filtered = [
            e for e in elements
            if e.get("type") in ("form", "link", "clickable")
        ]
        tasks = await self.browser.generate_tasks(
            elements=filtered,
            page_description=(html or "")[:500],
            openai_client=self.openai_client,
            llm_model=self.llm_model,
            target_url=target_url,
            deep=True,
        )

        nav_graph: Dict = {}
        paper_coverage: Dict = {}
        interstate: Dict = {}
        interstate_flows: List = []
        crawl = await self.browser.deep_crawl(
            tasks=tasks,
            base_url=target_url,
            max_tasks=len(tasks) or 15,
            max_steps_per_task=18,
            verbose=verbose,
        )
        tasks_executed = int(crawl.get("tasks_executed") or 0)
        tasks_progressed = int(crawl.get("tasks_with_progress") or 0)
        all_forms.extend(crawl.get("forms") or [])
        all_urls.extend(crawl.get("urls") or [])
        crawl_apis = list(crawl.get("api_urls") or [])
        all_urls.extend(crawl_apis)
        nav_graph = crawl.get("nav_graph") or {}
        paper_coverage = crawl.get("paper_coverage") or {}
        interstate = crawl.get("interstate") or {}
        interstate_flows = interstate.get("flows") or []
        crawl_findings = list(crawl.get("crawl_findings") or [])

        if crawl_apis:
            from .vulnerability_tester import synthesize_injectable_urls
            all_urls.extend(synthesize_injectable_urls(
                target_url, crawl_apis, page_html=html or "",
            ))

        all_urls  = _dedup_urls(all_urls)[:180]
        all_forms = _dedup_forms(all_forms)[:50]

        all_params: Set[str] = set()
        for url in all_urls:
            all_params.update(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys())

        if verbose:
            print(
                f"   Deep crawl: {tasks_executed}/{len(tasks)} tasks "
                f"({tasks_progressed} with new surface) | "
                f"{len(all_forms)} forms | {len(all_urls)} URLs | "
                f"{len(crawl_apis)} network APIs | "
                f"states={((nav_graph.get('summary') or {}).get('states') or 0)} "
                f"edges={((nav_graph.get('summary') or {}).get('edges') or 0)} "
                f"frontier={((nav_graph.get('summary') or {}).get('frontier_taken') or 0)} "
                f"traces={((nav_graph.get('summary') or {}).get('traces_recorded') or 0)} "
                f"replay={((nav_graph.get('summary') or {}).get('replay_probes') or 0)} "
                f"xss_in_page={paper_coverage.get('xss_confirmed_in_page') or 0} "
                f"(safe={paper_coverage.get('xss_safe_phase') or 0} "
                f"aggressive={paper_coverage.get('xss_aggressive_phase') or 0})\n"
            )


        await _keep_session()
        if verbose:
            print("SPA Scanning...")
        try:
            spa_forms, spa_urls = await _scan_spa_routes(target_url, verbose=verbose)
            if spa_forms or spa_urls:
                all_forms.extend(spa_forms)
                all_urls.extend(spa_urls)
                from .vulnerability_tester import synthesize_injectable_urls
                all_urls.extend(synthesize_injectable_urls(
                    target_url,
                    list(spa_urls) + [
                        ep.get("url", "") for ep in discovered_endpoints
                        if ep.get("url") and (
                            ep.get("interesting")
                            or ep.get("source") in ("js_bundle", "spa")
                        )
                    ],
                    page_html=html or "",
                ))
                all_urls  = _dedup_urls(all_urls)[:160]
                all_forms = _dedup_forms(all_forms)[:50]
                if verbose:
                    print(f"   SPA: {len(spa_forms)} forms, {len(spa_urls)} URLs\n")
            elif verbose:
                print("  Not an SPA or Playwright unavailable\n")
        except Exception as e:
            logger.warning(f"SPA scanning failed: {e}")


        await _keep_session()
        if verbose:
            print("Vulnerability Testing...")
        skipped_password_forms: List[Dict] = []
        if authed:
            def _pw_fields(form):
                return sum(
                    1 for i in (form.get("inputs") or form.get("fields") or [])
                    if isinstance(i, dict)
                    and (i.get("type") or "").lower() == "password"
                )
            skipped_password_forms = [f for f in all_forms if _pw_fields(f) >= 2]
            if skipped_password_forms:
                all_forms = [f for f in all_forms if _pw_fields(f) < 2]
                if verbose:
                    print(f"   Skipping {len(skipped_password_forms)} password-change/"
                          "registration form(s) to protect the scan account")
        raw_findings: List[Dict] = list(crawl_findings)
        forms_exercised: List[Dict] = []
        try:
            disco_paths = [
                ep.get("url", "") for ep in discovered_endpoints
                if ep.get("url") and (
                    ep.get("interesting")
                    or ep.get("source") in ("js_bundle", "spa", "manifest")
                    or ep.get("api_endpoint")
                )
            ]
            disco_paths.extend(crawl_apis)
            disco_paths.extend(
                u for u in all_urls
                if "/api/" in u or "/rest/" in u or "/graphql" in u
            )
            vuln_bundle = await self.vuln_tester.test_all(
                forms=all_forms, urls=all_urls, page_html=html,
                target_url=target_url,
                discovered_paths=disco_paths,
                shared_headers=initial_headers,
                interstate_flows=interstate_flows,
                verbose=verbose,
            )
            if isinstance(vuln_bundle, dict):
                raw_findings.extend(vuln_bundle.get("findings") or [])
                forms_exercised = vuln_bundle.get("forms_exercised") or []
            else:
                raw_findings.extend(vuln_bundle or [])
                forms_exercised = getattr(
                    self.vuln_tester, "last_forms_exercised", None
                ) or []
        except Exception as e:
            logger.error(f"Vuln testing failed: {e}")
            forms_exercised = []

        per_form = list(forms_exercised or [])
        with_findings = sum(1 for r in per_form if r.get("outcome") == "finding")
        forms_testing = {
            "discovered": len(all_forms or []),
            "tested": len(per_form) if per_form else min(len(all_forms or []), 10),
            "with_findings": with_findings,
            "errored": 0,
            "per_form": per_form,
        }

        if verbose:
            c = sum(1 for f in raw_findings if f.get("status") == "Confirmed")
            p = sum(1 for f in raw_findings if f.get("status") == "Potential")
            print(f"  {c} confirmed, {p} potential\n")


        await _keep_session()
        if verbose:
            print(" Attack Verification...")
        verified_findings: List[Dict] = []
        cors_mode = None

        def _cors_mode_from_finding(f: Dict) -> Optional[str]:
            if "CORS" not in (f.get("type") or "") or f.get("status") != "Confirmed":
                return None
            ev = f.get("evidence") or {}
            headers = ev.get("response_headers") or {}
            if not isinstance(headers, dict):
                headers = {}
            headers_l = {str(k).lower(): str(v or "") for k, v in headers.items()}
            acao = (
                str(ev.get("access_control_allow_origin") or "")
                or headers_l.get("access-control-allow-origin", "")
            ).strip()
            acac = (
                str(ev.get("access_control_allow_credentials") or "")
                or headers_l.get("access-control-allow-credentials", "")
            ).strip().lower()
            creds = acac == "true"
            if not acao:
                return None
            if creds and (acao == "*" or "evil" in acao.lower() or acao.startswith("http")):
                return "credentialed"
            if acao == "*":
                return "wildcard"
            if "evil" in acao.lower() or acao.startswith("http"):
                return "reflected"
            return None

        _CORS_RANK = {"wildcard": 1, "reflected": 2, "credentialed": 3}

        try:
            av_findings = await self.verifier.verify_all(
                target_url=target_url, candidate_urls=all_urls,
                candidate_forms=all_forms, stack=stack,
                vuln_hints=stack.get("vuln_hints", []),
                shared_headers=initial_headers, verbose=verbose,
            )
            for f in av_findings:
                d = f.to_dict() if hasattr(f, "to_dict") else f
                if isinstance(d, dict):
                    d.setdefault("type",     d.pop("vuln_type", "Unknown"))
                    d.setdefault("details",  d.get("description", ""))
                    d.setdefault("poc",      d.get("location", ""))
                    d.setdefault("category", "vulnerability")
                    if "Missing Security Header" in d.get("type", "") or \
                       ("Information Disclosure" in d.get("type", "") and
                        "header" in d.get("type", "").lower()):
                        d["category"] = "security_header"
                        if d.get("severity") in ("Critical", "High"):
                            d["severity"] = "Medium"
                    mode = _cors_mode_from_finding(d)
                    if mode and _CORS_RANK.get(mode, 0) > _CORS_RANK.get(cors_mode or "", 0):
                        cors_mode = mode
                    verified_findings.append(d)
        except Exception as e:
            logger.error(f"Attack verification failed: {e}")

        for f in raw_findings:
            mode = _cors_mode_from_finding(f if isinstance(f, dict) else {})
            if mode and _CORS_RANK.get(mode, 0) > _CORS_RANK.get(cors_mode or "", 0):
                cors_mode = mode

        stride_threats = []
        if all_forms or all_params or cors_mode or initial_headers:
            stride_threats = _build_evidence_gated_stride(
                target_url, initial_headers, all_params,
                all_forms, cors_mode, stack,
                headers_capture_failed=headers_capture_failed,
            )

        seen:         set        = set()
        all_findings: List[Dict] = []

        has_clickjacking = any(
            "Clickjacking" in f.get("type", "") and f.get("status") == "Confirmed"
            for f in verified_findings
        )

        for f in raw_findings + verified_findings:
            ftype    = f.get("type", "")
            location = f.get("location", "").rstrip("/")
            if has_clickjacking and "X-Frame-Options" in ftype and "Missing Security Header" in ftype:
                continue
            key = (ftype.lower(), location)
            if key not in seen:
                seen.add(key)
                all_findings.append(f)

        if ai_vuln_results:
            for f in ai_vuln_results.get("confirmed_ai_vulns", []):
                f.setdefault("category", "ai_vulnerability")
                key = (f.get("type", "").lower(), f.get("location", ""))
                if key not in seen:
                    seen.add(key)
                    all_findings.append(f)
            for f in ai_vuln_results.get("potential_ai_vulns", []):
                f.setdefault("category", "ai_vulnerability")
                key = (f.get("type", "").lower(), f.get("location", ""))
                if key not in seen:
                    seen.add(key)
                    all_findings.append(f)

        if verbose:
            print(" Action Agent (PoC + fix generation)...")
        action_results: List[Dict] = []
        try:
            from .action_agent import ActionAgent
            action_results = ActionAgent().process_all(
                findings=all_findings, target_url=target_url,
                stack=stack, verbose=verbose,
                response_headers=initial_headers,
            )
        except Exception as e:
            logger.warning(f"Action agent failed: {e}")

        duration = (datetime.now() - start).total_seconds()

        if verbose:
            print(f"\n{'='*70}")
            print(f"Scan complete in {duration:.1f}s")
            print(f"  Confirmed   : {sum(1 for f in all_findings if f.get('status')=='Confirmed')}")
            print(f"  Potential   : {sum(1 for f in all_findings if f.get('status')=='Potential')}")
            print(f"  CVEs (NVD)  : {len(verified_cves) if verified_cves is not None else 'lookup failed'}")
            print(f"  STRIDE      : {len(stride_threats)}")
            print(f"  Action items: {len(action_results)}")
            if is_ai_powered:
                print(f"  AI Powered  : YES — AI backdoor analysis included")
                print(f"  AVID CVEs   : {(avid_results or {}).get('total_found',0)}")
                print(f"  Infra threats: {len(ai_infra_result.threats) if ai_infra_result else 0}")
            print(f"{'='*70}\n")

        report_endpoints = []
        not_assessed_endpoints: List[Dict] = []
        try:
            from .endpoint_discovery_agent import is_static_asset as _is_static
        except Exception:
            def _is_static(url="", content_type=""):
                return False
        for ep in discovered_endpoints:
            if ep.get("static_asset") or _is_static(
                ep.get("url", ""), ep.get("content_type", "")
            ):
                continue
            if ep.get("spa_catch_all") or ep.get("excluded"):
                report_endpoints.append(dict(ep, interesting=False))
                continue
            if ep.get("access_controlled") or ep.get("auth_required") or ep.get(
                "redirects_to_auth"
            ):
                report_ep = dict(ep)
                report_ep["category"] = "discovered_protected"
                report_ep["note"] = (
                    f"HTTP {ep.get('status')} — path exists but is access-controlled. "
                    "Recon only, not an exposure."
                )
                report_endpoints.append(report_ep)
                not_assessed_endpoints.append({
                    "url": ep.get("url") or "",
                    "reason": "auth_required",
                    "status": ep.get("status"),
                    "assessment": "not_assessed",
                })
            elif ep.get("interesting"):
                report_endpoints.append(ep)

        for f in skipped_password_forms:
            not_assessed_endpoints.append({
                "url": f.get("action") or "",
                "reason": "password_form_skipped_while_authenticated",
                "status": None,
                "assessment": "not_assessed",
            })

        assessed_count = sum(
            1 for ep in report_endpoints
            if ep.get("interesting")
            and not ep.get("static_asset")
            and ep.get("category") != "discovered_protected"
            and not ep.get("auth_required")
            and not ep.get("redirects_to_auth")
            and not ep.get("access_controlled")
        )
        auth_gated_count = sum(
            1 for e in not_assessed_endpoints if e.get("reason") == "auth_required"
        )
        auth_wall_dominated = auth_gated_count > 0 and (
            auth_gated_count >= max(assessed_count, 1) or assessed_count <= 1
        )
        discovered_ep_count = len(discovered_endpoints or [])
        coverage_pct = (
            round(100.0 * assessed_count / discovered_ep_count, 1)
            if discovered_ep_count else 0.0
        )
        scan_scope = "authenticated" if authed else "blackbox_unauth"
        surface = "authenticated" if authed else "pre-authentication"
        coverage_assessment = {
            "scope": scan_scope,
            "assessed_count": assessed_count,
            "auth_gated_count": auth_gated_count,
            "auth_wall_dominated": auth_wall_dominated,
            "discovered_count": discovered_ep_count,
            "coverage_percent": coverage_pct,
            "note": (
                f"Assessed surface limited to {surface} endpoints; "
                f"{auth_gated_count} functional surface(s) were access-controlled "
                f"for this session and not tested."
                if auth_gated_count > 0 else
                f"Full discovered {surface} surface assessed."
            ),
        }

        ai_fp = ai_fingerprint or {}
        ml_eps = list(ai_fp.get("ml_endpoints") or [])
        auth_req = ai_fp.get("auth_required_paths") or []
        auth_urls = {
            (a.get("endpoint") if isinstance(a, dict) else str(a))
            for a in auth_req
        }
        ai_unauth = [e for e in ml_eps if e not in auth_urls]
        classified = ai_fp.get("classified_endpoints") or []
        if not ml_eps and classified:
            ai_surfaces_discovered = len(classified)
            ai_surfaces_unauth = sum(
                1 for e in classified
                if isinstance(e, dict) and not e.get("auth_required")
            )
        else:
            ai_surfaces_discovered = len(ml_eps)
            ai_surfaces_unauth = len(ai_unauth)
        ai_vr = ai_vuln_results or {}
        eval_metrics = {
            "ai_surfaces_discovered": ai_surfaces_discovered,
            "ai_surfaces_unauthenticated": ai_surfaces_unauth,
            "prompt_injection_attempted": int(
                ai_vr.get("prompt_injection_attempts")
                or ai_vr.get("requests_sent")
                or 0
            ),
            "prompt_injection_confirmed": int(
                ai_vr.get("prompt_injection_confirmed")
                or len(ai_vr.get("confirmed_ai_vulns") or [])
            ),
            "prompt_injection_potential": int(
                ai_vr.get("prompt_injection_potential")
                or len(ai_vr.get("potential_ai_vulns") or [])
            ),
            "endpoint_coverage_percent": coverage_pct,
            "forms_discovered": len(all_forms or []),
            "forms_tested": int((forms_testing or {}).get("tested") or 0),
            "has_live_surface": bool(ai_fp.get("has_live_surface")),
            "ai_brand_only": bool(brand_only_ai),
        }
        from .interstate_tracker import class_coverage_metrics
        nav_summary = (nav_graph or {}).get("summary") or {}
        inter_summary = (interstate or {}).get("summary") or {}
        eval_metrics.update(class_coverage_metrics(
            all_findings,
            forms_exercised,
            nav_summary,
            inter_summary,
        ))

        clickjacking_type = next(
            (
                f.get("type") for f in all_findings
                if "Clickjacking" in (f.get("type") or "")
                and f.get("status") == "Confirmed"
            ),
            None,
        )
        if clickjacking_type:
            for t in stride_threats:
                if t.get("threat") == "Clickjacking" and t.get("confirmed"):
                    t["evidence"] = (
                        f"See Section 3: {clickjacking_type} "
                        "(X-Frame-Options and CSP frame-ancestors absent)"
                    )

        return {
            "target_url":             target_url,
            "stack":                  stack,
            "app_name":               stack.get("app_identity_name", ""),
            "app_version":            stack.get("app_identity_version", ""),
            "verified_cves":          verified_cves,
            "nvd_section_visible":    not is_ai_powered,
            "endpoints_discovered":   report_endpoints,
            "not_assessed_endpoints": not_assessed_endpoints,
            "coverage_assessment":    coverage_assessment,
            "eval_metrics":           eval_metrics,
            "nav_graph":              nav_graph,
            "paper_coverage":         paper_coverage,
            "interstate":             interstate,
            "vulnerabilities":        all_findings,
            "stride_threats":         stride_threats,
            "confirmed_count":        sum(1 for f in all_findings if f.get("status") == "Confirmed"),
            "potential_count":        sum(1 for f in all_findings if f.get("status") == "Potential"),
            "tasks_generated":        len(tasks),
            "tasks_executed":         tasks_executed,
            "forms_discovered":       len(all_forms),
            "forms_testing":          forms_testing,
            "discovered_urls":        list(all_urls),
            "discovered_forms":       [
                {
                    "action": f.get("action", "") if isinstance(f, dict) else "",
                    "method": (f.get("method", "get") if isinstance(f, dict) else "get"),
                    "fields": [
                        i.get("name", "") for i in (
                            (f.get("fields") or f.get("inputs") or [])
                            if isinstance(f, dict) else [])
                        if isinstance(i, dict) and i.get("name")
                    ],
                }
                for f in (all_forms or [])
            ],
            "urls_discovered":        len(all_urls),
            "scan_duration":          round(duration, 1),
            "scan_scope":             scan_scope,
            "auth":                   session.summary() if session else {"enabled": False},
            "ai_scan_authenticated":  bool(ai_auth_headers),
            "timestamp":              datetime.now().isoformat(),
            "is_ai_powered":          is_ai_powered or brand_only_ai or route_confirmed_only_ai,
            "ai_brand_only":          brand_only_ai,
            "ai_route_confirmed_only": route_confirmed_only_ai,
            "ai_surface_status": (
                "live" if is_ai_powered else
                "route_confirmed" if route_confirmed_only_ai else
                "brand_only" if brand_only_ai else
                "none"
            ),
            "has_live_surface":       bool(
                (ai_fingerprint or {}).get("has_live_surface")
            ) if ai_fingerprint else False,
            "ai_fingerprint":         ai_fingerprint,
            "avid_findings":          (avid_results or {}).get("avid_findings", []),
            "avid_backdoor_relevant": (avid_results or {}).get("backdoor_relevant", []),
            "strategic_recommendations": (ai_vuln_results or {}).get("strategic_recommendations", []),
            "ai_infrastructure": (
                self.ai_infra_agent.format_for_stride_report(ai_infra_result)
                if ai_infra_result else None
            ),
            "action_results": action_results,
            "headers_capture_failed": headers_capture_failed,
        }

    async def _get_real_headers(self, url: str, verbose: bool = False) -> tuple:
        """Fetch the target's response headers once, to be shared as ground"""
        loop = asyncio.get_event_loop()
        headers, error = await loop.run_in_executor(
            None, lambda: self._sync_headers(url)
        )
        if not headers:
            logger.warning(
                "Header capture failed for %s — downstream header-based "
                "findings will be marked evidence-incomplete. Cause: %s",
                url, error or "empty response",
            )
            if verbose:
                print(f"   ⚠ Header capture failed for {url}: {error or 'empty response'}")
            return {}, True
        return headers, False

    def _sync_headers(self, url: str) -> tuple:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0 (SecurityScanner)"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return {k.lower(): v for k, v in resp.headers.items()}, None
        except urllib.error.HTTPError as e:
            if e.headers:
                return {k.lower(): v for k, v in e.headers.items()}, None
            return {}, f"HTTPError {e.code} with no headers"
        except Exception as e:
            return {}, f"{type(e).__name__}: {e}"

async def _scan_spa_routes(base_url: str, verbose: bool = False):
    if _spa_scanner_instance is None:
        return [], []
    try:
        result = await _spa_scanner_instance.scan(base_url, verbose=verbose)
        return result.get("forms", []), result.get("urls", [])
    except Exception as e:
        logger.warning(f"SPA scan failed: {e}")
        return [], []

def _resolve_docker_url(url: str, verbose: bool = False) -> str:
    import socket, os
    if "localhost" not in url and "127.0.0.1" not in url:
        return url
    in_docker = os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")
    if not in_docker:
        return url
    try:
        host_ip    = socket.gethostbyname("host.docker.internal")
        translated = url.replace("localhost", host_ip).replace("127.0.0.1", host_ip)
        if verbose:
            print(f"  Docker: localhost → {host_ip}")
        return translated
    except socket.gaierror:
        pass
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if parts[1] == "00000000":
                    gw = ".".join(str(b) for b in bytes.fromhex(parts[2])[::-1])
                    if gw and gw != "0.0.0.0":
                        translated = url.replace("localhost", gw).replace("127.0.0.1", gw)
                        if verbose:
                            print(f"  Docker: localhost → gateway {gw}")
                        return translated
    except Exception:
        pass
    for candidate in ["172.17.0.1", "172.18.0.1", "10.0.0.1"]:
        try:
            test = url.replace("localhost", candidate).replace("127.0.0.1", candidate)
            req  = urllib.request.Request(test, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status < 500:
                    if verbose:
                        print(f"  Docker: localhost → {candidate}")
                    return test
        except Exception:
            continue
    return url

def _normalise_url(url: str) -> str:
    try:
        p = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse((
            p.scheme.lower(), p.netloc.lower(),
            p.path.rstrip("/") or "/",
            p.params, p.query, "",
        ))
    except Exception:
        return url.rstrip("/")

def _dedup_urls(urls: List[str]) -> List[str]:
    seen, result = set(), []
    for url in urls:
        norm = _normalise_url(url)
        if norm not in seen:
            seen.add(norm)
            result.append(url)
    return result

def _dedup_forms(forms: List[Dict]) -> List[Dict]:
    seen, result = set(), []
    for form in forms:
        if not isinstance(form, dict):
            continue
        action = form.get("action", "")
        key = action if isinstance(action, str) and action else str(form)
        if key not in seen:
            seen.add(key)
            result.append(form)
            continue
        incoming = form.get("reach_trace") or []
        for i, kept in enumerate(result):
            kept_action = kept.get("action", "")
            kept_key = kept_action if isinstance(kept_action, str) and kept_action else str(kept)
            if kept_key != key:
                continue
            if len(incoming) > len(kept.get("reach_trace") or []):
                result[i] = form
            break
    return result
