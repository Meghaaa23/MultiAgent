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

from .fingerprint_agent         import TechFingerprintAgent
from .pipeline_agent            import CVEVerificationPipeline
from .endpoint_discovery_agent  import EndpointDiscoveryAgent
from .browser_controller        import BrowserController
from .vulnerability_tester      import VulnerabilityTester
from .attack_verification_agent import AttackVerificationAgent, VulnStatus
from ..ai_agents.ai_fingerprint            import AIFingerprintAgent
from ..ai_agents.avid_lookup_agent         import AVIDLookupAgent
from ..ai_agents.ai_vulnerability_test     import AIVulnerabilityTester
from ..ai_agents.Ai_Infra_agent            import AIInfraAgent

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
                                  cors_misconfigured, stack,
                                  headers_capture_failed: bool = False) -> List[Dict]:
    threats = []
    hdrs    = {k.lower(): v for k, v in response_headers.items()}
    xfo     = hdrs.get("x-frame-options", "")
    csp     = hdrs.get("content-security-policy", "")

    if not headers_capture_failed and not xfo and "frame-ancestors" not in csp.lower():
        threats.append({
            "category":   "Spoofing",
            "threat":     "Clickjacking",
            "evidence":   "X-Frame-Options and CSP frame-ancestors absent",
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

    if cors_misconfigured:
        threats.append({
            "category":   "Information Disclosure",
            "threat":     "CORS Misconfiguration",
            "evidence":   "ACAO reflects attacker-controlled origin (confirmed)",
            "likelihood": "High",
            "impact":     "High",
            "mitigation": "Restrict ACAO to trusted origins; remove wildcard",
            "confirmed":  True,
        })

    def _inputs(form):
        return form.get("inputs") or form.get("fields") or []

    if any(
        any(i.get("type", "").lower() == "password" for i in _inputs(f) if isinstance(i, dict))
        for f in discovered_forms
    ):
        threats.append({
            "category":   "Elevation of Privilege",
            "threat":     "SQL Injection via Login Form",
            "evidence":   "Login form with password field discovered — not actively tested (black-box)",
            "likelihood": "Low",
            "impact":     "Critical",
            "mitigation": "Use parameterised queries; never interpolate user input into SQL statements",
            "confirmed":  False,
        })

    if any(
        any(i.get("type", "text").lower() in ("text", "search", "textarea", "url")
            for i in _inputs(f) if isinstance(i, dict))
        for f in discovered_forms
    ):
        threats.append({
            "category":   "Tampering",
            "threat":     "Cross-Site Scripting (XSS)",
            "evidence":   "Text/textarea input field(s) discovered in crawl",
            "likelihood": "Medium",
            "impact":     "High",
            "mitigation": "Apply output encoding; implement strict CSP",
            "confirmed":  False,
        })

    return threats


class WebScannerAgent:

    def __init__(self, openai_client, llm_model: str):
        self.openai_client = openai_client
        self.llm_model     = llm_model

        self.fingerprinter  = TechFingerprintAgent(openai_client, llm_model)
        self.cve_pipeline   = CVEVerificationPipeline(nvd_api_key=os.environ.get("NVD_API_KEY", ""))
        self.endpoint_disco = EndpointDiscoveryAgent(timeout=5, max_probe_paths=30)
        self.browser        = BrowserController(openai_client, llm_model)
        self.vuln_tester    = VulnerabilityTester(timeout=10)
        self.verifier       = AttackVerificationAgent(openai_client, llm_model)

        self.ai_fingerprinter = AIFingerprintAgent(timeout=8)
        self.avid_lookup      = AVIDLookupAgent(timeout=15)
        self.ai_vuln_tester   = AIVulnerabilityTester(
            timeout=10,
            llm_model=self.llm_model,
            openai_client=self.openai_client,
        )
        self.ai_infra_agent   = AIInfraAgent(openai_client=self.openai_client, llm_model=self.llm_model)

        print(" WebScannerAgent initialized ")

    async def scan_application(self, target_url: str,
                               max_time_minutes: int = 10,
                               verbose: bool = False,
                               auth_cookie: str = "") -> Dict:
        start = datetime.now()

        if "#" in target_url:
            target_url = target_url.split("#")[0].rstrip("/")

        target_url = _resolve_docker_url(target_url, verbose=verbose)
        self.vuln_tester.auth_cookie = auth_cookie or ""

        if verbose:
            print(f"\n{'='*70}")
            print(f"Evidence Based Web Application Scan + AI Backdoor Detection")
            if auth_cookie:
                print(f"  Auth   : Session cookie provided (authenticated scan)")
            print(f"  Target : {target_url}")
            print(f"  Budget : {max_time_minutes} minutes")
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
            initial_headers, headers_capture_failed = await self._get_real_headers(target_url, verbose=verbose)
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
                    existing = stack.get("technologies", [])
                    if existing and isinstance(existing[0], dict):
                        stack["app_identity_name"]    = app_identity.name
                        stack["app_identity_version"] = app_identity.version or ""
                        stack["app_identity"]         = app_identity
                        current_summary = stack.get("stack_summary", "")
                        app_str = app_identity.name
                        if app_identity.version:
                            app_str += f" {app_identity.version}"
                        if app_str.lower() not in current_summary.lower():
                            stack["stack_summary"] = (
                                f"{app_str} · {current_summary}"
                                if current_summary and current_summary != "Unknown"
                                else app_str
                            )
                    else:
                        ver_str    = f" {app_identity.version}" if app_identity.version else ""
                        name_entry = f"{app_identity.name}{ver_str}"
                        merged     = [name_entry] + app_identity.technologies + existing
                        seen_t: set = set()
                        deduped_t   = []
                        for t in merged:
                            tkey = t.get("name", str(t)).lower() if isinstance(t, dict) else str(t).lower()
                            if tkey not in seen_t:
                                seen_t.add(tkey)
                                deduped_t.append(t)
                        stack["technologies"] = deduped_t
                        stack["app_identity"] = app_identity
                        if "Unknown" in stack.get("stack_summary", ""):
                            stack["stack_summary"] = app_identity.name
                    if verbose:
                        print(f"   App identity: {app_identity.name!r} v{app_identity.version or '?'} [{app_identity.confidence}]\n")
            except Exception as e:
                logger.debug(f"App identity failed: {e}")

        verified_cves = None

      
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
        except Exception as e:
            logger.warning(f"Endpoint discovery failed: {e}")

        if verbose:
            interesting = sum(1 for e in discovered_endpoints if e.get("interesting"))
            protected   = sum(1 for e in discovered_endpoints if e.get("access_controlled"))
            soft_mode   = getattr(self.endpoint_disco, "_soft_mode", False)
            print(f"   {len(discovered_endpoints)} endpoints "
                  f"({interesting} interesting, {protected} access-controlled)"
                  + (" [soft-404 filter active]" if soft_mode else "") + "\n")

      
        if verbose:
            print("AI/ML Component Detection...")

        ai_fingerprint  = None
        avid_results    = None
        ai_vuln_results = None
        is_ai_powered   = False

        try:
            ai_fingerprint = await self.ai_fingerprinter.fingerprint(
                target_url           = target_url,
                discovered_endpoints = discovered_endpoints,
                page_html            = html,
                response_headers     = initial_headers,
                verbose              = verbose,
            )

            raw_is_ai    = ai_fingerprint.get("is_ai_powered", False)
            confidence   = ai_fingerprint.get("confidence", "low")
            has_concrete = bool(ai_fingerprint.get("ml_endpoints") or ai_fingerprint.get("ai_headers"))
            is_ai_powered = raw_is_ai and (confidence == "high" or has_concrete)

            if is_ai_powered:
                if verbose:
                    print(f"  AI-powered app detected [{confidence} confidence]")
                    print(f"     ML endpoints: {ai_fingerprint.get('ml_endpoints',[])[:3]}")
                    print(f"     ML libraries: {ai_fingerprint.get('ml_libraries',[])[:3]}\n")

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
                ai_vuln_results = await self.ai_vuln_tester.test_all(
                    ai_fingerprint=ai_fingerprint, target_url=target_url, verbose=verbose,
                )
                if verbose:
                    c = len(ai_vuln_results.get("confirmed_ai_vulns", []))
                    p = len(ai_vuln_results.get("potential_ai_vulns", []))
                    s = len(ai_vuln_results.get("strategic_recommendations", []))
                    print(f"   AI vulns: {c} confirmed, {p} potential")
                    print(f"   Strategic recommendations: {s} ATLAS-based\n")
            else:
                if verbose:
                    if raw_is_ai and not has_concrete:
                        print(f"  Weak AI signals (confidence: {confidence}) — skipping AI escalation\n")
                    else:
                        print(f"  No AI/ML components detected — AI-specific tests skipped\n")

        except Exception as e:
            logger.warning(f"AI detection failed: {e}")

        ai_infra_result = None
        try:
            if ai_fingerprint and ai_fingerprint.get("is_ai_powered"):
                if verbose:
                    print("  AI Infrastructure Build Attack Analysis...")
                ai_infra_result = await self.ai_infra_agent.scan(
                    target_url=target_url, ai_stack=ai_fingerprint,
                )
                if verbose:
                    print(f"   AI Infra threats: {len(ai_infra_result.threats)} total\n")
        except Exception as e:
            logging.warning(f"AIInfraAgent failed: {e}")

        if verbose:
            print(" CVE Lookup ")
        try:
            app_name    = stack.get("app_identity_name", "")
            app_version = stack.get("app_identity_version", "")

            if not app_name and app_identity and app_identity.name:
                app_name    = app_identity.name
                app_version = app_identity.version or ""

            if is_ai_powered and app_name:
                cve_queries = []
                if app_version:
                    cve_queries.append(f"{app_name} {app_version}")
                cve_queries.append(app_name)
                ml_libs = (ai_fingerprint or {}).get("ml_libraries", [])
                for lib in ml_libs[:2]:
                    if lib and lib not in cve_queries:
                        cve_queries.append(lib)
                cve_stack = {
                    "technologies":  cve_queries,
                    "stack_summary": app_name,
                    "app_name":      app_name,
                    "app_version":   app_version,
                }
                verified_cves = await self.cve_pipeline.lookup(cve_stack, verbose=verbose)
                

            elif not is_ai_powered:
                
                cve_stack = {
                    "technologies": stack.get("technologies", []),
                    "stack_summary": stack.get("stack_summary", ""),
                    "server": stack.get("server"),
                    "framework": stack.get("framework"),
                    "cms": stack.get("cms"),
                    "language": stack.get("language"),
                }
                print("\n===== STACK SENT TO CVE LOOKUP =====")
                pprint(cve_stack)
                print("====================================")
                verified_cves = await self.cve_pipeline.lookup(cve_stack, verbose=verbose)
                verified_cves = verified_cves or []
                
                print("\n===== TECHNOLOGIES =====")
                pprint(stack["technologies"])
                print("========================")
                print("\n========== VERIFIED CVES ==========")
                
                pprint(verified_cves)
                print("===================================\n")

            else:
                verified_cves = []

        except Exception as e:
            logger.warning(f"CVE lookup error: {e}")

        if verbose:
            cve_count = len(verified_cves) if verified_cves is not None else "lookup failed"
            print(f"   Verified CVEs: {cve_count}\n")

        if verbose:
            print("Browser Crawl...")

        filtered = [e for e in elements if e.get("type") in ("form", "link")]
        tasks    = await self.browser.generate_tasks(
            elements=filtered, page_description="",
            openai_client=self.openai_client, llm_model=self.llm_model,
            target_url=target_url,
        )

        tasks_executed = 0
        for idx, task in enumerate(tasks[:8], 1):
            elapsed = (datetime.now() - start).total_seconds() / 60
            if elapsed > max_time_minutes * 0.40:
                if verbose:
                    print(f"  Crawl budget reached ({elapsed:.1f}m)")
                break
            result = await self.browser.execute_task(task, target_url)
            all_forms.extend(result.get("forms", []))
            all_urls.extend(result.get("urls", []))
            tasks_executed += 1

        all_urls  = _dedup_urls(all_urls)[:30]
        all_forms = _dedup_forms(all_forms)[:15]

        all_params: Set[str] = set()
        for url in all_urls:
            all_params.update(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).keys())

        if verbose:
            print(f"   {tasks_executed}/{len(tasks)} tasks | {len(all_forms)} forms | {len(all_urls)} URLs\n")

   
        if verbose:
            print("SPA Scanning...")
        try:
            spa_forms, spa_urls = await _scan_spa_routes(target_url, verbose=verbose)
            if spa_forms or spa_urls:
                all_forms.extend(spa_forms)
                all_urls.extend(spa_urls)
                all_urls  = _dedup_urls(all_urls)[:50]
                all_forms = _dedup_forms(all_forms)[:20]
                if verbose:
                    print(f"   SPA: {len(spa_forms)} forms, {len(spa_urls)} URLs\n")
            elif verbose:
                print("  Not an SPA or Playwright unavailable\n")
        except Exception as e:
            logger.warning(f"SPA scanning failed: {e}")

       
        if verbose:
            print("Vulnerability Testing...")
        raw_findings: List[Dict] = []
        try:
            raw_findings = await self.vuln_tester.test_all(
                forms=all_forms, urls=all_urls, page_html=html,
                target_url=target_url,
                discovered_paths=[
                    ep.get("url", "") for ep in discovered_endpoints
                    if ep.get("interesting")
                ],
                shared_headers=initial_headers,
                verbose=verbose,
            )
        except Exception as e:
            logger.error(f"Vuln testing failed: {e}")

        if verbose:
            c = sum(1 for f in raw_findings if f.get("status") == "Confirmed")
            p = sum(1 for f in raw_findings if f.get("status") == "Potential")
            print(f"  {c} confirmed, {p} potential\n")

     
        if verbose:
            print(" Attack Verification...")
        verified_findings: List[Dict] = []
        cors_misconfigured = False
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
                    if "CORS" in d.get("type", "") and d.get("status") == "Confirmed":
                        cors_misconfigured = True
                    verified_findings.append(d)
        except Exception as e:
            logger.error(f"Attack verification failed: {e}")

        stride_threats = []
        if all_forms or all_params or cors_misconfigured or initial_headers:
            stride_threats = _build_evidence_gated_stride(
                target_url, initial_headers, all_params,
                all_forms, cors_misconfigured, stack,
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
        for ep in discovered_endpoints:
            if ep.get("access_controlled"):
          
                report_ep = dict(ep)
                report_ep["category"]   = "discovered_protected"
                report_ep["note"]       = (
                    f"HTTP {ep.get('status')} — path exists but is access-controlled. "
                    "Recon only, not an exposure."
                )
                report_endpoints.append(report_ep)
            elif ep.get("interesting"):
                report_endpoints.append(ep)

        return {
            "target_url":             target_url,
            "stack":                  stack,
            "app_name":               stack.get("app_identity_name", ""),
            "app_version":            stack.get("app_identity_version", ""),
            "verified_cves":          verified_cves,
            "nvd_section_visible":    not is_ai_powered,
            "endpoints_discovered":   report_endpoints,
            "vulnerabilities":        all_findings,
            "stride_threats":         stride_threats,
            "confirmed_count":        sum(1 for f in all_findings if f.get("status") == "Confirmed"),
            "potential_count":        sum(1 for f in all_findings if f.get("status") == "Potential"),
            "tasks_generated":        len(tasks),
            "tasks_executed":         tasks_executed,
            "forms_discovered":       len(all_forms),
            "urls_discovered":        len(all_urls),
            "scan_duration":          round(duration, 1),
            "authenticated_scan":     bool(auth_cookie),
            "timestamp":              datetime.now().isoformat(),
            "is_ai_powered":          is_ai_powered,
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
        """
        Fetch the target's response headers once, to be shared as ground
        truth across the AI fingerprinter, STRIDE builder, and Action Agent.

        Returns (headers_dict, capture_failed_bool). A failure is logged
        (not swallowed) so a downstream "no evidence captured" placeholder
        can be traced back to its actual cause instead of looking like a
        mystery three call-layers later.
        """
        loop = asyncio.get_event_loop()
        headers, error = await loop.run_in_executor(None, lambda: self._sync_headers(url))
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
            # An HTTP error still carries real headers (e.g. a 403 from a WAF) —
            # this is captured evidence, not a failure.
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
        key = form.get("action", "") or str(form)
        if key not in seen:
            seen.add(key)
            result.append(form)
    return result