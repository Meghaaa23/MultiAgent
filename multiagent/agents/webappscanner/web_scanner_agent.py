# agents/webappscanner/web_scanner_agent.py


import asyncio
import logging
import json
import re
import urllib.request
import urllib.parse
from typing import Dict, List, Optional, Set
from datetime import datetime

from .fingerprint_agent          import TechFingerprintAgent
from .pipeline_agent             import CVEVerificationPipeline
from .endpoint_discovery_agent   import EndpointDiscoveryAgent
from .browser_controller         import BrowserController
from .vulnerability_tester       import VulnerabilityTester
from .attack_verification_agent  import AttackVerificationAgent, VulnStatus

# AI backdoor detection agents
from .ai_fingerprint import AIFingerprintAgent
from .avid_lookup_agent import AVIDLookupAgent
from .ai_vulnerability_test import AIVulnerabilityTester

logger = logging.getLogger(__name__)

# App identity detector
try:
    from .app_identity import detect_app_identity, AppIdentity
    _HAS_APP_IDENTITY = True
except Exception as _e:
    logger.warning(f"app_identity import failed: {_e}")
    _HAS_APP_IDENTITY = False

# SPA scanner
try:
    from .spa_scanner import SPAScanner as _SPAScanner
    _spa_scanner_instance = _SPAScanner(timeout_ms=15000, max_routes=12)
except Exception as _e:
    logger.warning(f"SPAScanner import failed: {_e}")
    _spa_scanner_instance = None


# ---------------------------------------------------------------------------
# Stack validation (unchanged)
# ---------------------------------------------------------------------------

_HEADER_VERIFIABLE_TECH = {
    "apache":    ["server"], "nginx":     ["server"], "iis":    ["server"],
    "lighttpd":  ["server"], "caddy":     ["server"], "gunicorn":["server"],
    "php":       ["x-powered-by", "set-cookie"],
    "java":      ["x-powered-by"],
    "spring boot": ["x-application-context", "x-powered-by"],
    ".net":      ["x-aspnet-version", "x-powered-by"],
    "ruby":      ["x-powered-by", "x-runtime"],
    "rails":     ["x-powered-by", "x-runtime", "x-request-id"],
    "node.js":   ["x-powered-by"], "express": ["x-powered-by"],
    "python":    ["x-powered-by"],
    "cloudflare":["cf-ray", "cf-cache-status"],
    "cloudfront":["x-amz-cf-id", "via"],
}

_BODY_VERIFIABLE_TECH = {
    "wordpress": [r"wp-content", r"wp-json", r"wordpress"],
    "drupal":    [r"drupal", r"sites/default/files"],
    "joomla":    [r"joomla", r"/components/com_"],
    "django":    [r"csrfmiddlewaretoken", r"django"],
    "rails":     [r"authenticity_token", r"rails"],
    "php":       [r"PHPSESSID", r"\.php"],
    "angular":   [r"ng-version", r"app-root", r"router-outlet",
                  r"_nghost", r"\[formcontrolname\]"],
    "react":     [r"React\.createElement", r"__reactFiber",
                  r"data-reactroot", r"_reactRootContainer"],
    "vue":       [r"__vue_app__", r"data-v-app", r"createApp\("],
    "next.js":   [r"__NEXT_DATA__", r"_next/static"],
    "nuxt":      [r"__NUXT__", r"_nuxt/"],
}


def _validate_stack(stack: Dict, response_headers: Dict, body: str) -> Dict:
    if not stack:
        return {"stack_summary": "Unknown", "technologies": [], 
                "unverified_hints": [], "vuln_hints": []}
    
    if stack.get("stack_summary", "Unknown") == "Unknown":
        return stack

    raw_tech = stack.get("technologies", [])
    tech_strings = [
        t.get("name", t) if isinstance(t, dict) else str(t)
        for t in (raw_tech if isinstance(raw_tech, list) else [])
    ]

    headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}
    body_lower    = (body or "").lower()
    confirmed, unverified, evidence_map = [], [], {}

    for tech in tech_strings:
        tl = tech.lower()
        confirmed_by_header = any(
            hk in headers_lower and tl in headers_lower[hk]
            for hk in _HEADER_VERIFIABLE_TECH.get(tl, [])
        )
        if confirmed_by_header:
            confirmed.append(tech)
            evidence_map[tech] = "header"
            continue

        if any(re.search(p, body_lower, re.IGNORECASE)
               for p in _BODY_VERIFIABLE_TECH.get(tl, [])):
            confirmed.append(tech)
            evidence_map[tech] = "body_pattern"
            continue

        if tl in headers_lower.get("server", "") or \
           tl in headers_lower.get("x-powered-by", ""):
            confirmed.append(tech)
            evidence_map[tech] = "header:server/x-powered-by"
            continue

        unverified.append(tech)

    if confirmed:
        seen_lower = set()
        confirmed_deduped = []
        for t in confirmed:
            if t.lower() not in seen_lower:
                seen_lower.add(t.lower())
                confirmed_deduped.append(t)
        stack["technologies"]     = confirmed_deduped
        stack["unverified_hints"] = unverified
        stack["confirmed_by"]     = evidence_map
    else:
        noise_words = {"content", "signals", "unknown", "none", "null", "true", "false"}
        filtered_unverified = [
            t for t in unverified
            if t and len(t.strip()) > 3
            and t.strip().lower() not in noise_words
            and not t.strip().lower().startswith("content signal")
        ]

        server  = response_headers.get("server", "") or response_headers.get("Server", "")
        powered = response_headers.get("x-powered-by", "") or response_headers.get("X-Powered-By", "")
        cdn_hints = []
        if server and "cloudflare" in server.lower():
            cdn_hints.append("Cloudflare")
        if server and server.strip():
            cdn_hints.append(server.strip())
        if powered and powered.strip():
            cdn_hints.append(powered.strip())

        final_techs = cdn_hints or filtered_unverified
        seen_lower = set()
        final_techs_deduped = []
        for t in final_techs:
            if t.lower() not in seen_lower:
                seen_lower.add(t.lower())
                final_techs_deduped.append(t)
        final_techs = final_techs_deduped

        stack["technologies"]     = final_techs
        stack["unverified_hints"] = []
        stack["confirmed_by"]     = {}
        if final_techs:
            stack["stack_summary"] = " · ".join(final_techs[:3])
        else:
            stack["stack_summary"] = "Unknown (no technology confirmed from HTTP evidence)"


# ---------------------------------------------------------------------------
# Evidence-gated STRIDE (unchanged)
# ---------------------------------------------------------------------------

def _build_evidence_gated_stride(target_url, response_headers,
                                  discovered_params, discovered_forms,
                                  cors_misconfigured, stack) -> List[Dict]:
    threats = []
    hdrs    = {k.lower(): v for k, v in response_headers.items()}
    xfo     = hdrs.get("x-frame-options", "")
    csp     = hdrs.get("content-security-policy", "")

    if not xfo and "frame-ancestors" not in csp.lower():
        threats.append({
            "category":   "Spoofing", "threat": "Clickjacking",
            "evidence":   "X-Frame-Options and CSP frame-ancestors absent",
            "likelihood": "Medium", "impact": "Medium",
            "mitigation": "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'",
            "confirmed":  True,
        })

    redirect_kws    = {"redirect", "url", "next", "return", "goto", "dest", "to"}
    redirect_params = [p for p in discovered_params
                       if any(k in p.lower() for k in redirect_kws)]
    if redirect_params:
        threats.append({
            "category":   "Tampering", "threat": "Open Redirect",
            "evidence":   f"Redirect params in crawl: {redirect_params}",
            "likelihood": "Medium", "impact": "Medium",
            "mitigation": "Validate redirects against allowlist",
            "confirmed":  False,
        })

    if cors_misconfigured:
        threats.append({
            "category":   "Information Disclosure", "threat": "CORS Misconfiguration",
            "evidence":   "ACAO reflects attacker-controlled origin (confirmed)",
            "likelihood": "High", "impact": "High",
            "mitigation": "Restrict ACAO to trusted origins; remove wildcard",
            "confirmed":  True,
        })

    def _inputs(form):
        return form.get("inputs") or form.get("fields") or []

    if any(
        any(i.get("type", "").lower() == "password"
            for i in _inputs(f) if isinstance(i, dict))
        for f in discovered_forms
    ):
        threats.append({
            "category":   "Elevation of Privilege",
            "threat":     "SQL Injection via Login Form",
            "evidence":   "Login form with password field discovered — "
                          "not actively tested (black-box)",
            "likelihood": "Low", "impact": "Critical",
            "mitigation": "Use parameterised queries; never interpolate user "
                          "input into SQL statements",
            "confirmed":  False,
        })

    if any(
        any(i.get("type", "text").lower() in
            # email/password excluded: email has browser validation,
            # password is hashed server-side — neither is an XSS surface
            ("text", "search", "textarea", "url")
            for i in _inputs(f) if isinstance(i, dict))
        for f in discovered_forms
    ):
        threats.append({
            "category":   "Tampering", "threat": "Cross-Site Scripting (XSS)",
            "evidence":   "Text/textarea input field(s) discovered in crawl",
            "likelihood": "Medium", "impact": "High",
            "mitigation": "Apply output encoding; implement strict CSP",
            "confirmed":  False,
        })

    return threats


# ---------------------------------------------------------------------------
# Main scanner class
# ---------------------------------------------------------------------------

class WebScannerAgent:

    def __init__(self, openai_client, llm_model: str):
        self.openai_client = openai_client
        self.llm_model     = llm_model

        # Existing agents
        self.fingerprinter  = TechFingerprintAgent(openai_client, llm_model)
        self.cve_pipeline   = CVEVerificationPipeline()
        self.endpoint_disco = EndpointDiscoveryAgent(timeout=5, max_probe_paths=30)
        self.browser        = BrowserController(openai_client, llm_model)
        self.vuln_tester    = VulnerabilityTester(timeout=10)
        self.verifier       = AttackVerificationAgent(openai_client, llm_model)

        # AI backdoor detection agents
        self.ai_fingerprinter = AIFingerprintAgent(timeout=8)
        self.avid_lookup      = AVIDLookupAgent(timeout=15)
        self.ai_vuln_tester   = AIVulnerabilityTester(timeout=10)

        print("✓ WebScannerAgent initialized (v6 — AI Backdoor Detection)")

    async def scan_application(self, target_url: str,
                               max_time_minutes: int = 10,
                               verbose: bool = False,
                               auth_cookie: str = "") -> Dict:
        start = datetime.now()

        # Strip fragment
        if "#" in target_url:
            target_url = target_url.split("#")[0].rstrip("/")

        # Docker translation
        target_url = _resolve_docker_url(target_url, verbose=verbose)

        # Inject auth cookie for authenticated scanning
        self.vuln_tester.auth_cookie = auth_cookie or ""

        if verbose:
            print(f"\n{'='*70}")
            print(f"Evidence-Based Web Application Scan + AI Backdoor Detection")
            if auth_cookie:
                print(f"  Auth   : Session cookie provided (authenticated scan)")
            print(f"  Target : {target_url}")
            print(f"  Budget : {max_time_minutes} minutes")
            print(f"{'='*70}\n")

        all_forms:  List[Dict] = []
        all_urls:   List[str]  = [target_url]
        html                    = ""
        stack:      Dict        = {}
        elements:   List[Dict]  = []
        initial_headers: Dict   = {}

        # ── Phase 0: Technology Fingerprinting ────────────────────────
        if verbose:
            print("Phase 0: Technology Fingerprinting...")
        try:
            page            = await self.browser.capture_page(target_url)
            html            = page.get("html", "")
            elements        = page.get("elements", [])
            initial_headers = await self._get_real_headers(target_url)
            stack           = await self.fingerprinter.fingerprint(
                target_url=target_url, page_html=html, verbose=verbose
            )
            stack = _validate_stack(stack, initial_headers, html) or {
                "stack_summary": "Unknown",
                "technologies": [],
                "unverified_hints": [],
                "vuln_hints": [],
            }
        except Exception as e:
            logger.warning(f"Fingerprinting failed: {e}")
            stack = {"stack_summary": "Unknown", "vuln_hints": []}

        if verbose:
            print(f"  ✓ Stack: {stack.get('stack_summary','Unknown')}\n")

        # ── Phase 0b: App Identity Detection ──────────────────────────
        app_identity = None
        if _HAS_APP_IDENTITY:
            try:
                app_identity = await detect_app_identity(
                    base_url=target_url, html=html or "",
                    response_headers=initial_headers, verbose=verbose,
                )
                if app_identity and app_identity.name:
                    ver_str    = f" {app_identity.version}" if app_identity.version else ""
                    name_entry = f"{app_identity.name}{ver_str}"
                    existing   = stack.get("technologies", [])
                    # Full case-insensitive dedup — prevents duplicates when
                    # signals loop + Phase 0b both add the same framework name
                    merged = [name_entry] + app_identity.technologies + existing
                    seen_t: set = set()
                    deduped_t   = []
                    for t in merged:
                        if t.lower() not in seen_t:
                            seen_t.add(t.lower())
                            deduped_t.append(t)
                    stack["technologies"] = deduped_t
                    stack["app_identity"] = app_identity
                    if "Unknown" in stack.get("stack_summary", ""):
                        stack["stack_summary"] = app_identity.name
                    if verbose:
                        print(f"  ✓ App identity: {app_identity.name!r} "
                              f"v{app_identity.version or '?'} "
                              f"[{app_identity.confidence}]\n")
            except Exception as e:
                logger.debug(f"App identity failed: {e}")

        # ── Phase 1: CVE Lookup —
        verified_cves = []

        # ── Phase 2a: Endpoint Discovery ──────────────────────────────
        if verbose:
            print("Phase 2a: Endpoint Discovery...")
        discovered_endpoints: List[Dict] = []
        try:
            discovered_endpoints = await self.endpoint_disco.discover(
                target_url=target_url, page_html=html, verbose=verbose
            )
            for ep in discovered_endpoints:
                if ep.get("url") and ep.get("interesting") and \
                        ep.get("method") == "GET":
                    all_urls.append(ep["url"])
        except Exception as e:
            logger.warning(f"Endpoint discovery failed: {e}")

        if verbose:
            interesting = sum(1 for e in discovered_endpoints if e.get("interesting"))
            print(f"  ✓ {len(discovered_endpoints)} endpoints ({interesting} interesting)\n")

        # ── Phase 0c: AI/ML Component Detection ───────────────────────
        if verbose:
            print("Phase 0c: AI/ML Component Detection...")

        ai_fingerprint   = None
        avid_results     = None
        ai_vuln_results  = None
        is_ai_powered    = False

        try:
            ai_fingerprint = await self.ai_fingerprinter.fingerprint(
                target_url           = target_url,
                discovered_endpoints = discovered_endpoints,
                page_html            = html,
                response_headers     = initial_headers,
                verbose              = verbose,
            )

          
            # ─────────────────────────────────────────────────────────

            raw_is_ai  = ai_fingerprint.get("is_ai_powered", False)
            confidence = ai_fingerprint.get("confidence", "low")
            has_concrete = bool(
                ai_fingerprint.get("ml_endpoints") or
                ai_fingerprint.get("ai_headers")
            )

            is_ai_powered = raw_is_ai and (confidence == "high" or has_concrete)

            if is_ai_powered:
                if verbose:
                    print(f"  🤖 AI-powered app detected "
                          f"[{confidence} confidence]")
                    print(f"     ML endpoints: {ai_fingerprint.get('ml_endpoints',[])[:3]}")
                    print(f"     ML libraries: {ai_fingerprint.get('ml_libraries',[])[:3]}")
                    print()

                # Query AVID for AI-specific CVEs
                if verbose:
                    print("  Querying AVID database for AI vulnerabilities...")
                ml_stack = (
                    ai_fingerprint.get("ml_libraries", []) +
                    [ep.split("/")[-1] for ep in
                     ai_fingerprint.get("ml_endpoints", [])[:3]]
                )
                avid_results = await self.avid_lookup.lookup(
                    ai_fingerprint=ai_fingerprint,
                    ml_stack=ml_stack,
                    verbose=verbose,
                )
                if verbose:
                    print(f"  ✓ AVID: {avid_results.get('total_found',0)} findings "
                          f"({len(avid_results.get('backdoor_relevant',[]))} backdoor-relevant)")
                    print()

                # Run AI-specific vulnerability tests
                if verbose:
                    print("  Running AI-specific vulnerability tests...")
                ai_vuln_results = await self.ai_vuln_tester.test_all(
                    ai_fingerprint=ai_fingerprint,
                    target_url=target_url,
                    verbose=verbose,
                )
                if verbose:
                    c = len(ai_vuln_results.get("confirmed_ai_vulns", []))
                    p = len(ai_vuln_results.get("potential_ai_vulns", []))
                    s = len(ai_vuln_results.get("strategic_recommendations", []))
                    print(f"  ✓ AI vulns: {c} confirmed, {p} potential")
                    print(f"  ✓ Strategic recommendations: {s} ATLAS-based\n")

            else:
                if verbose:
                    if raw_is_ai and not has_concrete:
                        print(f"  ℹ Weak AI signals detected (confidence: {confidence}) "
                              f"— insufficient for AI vuln escalation\n"
                              f"    Requires ml_endpoint or ai_header confirmation\n")
                    else:
                        print(f"  ℹ No AI/ML components detected — AI-specific tests skipped\n")

        except Exception as e:
            logger.warning(f"AI detection failed: {e}")

        # ── Phase 1b: CVE Lookup (NVD/OSV) ───────────────────────────
   
            print("Phase 1b: CVE Lookup (NVD/OSV)...")
        try:
            if is_ai_powered:
                
                ai_cve_queries = []

                # 1. Named platform from app_identity (highest specificity)
                if app_identity and app_identity.name:
                    if app_identity.version:
                        ai_cve_queries.append(
                            f"{app_identity.name} {app_identity.version}"
                        )
                    ai_cve_queries.append(app_identity.name)

                # 2. ML libraries actually detected in source
                ml_libs = (ai_fingerprint or {}).get("ml_libraries", [])
                for lib in ml_libs[:2]:
                    if lib not in ai_cve_queries:
                        ai_cve_queries.append(lib)

                # 3. Infer platform from responding ML endpoint paths
              
                ml_eps = (ai_fingerprint or {}).get("ml_endpoints", [])
                for ep in ml_eps[:3]:
                    path = ep.replace(target_url, "")
                    if "/openai/" in path or "/api/models" in path:
                        if "Open WebUI" not in ai_cve_queries:
                            ai_cve_queries.append("Open WebUI")
                    if "/api/tags" in path or "/api/generate" in path:
                        if "Ollama" not in ai_cve_queries:
                            ai_cve_queries.append("Ollama")
                    if "/api/v1/prediction" in path or "/api/v1/chatflows" in path:
                        if "Flowise" not in ai_cve_queries:
                            ai_cve_queries.append("Flowise")

                if ai_cve_queries:
                    cve_stack = {**stack,
                                 "technologies": ai_cve_queries,
                                 "stack_summary": ai_cve_queries[0]}
                    verified_cves = await self.cve_pipeline.lookup(
                        cve_stack, verbose=verbose
                    )

            else:
                # Non-AI app — full NVD/OSV stack lookup shown in Section 2
                if app_identity and app_identity.cve_queries:
                    cve_stack = {**stack,
                                 "technologies": app_identity.cve_queries,
                                 "stack_summary": app_identity.name or ""}
                    verified_cves = await self.cve_pipeline.lookup(
                        cve_stack, verbose=verbose
                    )
                elif stack.get("technologies"):
                    verified_cves = await self.cve_pipeline.lookup(
                        stack, verbose=verbose
                    )

        except Exception as e:
            logger.warning(f"CVE lookup error: {e}")
        if verbose:
            print(f"  ✓ Verified CVEs: {len(verified_cves)}\n")

        # ── Phase 2b: Browser Crawl ────────────────────────────────────
        if verbose:
            print("Phase 2b: Browser Crawl...")

        filtered = [e for e in elements if e.get("type") in ("form", "link")]
        tasks    = await self.browser.generate_tasks(
            elements=filtered, page_description="",
            openai_client=self.openai_client,
            llm_model=self.llm_model, target_url=target_url,
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
            all_params.update(urllib.parse.parse_qs(
                urllib.parse.urlparse(url).query
            ).keys())

        if verbose:
            print(f"  ✓ {tasks_executed}/{len(tasks)} tasks | "
                  f"{len(all_forms)} forms | {len(all_urls)} URLs\n")

        # ── Phase 2c: SPA Scanning ─────────────────────────────────────
        if verbose:
            print("Phase 2c: SPA Scanning...")
        try:
            spa_forms, spa_urls = await _scan_spa_routes(target_url, verbose=verbose)
            if spa_forms or spa_urls:
                all_forms.extend(spa_forms)
                all_urls.extend(spa_urls)
                all_urls  = _dedup_urls(all_urls)[:50]
                all_forms = _dedup_forms(all_forms)[:20]
                if verbose:
                    print(f"  ✓ SPA: {len(spa_forms)} forms, {len(spa_urls)} URLs\n")
            elif verbose:
                print("  ℹ Not an SPA or Playwright unavailable\n")
        except Exception as e:
            logger.warning(f"SPA scanning failed: {e}")

        # ── Phase 3: Vulnerability Testing ────────────────────────────
        if verbose:
            print("Phase 3: Vulnerability Testing...")
        raw_findings: List[Dict] = []
        try:
            raw_findings = await self.vuln_tester.test_all(
                forms=all_forms, urls=all_urls, page_html=html,
                target_url=target_url,
                discovered_paths=[
                    ep.get("url", "") for ep in discovered_endpoints
                    if ep.get("interesting")
                ],
                verbose=verbose,
            )
        except Exception as e:
            logger.error(f"Vuln testing failed: {e}")

        if verbose:
            c = sum(1 for f in raw_findings if f.get("status") == "Confirmed")
            p = sum(1 for f in raw_findings if f.get("status") == "Potential")
            print(f"  ✓ {c} confirmed, {p} potential\n")

        # ── Phase 4: Attack Verification ──────────────────────────────
        if verbose:
            print("Phase 4: Attack Verification...")
        verified_findings: List[Dict] = []
        cors_misconfigured = False
        try:
            av_findings = await self.verifier.verify_all(
                target_url=target_url, candidate_urls=all_urls,
                candidate_forms=all_forms, stack=stack,
                vuln_hints=stack.get("vuln_hints", []), verbose=verbose,
            )
            for f in av_findings:
                d = f.to_dict() if hasattr(f, "to_dict") else f
                if isinstance(d, dict):
                    d.setdefault("type",    d.pop("vuln_type", "Unknown"))
                    d.setdefault("details", d.get("description", ""))
                    d.setdefault("poc",     d.get("location", ""))
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

        # ── Phase 4b: STRIDE ──────────────────────────────────────────
        stride_threats = []
        if all_forms or all_params or cors_misconfigured or initial_headers:
            stride_threats = _build_evidence_gated_stride(
                target_url, initial_headers, all_params,
                all_forms, cors_misconfigured, stack,
            )

        # ── Merge all findings ────────────────────────────────────────
        seen:         set        = set()
        all_findings: List[Dict] = []

        for f in raw_findings + verified_findings:
            key = (f.get("type", ""), f.get("location", ""))
            if key not in seen:
                seen.add(key)
                all_findings.append(f)

        # Merge AI vulnerability findings
        if ai_vuln_results:
            for f in ai_vuln_results.get("confirmed_ai_vulns", []):
                f.setdefault("category", "ai_vulnerability")
                key = (f.get("type", ""), f.get("location", ""))
                if key not in seen:
                    seen.add(key)
                    all_findings.append(f)
            for f in ai_vuln_results.get("potential_ai_vulns", []):
                f.setdefault("category", "ai_vulnerability")
                key = (f.get("type", ""), f.get("location", ""))
                if key not in seen:
                    seen.add(key)
                    all_findings.append(f)

        # ── Phase 4c: Action Agent ────────────────────────────────────
        
        if verbose:
            print("Phase 4c: Action Agent (PoC + fix generation)...")
        action_results: List[Dict] = []
        try:
            from .action_agent import ActionAgent
            action_results = ActionAgent().process_all(
                findings   = all_findings,
                target_url = target_url,
                stack      = stack,
                verbose    = verbose,
            )
        except Exception as e:
            logger.warning(f"Action agent failed: {e}")

        duration = (datetime.now() - start).total_seconds()

        if verbose:
            print(f"\n{'='*70}")
            print(f"Scan complete in {duration:.1f}s")
            print(f"  Confirmed   : {sum(1 for f in all_findings if f.get('status')=='Confirmed')}")
            print(f"  Potential   : {sum(1 for f in all_findings if f.get('status')=='Potential')}")
            print(f"  CVEs (NVD)  : {len(verified_cves)}")
            print(f"  STRIDE      : {len(stride_threats)}")
            print(f"  Action items: {len(action_results)}")
            if is_ai_powered:
                print(f"  AI Powered  : YES — AI backdoor analysis included")
                print(f"  AVID CVEs   : {(avid_results or {}).get('total_found',0)}")
                print(f"  Strategic   : {len((ai_vuln_results or {}).get('strategic_recommendations',[]))}")
            print(f"{'='*70}\n")

        return {
            "target_url":            target_url,
            "stack":                 stack,
            
            "verified_cves":         verified_cves,
            "nvd_section_visible":   not is_ai_powered,  
            "endpoints_discovered":  discovered_endpoints,
            "vulnerabilities":       all_findings,
            "stride_threats":        stride_threats,
            "confirmed_count":       sum(1 for f in all_findings if f.get("status") == "Confirmed"),
            "potential_count":       sum(1 for f in all_findings if f.get("status") == "Potential"),
            "tasks_generated":       len(tasks),
            "tasks_executed":        tasks_executed,
            "forms_discovered":      len(all_forms),
            "urls_discovered":       len(all_urls),
            "scan_duration":         round(duration, 1),
            "authenticated_scan":    bool(auth_cookie),
            "timestamp":             datetime.now().isoformat(),
            # AI backdoor fields
            "is_ai_powered":         is_ai_powered,
            "ai_fingerprint":        ai_fingerprint,
            "avid_findings":         (avid_results or {}).get("avid_findings", []),
            "avid_backdoor_relevant":(avid_results or {}).get("backdoor_relevant", []),
            "strategic_recommendations": (ai_vuln_results or {}).get(
                "strategic_recommendations", []
            ),
            
            "action_results":            action_results,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _get_real_headers(self, url: str) -> Dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self._sync_headers(url))

    def _sync_headers(self, url: str) -> Dict:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0 (SecurityScanner)"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return {k.lower(): v for k, v in resp.headers.items()}
        except urllib.request.HTTPError as e:
            return {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        except Exception:
            return {}


# ---------------------------------------------------------------------------
# SPA scanner wrapper
# ---------------------------------------------------------------------------

async def _scan_spa_routes(base_url: str, verbose: bool = False):
    if _spa_scanner_instance is None:
        return [], []
    try:
        result = await _spa_scanner_instance.scan(base_url, verbose=verbose)
        return result.get("forms", []), result.get("urls", [])
    except Exception as e:
        logger.warning(f"SPA scan failed: {e}")
        return [], []


# ---------------------------------------------------------------------------
# Docker network translation
# ---------------------------------------------------------------------------

def _resolve_docker_url(url: str, verbose: bool = False) -> str:
    import socket, os
    if "localhost" not in url and "127.0.0.1" not in url:
        return url
    in_docker = os.path.exists("/.dockerenv") or \
                os.path.exists("/run/.containerenv")
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


# ---------------------------------------------------------------------------
# Deduplication helpers
# ---------------------------------------------------------------------------

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