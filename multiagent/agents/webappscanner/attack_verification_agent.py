# agents/attack_verification_agent.py
"""
AttackVerificationAgent
=======================
Implements the 3-agent verification loop:

  Agent 1 → detect possible vulnerability (from scanner)
  Agent 2 → attempt exploit with real HTTP request
  Agent 3 → verify result → confirmed | potential | false_positive

FIX CHANGELOG
=============
Fix 1 — HTTP Response Gate (_check_sensitive_paths)
Fix 2 — Clickjacking evidence-gated
Fix 3 — CORS check correct
Fix 4 — LLM enrichment guarded
Fix 5 — Removed "email" from XSS-testable input types in _check_forms.
         email inputs have browser-level format validation and are not
         XSS surfaces. Also removed number/tel/date/time/color/range.
"""

import re
import json
import logging
import asyncio
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class VulnStatus(str, Enum):
    CONFIRMED  = "Confirmed"
    POTENTIAL  = "Potential"
    DOWNGRADED = "Downgraded"


class Confidence(str, Enum):
    HIGH   = "High"
    MEDIUM = "Medium"
    LOW    = "Low"


@dataclass
class Evidence:
    request:              str  = ""
    response_status:      int  = 0
    response_body_snippet:str  = ""
    response_headers:     Dict = field(default_factory=dict)
    payload_reflected:    bool = False
    execution_confirmed:  bool = False
    verified:             bool = False
    confidence:           str  = Confidence.LOW

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Finding:
    vuln_type:   str
    severity:    str
    status:      str       = VulnStatus.POTENTIAL
    location:    str       = ""
    parameter:   str       = ""
    payload:     str       = ""
    description: str       = ""
    impact:      str       = ""
    remediation: str       = ""
    confidence:  str       = Confidence.LOW
    evidence:    Evidence  = field(default_factory=Evidence)
    cwe:         str       = ""
    owasp:       str       = ""

    def to_dict(self) -> Dict:
        d = asdict(self)
        return d


# ---------------------------------------------------------------------------
# Payloads library
# ---------------------------------------------------------------------------

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    'javascript:alert(1)',
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR "1"="1',
    "1' AND SLEEP(2)--",
    "1; DROP TABLE users--",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/wp-config.php",
    "/config.php",
    "/phpinfo.php",
    "/server-status",
    "/actuator",
    "/actuator/env",
    "/api/swagger.json",
    "/api/openapi.json",
    "/admin",
    "/admin/",
    "/.htaccess",
    "/web.config",
    "/backup.zip",
    "/backup.sql",
    "/dump.sql",
]

# ---------------------------------------------------------------------------
# FIX 5: Input types that are NOT XSS surfaces
# These have browser-level validation or format constraints that prevent
# arbitrary HTML/JS injection from being meaningful.
# ---------------------------------------------------------------------------

_NON_XSS_INPUT_TYPES = frozenset({
    "hidden", "submit", "button", "checkbox", "radio",
    "file", "password",
    "email",            # browser validates email format, rejects HTML
    "number",           # numeric only
    "range",            # numeric slider
    "tel",              # telephone format
    "date",             # date picker
    "time",             # time picker
    "datetime-local",   # date+time picker
    "month",            # month picker
    "week",             # week picker
    "color",            # color picker
    "image",            # image submit button
})

# ---------------------------------------------------------------------------
# HTTP status → finding mapping for sensitive paths
# ---------------------------------------------------------------------------

_SENSITIVE_PATH_STATUS_MAP = {
    200: {"status": VulnStatus.CONFIRMED, "severity_cap": None,  "should_report": True},
    403: {"status": VulnStatus.POTENTIAL, "severity_cap": "Low", "should_report": True},
    301: {"status": VulnStatus.POTENTIAL, "severity_cap": "Info","should_report": True},
    302: {"status": VulnStatus.POTENTIAL, "severity_cap": "Info","should_report": True},
}

_SEVERITY_ORDER = ["Info", "Low", "Medium", "High", "Critical"]

def _cap_severity(severity: str, cap: Optional[str]) -> str:
    if cap is None:
        return severity
    try:
        if _SEVERITY_ORDER.index(severity) > _SEVERITY_ORDER.index(cap):
            return cap
    except ValueError:
        pass
    return cap


SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]


class AttackVerificationAgent:

    def __init__(self, openai_client, llm_model: str, timeout: int = 10):
        self.openai_client = openai_client
        self.llm_model     = llm_model
        self.timeout       = timeout

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def verify_all(self, target_url: str,
                         candidate_urls: List[str],
                         candidate_forms: List[Dict],
                         stack: Dict,
                         vuln_hints: List[str] = None,
                         verbose: bool = False) -> List[Finding]:
        if verbose:
            print(f"\n Attack Verification Agent")
            print(f"   Target: {target_url}")
            print(f"   URLs: {len(candidate_urls)} | Forms: {len(candidate_forms)}")

        findings: List[Finding] = []

        tasks = [
            self._check_security_headers(target_url, verbose),
            self._check_urls_for_params(target_url, candidate_urls, verbose),
            self._check_forms(candidate_forms, verbose),
            self._check_cors(target_url, verbose),
            self._check_clickjacking(target_url, verbose),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, Finding):
                findings.append(r)

        if findings:
            findings = await self._llm_enrich_findings(
                target_url, findings, stack, verbose
            )

        # ------------------------------------------------------------------
        # Deduplication: suppress redundant findings.
        #
        # Rule 1 — X-Frame-Options vs Clickjacking:
        #   Both describe the same framing issue. Keep Clickjacking (higher severity,
        #   confirmed via iframe test) and drop the header finding.
        #
        # Rule 2 — CWE-based dedup:
        #   If two findings share the same CWE and location, keep the higher severity.
        # ------------------------------------------------------------------
        has_clickjacking = any(
            "Clickjacking" in f.vuln_type and f.status == VulnStatus.CONFIRMED
            for f in findings
        )
        if has_clickjacking:
            findings = [
                f for f in findings
                if not (
                    "X-Frame-Options" in f.vuln_type and
                    "Missing Security Header" in f.vuln_type
                )
            ]

        # CWE-based dedup — keep highest severity per (cwe, location) pair
        severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
        seen_cwe: dict = {}
        deduped: List[Finding] = []
        for f in findings:
            key = (f.cwe, f.location)
            existing = seen_cwe.get(key)
            if existing is None:
                seen_cwe[key] = f
                deduped.append(f)
            else:
                if severity_rank.get(f.severity, 0) > severity_rank.get(existing.severity, 0):
                    deduped = [x for x in deduped if x is not existing]
                    deduped.append(f)
                    seen_cwe[key] = f
        findings = deduped

        # Downgrade confidence when the evidence has no valid HTTP response
        # (response_status == 0 means the check never got a real reply).
        for f in findings:
            if f.evidence.response_status == 0 and f.confidence != Confidence.LOW:
                f.confidence          = Confidence.LOW
                f.evidence.confidence = Confidence.LOW

        confirmed = [f for f in findings if f.status == VulnStatus.CONFIRMED]
        potential = [f for f in findings if f.status == VulnStatus.POTENTIAL]

        if verbose:
            print(f"   ✓ Confirmed: {len(confirmed)} | Potential: {len(potential)}")

        return findings

    # ------------------------------------------------------------------
    # Check 1: Security Headers
    # ------------------------------------------------------------------

    async def _check_security_headers(self, url: str,
                                      verbose: bool = False) -> List[Finding]:
        findings = []
        try:
            headers = await self._get_headers(url)
            if not headers:
                return findings

            missing = [h for h in SECURITY_HEADERS if h not in headers]

            for h in missing:
                findings.append(Finding(
                    vuln_type   = f"Missing Security Header: {h}",
                    severity    = "Low" if h not in (
                        "Content-Security-Policy", "Strict-Transport-Security"
                    ) else "Medium",
                    status      = VulnStatus.CONFIRMED,
                    location    = url,
                    description = f"The response is missing the {h} header.",
                    impact      = self._header_impact(h),
                    remediation = f"Add the {h} header to all HTTP responses.",
                    confidence  = Confidence.HIGH,
                    evidence    = Evidence(
                        request          = f"GET {url}",
                        response_status  = 200,
                        response_headers = dict(headers),
                        verified         = True,
                        confidence       = Confidence.HIGH
                    ),
                    cwe   = "CWE-693",
                    owasp = "A05:2021"
                ))

            for key, val in headers.items():
                if key.lower() in ("server", "x-powered-by", "x-aspnet-version"):
                    has_version = bool(re.search(r'\d+\.\d+', val))
                    findings.append(Finding(
                        vuln_type   = f"Information Disclosure: {key} header",
                        severity    = "Low",
                        status      = VulnStatus.CONFIRMED,
                        location    = url,
                        description = f"Server exposes technology info: {key}: {val}"
                                      + (" (version number exposed)" if has_version else ""),
                        impact      = "Attackers can fingerprint the stack and target known CVEs.",
                        remediation = f"Remove or obscure the {key} header.",
                        confidence  = Confidence.HIGH if has_version else Confidence.MEDIUM,
                        evidence    = Evidence(
                            request          = f"GET {url}",
                            response_status  = 200,
                            response_headers = {key: val},
                            verified         = True,
                            confidence       = Confidence.HIGH
                        ),
                        cwe   = "CWE-200",
                        owasp = "A01:2021"
                    ))

        except Exception as e:
            logger.warning(f"Header check failed: {e}")

        return findings

    def _header_impact(self, header: str) -> str:
        impacts = {
            "X-Frame-Options":          "Enables clickjacking attacks.",
            "X-Content-Type-Options":   "Allows MIME-type sniffing attacks.",
            "Content-Security-Policy":  "Increases XSS attack surface.",
            "Strict-Transport-Security":"Enables SSL stripping attacks.",
            "X-XSS-Protection":         "Disables browser XSS filter (legacy browsers).",
            "Referrer-Policy":          "Leaks URL information to third parties.",
            "Permissions-Policy":       "Allows unrestricted access to browser features.",
        }
        return impacts.get(header, "Reduces browser security protections.")

    # ------------------------------------------------------------------
    # Check 2: Sensitive Paths
    # ------------------------------------------------------------------

    async def _check_sensitive_paths(self, base_url: str,
                                     verbose: bool = False) -> List[Finding]:
        findings = []
        base = base_url.rstrip("/")

        async def check_path(path: str):
            url = base + path
            try:
                status, headers, body = await self._get_full_response(url)

                mapping = _SENSITIVE_PATH_STATUS_MAP.get(status)
                if mapping is None or not mapping["should_report"]:
                    return

                vuln_status  = mapping["status"]
                severity_cap = mapping["severity_cap"]

                base_severity = (
                    "Critical" if path in ("/.env", "/.git/config", "/wp-config.php") else
                    "High"     if path in ("/backup.zip", "/backup.sql", "/dump.sql") else
                    "Medium"
                )

                sensitive_patterns = [
                    r"DB_PASSWORD|DB_HOST|DB_USER",
                    r"\[core\]|repositoryformatversion",
                    r"define\('DB_",
                    r"password\s*=",
                    r"secret_key\s*=",
                ]
                has_sensitive = status == 200 and any(
                    re.search(p, body or "", re.IGNORECASE)
                    for p in sensitive_patterns
                )

                if has_sensitive:
                    final_severity = "Critical"
                    confidence     = Confidence.HIGH
                else:
                    final_severity = _cap_severity(base_severity, severity_cap)
                    confidence = (
                        Confidence.HIGH   if status == 200 else
                        Confidence.MEDIUM if status == 403 else
                        Confidence.LOW
                    )

                if status == 200 and has_sensitive:
                    desc = (f"Sensitive path {path} returned HTTP 200 "
                            f"and response contains sensitive data.")
                elif status == 200:
                    desc = (f"Sensitive path {path} returned HTTP 200. "
                            f"File is accessible — manual review recommended.")
                elif status == 403:
                    desc = (f"Sensitive path {path} returned HTTP 403 (Forbidden). "
                            f"Path exists but access is blocked. Severity downgraded to Low.")
                else:
                    desc = (f"Sensitive path {path} returned HTTP {status} (redirect). "
                            f"Path may exist — follow redirect to confirm.")

                findings.append(Finding(
                    vuln_type   = f"Sensitive File Exposed: {path}",
                    severity    = final_severity,
                    status      = vuln_status,
                    location    = url,
                    description = desc,
                    impact      = ("Potential exposure of credentials, source code, or config."
                                   if status == 200 else
                                   "Path exists but is currently access-controlled."),
                    remediation = f"Block access to {path} or remove the file.",
                    confidence  = confidence,
                    evidence    = Evidence(
                        request              = f"GET {url}",
                        response_status      = status,
                        response_body_snippet= (body or "")[:300] if status == 200 else
                                              f"HTTP {status}",
                        response_headers     = headers,
                        verified             = (status == 200),
                        confidence           = confidence
                    ),
                    cwe   = "CWE-538",
                    owasp = "A01:2021"
                ))

            except Exception as e:
                logger.debug(f"Path check failed for {path}: {e}")

        tasks = [check_path(p) for p in SENSITIVE_PATHS]
        await asyncio.gather(*tasks, return_exceptions=True)

        if verbose:
            confirmed = sum(1 for f in findings if f.status == VulnStatus.CONFIRMED)
            potential = sum(1 for f in findings if f.status == VulnStatus.POTENTIAL)
            print(f"   Sensitive paths: {confirmed} confirmed, {potential} potential")

        return findings

    # ------------------------------------------------------------------
    # Check 3: URL parameter injection
    # ------------------------------------------------------------------

    async def _check_urls_for_params(self, base_url: str,
                                     urls: List[str],
                                     verbose: bool = False) -> List[Finding]:
        findings = []

        for url in urls:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)

            if not params:
                continue

            for param_name in params:
                xss_finding = await self._test_reflected_xss(url, param_name, parsed)
                if xss_finding:
                    findings.append(xss_finding)

                if any(kw in param_name.lower() for kw in
                       ("redirect", "url", "next", "return", "goto", "dest")):
                    redir_finding = await self._test_open_redirect(url, param_name, parsed)
                    if redir_finding:
                        findings.append(redir_finding)

        return findings

    async def _test_reflected_xss(self, url: str, param: str,
                                   parsed) -> Optional[Finding]:
        for payload in XSS_PAYLOADS[:3]:
            try:
                test_url = self._inject_param(parsed, param, payload)
                status, headers, body = await self._get_full_response(test_url)

                if body and payload in body:
                    return Finding(
                        vuln_type   = "Reflected XSS",
                        severity    = "High",
                        status      = VulnStatus.CONFIRMED,
                        location    = url,
                        parameter   = param,
                        payload     = payload,
                        description = (f"The '{param}' parameter reflects user input "
                                       f"without sanitization."),
                        impact      = ("Attacker can execute arbitrary JavaScript in the "
                                       "victim's browser."),
                        remediation = ("Apply output encoding to all user-supplied input. "
                                       "Implement a strict Content-Security-Policy."),
                        confidence  = Confidence.HIGH,
                        evidence    = Evidence(
                            request              = f"GET {test_url}",
                            response_status      = status,
                            response_body_snippet= self._extract_context(body, payload),
                            payload_reflected    = True,
                            verified             = True,
                            confidence           = Confidence.HIGH
                        ),
                        cwe   = "CWE-79",
                        owasp = "A03:2021"
                    )
            except Exception:
                continue

        return None

    async def _test_open_redirect(self, url: str, param: str,
                                   parsed) -> Optional[Finding]:
        for payload in OPEN_REDIRECT_PAYLOADS[:2]:
            try:
                test_url = self._inject_param(parsed, param, payload)
                status, headers, body = await self._get_full_response(
                    test_url, follow_redirects=False
                )

                location = headers.get("Location", headers.get("location", ""))

                if status in (301, 302, 303, 307, 308) and (
                    "evil.com" in location or payload in location
                ):
                    return Finding(
                        vuln_type   = "Open Redirect",
                        severity    = "Medium",
                        status      = VulnStatus.CONFIRMED,
                        location    = url,
                        parameter   = param,
                        payload     = payload,
                        description = (f"The '{param}' parameter redirects to "
                                       f"attacker-controlled URL."),
                        impact      = "Phishing attacks via trusted domain redirection.",
                        remediation = ("Validate redirect URLs against an allowlist. "
                                       "Never redirect to user-supplied URLs directly."),
                        confidence  = Confidence.HIGH,
                        evidence    = Evidence(
                            request          = f"GET {test_url}",
                            response_status  = status,
                            response_headers = {"Location": location},
                            payload_reflected= True,
                            verified         = True,
                            confidence       = Confidence.HIGH
                        ),
                        cwe   = "CWE-601",
                        owasp = "A01:2021"
                    )
            except Exception:
                continue

        return None

    # ------------------------------------------------------------------
    # Check 4: Forms — FIX 5 APPLIED HERE
    # ------------------------------------------------------------------

    async def _check_forms(self, forms: List[Dict],
                           verbose: bool = False) -> List[Finding]:
        findings = []

        for form in forms:
            action = form.get("action", "")
            inputs = form.get("inputs", [])

            def _has_csrf(inp):
                name = ""
                if isinstance(inp, dict):
                    name = (inp.get("name", "") or "").lower()
                else:
                    name = str(inp).lower()
                csrf_keywords = ("csrf", "_token", "authenticity_token",
                                 "nonce", "__requestverificationtoken")
                return (name == "token" or
                        any(kw in name for kw in csrf_keywords))

            has_csrf_token = any(_has_csrf(inp) for inp in inputs)

            if not has_csrf_token and form.get("method", "get").lower() == "post":
                findings.append(Finding(
                    vuln_type   = "Missing CSRF Protection",
                    severity    = "Medium",
                    status      = VulnStatus.POTENTIAL,
                    location    = action,
                    description = "POST form does not appear to include a CSRF token.",
                    impact      = "Attacker can forge requests on behalf of authenticated users.",
                    remediation = ("Implement synchronizer token pattern or "
                                   "SameSite cookie attribute."),
                    confidence  = Confidence.MEDIUM,
                    evidence    = Evidence(
                        request         = f"Analyzed form at {action}",
                        response_status = 0,
                        verified        = False,
                        confidence      = Confidence.MEDIUM
                    ),
                    cwe   = "CWE-352",
                    owasp = "A01:2021"
                ))

            for inp in inputs:
                inp_type = str(inp.get("type", "text")).lower() if isinstance(inp, dict) else "text"
                inp_name = str(inp.get("name", "")) if isinstance(inp, dict) else str(inp)

                # FIX 5: Only flag input types that are actual XSS surfaces.
                # Excluded: email (browser format validation), number/range (numeric only),
                # tel/date/time/color (format-constrained), password (not rendered in page),
                # hidden/submit/button/checkbox/radio/file (not text injection vectors).
                if inp_type in _NON_XSS_INPUT_TYPES:
                    continue

                # Only flag text, search, url, textarea — genuine XSS surfaces
                if inp_type in ("text", "search", "url", "textarea"):
                    findings.append(Finding(
                        vuln_type   = "Potential Stored/Reflected XSS (Form Input)",
                        severity    = "High",
                        status      = VulnStatus.POTENTIAL,
                        location    = action,
                        parameter   = inp_name,
                        description = (
                            f"Unvalidated text input '{inp_name}' may be vulnerable to XSS. "
                            "Manual verification required."
                        ),
                        impact      = "XSS if input not properly sanitized server-side.",
                        remediation = "Apply strict input validation and output encoding.",
                        confidence  = Confidence.LOW,
                        evidence    = Evidence(
                            request    = f"Form field '{inp_name}' at {action}",
                            verified   = False,
                            confidence = Confidence.LOW
                        ),
                        cwe   = "CWE-79",
                        owasp = "A03:2021"
                    ))

        return findings

    # ------------------------------------------------------------------
    # Check 5: CORS
    # ------------------------------------------------------------------
    # Multi-stage CORS verification:
    #
    # Stage 1 — Reflection test: does the server reflect an attacker origin?
    # Stage 2 — Credentials check: is Access-Control-Allow-Credentials: true?
    # Stage 3 — Preflight test: does OPTIONS also reflect the evil origin?
    # Stage 4 — API endpoint test: does reflection occur on API paths too?
    #
    # Severity rules (real-world accurate):
    #   HIGH:    reflection + credentials=true (attacker can steal auth'd data)
    #   MEDIUM:  reflection only on API endpoints (no credentials)
    #   LOW:     reflection only on public homepage (no credentials, low impact)
    #   SKIP:    wildcard (*) without credentials on public page (intended CDN pattern)
    #
    # A finding is CONFIRMED only when:
    #   - The server actively reflects the attacker origin (not wildcard)
    #   - OR wildcard + credentials=true (always High)
    #   - AND preflight (OPTIONS) also permits the method
    # ------------------------------------------------------------------

    async def _check_cors(self, url: str,
                          verbose: bool = False) -> List[Finding]:
        findings  = []
        base      = url.rstrip("/")
        evil_orig = "https://evil-cors-probe.attacker-test.example.com"

        # API paths to probe in addition to the base URL
        api_paths = [
            "/api", "/api/v1", "/api/v2",
            "/graphql", "/api/user", "/api/me",
            "/api/data", "/api/config",
        ]

        loop = asyncio.get_event_loop()

        # ------------------------------------------------------------------
        # Helper: single CORS probe
        # ------------------------------------------------------------------
        def _probe(probe_url: str, method: str = "GET") -> Dict:
            """
            Returns dict with acao, acac, acam, acah, status_code.
            """
            try:
                req = urllib.request.Request(
                    probe_url,
                    headers={
                        "Origin":                        evil_orig,
                        "Access-Control-Request-Method": method,
                        "User-Agent":                    "Mozilla/5.0 (SecurityScanner)",
                    },
                    method=method if method == "OPTIONS" else "GET",
                )
                with urllib.request.urlopen(req, timeout=8) as resp:
                    h = {k.lower(): v for k, v in resp.headers.items()}
                    return {
                        "acao":   h.get("access-control-allow-origin",      ""),
                        "acac":   h.get("access-control-allow-credentials",  ""),
                        "acam":   h.get("access-control-allow-methods",      ""),
                        "acah":   h.get("access-control-allow-headers",      ""),
                        "status": resp.status,
                        "url":    probe_url,
                    }
            except urllib.error.HTTPError as e:
                h = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
                return {
                    "acao":   h.get("access-control-allow-origin",      ""),
                    "acac":   h.get("access-control-allow-credentials",  ""),
                    "acam":   h.get("access-control-allow-methods",      ""),
                    "acah":   h.get("access-control-allow-headers",      ""),
                    "status": e.code,
                    "url":    probe_url,
                }
            except Exception:
                return {"acao": "", "acac": "", "acam": "", "acah": "",
                        "status": 0, "url": probe_url}

        def _reflects_evil(acao: str) -> bool:
            """True if the server reflected our exact attacker origin."""
            return bool(acao) and (
                evil_orig in acao or
                acao.strip() == "*"
            )

        def _is_wildcard_only(acao: str) -> bool:
            return acao.strip() == "*"

        def _credentials_true(acac: str) -> bool:
            return acac.strip().lower() == "true"

        try:
            # ── Stage 1: Probe base URL ────────────────────────────────
            base_result = await loop.run_in_executor(
                None, lambda: _probe(base)
            )
            acao = base_result["acao"]
            acac = base_result["acac"]

            if verbose:
                print(f"   CORS base: ACAO={acao!r} ACAC={acac!r}")

            # ── Stage 2: Preflight (OPTIONS) on base URL ───────────────
            preflight_result = await loop.run_in_executor(
                None, lambda: _probe(base, method="OPTIONS")
            )
            preflight_reflects = _reflects_evil(preflight_result["acao"])

            # ── Stage 3: Probe API endpoints ───────────────────────────
            api_probes = await asyncio.gather(
                *[
                    loop.run_in_executor(None, lambda p=path: _probe(base + p))
                    for path in api_paths
                ],
                return_exceptions=True
            )
            # Keep only responses from existing endpoints (not 404)
            api_hits = [
                r for r in api_probes
                if isinstance(r, dict) and r.get("status", 0) not in (0, 404)
                and _reflects_evil(r.get("acao", ""))
            ]

            # ── Stage 4: Classify severity ─────────────────────────────
            #
            # HIGH: reflection + credentials=true anywhere
            # MEDIUM: reflection on API endpoint (no credentials)
            # LOW: reflection on homepage only (no credentials, no API)
            # SKIP: wildcard-only without credentials (standard CDN pattern)

            reflects_base = _reflects_evil(acao)
            creds_true    = _credentials_true(acac)

            # Check if any API endpoint also has credentials=true
            api_creds = any(
                _credentials_true(r.get("acac", ""))
                for r in api_hits
            )

            if not reflects_base and not api_hits:
                # No CORS issue found
                return findings

            if _is_wildcard_only(acao) and not creds_true and not api_hits:
                # Wildcard on public page without credentials — very common CDN
                # pattern, not a meaningful security issue on its own.
                # Only report if preflight also reflects.
                if not preflight_reflects:
                    return findings

            # Determine severity
            if creds_true or api_creds:
                severity    = "High"
                impact      = (
                    "Server reflects attacker-controlled origin AND allows credentials. "
                    "An attacker can make authenticated cross-origin requests from any "
                    "domain, potentially stealing session data, user info, or API tokens."
                )
                status      = VulnStatus.CONFIRMED
                confidence  = Confidence.HIGH
            elif api_hits:
                severity    = "Medium"
                impact      = (
                    f"Server reflects attacker origin on {len(api_hits)} API endpoint(s) "
                    f"({', '.join(r['url'].split(base)[-1] for r in api_hits[:3])}). "
                    "Without credentials, direct data theft requires user interaction "
                    "but enables cross-origin API probing."
                )
                status      = VulnStatus.CONFIRMED
                confidence  = Confidence.HIGH
            elif reflects_base and preflight_reflects:
                severity    = "Medium"
                impact      = (
                    "Server reflects attacker-controlled origin on main page and "
                    "preflight requests. No credential exposure confirmed — "
                    "manual testing of authenticated API endpoints recommended."
                )
                status      = VulnStatus.CONFIRMED
                confidence  = Confidence.MEDIUM
            else:
                # Reflection on homepage only, no preflight confirmation
                severity    = "Low"
                impact      = (
                    "Server reflects attacker-controlled origin on homepage only. "
                    "No API endpoint reflection or credential exposure detected. "
                    "Low exploitability — manual verification recommended."
                )
                status      = VulnStatus.POTENTIAL
                confidence  = Confidence.MEDIUM

            # Build evidence string
            evidence_lines = [f"GET {base} (Origin: {evil_orig})"]
            if api_hits:
                for r in api_hits[:3]:
                    evidence_lines.append(
                        f"GET {r['url']} → ACAO: {r['acao']}"
                        + (f", ACAC: {r['acac']}" if r.get('acac') else "")
                    )
            if preflight_reflects:
                evidence_lines.append(
                    f"OPTIONS {base} → ACAO: {preflight_result['acao']}"
                )

            findings.append(Finding(
                vuln_type   = "CORS Misconfiguration",
                severity    = severity,
                status      = status,
                location    = base,
                description = (
                    f"Server reflects attacker-controlled Origin "
                    f"(ACAO: {acao})"
                    + (f" with credentials=true" if creds_true else "")
                    + (f". Also reflected on {len(api_hits)} API endpoint(s)."
                       if api_hits else ".")
                ),
                impact      = impact,
                remediation = (
                    "Restrict Access-Control-Allow-Origin to an explicit allowlist "
                    "of trusted origins. Never combine wildcard (*) with "
                    "Access-Control-Allow-Credentials: true. "
                    "Validate Origin header server-side against the allowlist."
                ),
                confidence  = confidence,
                evidence    = Evidence(
                    request          = " | ".join(evidence_lines),
                    response_status  = base_result["status"],
                    response_headers = {
                        "Access-Control-Allow-Origin":      acao,
                        "Access-Control-Allow-Credentials": acac,
                        "Access-Control-Allow-Methods":     base_result.get("acam", ""),
                    },
                    verified         = (status == VulnStatus.CONFIRMED),
                    confidence       = confidence,
                    confirmation_method = "header",
                ),
                cwe   = "CWE-942",
                owasp = "A05:2021"
            ))

        except Exception as e:
            logger.debug(f"CORS check failed: {e}")

        return findings

    # ------------------------------------------------------------------
    # Check 6: Clickjacking
    # ------------------------------------------------------------------

    async def _check_clickjacking(self, url: str,
                                  verbose: bool = False) -> Optional[Finding]:
        try:
            headers = await self._get_headers(url)
            if not headers:
                return None

            xfo = headers.get("X-Frame-Options", "")
            csp = headers.get("Content-Security-Policy", "")
            has_frame_ancestors = "frame-ancestors" in csp.lower()

            if not xfo and not has_frame_ancestors:
                # headers is non-empty here, so we got a real HTTP response.
                # response_status must be set explicitly — Evidence defaults to 0
                # which would be misleading and incorrectly downgrade confidence.
                _confidence = Confidence.HIGH
                return Finding(
                    vuln_type   = "Clickjacking",
                    severity    = "Medium",
                    status      = VulnStatus.CONFIRMED,
                    location    = url,
                    description = (
                        "Page can be embedded in an iframe on attacker-controlled sites. "
                        "Confirmed: both X-Frame-Options and CSP frame-ancestors are absent."
                    ),
                    impact      = (
                        "Attacker tricks users into clicking UI elements they cannot see, "
                        "enabling account takeover or unauthorized actions."
                    ),
                    remediation = (
                        "Add X-Frame-Options: DENY or "
                        "Content-Security-Policy: frame-ancestors 'none'."
                    ),
                    confidence  = _confidence,
                    evidence    = Evidence(
                        request          = f"GET {url}",
                        response_status  = 200,
                        response_headers = {
                            "X-Frame-Options":        "(missing)",
                            "Content-Security-Policy": csp or "(missing)"
                        },
                        verified         = True,
                        confidence       = _confidence
                    ),
                    cwe   = "CWE-1021",
                    owasp = "A04:2021"
                )
        except Exception as e:
            logger.debug(f"Clickjacking check failed: {e}")

        return None

    # ------------------------------------------------------------------
    # LLM enrichment
    # ------------------------------------------------------------------

    _RULE_BASED_ENRICHMENTS: Dict[str, Dict[str, str]] = {
        "Missing Security Header: X-Frame-Options": {
            "impact":      "Page can be embedded in an iframe enabling clickjacking attacks.",
            "remediation": "Add 'X-Frame-Options: DENY' or CSP frame-ancestors directive.",
        },
        "Missing Security Header: X-Content-Type-Options": {
            "impact":      "Browser may MIME-sniff responses enabling content-injection attacks.",
            "remediation": "Add 'X-Content-Type-Options: nosniff' to all responses.",
        },
        "Missing Security Header: Content-Security-Policy": {
            "impact":      "No CSP means XSS payloads can load external scripts freely.",
            "remediation": "Define a strict CSP starting with 'default-src \\'self\\''.",
        },
        "Missing Security Header: Strict-Transport-Security": {
            "impact":      "Clients may connect over HTTP, enabling SSL stripping attacks.",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
        },
        "Missing Security Header: X-XSS-Protection": {
            "impact":      "Legacy browsers without built-in XSS filtering are unprotected.",
            "remediation": "Add 'X-XSS-Protection: 1; mode=block'.",
        },
        "Missing Security Header: Referrer-Policy": {
            "impact":      "Full URL (including tokens/paths) may leak to third-party sites.",
            "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
        },
        "Missing Security Header: Permissions-Policy": {
            "impact":      "Browser features (camera, microphone, geolocation) unrestricted.",
            "remediation": "Add 'Permissions-Policy: geolocation=(), microphone=(), camera=()'.",
        },
        "Clickjacking": {
            "impact":      "Attacker can overlay invisible UI and trick users into unintended clicks.",
            "remediation": "Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors \\'none\\''.",
        },
        "CORS Misconfiguration": {
            "impact":      "Cross-origin requests from attacker-controlled origins may access sensitive data.",
            "remediation": "Restrict Access-Control-Allow-Origin to known trusted origins.",
        },
        "Missing CSRF Protection": {
            "impact":      "Attacker can forge state-changing requests on behalf of authenticated users.",
            "remediation": "Implement synchronizer token pattern (CSRF token) in all POST forms.",
        },
    }

    async def _llm_enrich_findings(self, target_url: str,
                                   findings: List[Finding],
                                   stack: Dict,
                                   verbose: bool = False) -> List[Finding]:
        if not findings:
            return findings

        needs_llm: List[Finding] = []

        for f in findings:
            rule = self._RULE_BASED_ENRICHMENTS.get(f.vuln_type)
            if rule:
                f.impact      = rule["impact"]
                f.remediation = rule["remediation"]
                continue

            matched = False
            for key, rule in self._RULE_BASED_ENRICHMENTS.items():
                if f.vuln_type.startswith(key) or key in f.vuln_type:
                    f.impact      = rule["impact"]
                    f.remediation = rule["remediation"]
                    matched = True
                    break

            if matched:
                continue

            header_types = {
                "Missing Security Header", "Information Disclosure",
                "Clickjacking", "CORS Misconfiguration", "Missing CSRF Protection"
            }
            is_infra = any(t in f.vuln_type for t in header_types)
            if is_infra:
                continue

            needs_llm.append(f)

        if needs_llm and stack.get("stack_summary", "Unknown") != "Unknown":
            findings_summary = json.dumps(
                [{"vuln_type": f.vuln_type, "location": f.location,
                  "parameter": f.parameter, "payload": f.payload}
                 for f in needs_llm],
                indent=2
            )

            prompt = f"""You are a security analyst writing brief explanations.
You are given a list of vulnerabilities CONFIRMED by automated scanning.
Write a short plain-English explanation for each.

Target: {target_url}
Stack: {stack.get('stack_summary', 'Unknown')}

Confirmed findings:
{findings_summary}

For EACH finding write:
1. stack_impact: One sentence of real-world impact for THIS specific stack.
2. stack_remediation: One sentence with the specific fix for THIS stack.

STRICT RULES:
- Explain findings only — do NOT add new findings.
- Do NOT change severity or status.
- Keep each field to one sentence.

Respond with a JSON array:
[{{"vuln_type": "...", "stack_impact": "...", "stack_remediation": "..."}}]
"""
            try:
                response = self.openai_client.chat.completions.create(
                    model=self.llm_model,
                    messages=[
                        {"role": "system",
                         "content": "Security analyst. JSON array only. No new findings."},
                        {"role": "user", "content": prompt}
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.1,
                    max_tokens=400
                )

                raw    = response.choices[0].message.content.strip()
                parsed = json.loads(raw)
                items  = (parsed if isinstance(parsed, list) else
                          parsed.get("items", parsed.get("findings",
                          parsed.get("vulnerabilities", []))))

                enrich_map = {
                    e["vuln_type"]: e for e in items
                    if isinstance(e, dict) and "vuln_type" in e
                }

                for f in needs_llm:
                    if f.vuln_type in enrich_map:
                        e = enrich_map[f.vuln_type]
                        if e.get("stack_impact"):
                            f.impact = e["stack_impact"]
                        if e.get("stack_remediation"):
                            f.remediation = e["stack_remediation"]

                if verbose:
                    print(f"   ✓ LLM enriched {len(needs_llm)} findings")

            except Exception as e:
                logger.warning(f"LLM enrichment failed: {e}")

        return findings

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    async def _get_headers(self, url: str) -> Dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sync_request, url)

    async def _get_full_response(self, url: str,
                                 follow_redirects: bool = True) -> Tuple[int, Dict, str]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, lambda: self._sync_full_request(url, follow_redirects)
        )

    def _sync_request(self, url: str, extra_headers: Dict = None) -> Dict:
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (SecurityScanner)"}
            )
            if extra_headers:
                for k, v in extra_headers.items():
                    req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return dict(resp.headers)
        except Exception:
            return {}

    def _sync_full_request(self, url: str,
                            follow_redirects: bool = True) -> Tuple[int, Dict, str]:
        try:
            if not follow_redirects:
                class NoRedirect(urllib.request.HTTPErrorProcessor):
                    def http_response(self, request, response):
                        return response
                    https_response = http_response
                opener = urllib.request.build_opener(NoRedirect)
            else:
                opener = urllib.request.build_opener()

            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (SecurityScanner)"}
            )
            with opener.open(req, timeout=self.timeout) as resp:
                body = resp.read(8192).decode("utf-8", errors="replace")
                return resp.status, dict(resp.headers), body
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers) if e.headers else {}, ""
        except Exception:
            return 0, {}, ""

    def _inject_param(self, parsed, param: str, value: str) -> str:
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [value]
        new_query = urllib.parse.urlencode(qs, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _extract_context(self, body: str, payload: str,
                          context_chars: int = 200) -> str:
        idx = body.find(payload)
        if idx == -1:
            return ""
        start = max(0, idx - context_chars)
        end   = min(len(body), idx + len(payload) + context_chars)
        return f"...{body[start:end]}..."