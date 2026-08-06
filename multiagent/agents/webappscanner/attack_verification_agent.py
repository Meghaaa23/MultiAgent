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
    request:               str  = ""
    response_status:       int  = 0
    response_body_snippet: str  = ""
    response_headers:      Dict = field(default_factory=dict)
    payload_reflected:     bool = False
    execution_confirmed:   bool = False
    verified:              bool = False
    confidence:            str  = Confidence.LOW
    confirmation_method:   str  = "header"

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Finding:
    vuln_type:   str
    severity:    str
    status:      str      = VulnStatus.POTENTIAL
    location:    str      = ""
    parameter:   str      = ""
    payload:     str      = ""
    description: str      = ""
    impact:      str      = ""
    remediation: str      = ""
    confidence:  str      = Confidence.LOW
    evidence:    Evidence = field(default_factory=Evidence)
    cwe:         str      = ""
    owasp:       str      = ""

    def to_dict(self) -> Dict:
        return asdict(self)


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

_NON_XSS_INPUT_TYPES = frozenset({
    "hidden", "submit", "button", "checkbox", "radio",
    "file", "password", "email", "number", "range",
    "tel", "date", "time", "datetime-local", "month",
    "week", "color", "image",
})

_SENSITIVE_PATH_STATUS_MAP = {
    200: {"status": VulnStatus.CONFIRMED, "severity_cap": None,   "should_report": True},
    403: {"status": VulnStatus.POTENTIAL, "severity_cap": "Low",  "should_report": True},
    301: {"status": VulnStatus.POTENTIAL, "severity_cap": "Info", "should_report": True},
    302: {"status": VulnStatus.POTENTIAL, "severity_cap": "Info", "should_report": True},
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
    "Referrer-Policy",
    "Permissions-Policy",
]

# Server/X-Powered-By values that disclose no version or meaningful software
# detail — kept consistent with vulnerability_tester._server_header_is_leaky
# and action_agent._server_is_leaky so all three agree on what counts as a
# real information-disclosure finding.
_SAFE_SERVER_PATTERNS = re.compile(
    r"^(cloudflare|cloudfront|awselb|fastly|google frontend|"
    r"nginx|apache|lighttpd|iis|openresty|caddy|envoy|traefik)$",
    re.I,
)


def _server_header_is_leaky(value: str) -> bool:
    v = (value or "").strip()
    if not v:
        return False
    if re.search(r"\d+\.\d+", v):
        return True
    if _SAFE_SERVER_PATTERNS.fullmatch(v):
        return False
    return True


class AttackVerificationAgent:

    def __init__(self, openai_client, llm_model: str, timeout: int = 10):
        self.openai_client = openai_client
        self.llm_model     = llm_model
        self.timeout       = timeout

    async def verify_all(self, target_url: str,
                         candidate_urls: List[str],
                         candidate_forms: List[Dict],
                         stack: Dict,
                         vuln_hints: List[str] = None,
                         shared_headers: Optional[Dict] = None,
                         verbose: bool = False) -> List[Finding]:
        """
        shared_headers: pre-fetched response headers for target_url, supplied
            by the caller (WebScannerAgent) so the header/clickjacking checks
            below use the SAME captured response as the fingerprinter and
            Action Agent, instead of making yet another independent request
            that could disagree (e.g. a CDN edge returning a different
            Server header on a second hit).
        """
        if verbose:
            print(f"\n Attack Verification Agent")
            print(f"   Target: {target_url}")
            print(f"   URLs: {len(candidate_urls)} | Forms: {len(candidate_forms)}")

        findings: List[Finding] = []

        results = await asyncio.gather(
            self._check_security_headers(target_url, verbose, shared_headers=shared_headers),
            self._check_urls_for_params(target_url, candidate_urls, verbose),
            self._check_forms(candidate_forms, verbose),
            self._check_cors(target_url, verbose),
            self._check_clickjacking(target_url, verbose, shared_headers=shared_headers),
            return_exceptions=True
        )

        for r in results:
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, Finding):
                findings.append(r)

        has_clickjacking = any(
            "Clickjacking" in f.vuln_type and f.status == VulnStatus.CONFIRMED
            for f in findings
        )
        # Dedup: XFO header absence is the clickjacking finding's evidence.
        # STRIDE cites that Section 3 finding rather than re-deriving XFO alone.
        if has_clickjacking:
            findings = [
                f for f in findings
                if not ("X-Frame-Options" in f.vuln_type and "Missing Security Header" in f.vuln_type)
            ]

        severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
        seen_cwe: dict = {}
        deduped: List[Finding] = []
        for f in findings:
            key      = (f.cwe, f.location)
            existing = seen_cwe.get(key)
            if existing is None:
                seen_cwe[key] = f
                deduped.append(f)
            else:
                if severity_rank.get(f.severity, 0) > severity_rank.get(existing.severity, 0):
                    deduped   = [x for x in deduped if x is not existing]
                    deduped.append(f)
                    seen_cwe[key] = f
        findings = deduped

        for f in findings:
            if f.evidence.response_status == 0 and f.confidence != Confidence.LOW:
                f.confidence          = Confidence.LOW
                f.evidence.confidence = Confidence.LOW

        if verbose:
            confirmed = sum(1 for f in findings if f.status == VulnStatus.CONFIRMED)
            potential = sum(1 for f in findings if f.status == VulnStatus.POTENTIAL)
            print(f"   ✓ Confirmed: {confirmed} | Potential: {potential}")

        return findings

    async def _check_security_headers(self, url: str,
                                      verbose: bool = False,
                                      shared_headers: Optional[Dict] = None) -> List[Finding]:
        findings = []
        try:
            if shared_headers:
                headers = shared_headers
                if verbose:
                    print(f"      [AttackVerification] using shared headers ({len(headers)} keys)")
            else:
                headers = await self._get_headers(url)
                if verbose and headers:
                    print(f"      [AttackVerification] fetched {len(headers)} headers independently")
            if not headers:
                return findings

            # Keep latest publisher header logic from remove-mongodb-doc-ui branch
            headers_lower = {k.lower(): v for k, v in headers.items()}
            csp_value = headers_lower.get("content-security-policy", "")
            is_https = str(url).lower().startswith("https://")
            publishable = [
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Content-Security-Policy",
                "Strict-Transport-Security",
            ]
            for h in publishable:
                if h.lower() in headers_lower:
                    continue
                if h == "X-Frame-Options" and "frame-ancestors" in csp_value.lower():
                    continue
                if h == "Strict-Transport-Security" and not is_https:
                    continue
                findings.append(Finding(
                    vuln_type   = f"Missing Security Header: {h}",
                    severity    = "Medium" if h in (
                        "Content-Security-Policy", "Strict-Transport-Security"
                    ) else "Low",
                    status      = VulnStatus.CONFIRMED,
                    location    = url,
                    description = f"The response is missing the {h} header.",
                    impact      = self._header_impact(h),
                    remediation = f"Add the {h} header to all HTTP responses.",
                    confidence  = Confidence.HIGH,
                    evidence    = Evidence(
                        request             = f"GET {url}",
                        response_status     = 200,
                        response_headers    = dict(headers),
                        verified            = True,
                        confidence          = Confidence.HIGH,
                        confirmation_method = "header"
                    ),
                    cwe   = "CWE-693",
                    owasp = "A05:2021"
                ))

            for key, val in headers.items():
                if key.lower() in ("server", "x-powered-by", "x-aspnet-version"):
                    if not _server_header_is_leaky(val):
                        if verbose:
                            print(f"      [AttackVerification] {key}: {val!r} — not leaky, skipping")
                        continue
                    has_version = bool(re.search(r'\d+\.\d+', val))
                    findings.append(Finding(
                        vuln_type   = f"Information Disclosure: {key} header",
                        severity    = "Low",
                        status      = VulnStatus.CONFIRMED,
                        location    = url,
                        description = (
                            f"Server exposes technology info: {key}: {val}"
                            + (" (version number exposed)" if has_version else "")
                        ),
                        impact      = "Attackers can fingerprint the stack and target known CVEs.",
                        remediation = f"Remove or obscure the {key} header.",
                        confidence  = Confidence.HIGH if has_version else Confidence.MEDIUM,
                        evidence    = Evidence(
                            request             = f"GET {url}",
                            response_status     = 200,
                            response_headers    = {key: val},
                            verified            = True,
                            confidence          = Confidence.HIGH,
                            confirmation_method = "header"
                        ),
                        cwe   = "CWE-200",
                        owasp = "A05:2021"
                    ))

        except Exception as e:
            logger.warning(f"Header check failed: {e}")

        return findings

    def _header_impact(self, header: str) -> str:
        impacts = {
            "X-Frame-Options":           "Enables clickjacking attacks.",
            "X-Content-Type-Options":    "Allows MIME-type sniffing attacks.",
            "Content-Security-Policy":   "Increases XSS attack surface significantly.",
            "Strict-Transport-Security": "Enables SSL stripping attacks.",
            "Referrer-Policy":           "Leaks URL information to third parties.",
            "Permissions-Policy":        "Allows unrestricted access to browser features.",
        }
        return impacts.get(header, "Reduces browser security protections.")

    async def _check_sensitive_paths(self, base_url: str,
                                     verbose: bool = False) -> List[Finding]:
        findings = []
        base     = base_url.rstrip("/")

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
                    re.search(p, body or "", re.IGNORECASE) for p in sensitive_patterns
                )

                if has_sensitive:
                    final_severity = "Critical"
                    confidence     = Confidence.HIGH
                else:
                    final_severity = _cap_severity(base_severity, severity_cap)
                    confidence     = (
                        Confidence.HIGH   if status == 200 else
                        Confidence.MEDIUM if status == 403 else
                        Confidence.LOW
                    )

                if status == 200 and has_sensitive:
                    desc = f"Sensitive path {path} returned HTTP 200 and response contains sensitive data."
                elif status == 200:
                    desc = f"Sensitive path {path} returned HTTP 200. File is accessible — manual review recommended."
                elif status == 403:
                    desc = f"Sensitive path {path} returned HTTP 403. Path exists but access is blocked."
                else:
                    desc = f"Sensitive path {path} returned HTTP {status} (redirect). Path may exist."

                findings.append(Finding(
                    vuln_type   = (
                        f"Protected Administrative Endpoint: {path}"
                        if status == 403
                        else f"Sensitive File Exposed: {path}"
                    ),
                    severity    = final_severity,
                    status      = vuln_status,
                    location    = url,
                    description = desc,
                    impact      = (
                        "Potential exposure of credentials, source code, or config."
                        if status == 200 else
                        "Path exists but is currently access-controlled."
                    ),
                    remediation = f"Block access to {path} or remove the file.",
                    confidence  = confidence,
                    evidence    = Evidence(
                        request               = f"GET {url}",
                        response_status       = status,
                        response_body_snippet = (body or "")[:300] if status == 200 else f"HTTP {status}",
                        response_headers      = headers,
                        verified              = (status == 200),
                        confidence            = confidence,
                        confirmation_method   = "http_body"
                    ),
                    cwe   = "CWE-538",
                    owasp = "A01:2021"
                ))
            except Exception as e:
                logger.debug(f"Path check failed for {path}: {e}")

        await asyncio.gather(*[check_path(p) for p in SENSITIVE_PATHS], return_exceptions=True)

        if verbose:
            confirmed = sum(1 for f in findings if f.status == VulnStatus.CONFIRMED)
            potential = sum(1 for f in findings if f.status == VulnStatus.POTENTIAL)
            print(f"   Sensitive paths: {confirmed} confirmed, {potential} potential")

        return findings

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
                       ("redirect", "url", "next", "return", "goto", "dest", "to")):
                    redir_finding = await self._test_open_redirect(url, param_name, parsed)
                    if redir_finding:
                        findings.append(redir_finding)

        return findings

    async def _test_reflected_xss(self, url: str, param: str,
                                   parsed) -> Optional[Finding]:
        # Redirect params commonly echo into error pages (Juice Shop 406) — not XSS
        if any(kw in param.lower() for kw in
               ("redirect", "url", "next", "return", "goto", "dest", "to")):
            return None

        for payload in XSS_PAYLOADS[:3]:
            try:
                test_url             = self._inject_param(parsed, param, payload)
                status, headers, body = await self._get_full_response(test_url)

                if not body or payload not in body:
                    continue
                if status < 200 or status >= 300:
                    continue

                ctype = ""
                for k, v in (headers or {}).items():
                    if k.lower() == "content-type":
                        ctype = str(v).lower()
                        break
                lower = body.lower()
                # Reject error-page / allowlist echoes
                if any(m in lower for m in (
                    "unrecognized target url", "invalid redirect",
                    "bad request", "internal server error",
                )):
                    continue
                # Require unescaped payload (not &lt;script&gt;)
                idx = body.find(payload)
                window = body[max(0, idx - 40):idx + len(payload) + 40]
                if "&lt;" in window and "<script" not in window.lower() \
                        and "onerror" not in window.lower():
                    continue
                if ctype and "json" in ctype and "<" not in payload:
                    # Plain string reflection inside JSON is not browser XSS by itself
                    continue

                return Finding(
                    vuln_type   = "Reflected XSS",
                    severity    = "High",
                    status      = VulnStatus.CONFIRMED,
                    location    = url,
                    parameter   = param,
                    payload     = payload,
                    description = f"The '{param}' parameter reflects user input without sanitization.",
                    impact      = "Attacker can execute arbitrary JavaScript in the victim's browser.",
                    remediation = "Apply output encoding to all user-supplied input. Implement a strict Content-Security-Policy.",
                    confidence  = Confidence.HIGH,
                    evidence    = Evidence(
                        request               = f"GET {test_url}",
                        response_status       = status,
                        response_body_snippet = self._extract_context(body, payload),
                        response_headers      = {"Content-Type": ctype} if ctype else {},
                        payload_reflected     = True,
                        verified              = True,
                        confidence            = Confidence.HIGH,
                        confirmation_method   = "http_body"
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
                test_url              = self._inject_param(parsed, param, payload)
                status, headers, body = await self._get_full_response(test_url, follow_redirects=False)
                location              = headers.get("Location", headers.get("location", ""))

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
                        description = f"The '{param}' parameter redirects to attacker-controlled URL.",
                        impact      = "Phishing attacks via trusted domain redirection.",
                        remediation = "Validate redirect URLs against an allowlist. Never redirect to user-supplied URLs directly.",
                        confidence  = Confidence.HIGH,
                        evidence    = Evidence(
                            request             = f"GET {test_url}",
                            response_status     = status,
                            response_headers    = {"Location": location},
                            payload_reflected   = True,
                            verified            = True,
                            confidence          = Confidence.HIGH,
                            confirmation_method = "header"
                        ),
                        cwe   = "CWE-601",
                        owasp = "A01:2021"
                    )
            except Exception:
                continue
        return None

    async def _check_forms(self, forms: List[Dict],
                           verbose: bool = False) -> List[Finding]:
        findings = []

        for form in forms:
            action = form.get("action", "")
            inputs = form.get("inputs", [])

            def _has_csrf(inp):
                name = (inp.get("name", "") or "").lower() if isinstance(inp, dict) else str(inp).lower()
                csrf_keywords = ("csrf", "_token", "authenticity_token", "nonce", "__requestverificationtoken")
                return name == "token" or any(kw in name for kw in csrf_keywords)

            if not any(_has_csrf(inp) for inp in inputs) and form.get("method", "get").lower() == "post":
                # Align with VulnerabilityTester CSRF honesty gates
                try:
                    from .vulnerability_tester import (
                        _csrf_finding_should_skip, _form_inputs,
                    )
                    norm_inputs = _form_inputs(form) if inputs else []
                    if _csrf_finding_should_skip(form, norm_inputs or [
                        i if isinstance(i, dict) else {"name": str(i)}
                        for i in inputs
                    ]):
                        continue
                except Exception:
                    # Fallback: skip obvious login forms
                    action_l = (action or "").lower()
                    if any(k in action_l for k in ("/login", "/signin", "/register")):
                        continue
                findings.append(Finding(
                    vuln_type   = "Missing CSRF Protection",
                    severity    = "Medium",
                    status      = VulnStatus.POTENTIAL,
                    location    = action,
                    description = "POST form does not appear to include a CSRF token.",
                    impact      = "Attacker can forge requests on behalf of authenticated users.",
                    remediation = "Implement synchronizer token pattern or SameSite cookie attribute.",
                    confidence  = Confidence.MEDIUM,
                    evidence    = Evidence(
                        request             = f"Analyzed form at {action}",
                        response_status     = 0,
                        verified            = False,
                        confidence          = Confidence.MEDIUM,
                        confirmation_method = "code analysis"
                    ),
                    cwe   = "CWE-352",
                    owasp = "A01:2021"
                ))

            # Do not emit speculative XSS from field existence alone.
            # Confirmed XSS must come from reflection / execution tests.

        return findings

    async def _check_cors(self, url: str,
                          verbose: bool = False) -> List[Finding]:
        findings  = []
        base      = url.rstrip("/")
        evil_orig = "https://evil-cors-probe.attacker-test.example.com"
        api_paths = ["/api", "/api/v1", "/api/v2", "/graphql",
                     "/api/user", "/api/me", "/api/data", "/api/config"]
        loop      = asyncio.get_event_loop()

        def _probe(probe_url: str, method: str = "GET") -> Dict:
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
                    return {"acao": h.get("access-control-allow-origin", ""),
                            "acac": h.get("access-control-allow-credentials", ""),
                            "acam": h.get("access-control-allow-methods", ""),
                            "acah": h.get("access-control-allow-headers", ""),
                            "status": resp.status, "url": probe_url}
            except urllib.error.HTTPError as e:
                h = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
                return {"acao": h.get("access-control-allow-origin", ""),
                        "acac": h.get("access-control-allow-credentials", ""),
                        "acam": h.get("access-control-allow-methods", ""),
                        "acah": h.get("access-control-allow-headers", ""),
                        "status": e.code, "url": probe_url}
            except Exception:
                return {"acao": "", "acac": "", "acam": "", "acah": "", "status": 0, "url": probe_url}

        def _is_wildcard(acao: str) -> bool:
            return (acao or "").strip() == "*"

        def _reflects_origin(acao: str) -> bool:
            return bool(acao) and evil_orig in acao

        def _credentials_true(acac: str) -> bool:
            return (acac or "").strip().lower() == "true"

        try:
            base_result        = await loop.run_in_executor(None, lambda: _probe(base))
            acao               = base_result["acao"]
            acac               = base_result["acac"]
            preflight_result   = await loop.run_in_executor(None, lambda: _probe(base, method="OPTIONS"))
            preflight_reflects = (
                _reflects_origin(preflight_result["acao"])
                or _is_wildcard(preflight_result["acao"])
            )

            api_probes = await asyncio.gather(
                *[loop.run_in_executor(None, lambda p=path: _probe(base + p)) for path in api_paths],
                return_exceptions=True
            )
            api_hits = [
                r for r in api_probes
                if isinstance(r, dict) and r.get("status", 0) not in (0, 404)
                and (
                    _reflects_origin(r.get("acao", ""))
                    or _is_wildcard(r.get("acao", ""))
                )
            ]
            # Prefer reflected-origin API hits over bare * for severity
            api_reflected = [
                r for r in api_hits if _reflects_origin(r.get("acao", ""))
            ]

            reflects_base = _reflects_origin(acao)
            star_base     = _is_wildcard(acao)
            creds_true    = _credentials_true(acac)
            api_creds     = any(_credentials_true(r.get("acac", "")) for r in api_hits)

            if not reflects_base and not star_base and not api_hits:
                return findings

            if creds_true or api_creds:
                severity   = "High"
                impact     = ("Server reflects attacker-controlled origin AND allows credentials. "
                              "An attacker can make authenticated cross-origin requests from any domain.")
                status     = VulnStatus.CONFIRMED
                confidence = Confidence.HIGH
            elif api_reflected or reflects_base:
                severity   = "Medium"
                impact     = (
                    "Attacker-controlled origin reflected"
                    + (f" on {len(api_reflected)} API endpoint(s)" if api_reflected else "")
                    + ". Anonymous cross-origin reads possible (no credentials)."
                )
                status     = VulnStatus.CONFIRMED
                confidence = Confidence.HIGH
            elif star_base or any(_is_wildcard(r.get("acao", "")) for r in api_hits):
                # Bare ACAO=* without credentials — Low, still Confirmed as header fact
                severity   = "Low"
                impact     = (
                    "Wildcard ACAO (*) without credentials — public responses "
                    "readable cross-origin; cookie theft not enabled."
                )
                status     = VulnStatus.CONFIRMED
                confidence = Confidence.HIGH
            else:
                return findings

            evidence_lines = [f"GET {base} (Origin: {evil_orig})"]
            for r in api_hits[:3]:
                evidence_lines.append(
                    f"GET {r['url']} → ACAO: {r['acao']}"
                    + (f", ACAC: {r['acac']}" if r.get('acac') else "")
                )
            if preflight_reflects:
                evidence_lines.append(f"OPTIONS {base} → ACAO: {preflight_result['acao']}")

            findings.append(Finding(
                vuln_type   = "CORS Misconfiguration",
                severity    = severity,
                status      = status,
                location    = base,
                description = (
                    f"Server CORS ACAO={acao or '(empty)'}"
                    + (" with credentials=true" if creds_true else "")
                    + (f". Also on {len(api_hits)} API endpoint(s)." if api_hits else ".")
                ),
                impact      = impact,
                remediation = ("Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted origins. "
                               "Never combine wildcard (*) with Access-Control-Allow-Credentials: true."),
                confidence  = confidence,
                evidence    = Evidence(
                    request             = " | ".join(evidence_lines),
                    response_status     = base_result["status"],
                    response_headers    = {
                        "Access-Control-Allow-Origin":      acao,
                        "Access-Control-Allow-Credentials": acac,
                        "Access-Control-Allow-Methods":     base_result.get("acam", ""),
                    },
                    verified            = (status == VulnStatus.CONFIRMED),
                    confidence          = confidence,
                    confirmation_method = "header"
                ),
                cwe   = "CWE-942",
                owasp = "A05:2021"
            ))

        except Exception as e:
            logger.debug(f"CORS check failed: {e}")

        return findings

    async def _check_clickjacking(self, url: str,
                                  verbose: bool = False,
                                  shared_headers: Optional[Dict] = None) -> Optional[Finding]:
        try:
            if shared_headers:
                headers = shared_headers
                if verbose:
                    print(f"      [AttackVerification] clickjacking check using shared headers")
            else:
                headers = await self._get_headers(url)
                if verbose and headers:
                    print(f"      [AttackVerification] clickjacking check fetched headers independently")
            if not headers:
                return None

            # Headers may arrive with mixed casing depending on the source
            # (urllib.request preserves original casing; shared_headers from
            # WebScannerAgent is lowercased). Normalise locally so both work.
            headers_lower = {k.lower(): v for k, v in headers.items()}
            xfo = headers_lower.get("x-frame-options", "")
            csp = headers_lower.get("content-security-policy", "")

            if not xfo and "frame-ancestors" not in csp.lower():
                return Finding(
                    vuln_type   = "Missing Clickjacking Protection",
                    severity    = "Medium",
                    status      = VulnStatus.CONFIRMED,
                    location    = url,
                    description = ("Page can be embedded in an iframe on attacker-controlled sites. "
                                   "Confirmed: both X-Frame-Options and CSP frame-ancestors are absent."),
                    impact      = ("Attacker tricks users into clicking UI elements they cannot see, "
                                   "enabling account takeover or unauthorized actions."),
                    remediation = "Add X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none'.",
                    confidence  = Confidence.HIGH,
                    evidence    = Evidence(
                        request             = f"GET {url}",
                        response_status     = 200,
                        response_headers    = {
                            "X-Frame-Options":        "(missing)",
                            "Content-Security-Policy": csp or "(missing)"
                        },
                        verified            = True,
                        confidence          = Confidence.HIGH,
                        confirmation_method = "header"
                    ),
                    cwe   = "CWE-1021",
                    owasp = "A04:2021"
                )
        except Exception as e:
            logger.debug(f"Clickjacking check failed: {e}")

        return None

    async def _get_headers(self, url: str) -> Dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sync_request, url)

    async def _get_full_response(self, url: str,
                                 follow_redirects: bool = True) -> Tuple[int, Dict, str]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self._sync_full_request(url, follow_redirects))

    def _sync_request(self, url: str, extra_headers: Dict = None) -> Dict:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (SecurityScanner)"})
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

            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (SecurityScanner)"})
            with opener.open(req, timeout=self.timeout) as resp:
                body = resp.read(8192).decode("utf-8", errors="replace")
                return resp.status, dict(resp.headers), body
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read(8192).decode("utf-8", errors="replace")
            except Exception:
                pass
            return e.code, dict(e.headers) if e.headers else {}, body
        except Exception:
            return 0, {}, ""

    def _inject_param(self, parsed, param: str, value: str) -> str:
        qs        = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [value]
        return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)))

    def _extract_context(self, body: str, payload: str, context_chars: int = 200) -> str:
        idx = body.find(payload)
        if idx == -1:
            return ""
        return f"...{body[max(0, idx - context_chars):min(len(body), idx + len(payload) + context_chars)]}..."