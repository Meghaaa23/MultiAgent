# agents/fingerprint_agent.py
"""
TechFingerprintAgent
====================
Phase 0 of the scanning pipeline.

Identifies the target's technology stack BEFORE any vulnerability
search happens, so the rest of the pipeline asks stack-specific
questions instead of guessing.

Output shape
------------
{
    "server":    "nginx/1.18.0",
    "language":  "PHP/7.4",
    "framework": "Laravel",
    "frontend":  "Vue.js",
    "cms":       None,
    "headers":   { ... raw response headers ... },
    "cookies":   [ ... ],
    "raw_html_hints": [ "wp-content", ... ],
    "confidence": "High" | "Medium" | "Low",
    "stack_summary": "nginx · PHP 7.4 · Laravel · Vue.js"
}
"""

import re
import logging
from typing import Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Signature databases 
# ---------------------------------------------------------------------------

SERVER_SIGS = {
    "nginx":   r"nginx(?:/(\S+))?",
    "apache":  r"Apache(?:/(\S+))?",
    "iis":     r"Microsoft-IIS(?:/(\S+))?",
    "caddy":   r"Caddy",
    "gunicorn":r"gunicorn(?:/(\S+))?",
    "uvicorn": r"uvicorn",
    "tomcat":  r"Apache-Coyote|Tomcat",
    "lighttpd":r"lighttpd(?:/(\S+))?",
    "vercel": r"vercel",      
    "fastly": r"fastly",
}

FRAMEWORK_SIGS = {
    # Headers
    "Laravel":      r"laravel_session",
    "Django":       r"csrftoken|django",
    "Rails":        r"_rails_session|X-Runtime",
    "Express":      r"X-Powered-By: Express",
    "FastAPI":      r"fastapi|uvicorn",
    "Spring":       r"JSESSIONID|X-Application-Context",
    "ASP.NET":      r"ASP\.NET|X-AspNet-Version|__RequestVerificationToken",
    "Next.js":      r"__NEXT_DATA__|x-nextjs",
    "Nuxt":         r"__nuxt|_nuxt",
    "Angular":      r"ng-version|angular",
    "React":        r"__REACT_DEVTOOLS|react",
    "Vue":          r"__vue__|vue",
    "Next.js":   r"__NEXT_DATA__|x-nextjs|_next/static",
    "Vercel":    r"x-vercel|x-vercel-cache",        
    "Fastly":    r"x-served-by.*cache|x-cache.*HIT",
    "Cloudflare":r"cf-ray|cf-cache-status",
}

CMS_SIGS = {
    "WordPress":  r"wp-content|wp-includes|wordpress",
    "Drupal":     r"Drupal|drupal",
    "Joomla":     r"Joomla|joomla",
    "Magento":    r"Magento|mage|PHPSESSID.*mage",
    "OpenCart":   r"route=common|catalog/view",
    "Ghost":      r"ghost-url|ghost\.io",
    "Shopify":    r"shopify|myshopify\.com",
    "Wix":        r"wixsite\.com|X-Wix",
}

LANGUAGE_SIGS = {
    "PHP":    r"\.php|X-Powered-By: PHP|PHPSESSID",
    "Python": r"python|django|flask|fastapi",
    "Ruby":   r"\.rb|rack\.|_rails",
    "Java":   r"JSESSIONID|\.jsp|\.do\b",
    "Node":   r"X-Powered-By: Express|node\.js",
    ".NET":   r"X-AspNet-Version|\.aspx|ASP\.NET",
    "Go":     r"Go-http-client|gorilla",
}


class TechFingerprintAgent:
    """
    Passive + active fingerprinting of a web target.

    Strategy (no extra pip dependencies):
      1. HTTP HEAD/GET → inspect response headers
      2. Inspect cookies
      3. Inspect HTML body hints
      4. LLM synthesis of evidence into structured stack
    """

    def __init__(self, openai_client, llm_model: str):
        self.openai_client = openai_client
        self.llm_model = llm_model

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def fingerprint(self, target_url: str,
                          page_html: Optional[str] = None,
                          response_headers: Optional[Dict] = None,
                          verbose: bool = False) -> Dict:
        """
        Fingerprint the target.

        Parameters
        ----------
        target_url      : full URL
        page_html       : HTML body already fetched by BrowserController (optional)
        response_headers: HTTP response headers already captured (optional)
        verbose         : print progress
        """
        if verbose:
            print(f"\n Fingerprinting: {target_url}")

        evidence: Dict = {
            "url": target_url,
            "headers": response_headers or {},
            "cookies": [],
            "html_hints": [],
        }

        # Fetch headers 
        if not response_headers:
            evidence["headers"] = await self._fetch_headers(target_url, verbose)

        # Extract HTML hints 
        if page_html:
            evidence["html_hints"] = self._extract_html_hints(page_html)
            evidence["cookies"]    = self._extract_cookies_from_html(page_html)

        # Rule-based signature matching 
        rule_stack = self._apply_signatures(evidence)

        # LLM synthesis
        final_stack = await self._llm_synthesize(target_url, evidence, rule_stack, verbose)

        if verbose:
            print(f"Stack: {final_stack.get('stack_summary', 'Unknown')}")

        return final_stack

    # ------------------------------------------------------------------
    # Header fetching
    # ------------------------------------------------------------------

    async def _fetch_headers(self, url: str, verbose: bool = False) -> Dict:
        """Lightweight header fetch using urllib (no extra deps)."""
        import urllib.request
        import urllib.error

        headers = {}
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"},
                method="HEAD"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                for key, val in resp.headers.items():
                    headers[key] = val
            if verbose:
                print(f"   ✓ Fetched {len(headers)} headers")
        except Exception as e:
            logger.warning(f"Header fetch failed for {url}: {e}")
            # Try GET as fallback
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    for key, val in resp.headers.items():
                        headers[key] = val
            except Exception as e2:
                logger.warning(f"GET header fetch also failed: {e2}")

        return headers

    # ------------------------------------------------------------------
    # HTML hint extraction
    # ------------------------------------------------------------------

    def _extract_html_hints(self, html: str) -> List[str]:
        """Extract technology-revealing strings from HTML."""
        hint_patterns = [
            r"wp-content", r"wp-includes",          # WordPress
            r"drupal\.js", r"Drupal\.settings",      # Drupal
            r"/components/com_",                     # Joomla
            r"Magento",                              # Magento
            r"ng-version=['\"]([^'\"]+)['\"]",       # Angular version
            r"__NEXT_DATA__",                        # Next.js
            r"__nuxt",                               # Nuxt
            r"react(?:\.min)?\.js",                  # React
            r"vue(?:\.min)?\.js",                    # Vue
            r"bootstrap(?:\.min)?\.css",             # Bootstrap
            r"jquery(?:\.min)?\.js",                 # jQuery
            r"laravel",                              # Laravel
            r"csrf-token",                           # CSRF (Django/Rails/Laravel)
            r"X-Frame-Options",                      # Security header hint
            r"generator.*wordpress",                 # WP meta
            r"generator.*joomla",
        ]
        hints = []
        for pattern in hint_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                hints.append(pattern.replace(r"['\"]([^'\"]+)['\"]", "").strip())
        return list(set(hints))

    def _extract_cookies_from_html(self, html: str) -> List[str]:
        """Extract cookie names referenced in HTML (document.cookie patterns)."""
        return re.findall(r'document\.cookie\s*=\s*["\']([^"\']+)', html)

    # ------------------------------------------------------------------
    # Rule-based signature matching
    # ------------------------------------------------------------------

    def _apply_signatures(self, evidence: Dict) -> Dict:
        """Match known signatures against headers + HTML hints."""
        # Build a single searchable string
        header_str  = " ".join(f"{k}: {v}" for k, v in evidence["headers"].items())
        html_str    = " ".join(evidence.get("html_hints", []))
        cookie_str  = " ".join(evidence.get("cookies", []))
        combined    = f"{header_str} {html_str} {cookie_str}"

        result = {
            "server":    self._match(combined, SERVER_SIGS),
            "language":  self._match(combined, LANGUAGE_SIGS),
            "framework": self._match(combined, FRAMEWORK_SIGS),
            "cms":       self._match(combined, CMS_SIGS),
        }
        return result

    def _match(self, text: str, sigs: Dict[str, str]) -> Optional[str]:
        for name, pattern in sigs.items():
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                # If the pattern captured a version group, include it
                version = m.group(1) if m.lastindex else None
                return f"{name}/{version}" if version else name
        return None

    # ------------------------------------------------------------------
    # LLM synthesis
    # ------------------------------------------------------------------

    async def _llm_synthesize(self, url: str, evidence: Dict,
                               rule_stack: Dict, verbose: bool) -> Dict:
        """Ask the LLM to synthesize evidence into a final stack object."""

        header_summary = "\n".join(
            f"  {k}: {v}" for k, v in list(evidence["headers"].items())[:20]
        )
        html_hints = ", ".join(evidence.get("html_hints", [])) or "none"

        prompt = f"""You are a web technology fingerprinting expert.

Target URL: {url}

HTTP Response Headers:
{header_summary or "  (none captured)"}

HTML Hints Found: {html_hints}

Rule-Based Detection:
  Server:    {rule_stack.get('server') or 'unknown'}
  Language:  {rule_stack.get('language') or 'unknown'}
  Framework: {rule_stack.get('framework') or 'unknown'}
  CMS:       {rule_stack.get('cms') or 'none'}

Based on ALL evidence above, produce a JSON object with exactly these keys:
{{
  "server":        "<server software and version or null>",
  "language":      "<backend language and version or null>",
  "framework":     "<web framework or null>",
  "frontend":      "<frontend framework/library or null>",
  "cms":           "<CMS name or null>",
  "cdn":           "<CDN provider or null>",
  "waf":           "<WAF/security layer or null>",
  "stack_summary": "<concise one-line summary e.g. nginx · PHP 7.4 · Laravel · Vue.js>",
  "confidence":    "High" | "Medium" | "Low",
  "vuln_hints":    ["<specific thing to check based on this stack>", ...]
}}

vuln_hints should be 3-5 specific, actionable checks for THIS stack only.
Example for Laravel: ["Check Laravel debug mode /.env exposure",
                      "Test CSRF token validation",
                      "Check Laravel file upload restrictions"]

Respond with JSON only. No markdown.
"""

        try:
            response = self.openai_client.chat.completions.create(...)
            raw  = response.choices[0].message.content.strip()
            stack = json.loads(raw)

            # ── NOISE FILTER — remove garbage LLM values ──────────────────
            noise = {
                "content", "content signals", "unknown", "none",
                "null", "n/a", "", "not detected", "not identified",
            }
            for key in ("server", "language", "framework", "frontend",
                        "cms", "cdn", "waf"):
                val = stack.get(key)
                if val and str(val).strip().lower() in noise:
                    stack[key] = None

            # Clean technologies list
            techs = stack.get("technologies", [])
            if isinstance(techs, list):
                stack["technologies"] = [
                    t for t in techs
                    if t
                    and str(t).strip().lower() not in noise
                    and len(str(t).strip()) > 3
                    and "signal" not in str(t).lower()
                ]
            summary = stack.get("stack_summary", "")
            if summary and summary.strip().lower() in noise:
                stack["stack_summary"] = ""

            # Merge rule-based detections as fallback
            for key in ("server", "language", "framework", "cms"):
                if not stack.get(key) and rule_stack.get(key):
                    stack[key] = rule_stack[key]

            # If stack_summary is still empty, rebuild from fields
            if not stack.get("stack_summary") or \
                    stack["stack_summary"].strip().lower() in noise:
                parts = [
                    stack.get("server"), stack.get("language"),
                    stack.get("framework"), stack.get("cdn"),
                ]
                clean_parts = [
                    p for p in parts
                    if p and str(p).strip().lower() not in noise
                ]
                if clean_parts:
                    stack["stack_summary"] = " · ".join(clean_parts[:3])

            stack["headers"] = evidence["headers"]

            return stack

        except Exception as e:
            logger.warning(f"LLM fingerprint synthesis failed: {e}")
            # Return rule-based result as fallback
            return {
                "server":        rule_stack.get("server"),
                "language":      rule_stack.get("language"),
                "framework":     rule_stack.get("framework"),
                "frontend":      None,
                "cms":           rule_stack.get("cms"),
                "cdn":           None,
                "waf":           None,
                "stack_summary": " · ".join(
                    v for v in rule_stack.values() if v
                ) or "Unknown",
                "confidence":    "Low",
                "vuln_hints":    [],
                "headers":       evidence["headers"]
            }