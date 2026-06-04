# agents/webappscanner/spa_scanner.py
"""
Universal SPA Scanner
=====================
Discovers and scans Angular / React / Vue / Next.js / Nuxt / Svelte SPAs
without ANY hardcoded routes or application names.

Route discovery (in priority order):
  1. <a href> links from Playwright-rendered homepage
  2. JS bundle route config patterns (Angular/React/Vue Router)
  3. robots.txt Disallow entries
  4. sitemap.xml <loc> entries
  5. API endpoint URLs from fetch()/axios() in JS bundles
  6. Fallback: /login /register /search /contact (only if < 3 routes found)

Form extraction methods:
  A. Standard <form> elements (includes hidden inputs for CSRF detection)
  B. Angular reactive forms ([formcontrolname])
  C. Angular Material (mat-form-field)
  D. Generic visible inputs (React/Vue data-testid, aria-label)

Server-side frameworks (WordPress, Django, Rails, Drupal) are detected
and skipped — they render real HTML and don't need Playwright route scanning.
"""

import re
import asyncio
import logging
import urllib.request
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Framework detection
# ---------------------------------------------------------------------------

FRAMEWORK_SIGNATURES = {
    "angular": ["ng-version", "ng-app", "__ngContext__", "app-root",
                "router-outlet", "platformBrowserDynamic", "NgModule"],
    "react":   ["React.createElement", "__reactFiber", "data-reactroot",
                "ReactDOM.render", "_reactRootContainer", "react-dom"],
    "vue":     ["__vue_app__", "v-app", "data-v-app", "createApp",
                "Vue.component", "__vue__", "vue-router"],
    "nextjs":  ["__NEXT_DATA__", "_next/static", "next/dist", "__next"],
    "nuxt":    ["__NUXT__", "_nuxt", "nuxt-link", "@nuxt", "useNuxtApp"],
    "svelte":  ["__svelte", "svelte-", "SvelteComponent", "svelte/internal"],
}

# Server-side signals — if present, skip SPA scanning entirely
SERVER_SIDE_SIGNALS = [
    "wp-content", "wp-json",            # WordPress
    "sites/default/files",              # Drupal
    "/components/com_",                 # Joomla
    "csrfmiddlewaretoken",              # Django
    "authenticity_token",               # Rails
    "__VIEWSTATE",                      # ASP.NET WebForms
]

# Route URL patterns extracted from JS bundles
ROUTE_PATTERNS = [
    r"""path\s*:\s*['"]([a-zA-Z0-9/_-]{1,60})['"]""",
    r"""(?:path|to)\s*=\s*['"]([/][a-zA-Z0-9/_-]{1,60})['"]""",
    r"""path\s*:\s*['"]([/][a-zA-Z0-9/_-]{1,60})['"]""",
    r"""pages/([a-zA-Z0-9/_-]{1,40})""",
    r"""import\(['"]\.{0,2}/([a-zA-Z0-9/_-]{1,50})(?:\.|\b)""",
    r"""href\s*=\s*['"]([/][a-zA-Z0-9/_-]{1,60})['"]""",
    r"""\[routerLink\]\s*=\s*['"]\[?['"]([/a-zA-Z0-9/_-]{1,60})['"]""",
    r"""(?:fetch|axios\.(?:get|post|put|delete))\(['"]([/][a-zA-Z0-9/_-]{1,60})""",
]

# Keywords that suggest a route likely has user-input forms
FORM_ROUTE_KEYWORDS = [
    "login", "signin", "sign-in", "auth", "register", "signup", "sign-up",
    "contact", "feedback", "support", "message", "search", "find", "query",
    "forgot", "reset", "password", "recover", "checkout", "payment",
    "profile", "account", "settings", "edit", "submit", "form", "apply",
    "comment", "review", "rate", "order", "cart",
]

# Minimal fallback — only if discovery finds < 3 routes
FALLBACK_PATHS = ["/login", "/register", "/search", "/contact"]

ANGULAR_READY_SELECTORS = [
    "mat-form-field", "[formcontrolname]", "input[type='email']",
    "input[type='password']", "input[type='text']", "input[type='search']",
    "textarea", ".mat-input-element", "form", "app-navbar", "nav", "header", "main",
]
GENERIC_READY_SELECTORS = [
    "form", "input", "nav", "header", "main", "[data-testid]",
    ".container", "#root > *", "#app > *",
]


# ===========================================================================
# Main class
# ===========================================================================

class SPAScanner:
    """
    Universal SPA Scanner.
    Framework-agnostic — no hardcoded app names or routes.
    """

    def __init__(self, timeout_ms: int = 8000, max_routes: int = 6):
        self.timeout_ms = timeout_ms
        self.max_routes = max_routes
        try:
            from playwright.async_api import async_playwright
            self._has_playwright = True
        except ImportError:
            self._has_playwright = False
            logger.warning("Playwright not installed — SPA scanning disabled")

    async def scan(self, base_url: str, verbose: bool = False) -> Dict:
        """
        Entry point. Returns:
          { is_spa, framework, routes_found, routes_visited, forms, urls }
        """
        base = _normalise_base(base_url)

        # Fetch raw HTTP response
        status, raw_html, raw_headers = _fetch(base)
        if not raw_html and status == 0:
            logger.warning(f"SPAScanner: cannot reach {base}")
            return _empty_result()

        # Skip server-side frameworks — they don't need Playwright
        if _is_server_side(raw_html):
            if verbose:
                print(f"   ℹ SPAScanner: server-side framework — skipping")
            return _empty_result()

        # Detect SPA framework
        framework, is_spa = _detect_framework(raw_html, raw_headers)
        if not is_spa:
            if verbose:
                print(f"   ℹ SPAScanner: not an SPA — skipping")
            return _empty_result()

        if verbose:
            print(f"   ✓ SPAScanner: {framework} detected at {base}")

        if not self._has_playwright:
            return {**_empty_result(), "is_spa": True, "framework": framework}

        # Discover routes from the app itself
        routes = await self._discover_routes(base, raw_html, verbose)
        if verbose:
            form_routes = sum(1 for r in routes if r["has_form_hint"])
            print(f"   ✓ Routes: {len(routes)} ({form_routes} with form hints)")

        # Visit routes with Playwright
        all_forms, all_urls = await self._visit_routes(base, routes, framework, verbose)

        # Discover REST/API endpoints from JS bundles
        api_urls = await self._discover_api_endpoints(base, raw_html, verbose)
        all_urls.extend(api_urls)

        return {
            "is_spa":         True,
            "framework":      framework,
            "routes_found":   len(routes),
            "routes_visited": min(len(routes), self.max_routes),
            "forms":          _dedup_forms(all_forms),
            "urls":           list(set(all_urls)),
        }

    # ------------------------------------------------------------------
    # Route discovery — fully dynamic, no hardcoded paths
    # Returns List[Dict] with keys: url, path, has_form_hint, priority
    # ------------------------------------------------------------------

    async def _discover_routes(self, base: str, raw_html: str,
                                verbose: bool) -> List[Dict]:
        """
        Discover routes from the app itself.
        Returns list of route dicts sorted by priority (form-likely first).
        """
        discovered: Set[str] = set()

        # Method 1: Rendered hrefs from Playwright homepage visit
        rendered = await self._extract_rendered_hrefs(base, verbose)
        discovered.update(rendered)

        # Method 2: JS bundle route configs
        js_routes = await self._extract_js_routes(base, raw_html, verbose)
        discovered.update(js_routes)

        # Method 3: robots.txt + sitemap.xml
        static = await self._extract_static_hints(base)
        discovered.update(static)

        # Method 4: Fallback — minimal structural routes
        # Only added if we found very few routes through other methods
        if len(discovered) < 3:
            if verbose:
                print(f"      < 3 routes found — adding structural fallbacks")
            discovered.update(FALLBACK_PATHS)

        # Build route objects with priority scoring
        routes = []
        for path in discovered:
            # Skip routes that shouldn't be visited
            if any(skip in path.lower() for skip in
                   ["logout", "signout", "sign-out", "delete",
                    ".js", ".css", ".png", ".jpg", ".ico", "favicon"]):
                continue

            has_form = any(kw in path.lower() for kw in FORM_ROUTE_KEYWORDS)
            # Form-likely routes first (lower score = higher priority)
            priority = (0 if has_form else 1) * 100 + len(path)

            routes.append({
                "path":          path,
                "url":           _build_url(base, path),
                "has_form_hint": has_form,
                "priority":      priority,
            })

        routes.sort(key=lambda r: r["priority"])
        return routes[:self.max_routes]

    async def _extract_rendered_hrefs(self, base: str,
                                       verbose: bool) -> Set[str]:
        """Method 1: Visit homepage with Playwright, collect rendered links."""
        paths: Set[str] = set()
        if not self._has_playwright:
            return paths
        from playwright.async_api import async_playwright
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage"]
                )
                page = await browser.new_page()
                await page.goto(base, timeout=self.timeout_ms,
                                wait_until="networkidle")
                await page.wait_for_timeout(2000)
                await _dismiss_overlays(page)

                hrefs = await page.evaluate(f"""() => {{
                    const base = '{base}';
                    const links = new Set();
                    document.querySelectorAll('a[href]').forEach(a => {{
                        const href = a.href || a.getAttribute('href') || '';
                        try {{
                            const url = new URL(href, base);
                            if (url.origin === new URL(base).origin) {{
                                const path = url.hash
                                    ? url.hash.replace('#', '')
                                    : url.pathname;
                                if (path && path.length > 1) links.add(path);
                            }}
                        }} catch(e) {{}}
                    }});
                    return Array.from(links);
                }}""")
                await browser.close()

                for href in (hrefs or []):
                    clean = href.strip().split("?")[0]
                    if clean and len(clean) > 1:
                        paths.add(clean if clean.startswith("/")
                                  else "/" + clean)
                if verbose:
                    print(f"      Method 1 (rendered hrefs): {len(paths)} paths")
        except Exception as e:
            logger.debug(f"Rendered href extraction failed: {e}")
        return paths

    async def _extract_js_routes(self, base: str, raw_html: str,
                                  verbose: bool) -> Set[str]:
        """Method 2: Parse JS bundles for router configuration patterns."""
        paths: Set[str] = set()
        script_urls = re.findall(
            r'<script[^>]+src=[\'"]([^\'"]+\.js[^\'"]*)[\'"]',
            raw_html, re.IGNORECASE
        )
        main_scripts = sorted(
            script_urls,
            key=lambda u: ("main" in u or "chunk" in u, len(u)),
            reverse=True
        )[:3]

        for src in main_scripts:
            js_url = src if src.startswith("http") \
                     else urllib.parse.urljoin(base + "/", src)
            try:
                _, js_body, _ = _fetch(js_url, max_bytes=512 * 1024)
                if not js_body:
                    continue
                for pattern in ROUTE_PATTERNS:
                    for m in re.finditer(pattern, js_body):
                        path = m.group(1).strip("/")
                        if (path and 2 <= len(path) <= 60 and
                                not path.startswith(".") and
                                not any(s in path for s in
                                        [".js", ".css", "node_modules",
                                         "webpack", "__"])):
                            paths.add("/" + path.lstrip("/"))
            except Exception as e:
                logger.debug(f"JS route extraction failed {js_url}: {e}")

        if verbose and paths:
            print(f"      Method 2 (JS bundles): {len(paths)} paths")
        return paths

    async def _extract_static_hints(self, base: str) -> Set[str]:
        """Method 3: Parse robots.txt and sitemap.xml for path hints."""
        paths: Set[str] = set()
        # robots.txt
        try:
            _, body, _ = _fetch(f"{base}/robots.txt")
            if body:
                for line in body.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("allow:", "disallow:")):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/" and "." not in path.split("/")[-1]:
                            paths.add(path.split("?")[0])
        except Exception:
            pass
        # sitemap.xml
        try:
            _, body, _ = _fetch(f"{base}/sitemap.xml")
            if body:
                for m in re.finditer(r'<loc>([^<]+)</loc>', body):
                    try:
                        p = urllib.parse.urlparse(m.group(1).strip())
                        if p.path and p.path != "/":
                            paths.add(p.path)
                    except Exception:
                        pass
        except Exception:
            pass
        return paths

    async def _discover_api_endpoints(self, base: str,
                                       raw_html: str,
                                       verbose: bool) -> List[str]:
        """Method 4: Extract REST API endpoints from JS bundles."""
        api_urls: List[str] = []
        patterns = [
            r"""['"]([/](?:api|rest|v\d+|graphql)[/][a-zA-Z0-9/_-]{1,60})['"]""",
            r"""(?:fetch|axios\.(?:get|post))\s*\(\s*['"]([/][a-zA-Z0-9/_?=&-]{1,80})""",
            r"""(?:baseURL|apiUrl|API_URL)\s*[=:]\s*['"]([/][a-zA-Z0-9/_-]{1,60})""",
        ]
        script_urls = re.findall(
            r'<script[^>]+src=[\'"]([^\'"]+\.js[^\'"]*)[\'"]',
            raw_html, re.IGNORECASE
        )[:2]

        for src in script_urls:
            js_url = src if src.startswith("http") \
                     else urllib.parse.urljoin(base + "/", src)
            try:
                _, js_body, _ = _fetch(js_url, max_bytes=256 * 1024)
                if not js_body:
                    continue
                for pattern in patterns:
                    for m in re.finditer(pattern, js_body):
                        full = base + m.group(1)
                        if full not in api_urls:
                            api_urls.append(full)
                        if len(api_urls) >= 10:
                            break
            except Exception:
                pass

        if verbose and api_urls:
            print(f"      API endpoints discovered: {len(api_urls)}")
        return api_urls[:10]

    # ------------------------------------------------------------------
    # Route visiting with Playwright
    # ------------------------------------------------------------------

    async def _visit_routes(self, base: str, routes: List[Dict],
                             framework: str,
                             verbose: bool) -> Tuple[List[Dict], List[str]]:
        """Visit each route with Playwright and extract rendered forms."""
        if not self._has_playwright or not routes:
            return [], []

        from playwright.async_api import async_playwright

        all_forms: List[Dict] = []
        all_urls:  List[str]  = []
        ready_sels = (ANGULAR_READY_SELECTORS if framework == "angular"
                      else GENERIC_READY_SELECTORS)

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage",
                      "--disable-web-security"]
            )
            ctx = await browser.new_context(
                user_agent="Mozilla/5.0 (SecurityScanner/YuraRAG)"
            )

            for route in routes[:self.max_routes]:
                url  = route["url"]
                page = await ctx.new_page()
                try:
                    await page.goto(url, timeout=self.timeout_ms,
                                    wait_until="domcontentloaded")
                    for sel in ready_sels:
                        try:
                            await page.wait_for_selector(
                                sel, timeout=3000, state="attached"
                            )
                            break
                        except Exception:
                            continue
                    await page.wait_for_timeout(1200)
                    await _dismiss_overlays(page)

                    forms = await _extract_forms(page, url, framework)
                    all_forms.extend(forms)

                    links = await page.evaluate(f"""() =>
                        Array.from(document.querySelectorAll('a[href]'))
                            .map(a => a.href)
                            .filter(h => h.startsWith('{base}'))
                            .slice(0, 10)
                    """)
                    all_urls.extend(links)

                    if verbose and forms:
                        n = sum(len(f.get("inputs", [])) for f in forms)
                        print(f"      {route['path']}: "
                              f"{len(forms)} form(s), {n} input(s)")
                except Exception as e:
                    logger.debug(f"Route visit failed {url}: {e}")
                finally:
                    await page.close()

            await browser.close()

        return all_forms, all_urls


# ===========================================================================
# Module-level helpers
# ===========================================================================

def _normalise_base(url: str) -> str:
    return url.split("#")[0].rstrip("/") if url.startswith("http") \
           else "http://" + url.split("#")[0].rstrip("/")


def _build_url(base: str, path: str) -> str:
    return base + path if path.startswith("/") else base + "/" + path


def _fetch(url: str, max_bytes: int = 65536) -> Tuple[int, str, Dict]:
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (SecurityScanner)"}
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.status, \
                   resp.read(max_bytes).decode("utf-8", errors="replace"), \
                   dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, "", {}
    except Exception:
        return 0, "", {}


def _is_server_side(html: str) -> bool:
    """Returns True if HTML contains server-side framework signals."""
    if not html:
        return False
    html_lower = html.lower()
    return any(s.lower() in html_lower for s in SERVER_SIDE_SIGNALS)


def _detect_framework(html: str,
                       headers: Dict) -> Tuple[str, bool]:
    """Detect SPA framework. Returns (name, is_spa)."""
    combined = html + " " + " ".join(str(v) for v in headers.values())
    scores: Dict[str, int] = {
        fw: sum(1 for s in sigs if s in combined)
        for fw, sigs in FRAMEWORK_SIGNATURES.items()
    }
    scores = {k: v for k, v in scores.items() if v > 0}
    if not scores:
        visible     = re.sub(r'<[^>]+>', '', html).strip()
        has_scripts = bool(re.search(r'<script[^>]+src=', html))
        if len(visible) < 150 and has_scripts:
            return "unknown_spa", True
        return "none", False
    return max(scores, key=lambda k: scores[k]), True


def _empty_result() -> Dict:
    return {"is_spa": False, "framework": "none",
            "routes_found": 0, "routes_visited": 0,
            "forms": [], "urls": []}


async def _dismiss_overlays(page) -> None:
    """Dismiss cookie banners / GDPR modals — framework-agnostic."""
    for text in ["dismiss", "close", "accept", "got it", "agree",
                 "ok", "i understand", "continue", "allow", "consent"]:
        try:
            els = await page.query_selector_all(
                f"button, a, [role='button']"
            )
            for el in els[:2]:
                label = (await el.text_content() or "").strip().lower()
                if text in label and len(label) < 50:
                    await el.click(timeout=800)
                    await page.wait_for_timeout(400)
                    break
        except Exception:
            pass


async def _extract_forms(page, page_url: str,
                          framework: str) -> List[Dict]:
    """
    Extract forms from a rendered page.
    Includes hidden inputs so CSRF tokens (authenticity_token, _token) are visible.
    """
    try:
        return await page.evaluate(f"""() => {{
            const results = [];
            const pageUrl = '{page_url}';

            // A: Standard <form> elements
            // Includes ALL inputs (including hidden) so CSRF tokens are detected
            document.querySelectorAll('form').forEach(form => {{
                const inputs = extractInputs(form);
                if (inputs.length > 0) {{
                    results.push({{
                        action: form.action || pageUrl,
                        method: (form.method || 'post').toLowerCase(),
                        inputs: inputs,
                        source: 'html_form'
                    }});
                }}
            }});

            // B: Angular reactive forms ([formcontrolname])
            if (results.length === 0) {{
                const fcs = document.querySelectorAll('[formcontrolname]');
                if (fcs.length > 0) {{
                    const inputs = [];
                    fcs.forEach(el => {{
                        const name = el.getAttribute('formcontrolname')
                                   || el.name || el.id || '';
                        if (name) inputs.push({{
                            name, type: el.type || el.tagName.toLowerCase(), id: el.id || ''
                        }});
                    }});
                    if (inputs.length > 0)
                        results.push({{ action: pageUrl, method: 'post',
                                        inputs, source: 'angular_reactive' }});
                }}
            }}

            // C: Angular Material
            if (results.length === 0) {{
                const matInputs = document.querySelectorAll(
                    'mat-form-field input, mat-form-field textarea, .mat-input-element'
                );
                if (matInputs.length > 0) {{
                    const inputs = [];
                    matInputs.forEach(el => {{
                        const name = el.getAttribute('formcontrolname')
                                   || el.name || el.id || el.placeholder || 'input';
                        inputs.push({{ name, type: el.type || 'text', id: el.id || '' }});
                    }});
                    results.push({{ action: pageUrl, method: 'post',
                                    inputs, source: 'angular_material' }});
                }}
            }}

            // D: Generic visible inputs (React, Vue, others)
            if (results.length === 0) {{
                const vis = document.querySelectorAll(
                    'input:not([type="submit"]):not([type="button"]),' +
                    'textarea'
                );
                const inputs = [];
                vis.forEach(el => {{
                    const rect = el.getBoundingClientRect();
                    if (rect.width > 0 && rect.height > 0) {{
                        const name = el.getAttribute('data-testid')
                                   || el.getAttribute('aria-label')
                                   || el.name || el.id || el.placeholder || el.type || 'input';
                        inputs.push({{ name, type: el.type || el.tagName.toLowerCase(),
                                       id: el.id || '' }});
                    }}
                }});
                if (inputs.length > 0) {{
                    const container = vis[0] && vis[0].closest(
                        'form, [role="form"], .form, section, main, article'
                    );
                    results.push({{
                        action: (container && container.tagName === 'FORM')
                                ? container.action || pageUrl : pageUrl,
                        method: 'post', inputs, source: 'generic_inputs'
                    }});
                }}
            }}

            return results;

            function extractInputs(container) {{
                const inputs = [];
                // Include ALL inputs (visible + hidden CSRF tokens)
                container.querySelectorAll(
                    'input:not([type="submit"]):not([type="button"]),' +
                    'textarea, select'
                ).forEach(el => {{
                    const name = el.getAttribute('formcontrolname')
                               || el.name || el.id
                               || el.getAttribute('data-testid')
                               || el.getAttribute('aria-label')
                               || el.placeholder || '';
                    if (name) inputs.push({{
                        name, type: el.type || el.tagName.toLowerCase(), id: el.id || ''
                    }});
                }});
                return inputs;
            }}
        }}""")
    except Exception as e:
        logger.debug(f"Form extraction failed: {e}")
        return []


def _dedup_forms(forms: List[Dict]) -> List[Dict]:
    seen: Set[str] = set()
    result: List[Dict] = []
    for f in forms:
        key = f.get("action", "") + "|" + ",".join(
            i.get("name", "") for i in f.get("inputs", [])
        )
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result