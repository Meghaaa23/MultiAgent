# agents/endpoint_discovery_agent.py
"""
EndpointDiscoveryAgent  — Tier 2
=================================
Discovers API endpoints and hidden paths that are invisible to a
standard DOM crawler.  Modern web apps (Angular/React/Vue SPAs backed
by FastAPI/Express/Laravel) expose most of their attack surface through
API routes that never appear in HTML.

Three discovery strategies (passive → semi-active → active):

  Strategy 1 — Passive file parsing
    robots.txt, sitemap.xml, manifest.json, swagger/openapi docs
    → zero risk, no injection, pure reading

  Strategy 2 — JavaScript endpoint extraction
    Scan page JS bundles for /api/... patterns via regex
    → read-only, no side-effects

  Strategy 3 — Common path probing
    Small, curated wordlist of admin / api / debug paths
    → GET-only, timeouts respected

Output shape (per discovered endpoint)
---------------------------------------
{
  "url":        "https://example.com/api/users",
  "method":     "GET",
  "source":     "robots.txt" | "sitemap" | "js_bundle" | "probe" | "swagger",
  "status":     200,
  "interesting": True,        # 200/301/302/403 — exists
  "auth_required": True,      # returned 401/403
  "params":     ["id", "q"],  # query params seen in JS
}
"""

import os
import re
import json
import asyncio
import logging
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Common path wordlist  (curated — not a huge brute-force list)
# ---------------------------------------------------------------------------

COMMON_PATHS = [
    # API roots
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/rest",
    "/graphql",
    "/query",
    # Auth
    "/api/auth",
    "/api/login",
    "/api/logout",
    "/api/register",
    "/api/token",
    "/api/refresh",
    "/oauth",
    "/oauth2",
    # User / admin
    "/api/users",
    "/api/user",
    "/api/me",
    "/api/profile",
    "/api/admin",
    "/admin",
    "/administrator",
    "/dashboard",
    "/manage",
    "/management",
    # Debug / info
    "/api/health",
    "/api/status",
    "/health",
    "/status",
    "/ping",
    "/metrics",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/mappings",
    "/debug",
    "/info",
    # Docs
    "/api/docs",
    "/docs",
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/openapi.yaml",
    "/api/swagger.json",
    "/api/openapi.json",
    "/redoc",
    # Config / secrets
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/config",
    "/config",
    "/config.json",
    "/config.yaml",
    "/settings",
    "/web.config",
    "/.htaccess",
    # Backups
    "/backup",
    "/backup.zip",
    "/backup.sql",
    "/dump.sql",
    "/db.sql",
    # CMS
    "/wp-admin",
    "/wp-login.php",
    "/wp-json/wp/v2/users",
    "/xmlrpc.php",
    "/phpmyadmin",
    "/phpinfo.php",
    # Misc
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/.well-known/security.txt",
    "/server-status",
    "/server-info",
    "/console",
    "/shell",
    "/terminal",
    "/upload",
    "/uploads",
    "/files",
    "/static",
    "/assets",
]

# Patterns to find API endpoints in JS source
JS_ENDPOINT_PATTERNS = [
    r'["\'](/api/[^"\'?\s]{2,80})["\']',
    r'["\'](/v\d+/[^"\'?\s]{2,80})["\']',
    r'fetch\(["\']([^"\']+)["\']',
    r'axios\.[a-z]+\(["\']([^"\']+)["\']',
    r'\.get\(["\']([^"\']+)["\']',
    r'\.post\(["\']([^"\']+)["\']',
    r'\.put\(["\']([^"\']+)["\']',
    r'\.delete\(["\']([^"\']+)["\']',
    r'url:\s*["\']([^"\']+)["\']',
    r'path:\s*["\']([^"\']+)["\']',
    r'endpoint:\s*["\']([^"\']+)["\']',
    r'baseURL:\s*["\']([^"\']+)["\']',
    r'BASE_URL\s*=\s*["\']([^"\']+)["\']',
]

# Status codes that mean "endpoint exists / interesting"
# Split into two tiers:
#   PROBE_INTERESTING   → worth reporting regardless of path type
#   SENSITIVE_INTERESTING → only interesting when the PATH itself is sensitive
#
# The key insight: a 403 on /robots.txt is NOT interesting (every site blocks it).
# A 403 on /.env IS interesting (something is there, just blocked).
# A 200 on /admin IS interesting but needs content verification.
# A 200 on /robots.txt is NOT a vulnerability — it's expected.

PROBE_INTERESTING    = {200, 201, 204, 301, 302, 307, 308, 401, 405}
SENSITIVE_INTERESTING = {200, 201, 401, 403, 405}  # 403 only for sensitive paths

# Paths where a 403 response IS meaningful (something exists but is blocked)
SENSITIVE_PATH_PREFIXES = {
    "/.env", "/.git", "/wp-config", "/config.php", "/phpinfo",
    "/backup", "/dump", "/db.sql", "/.htaccess", "/web.config",
    "/actuator", "/server-status", "/server-info",
    "/phpmyadmin", "/xmlrpc.php",
}

# Paths where a 200 is expected and NOT a finding (public by design)
EXPECTED_200_PATHS = {
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/.well-known/security.txt", "/favicon.ico",
    "/health", "/ping", "/status",
}


class EndpointDiscoveryAgent:
    """
    Discovers API endpoints via passive parsing + JS extraction + path probing.
    All requests are GET-only (read-only).  No payload injection at this stage.
    """

    def __init__(self, timeout: int = 5, max_probe_paths: int = 30):
        self.timeout        = timeout
        self.max_probe_paths = max_probe_paths  # cap active probing

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def discover(self, target_url: str,
                       page_html: str = "",
                       verbose: bool = False) -> List[Dict]:
        """
        Run all three discovery strategies and return deduplicated,
        verified endpoints.

        Fix 1: Deduplicate by normalised URL (strip trailing slash,
               lowercase scheme+host, keep path case).
        Fix 5: After discovery, verify interesting endpoints beyond
               just HTTP status — check for login forms, admin panels,
               API JSON responses, directory listings.
        """
        if verbose:
            print(f"\n  Endpoint Discovery Agent")
            print(f"   Target: {target_url}")

        base = self._base_url(target_url)
        found: List[Dict] = []

        results = await asyncio.gather(
            self._strategy_passive_files(base, verbose),
            self._strategy_js_extraction(base, page_html, verbose),
            self._strategy_common_paths(base, verbose),
            return_exceptions=True
        )

        for r in results:
            if isinstance(r, list):
                found.extend(r)

        # ── Fix 1: Deduplicate by normalised URL ─────────────────────
        # Prefer probed entries (non-None status) over passive-parse entries
        # (robots.txt/sitemap set status=None and are never deep-verified).
        seen:   Dict[str, Dict] = {}
        for ep in found:
            url = ep.get("url", "")
            if not url:
                continue
            norm     = self._normalise_url(url)
            existing = seen.get(norm)
            if existing is None:
                seen[norm] = ep
            elif existing.get("status") is None and ep.get("status") is not None:
                seen[norm] = ep  # upgrade to the probed version
        unique: List[Dict] = list(seen.values())

        # ── Fix 5: Deep verification for interesting endpoints ────────
        if verbose:
            print(f"    Verifying {len(unique)} endpoints...")

        verified: List[Dict] = []
        verify_tasks = [self._verify_endpoint(ep) for ep in unique]
        verify_results = await asyncio.gather(*verify_tasks, return_exceptions=True)

        for ep, result in zip(unique, verify_results):
            if isinstance(result, dict):
                verified.append(result)
            else:
                verified.append(ep)

        # Sort: interesting first, then by URL
        verified.sort(key=lambda x: (not x.get("interesting"), x.get("url", "")))

        if verbose:
            interesting = [e for e in verified if e.get("interesting")]
            print(f"   ✓ Discovered {len(verified)} endpoints "
                  f"({len(interesting)} interesting)\n")

        return verified

    async def _verify_endpoint(self, ep: Dict) -> Dict:
        """
        Fix 5: Deep endpoint verification.

        Goes beyond HTTP status to check what the endpoint actually contains:
          - Login/auth forms → tag as auth_endpoint
          - Admin panel indicators → tag as admin_panel
          - JSON API response → tag as api_endpoint
          - Directory listing → tag as directory_listing
          - Sensitive file content → tag as sensitive_file
          - 403 on sensitive path → tag as access_controlled (not exposed)

        This prevents /wp-config.php returning 403 from being reported as
        "exposed" — it's access-controlled, which is the correct behaviour.
        """
        url    = ep.get("url", "")
        status = ep.get("status")

        # Only deep-verify endpoints we actually probed (have a status)
        if status is None:
            return ep

        # 403 on a sensitive path = access controlled = NOT a finding
        sensitive_paths = (
            "wp-config", ".env", "config.php", "database.yml",
            ".git/config", "backup", "dump.sql"
        )
        if status == 403:
            path_lower = url.lower()
            if any(s in path_lower for s in sensitive_paths):
                ep["interesting"]    = False
                ep["access_controlled"] = True
                ep["verification"]   = "403 — access controlled, not exposed"
                return ep

        # For 200 responses, fetch body and classify
        if status == 200:
            body = await self._fetch_text(url) or ""
            body_lower = body.lower()

            # Sensitive file actually exposed (200 + content match)
            sensitive_content_patterns = [
                ("DB_PASSWORD",   "env_file_exposed"),
                ("database.yml",  "config_exposed"),
                ("secret_key",    "secret_exposed"),
                ("password",      "credential_exposed"),
                ("[boot loader]", "windows_hosts_exposed"),
                ("root:x:",       "etc_passwd_exposed"),
            ]
            for pattern, tag in sensitive_content_patterns:
                if pattern.lower() in body_lower:
                    ep["interesting"]       = True
                    ep["verification"]      = f"Sensitive content detected: {tag}"
                    ep["content_type_tag"]  = tag
                    ep["severity"]          = "Critical"
                    return ep

            # Login / auth form
            if any(kw in body_lower for kw in (
                'type="password"', "type='password'",
                "login", "sign in", "signin", "authenticate"
            )):
                ep["interesting"]  = True
                ep["auth_endpoint"] = True
                ep["verification"] = "Login form detected"
                return ep

            # Admin panel
            if any(kw in body_lower for kw in (
                "admin", "dashboard", "control panel",
                "management console", "administrator"
            )):
                ep["interesting"]   = True
                ep["admin_panel"]   = True
                ep["verification"]  = "Admin panel indicators detected"
                return ep

            # JSON API response
            stripped = body.strip()
            if stripped.startswith(("{", "[")):
                try:
                    import json as _json
                    _json.loads(stripped[:500])
                    ep["interesting"]  = True
                    ep["api_endpoint"] = True
                    ep["verification"] = "JSON API response confirmed"
                    return ep
                except Exception:
                    pass

            # Directory listing
            if "index of /" in body_lower or "<title>directory listing" in body_lower:
                ep["interesting"]        = True
                ep["directory_listing"]  = True
                ep["verification"]       = "Directory listing enabled"
                ep["severity"]           = "Medium"
                return ep

            # Generic 200 — mark as interesting but unclassified
            ep["verification"] = "HTTP 200 — content unclassified"
            return ep

        # 401 = auth required (endpoint exists, protected)
        if status == 401:
            ep["auth_required"] = True
            ep["verification"]  = "HTTP 401 — authentication required"
            return ep

        # 405 = method not allowed (endpoint exists, wrong method)
        if status == 405:
            ep["verification"] = "HTTP 405 — endpoint exists, wrong method"
            return ep

        return ep

    def _normalise_url(self, url: str) -> str:
        """
        Normalise URL for deduplication.
        Strips trailing slash, lowercases scheme and host, preserves path case.
        e.g. https://Example.com/Admin/ → https://example.com/Admin
        """
        try:
            from urllib.parse import urlparse, urlunparse
            p = urlparse(url)
            norm = urlunparse((
                p.scheme.lower(),
                p.netloc.lower(),
                p.path.rstrip("/") or "/",
                p.params,
                p.query,
                ""  # drop fragment
            ))
            return norm
        except Exception:
            return url.rstrip("/")

    # ------------------------------------------------------------------
    # Strategy 1 — Passive file parsing
    # ------------------------------------------------------------------

    async def _strategy_passive_files(self, base: str,
                                       verbose: bool = False) -> List[Dict]:
        """Parse robots.txt, sitemap.xml, swagger, manifest."""
        if verbose:
            print("    Strategy 1: Passive file parsing...")

        endpoints: List[Dict] = []

        tasks = [
            self._parse_robots(base),
            self._parse_sitemap(base),
            self._parse_swagger(base),
            self._parse_manifest(base),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                endpoints.extend(r)

        if verbose:
            print(f"     ✓ Passive: {len(endpoints)} endpoints")

        return endpoints

    async def _parse_robots(self, base: str) -> List[Dict]:
        endpoints = []
        url = f"{base}/robots.txt"
        body = await self._fetch_text(url)
        if not body:
            return endpoints

        _STATIC_EXTS = frozenset({
            ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
            ".css", ".js", ".woff", ".woff2", ".ttf", ".eot", ".otf",
            ".pdf", ".mp4", ".mp3", ".zip",
        })

        for line in body.splitlines():
            line = line.strip()
            if line.lower().startswith(("disallow:", "allow:")):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    path = parts[1].strip()
                    if not path or path == "/":
                        continue
                    # Glob patterns are crawler directives, not real endpoints
                    if "*" in path:
                        continue
                    # Static assets have no scannable attack surface
                    ext = os.path.splitext(path.split("?")[0])[-1].lower()
                    if ext in _STATIC_EXTS:
                        continue
                    full_url = urljoin(base, path)
                    endpoints.append({
                        "url":          full_url,
                        "method":       "GET",
                        "source":       "robots.txt",
                        "status":       None,
                        "interesting":  True,
                        "auth_required":False,
                        "params":       []
                    })
        return endpoints

    async def _parse_sitemap(self, base: str) -> List[Dict]:
        endpoints = []
        for path in ("/sitemap.xml", "/sitemap_index.xml"):
            body = await self._fetch_text(f"{base}{path}")
            if not body:
                continue
            # Extract <loc> URLs
            for loc in re.findall(r'<loc>([^<]+)</loc>', body):
                loc = loc.strip()
                if loc:
                    endpoints.append({
                        "url":          loc,
                        "method":       "GET",
                        "source":       "sitemap",
                        "status":       None,
                        "interesting":  True,
                        "auth_required":False,
                        "params":       []
                    })
        return endpoints

    async def _parse_swagger(self, base: str) -> List[Dict]:
        """Parse OpenAPI/Swagger JSON for all defined routes."""
        endpoints = []
        swagger_paths = [
            "/swagger.json", "/openapi.json",
            "/api/swagger.json", "/api/openapi.json",
            "/api/docs/openapi.json", "/v1/openapi.json",
        ]

        for path in swagger_paths:
            body = await self._fetch_text(f"{base}{path}")
            if not body:
                continue
            try:
                spec = json.loads(body)
                paths = spec.get("paths", {})
                for route, methods in paths.items():
                    for method in methods.keys():
                        if method.lower() in ("get","post","put","delete","patch"):
                            full_url = urljoin(base, route)
                            # Extract query params from spec
                            params = []
                            for m_data in methods.values():
                                if isinstance(m_data, dict):
                                    for p in m_data.get("parameters", []):
                                        if isinstance(p, dict) and p.get("in") == "query":
                                            params.append(p.get("name", ""))
                            endpoints.append({
                                "url":          full_url,
                                "method":       method.upper(),
                                "source":       "swagger",
                                "status":       None,
                                "interesting":  True,
                                "auth_required":False,
                                "params":       [p for p in params if p]
                            })
                if endpoints:
                    break  # Found and parsed one swagger doc — stop
            except Exception:
                continue

        return endpoints

    async def _parse_manifest(self, base: str) -> List[Dict]:
        """Parse Angular/React manifest or asset-manifest for JS bundle URLs."""
        endpoints = []
        for path in ("/asset-manifest.json", "/manifest.json",
                     "/ngsw.json", "/assets/manifest.json"):
            body = await self._fetch_text(f"{base}{path}")
            if not body:
                continue
            try:
                data = json.loads(body)
                # Angular ngsw / React asset-manifest structure
                for key, val in (data.get("urls", {}) or {}).items():
                    if isinstance(val, str) and val.endswith(".js"):
                        endpoints.append({
                            "url":          urljoin(base, val),
                            "method":       "GET",
                            "source":       "manifest",
                            "status":       None,
                            "interesting":  False,
                            "auth_required":False,
                            "params":       [],
                            "_is_js_bundle": True  # flag for strategy 2
                        })
            except Exception:
                continue
        return endpoints

    # ------------------------------------------------------------------
    # Strategy 2 — JavaScript endpoint extraction
    # ------------------------------------------------------------------

    async def _strategy_js_extraction(self, base: str,
                                       page_html: str,
                                       verbose: bool = False) -> List[Dict]:
        """
        Extract API endpoint strings from JS source files.

        Fix 3: Extended JS discovery to handle modern frameworks:
          - Nuxt:  /_nuxt/ chunks referenced as .js or via __nuxt_manifest__
          - Next:  /_next/static/ chunks
          - Vite:  /assets/*.js chunks
          - React: /static/js/*.chunk.js
          Also scans inline <script> blocks (env vars, route configs often there).
        """
        if verbose:
            print("    Strategy 2: JavaScript endpoint extraction...")

        endpoints: List[Dict] = []
        js_urls: Set[str] = set()

        # From HTML: <script src="...">
        js_urls |= self._extract_js_urls(base, page_html)

        # From HTML: inline <script> blocks
        inline_scripts = re.findall(
            r'<script(?:[^>]*)>(.*?)</script>',
            page_html, re.DOTALL | re.IGNORECASE
        )

        # Framework-specific chunk manifests
        # Nuxt 3: __NUXT_MANIFEST__ or _payload.json links
        # Next.js: _next/static/chunks/pages/
        framework_paths = [
            # Common SPA entry points
            "/main.js", "/bundle.js", "/app.js",
            "/static/js/main.js", "/assets/index.js",
            # Nuxt 2/3
            "/_nuxt/app.js", "/_nuxt/manifest.js",
            "/_nuxt/client.js", "/_nuxt/index.js",
            # Next.js
            "/_next/static/chunks/main.js",
            "/_next/static/chunks/pages/index.js",
            # Vite
            "/assets/index.js",
            # Angular
            "/main.js", "/runtime.js", "/polyfills.js",
        ]
        for fp in framework_paths:
            js_urls.add(urljoin(base, fp))

        # Nuxt/Next chunk references in HTML  (e.g. /_nuxt/abc123.js)
        chunk_patterns = [
            r'/_nuxt/[^"\'>\s]+\.js',
            r'/_next/static/[^"\'>\s]+\.js',
            r'/assets/[^"\'>\s]+\.js',
            r'/static/js/[^"\'>\s]+\.js',
        ]
        for pat in chunk_patterns:
            for match in re.finditer(pat, page_html):
                js_urls.add(urljoin(base, match.group(0)))

        # Fetch up to 8 JS files (more than before — chunks matter)
        fetch_tasks = [self._fetch_text(url) for url in list(js_urls)[:8]]
        js_bodies   = await asyncio.gather(*fetch_tasks, return_exceptions=True)

        # Combine with inline scripts
        all_sources = list(js_bodies) + inline_scripts

        seen_paths: Set[str] = set()

        for source in all_sources:
            if not isinstance(source, str) or not source:
                continue

            for pattern in JS_ENDPOINT_PATTERNS:
                for match in re.finditer(pattern, source):
                    path = match.group(1).strip()
                    if not path or path in seen_paths:
                        continue

                    # Must start with / or http
                    if not (path.startswith("/") or path.startswith("http")):
                        continue

                    # Normalise absolute URLs to just the path
                    if path.startswith("http"):
                        try:
                            parsed_path = urllib.parse.urlparse(path)
                            if parsed_path.netloc and \
                               parsed_path.netloc not in base:
                                continue  # external domain, skip
                            path = parsed_path.path
                        except Exception:
                            continue

                    # Filter static assets
                    if re.search(
                        r'\.(png|jpg|gif|css|woff|woff2|svg|ico|map|ttf|eot)$',
                        path, re.I
                    ):
                        continue

                    # Filter very short or obviously non-API paths
                    if len(path) < 3 or path in ("/", "//"):
                        continue

                    seen_paths.add(path)
                    full_url = urljoin(base, path)
                    endpoints.append({
                        "url":          full_url,
                        "method":       "GET",
                        "source":       "js_bundle",
                        "status":       None,
                        "interesting":  True,
                        "auth_required":False,
                        "params":       []
                    })

        if verbose:
            print(f"     ✓ JS extraction: {len(endpoints)} endpoints "
                  f"(from {len(js_urls)} JS files + {len(inline_scripts)} inline blocks)")

        return endpoints

    def _extract_js_urls(self, base: str, html: str) -> Set[str]:
        """Find <script src="..."> URLs from page HTML — any .js or chunk file."""
        urls: Set[str] = set()
        # Standard src attribute
        for src in re.findall(
            r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I
        ):
            if src.endswith(".js") or "/chunk" in src or "/_nuxt/" in src \
               or "/_next/" in src:
                urls.add(urljoin(base, src))
        # Preload links (modern frameworks preload chunks)
        for href in re.findall(
            r'<link[^>]+href=["\']([^"\']+\.js)["\']', html, re.I
        ):
            urls.add(urljoin(base, href))
        return urls

    # ------------------------------------------------------------------
    # Strategy 3 — Common path probing
    # ------------------------------------------------------------------

    async def _strategy_common_paths(self, base: str,
                                      verbose: bool = False) -> List[Dict]:
        """Probe common API and admin paths with GET requests."""
        if verbose:
            print("    Strategy 3: Common path probing...")

        paths_to_probe = COMMON_PATHS[:self.max_probe_paths]

        # Run probes in batches of 10 to avoid hammering the server
        batch_size = 10
        endpoints: List[Dict] = []

        for i in range(0, len(paths_to_probe), batch_size):
            batch = paths_to_probe[i:i + batch_size]
            tasks = [self._probe_path(base, path) for path in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, dict):
                    endpoints.append(r)

        interesting = [e for e in endpoints if e.get("interesting")]

        if verbose:
            print(f"     ✓ Probed {len(paths_to_probe)} paths → "
                  f"{len(interesting)} interesting")

        return endpoints

    async def _probe_path(self, base: str, path: str) -> Optional[Dict]:
        """
        Probe a single path and return endpoint dict if interesting.

        Fix 1: Tiered status evaluation.
          - 403 only interesting on SENSITIVE_PATH_PREFIXES (/.env, /.git etc)
          - 200 on EXPECTED_200_PATHS (robots.txt, sitemap) → not a finding
          - Generic text/html 200s filtered unless path looks like a real endpoint
          - content_type recorded for downstream classification
        """
        url = f"{base}{path}"
        try:
            loop = asyncio.get_event_loop()
            status, headers = await loop.run_in_executor(
                None, lambda: self._sync_head(url)
            )

            if status == 0:
                return None

            path_lower    = path.lower()
            content_type  = headers.get("Content-Type", "").lower()
            auth_required = status in (401, 403)

            # Public-by-design: 200 is expected, mark non-interesting
            if path_lower in EXPECTED_200_PATHS and status == 200:
                return {
                    "url": url, "method": "GET", "source": "probe",
                    "status": status, "interesting": False,
                    "auth_required": False, "params": [],
                    "content_type": content_type, "note": "public-by-design"
                }

            # Sensitive paths: 403 IS meaningful
            is_sensitive = any(
                path_lower.startswith(p) for p in SENSITIVE_PATH_PREFIXES
            )

            if is_sensitive:
                is_interesting = status in SENSITIVE_INTERESTING
            else:
                # Generic: 403 is NOT interesting (could be any WAF block)
                is_interesting = status in PROBE_INTERESTING

            if not is_interesting:
                return None

            # For generic 200s: filter catch-all HTML pages
            if status == 200 and "text/html" in content_type and not is_sensitive:
                looks_like_endpoint = any(kw in path_lower for kw in (
                    "admin", "api", "login", "dashboard", "console",
                    "panel", "manage", "swagger", "debug", "shell", "graphql"
                ))
                if not looks_like_endpoint:
                    return None  # Likely WAF/CDN catch-all, not a real path

            return {
                "url":          url,
                "method":       "GET",
                "source":       "probe",
                "status":       status,
                "interesting":  True,
                "auth_required":auth_required,
                "params":       [],
                "content_type": content_type,
                "is_sensitive": is_sensitive,
            }
        except Exception:
            return None

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    async def _fetch_text(self, url: str) -> Optional[str]:
        """Fetch text content of a URL asynchronously."""
        loop = asyncio.get_event_loop()
        try:
            return await loop.run_in_executor(
                None, lambda: self._sync_get_text(url)
            )
        except Exception:
            return None

    def _sync_get_text(self, url: str, max_bytes: int = 500_000) -> Optional[str]:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (SecurityScanner)",
                    "Accept":     "*/*"
                }
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status not in (200, 201):
                    return None
                return resp.read(max_bytes).decode("utf-8", errors="replace")
        except Exception:
            return None

    def _sync_head(self, url: str):
        """Return (status, headers) for a URL using HEAD then GET fallback."""
        for method in ("HEAD", "GET"):
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (SecurityScanner)"},
                    method=method
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return resp.status, dict(resp.headers)
            except urllib.error.HTTPError as e:
                return e.code, dict(e.headers) if e.headers else {}
            except Exception:
                if method == "GET":
                    return 0, {}
        return 0, {}

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _base_url(self, url: str) -> str:
        """Return scheme://host:port with no path."""
        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}"
        return base.rstrip("/")