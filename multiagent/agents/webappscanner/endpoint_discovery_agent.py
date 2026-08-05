# agents/endpoint_discovery_agent.py


import os
import re
import json
import hashlib
import asyncio
import logging
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse, urljoin, urlsplit, urlunparse

logger = logging.getLogger(__name__)



# Classic server-rendered / PHP / CMS entrypoints (product-agnostic)
SSR_COMMON_PATHS = [
    "/login.php",
    "/login",
    "/signin",
    "/sign-in",
    "/setup.php",
    "/install.php",
    "/register.php",
    "/signup",
    "/index.php",
    "/admin.php",
    "/admin/login.php",
    "/admin/login",
    "/security.php",
    "/logout.php",
    "/user/login",
    "/account/login",
    "/wp-login.php",
    "/wp-admin",
    "/xmlrpc.php",
    "/phpmyadmin",
    "/phpinfo.php",
    "/admin",
    "/administrator",
    "/dashboard",
    "/manage",
    "/upload",
    "/uploads",
    "/files",
]

# Generic API / SPA surfaces (product-agnostic — no app brand paths)
API_COMMON_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/rest",
    "/graphql",
    "/query",
    "/api/auth",
    "/api/login",
    "/api/logout",
    "/api/register",
    "/api/token",
    "/api/users",
    "/api/user",
    "/api/me",
    "/api/profile",
    "/api/admin",
    "/api/search",
    "/api/v1/search",
    "/rest/search",
    "/api/config",
    "/api/admin/config",
    "/api/health",
    "/api/status",
    "/api/docs",
    "/swagger",
    "/swagger-ui",
    "/swagger.json",
    "/openapi.json",
    "/api/openapi.json",
    "/oauth",
    "/oauth2",
]

# Sensitive / ops / docs (always worth a few slots)
SENSITIVE_COMMON_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/config",
    "/config",
    "/config.json",
    "/config.php",
    "/settings",
    "/web.config",
    "/.htaccess",
    "/backup",
    "/backup.zip",
    "/backup.sql",
    "/dump.sql",
    "/db.sql",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/server-status",
    "/health",
    "/status",
    "/ping",
    "/metrics",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/debug",
    "/info",
    "/console",
]

# Backward-compatible flat list (SSR first so the probe budget hits classic apps)
COMMON_PATHS = SSR_COMMON_PATHS + API_COMMON_PATHS + SENSITIVE_COMMON_PATHS

# Patterns to find API endpoints in JS source
JS_ENDPOINT_PATTERNS = [
    r'["\'](/api/[^"\'?\s]{2,80})["\']',
    r'["\'](/rest/[^"\'?\s]{2,80})["\']',
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

PROBE_INTERESTING     = {200, 201, 204, 301, 302, 307, 308, 401, 405}
SENSITIVE_INTERESTING = {200, 201, 401, 403, 405}

SENSITIVE_PATH_PREFIXES = {
    "/.env", "/.git", "/wp-config", "/config.php", "/phpinfo",
    "/backup", "/dump", "/db.sql", "/.htaccess", "/web.config",
    "/actuator", "/server-status", "/server-info",
    "/phpmyadmin", "/xmlrpc.php",
}

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

    def __init__(self, timeout: int = 5, max_probe_paths: int = 60):
        self.timeout          = timeout
        self.max_probe_paths  = max_probe_paths
        self._soft_mode:          bool       = False
        self._soft404_lengths:    List[int]  = []
        self._soft404_bodies:     List[str]  = []

  
    # Soft-404 calibration
    async def calibrate(self, base: str) -> None:
        """
        Enable soft-404 mode only when unknown paths return a same-path 200
        with a reusable body baseline (true SPA/catch-all).
        Off-path redirects alone do NOT enable soft mode — classic PHP apps
        often redirect unknown URLs to login without being SPAs.
        """
        rand_paths = [
            f"/{hashlib.sha1(f'{base}{i}'.encode()).hexdigest()[:16]}-zz{i}"
            for i in range(3)
        ]
        same_path_hits = 0
        self._soft404_lengths = []
        self._soft404_bodies = []

        for p in rand_paths:
            url = f"{base}{p}"
            try:
                loop = asyncio.get_event_loop()
                status, _, final_url = await loop.run_in_executor(
                    None, lambda _u=url: self._sync_head(_u)
                )
                if 200 <= status < 300:
                    asked  = (urlsplit(url).path or "/").rstrip("/") or "/"
                    landed = (urlsplit(final_url).path or "/").rstrip("/") or "/"
                    if landed == asked or landed == asked + "/" or asked == landed + "/":
                        same_path_hits += 1
                        body = await self._fetch_text(url) or ""
                        self._soft404_lengths.append(len(body))
                        if body:
                            self._soft404_bodies.append(body)
                    # else: redirect to another path (e.g. /login.php) — not SPA soft-404
            except Exception:
                pass

        # Require body baselines so we can similarity-gate probes
        self._soft_mode = same_path_hits >= 2 and len(self._soft404_bodies) >= 1
        if self._soft_mode:
            logger.info(
                "EndpointDiscovery: soft-404/catch-all site detected "
                "(baseline body lengths: %s, bodies=%d)",
                self._soft404_lengths, len(self._soft404_bodies),
            )

    def _select_probe_paths(self, page_html: str = "") -> List[str]:
        """
        Product-agnostic probe list: prefer SSR/PHP paths when HTML/stack
        signals a classic app; prefer API paths when JS/API signals dominate.
        Always mix both families within the budget.
        """
        html = page_html or ""
        html_l = html.lower()
        php_signal = (
            ".php" in html_l
            or "x-powered-by: php" in html_l
            or "name=\"username\"" in html_l
            or "name='username'" in html_l
            or "name=\"password\"" in html_l
            or "<form" in html_l
        )
        api_signal = (
            "/api/" in html_l
            or "/rest/" in html_l
            or "fetch(" in html_l
            or "axios." in html_l
            or "graphql" in html_l
            or "application/json" in html_l
        )

        # Paths referenced in HTML always get priority (grounded, not guessed brands)
        html_paths: List[str] = []
        for m in re.finditer(
            r'''(?:href|action)=["']([^"']+)["']''', html, re.I
        ):
            raw = m.group(1).strip()
            if not raw or raw.startswith(("#", "javascript:", "mailto:")):
                continue
            path = urlsplit(raw).path or ""
            if path.startswith("/") and 1 < len(path) < 80:
                html_paths.append(path.split(";")[0])

        ordered: List[str] = []
        seen: Set[str] = set()

        def _extend(paths):
            for p in paths:
                if p not in seen:
                    seen.add(p)
                    ordered.append(p)

        _extend(html_paths)
        if php_signal and not api_signal:
            _extend(SSR_COMMON_PATHS)
            _extend(API_COMMON_PATHS[:12])
        elif api_signal and not php_signal:
            _extend(API_COMMON_PATHS)
            _extend(SSR_COMMON_PATHS[:12])
        else:
            # Mixed / unknown — interleave so classic apps aren't starved
            _extend(SSR_COMMON_PATHS)
            _extend(API_COMMON_PATHS)
        _extend(SENSITIVE_COMMON_PATHS)
        return ordered[: self.max_probe_paths]

    def _matches_spa_shell(self, body: str, content_type: str = "") -> bool:
        """True when response is the SPA catch-all shell (not a real endpoint)."""
        if not self._soft_mode or not body:
            return False
        ct = (content_type or "").lower()
        stripped = body.lstrip()
        # Real JSON/API bodies are never the Angular/HTML shell
        if "json" in ct or stripped.startswith(("{", "[")):
            return False
        try:
            from .vulnerability_tester import (
                _same_document_shell, _normalize_body_fingerprint,
            )
        except Exception:
            from multiagent.agents.webappscanner.vulnerability_tester import (  # type: ignore
                _same_document_shell, _normalize_body_fingerprint,
            )
        for baseline in self._soft404_bodies:
            # Real SPA shells are large; also accept exact normalized equality
            # for smaller catch-all templates (min_len relaxed to 80).
            if _same_document_shell(body, baseline, min_len=80):
                return True
            nb = _normalize_body_fingerprint(body)
            nbase = _normalize_body_fingerprint(baseline)
            if nb and nbase and nb == nbase:
                return True
        # Length prefilter when bodies weren't stored but lengths were
        if self._soft404_lengths and not self._soft404_bodies:
            blen = len(body)
            for bl in self._soft404_lengths:
                if bl > 200 and abs(blen - bl) <= max(80, int(bl * 0.05)):
                    # HTML-ish and same size as bogus path → treat as shell
                    if "<html" in body.lower() or "<!doctype" in body.lower():
                        return True
        return False


    async def discover(self, target_url: str,
                       page_html: str = "",
                       verbose: bool = False) -> List[Dict]:
        """
        Run all three discovery strategies and return deduplicated,
        verified endpoints.
        """
        if verbose:
            print(f"\n  Endpoint Discovery Agent")
            print(f"   Target: {target_url}")

        base = self._base_url(target_url)

        # Calibrate soft-404 detection before any probing
        await self.calibrate(base)
        if verbose and self._soft_mode:
            print(f"    ⚠ Soft-404/catch-all site detected — redirect filter active")

        found: List[Dict] = []

        results = await asyncio.gather(
            self._strategy_passive_files(base, verbose),
            self._strategy_js_extraction(base, page_html, verbose),
            self._strategy_common_paths(base, page_html=page_html, verbose=verbose),
            return_exceptions=True
        )

        for r in results:
            if isinstance(r, list):
                found.extend(r)

       
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
                seen[norm] = ep
        unique: List[Dict] = list(seen.values())

 
        if verbose:
            print(f"    Verifying {len(unique)} endpoints...")

        verified: List[Dict] = []
        verify_tasks   = [self._verify_endpoint(ep) for ep in unique]
        verify_results = await asyncio.gather(*verify_tasks, return_exceptions=True)

        for ep, result in zip(unique, verify_results):
            if isinstance(result, dict):
                verified.append(result)
            else:
                verified.append(ep)

    
        verified.sort(key=lambda x: (not x.get("interesting"), x.get("url", "")))

        if verbose:
            interesting = [e for e in verified if e.get("interesting")]
            print(f"   ✓ Discovered {len(verified)} endpoints "
                  f"({len(interesting)} interesting)\n")

        return verified



    async def _verify_endpoint(self, ep: Dict) -> Dict:
   
        url    = ep.get("url", "")
        status = ep.get("status")

        if status is None:
            return ep

        if status == 403:
            ep["interesting"]       = False
            ep["access_controlled"] = True
            ep["verification"]      = "403 — access controlled, not exposed"
            return ep
        
        if status == 200:
            body       = await self._fetch_text(url) or ""
            body_lower = body.lower()
            ctype      = (ep.get("content_type") or "").lower()

            # Drop SPA catch-all shells before keyword heuristics
            if self._matches_spa_shell(body, ctype):
                ep["interesting"]  = False
                ep["verification"] = "SPA/soft-404 shell — not a real endpoint"
                return ep

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
                    ep["interesting"]      = True
                    ep["verification"]     = f"Sensitive content detected: {tag}"
                    ep["content_type_tag"] = tag
                    ep["severity"]         = "Critical"
                    return ep

            # JSON API response (real surface — keep)
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

            # Login / auth form (HTML only — never on SPA shell, already gated)
            if any(kw in body_lower for kw in (
                'type="password"', "type='password'",
                "login", "sign in", "signin", "authenticate"
            )):
                ep["interesting"]   = True
                ep["auth_endpoint"] = True
                ep["verification"]  = "Login form detected"
                return ep

            # Admin panel indicators in HTML
            if any(kw in body_lower for kw in (
                "admin", "dashboard", "control panel",
                "management console", "administrator"
            )):
                ep["interesting"]  = True
                ep["admin_panel"]  = True
                ep["verification"] = "Admin panel indicators detected"
                return ep

            # Directory listing
            if "index of /" in body_lower or "<title>directory listing" in body_lower:
                ep["interesting"]       = True
                ep["directory_listing"] = True
                ep["verification"]      = "Directory listing enabled"
                ep["severity"]          = "Medium"
                return ep

            # Only drop unclassified HTML when it truly matches the SPA shell.
            # Classic SSR apps often return unique HTML 200s that must stay.
            if self._soft_mode and ("html" in ctype or "<html" in body_lower):
                if self._matches_spa_shell(body, ctype):
                    ep["interesting"]  = False
                    ep["verification"] = "SPA/soft-404 shell — not a real endpoint"
                    return ep

            # SSR signal: HTML page with a form is an injectable surface
            if "<form" in body_lower and ("html" in ctype or "<html" in body_lower):
                ep["interesting"]  = True
                ep["has_form"]     = True
                ep["verification"] = "HTML form surface detected"
                return ep

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
        try:
            p = urlparse(url)
            return urlunparse((
                p.scheme.lower(), p.netloc.lower(),
                p.path.rstrip("/") or "/",
                p.params, p.query, ""
            ))
        except Exception:
            return url.rstrip("/")

 

    async def _strategy_passive_files(self, base: str,
                                       verbose: bool = False) -> List[Dict]:
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
        url  = f"{base}/robots.txt"
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
                    if "*" in path:
                        continue
                    ext = os.path.splitext(path.split("?")[0])[-1].lower()
                    if ext in _STATIC_EXTS:
                        continue
                    full_url = urljoin(base, path)
                    endpoints.append({
                        "url":          full_url,
                        "method":       "GET",
                        "source":       "robots.txt",
                        "status":       None,
                        "final_url":    full_url,
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
            for loc in re.findall(r'<loc>([^<]+)</loc>', body):
                loc = loc.strip()
                if loc:
                    endpoints.append({
                        "url":          loc,
                        "method":       "GET",
                        "source":       "sitemap",
                        "status":       None,
                        "final_url":    loc,
                        "interesting":  True,
                        "auth_required":False,
                        "params":       []
                    })
        return endpoints

    async def _parse_swagger(self, base: str) -> List[Dict]:
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
                spec   = json.loads(body)
                paths  = spec.get("paths", {})
                for route, methods in paths.items():
                    for method in methods.keys():
                        if method.lower() in ("get","post","put","delete","patch"):
                            full_url = urljoin(base, route)
                            params   = []
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
                                "final_url":    full_url,
                                "interesting":  True,
                                "auth_required":False,
                                "params":       [p for p in params if p]
                            })
                if endpoints:
                    break
            except Exception:
                continue
        return endpoints

    async def _parse_manifest(self, base: str) -> List[Dict]:
        endpoints = []
        for path in ("/asset-manifest.json", "/manifest.json",
                     "/ngsw.json", "/assets/manifest.json"):
            body = await self._fetch_text(f"{base}{path}")
            if not body:
                continue
            try:
                data = json.loads(body)
                for key, val in (data.get("urls", {}) or {}).items():
                    if isinstance(val, str) and val.endswith(".js"):
                        full_url = urljoin(base, val)
                        endpoints.append({
                            "url":          full_url,
                            "method":       "GET",
                            "source":       "manifest",
                            "status":       None,
                            "final_url":    full_url,
                            "interesting":  False,
                            "auth_required":False,
                            "params":       [],
                            "_is_js_bundle": True
                        })
            except Exception:
                continue
        return endpoints


    async def _strategy_js_extraction(self, base: str,
                                       page_html: str,
                                       verbose: bool = False) -> List[Dict]:
        if verbose:
            print("    Strategy 2: JavaScript endpoint extraction...")

        endpoints: List[Dict] = []
        js_urls: Set[str]     = set()

        js_urls |= self._extract_js_urls(base, page_html)

        inline_scripts = re.findall(
            r'<script(?:[^>]*)>(.*?)</script>',
            page_html, re.DOTALL | re.IGNORECASE
        )

        framework_paths = [
            "/main.js", "/bundle.js", "/app.js",
            "/static/js/main.js", "/assets/index.js",
            "/_nuxt/app.js", "/_nuxt/manifest.js",
            "/_nuxt/client.js", "/_nuxt/index.js",
            "/_next/static/chunks/main.js",
            "/_next/static/chunks/pages/index.js",
            "/assets/index.js",
            "/main.js", "/runtime.js", "/polyfills.js",
        ]
        for fp in framework_paths:
            js_urls.add(urljoin(base, fp))

        chunk_patterns = [
            r'/_nuxt/[^"\'>\s]+\.js',
            r'/_next/static/[^"\'>\s]+\.js',
            r'/assets/[^"\'>\s]+\.js',
            r'/static/js/[^"\'>\s]+\.js',
        ]
        for pat in chunk_patterns:
            for match in re.finditer(pat, page_html):
                js_urls.add(urljoin(base, match.group(0)))

        fetch_tasks = [self._fetch_text(url) for url in list(js_urls)[:8]]
        js_bodies   = await asyncio.gather(*fetch_tasks, return_exceptions=True)

        all_sources  = list(js_bodies) + inline_scripts
        seen_paths: Set[str] = set()

        for source in all_sources:
            if not isinstance(source, str) or not source:
                continue
            for pattern in JS_ENDPOINT_PATTERNS:
                for match in re.finditer(pattern, source):
                    path = match.group(1).strip()
                    if not path or path in seen_paths:
                        continue
                    if not (path.startswith("/") or path.startswith("http")):
                        continue
                    if path.startswith("http"):
                        try:
                            parsed_path = urllib.parse.urlparse(path)
                            if parsed_path.netloc and parsed_path.netloc not in base:
                                continue
                            path = parsed_path.path
                        except Exception:
                            continue
                    if re.search(
                        r'\.(png|jpg|gif|css|woff|woff2|svg|ico|map|ttf|eot)$',
                        path, re.I
                    ):
                        continue
                    if len(path) < 3 or path in ("/", "//"):
                        continue
                    seen_paths.add(path)
                    full_url = urljoin(base, path)
                    endpoints.append({
                        "url":          full_url,
                        "method":       "GET",
                        "source":       "js_bundle",
                        "status":       None,
                        "final_url":    full_url,
                        "interesting":  True,
                        "auth_required":False,
                        "params":       []
                    })

        if verbose:
            print(f"     ✓ JS extraction: {len(endpoints)} endpoints "
                  f"(from {len(js_urls)} JS files + {len(inline_scripts)} inline blocks)")
        return endpoints

    def _extract_js_urls(self, base: str, html: str) -> Set[str]:
        urls: Set[str] = set()
        for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            if src.endswith(".js") or "/chunk" in src or "/_nuxt/" in src \
               or "/_next/" in src:
                urls.add(urljoin(base, src))
        for href in re.findall(r'<link[^>]+href=["\']([^"\']+\.js)["\']', html, re.I):
            urls.add(urljoin(base, href))
        return urls



    async def _strategy_common_paths(self, base: str,
                                      page_html: str = "",
                                      verbose: bool = False) -> List[Dict]:
        if verbose:
            print("    Strategy 3: Common path probing...")

        paths_to_probe = self._select_probe_paths(page_html)
        batch_size     = 10
        endpoints: List[Dict] = []

        for i in range(0, len(paths_to_probe), batch_size):
            batch   = paths_to_probe[i:i + batch_size]
            tasks   = [self._probe_path(base, path) for path in batch]
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

        url = f"{base}{path}"
        try:
            loop = asyncio.get_event_loop()
            status, headers, final_url = await loop.run_in_executor(
                None, lambda: self._sync_head(url)
            )

            if status == 0:
                return None

            path_lower    = path.lower()
            content_type  = ""
            for k, v in (headers or {}).items():
                if str(k).lower() == "content-type":
                    content_type = str(v).lower()
                    break
            auth_required = status in (401, 403)

            if final_url and final_url != url:
                asked  = (urlsplit(url).path or "/").rstrip("/") or "/"
                landed = (urlsplit(final_url).path or "/").rstrip("/") or "/"
           
                is_slash_redirect = (
                    landed == asked + "/" or asked == landed + "/"
                )
                if not is_slash_redirect and landed != asked:
                    # Keep only when redirect target or requested path looks like auth/setup.
                    landed_l = landed.lower()
                    authish = any(k in landed_l or k in path_lower for k in (
                        "login", "signin", "sign-in", "auth", "sso",
                        "account", "setup", "install", "register", "signup",
                    ))
                    if authish:
                        return {
                            "url":           url,
                            "method":        "GET",
                            "source":        "probe",
                            "status":        status,
                            "final_url":     final_url,
                            "interesting":   True,
                            "auth_required": True,
                            "auth_endpoint": True,
                            "params":        [],
                            "content_type":  content_type,
                            "verification":  f"Redirects to auth surface {landed}",
                        }
                    logger.debug(
                        "probe: drop %s — redirected off-path to %s", url, final_url
                    )
                    return None


            if path_lower in EXPECTED_200_PATHS and status == 200:
                return {
                    "url": url, "method": "GET", "source": "probe",
                    "status": status, "final_url": final_url or url,
                    "interesting": False, "auth_required": False,
                    "params": [], "content_type": content_type,
                    "note": "public-by-design"
                }


            is_sensitive = any(
                path_lower.startswith(p) for p in SENSITIVE_PATH_PREFIXES
            )

            if is_sensitive:
                is_interesting = status in SENSITIVE_INTERESTING
            else:
                is_interesting = status in PROBE_INTERESTING

            if not is_interesting:
                return None

            # Auth challenges prove the route exists without needing body compare
            if status in (401, 405):
                return {
                    "url":          url,
                    "method":       "GET",
                    "source":       "probe",
                    "status":       status,
                    "final_url":    final_url or url,
                    "interesting":  True,
                    "auth_required": auth_required,
                    "params":       [],
                    "content_type": content_type,
                    "is_sensitive": is_sensitive,
                }

            # SPA catch-all gate: do not trust status 200 alone
            if status == 200 and self._soft_mode:
                body = await self._fetch_text(url) or ""
                if self._matches_spa_shell(body, content_type):
                    logger.debug(
                        "probe: drop %s — SPA/soft-404 shell match (status 200)", url
                    )
                    return None
                # Persist body fingerprint hint for verify stage
                content_type = content_type or (
                    "application/json" if body.lstrip()[:1] in "{[" else content_type
                )

            if status == 200 and "text/html" in content_type and not is_sensitive:
                looks_like_endpoint = any(kw in path_lower for kw in (
                    "admin", "api", "login", "signin", "sign-in", "setup",
                    "install", "register", "signup", "dashboard", "console",
                    "panel", "manage", "swagger", "debug", "shell", "graphql",
                    "security", "upload", "vulnerability", ".php",
                ))
                if not looks_like_endpoint:
                    return None

            return {
                "url":          url,
                "method":       "GET",
                "source":       "probe",
                "status":       status,
                "final_url":    final_url or url,
                "interesting":  True,
                "auth_required":auth_required,
                "params":       [],
                "content_type": content_type,
                "is_sensitive": is_sensitive,
            }
        except Exception:
            return None



    async def _fetch_text(self, url: str) -> Optional[str]:
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
        """
        Return (status, headers, final_url) using HEAD then GET fallback.

        final_url is the URL after all redirects — used by _probe_path to
        detect catch-all / soft-404 sites that redirect unknown paths to an
        existing page (e.g. a blog article) while returning HTTP 200.
        """
        for method in ("HEAD", "GET"):
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (SecurityScanner)"},
                    method=method
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return resp.status, dict(resp.headers), resp.url
            except urllib.error.HTTPError as e:
                return e.code, dict(e.headers) if e.headers else {}, url
            except Exception:
                if method == "GET":
                    return 0, {}, url
        return 0, {}, url


    def _base_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")