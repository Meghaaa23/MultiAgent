

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

_SPA_STRONG_SIGNALS = (
    "<app-root", "ng-version", "router-outlet",
    "React.createElement", "__NEXT_DATA__", "__vue_app__",
    'id="root"', "id='root'", 'id="app"', "id='app'",
    "data-reactroot",
)
_SPA_WEAK_SIGNALS = (
    "<!DOCTYPE html>", "<script src=", "window.__",
    "webpackJsonp", "vite/client",
)

_ADMIN_STRONG_MARKERS = (
    "admin panel", "administration", "wp-admin",
    "django administration", "control panel",
    "management console", "admin dashboard",
    "administrator login", "site administration",
)

def looks_like_spa_shell(body: str) -> bool:
    if not body:
        return False
    has_strong = any(s in body for s in _SPA_STRONG_SIGNALS)
    weak_count = sum(1 for s in _SPA_WEAK_SIGNALS if s in body)
    return has_strong or weak_count >= 2

def has_strong_admin_content(body: str) -> bool:
    low = (body or "").lower()
    return any(m in low for m in _ADMIN_STRONG_MARKERS)

def _is_api_surface_path(url_or_path: str) -> bool:
    path = (url_or_path or "").lower()
    try:
        path = (urlsplit(url_or_path).path or path).lower()
    except Exception:
        pass
    return any(
        p in path for p in ("/api/", "/rest/", "/graphql", "/v1/", "/v2/", "/v3/")
    ) or path.rstrip("/").endswith(("/api", "/rest", "/graphql"))

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
    "/wp-json",
    "/wp-json/wp/v2",
    "/wp-json/wp/v2/users",
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

COMMON_PATHS = SSR_COMMON_PATHS + API_COMMON_PATHS + SENSITIVE_COMMON_PATHS

JS_ENDPOINT_PATTERNS = [
    r'["\'](/(?:api|rest|v\d+)/[^"\'\s]{2,120})["\']',
    r'["\'](/api/[^"\'\s]{2,100})["\']',
    r'["\'](/rest/[^"\'\s]{2,100})["\']',
    r'["\'](/v\d+/[^"\'\s]{2,100})["\']',
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

STATIC_EXTS = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
    ".css", ".js", ".map", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".mp4", ".mp3", ".zip", ".gz", ".tgz", ".rar",
})

STATIC_CONTENT_TYPES = (
    "text/css",
    "text/javascript",
    "application/javascript",
    "application/x-javascript",
    "image/",
    "font/",
    "application/font",
    "application/octet-stream",
)

def is_static_asset(url: str = "", content_type: str = "") -> bool:
    """True for CSS/JS/images/fonts — not API or HTML attack surface."""
    path = ""
    try:
        path = (urlsplit(url or "").path or "").lower()
    except Exception:
        path = (url or "").lower()
    ext = os.path.splitext(path.split("?")[0])[-1].lower()
    if ext in STATIC_EXTS:
        return True
    ct = (content_type or "").lower().split(";")[0].strip()
    if not ct:
        return False
    if ct.startswith("image/") or ct.startswith("font/"):
        return True
    if ct in (
        "text/css",
        "text/javascript",
        "application/javascript",
        "application/x-javascript",
        "application/font-woff",
        "application/font-woff2",
        "application/vnd.ms-fontobject",
    ):
        return True
    return False

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
            except Exception:
                pass

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

        html_paths: List[str] = []
        for m in re.finditer(
            r'''(?:href|action)=["']([^"']+)["']''', html, re.I
        ):
            raw = m.group(1).strip()
            if not raw or raw.startswith(("#", "javascript:", "mailto:")):
                continue
            path = urlsplit(raw).path or ""
            if path.startswith("/") and 1 < len(path) < 80:
                cleaned = path.split(";")[0]
                if is_static_asset(cleaned):
                    continue
                html_paths.append(cleaned)

        ordered: List[str] = []
        seen: Set[str] = set()

        def _extend(paths):
            for p in paths:
                if p not in seen:
                    seen.add(p)
                    ordered.append(p)

        _extend(html_paths)
        if getattr(self, "_soft_mode", False) or (api_signal and not php_signal):
            _extend(API_COMMON_PATHS)
            _extend(SSR_COMMON_PATHS[:12])
        elif php_signal and not api_signal:
            _extend(SSR_COMMON_PATHS)
            _extend(API_COMMON_PATHS[:12])
        else:
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
        if "json" in ct or stripped.startswith(("{", "[")):
            return False
        try:
            from .vulnerability_tester import (
                _same_document_shell, _normalize_body_fingerprint,
            )
        except Exception:
            from multiagent.agents.webappscanner.vulnerability_tester import (
                _same_document_shell, _normalize_body_fingerprint,
            )
        for baseline in self._soft404_bodies:
            if _same_document_shell(body, baseline, min_len=80):
                return True
            nb = _normalize_body_fingerprint(body)
            nbase = _normalize_body_fingerprint(baseline)
            if nb and nbase and nb == nbase:
                return True
        if self._soft404_lengths and not self._soft404_bodies:
            blen = len(body)
            for bl in self._soft404_lengths:
                if bl > 200 and abs(blen - bl) <= max(80, int(bl * 0.05)):
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

        try:
            oa_extra = await self._enrich_openapi_from_discovered(base, verified)
            if oa_extra:
                existing_keys = {
                    (e.get("method", "GET"), self._normalise_url(e.get("url", "")))
                    for e in verified
                }
                added = 0
                for ep in oa_extra:
                    key = (ep.get("method", "GET"), self._normalise_url(ep.get("url", "")))
                    if key in existing_keys:
                        continue
                    verified.append(ep)
                    existing_keys.add(key)
                    added += 1
                if verbose and added:
                    print(f"    OpenAPI enrichment: +{added} operation(s) from docs/spec")
        except Exception as e:
            logger.debug("OpenAPI enrichment failed: %s", e)

        verified.sort(key=lambda x: (not x.get("interesting"), x.get("url", "")))

        if verbose:
            interesting = [e for e in verified if e.get("interesting")]
            print(f"   ✓ Discovered {len(verified)} endpoints "
                  f"({len(interesting)} interesting)\n")

        return verified

    async def _enrich_openapi_from_discovered(
        self, base: str, endpoints: List[Dict]
    ) -> List[Dict]:
        """Parse OpenAPI from any discovered docs/spec URLs."""
        candidates: List[str] = []
        for ep in endpoints:
            url = ep.get("url") or ""
            if not url:
                continue
            path = (urllib.parse.urlsplit(url).path or "").lower()
            if any(
                k in path
                for k in (
                    "/docs", "swagger", "redoc", "openapi", "docs-json",
                    "documentation",
                )
            ):
                candidates.append(url)
        for path in (
            "/api/openapi.json", "/openapi.json", "/api/docs/json",
            "/api/docs-json", "/docs-json", "/api/swagger.json",
            "/v3/api-docs", "/api/v3/api-docs", "/api-docs",
            "/swagger/v1/swagger.json", "/api/v1/openapi.json",
            "/openapi.yaml", "/api/openapi.yaml",
        ):
            candidates.append(base.rstrip("/") + path)

        seen_cands: set = set()
        for cand in candidates:
            if cand in seen_cands:
                continue
            seen_cands.add(cand)
            path_l = (urllib.parse.urlsplit(cand).path or "").lower()
            if any(k in path_l for k in ("/docs", "swagger-ui", "redoc", "documentation")) and not path_l.endswith(
                (".json", ".yaml", ".yml")
            ):
                html = await self._fetch_text(cand)
                if html and not html.lstrip().startswith(("{", "[")):
                    embedded = self._endpoints_from_embedded_openapi(
                        html, base, source_url=cand
                    )
                    if embedded:
                        return embedded
                    for ref in self._extract_openapi_refs_from_html(html, base):
                        url = ref if ref.startswith("http") else urljoin(base, ref)
                        parsed = await self._endpoints_from_openapi_url(url, base)
                        if parsed:
                            return parsed
            parsed = await self._endpoints_from_openapi_url(cand, base)
            if parsed:
                return parsed
        return []

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

        ctype = (ep.get("content_type") or "").lower()
        if is_static_asset(url, ctype):
            ep["interesting"]  = False
            ep["static_asset"] = True
            ep["admin_panel"]  = False
            ep["verification"] = "Static asset — excluded from endpoint table"
            return ep
        
        if status == 200:
            body       = await self._fetch_text(url) or ""
            body_lower = body.lower()
            ctype      = (ep.get("content_type") or ctype or "").lower()
            if is_static_asset(url, ctype) or (
                body and not ("html" in ctype or "<html" in body_lower[:200])
                and (
                    ctype.startswith("text/css")
                    or ctype.startswith("image/")
                    or ctype.startswith("font/")
                )
            ):
                ep["interesting"]  = False
                ep["static_asset"] = True
                ep["admin_panel"]  = False
                ep["verification"] = "Static asset — excluded from endpoint table"
                return ep

            path_l = urllib.parse.urlsplit(ep.get("url") or "").path.lower()
            openapi_ish = any(
                k in path_l for k in (
                    "openapi", "swagger.json", "swagger.yaml", "swagger.yml",
                )
            )
            if openapi_ish and (
                self._matches_spa_shell(body, ctype)
                or not (body.lstrip()[:1] in "{[" or "json" in ctype)
            ):
                rescued = await self._fetch_text_accept_json(ep.get("url") or "")
                if rescued and rescued.lstrip()[:1] in "{[":
                    body = rescued
                    ctype = "application/json"
                    ep["content_type"] = ctype
                    try:
                        spec = json.loads(rescued)
                        if isinstance(spec, dict) and (
                            spec.get("openapi") or spec.get("swagger") or spec.get("paths")
                        ):
                            ep["interesting"] = True
                            ep["api_endpoint"] = True
                            ep["spa_catch_all"] = False
                            ep["excluded"] = False
                            ep["verification"] = "OpenAPI/Swagger spec confirmed"
                            return ep
                    except Exception:
                        pass

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

            is_html = "html" in ctype or "<html" in body_lower[:500]

            if is_html and any(kw in body_lower for kw in (
                'type="password"', "type='password'",
                "login", "sign in", "signin", "authenticate"
            )):
                ep["interesting"]   = True
                ep["auth_endpoint"] = True
                ep["verification"]  = "Login form detected"
                return ep

            if is_html and has_strong_admin_content(body):
                if looks_like_spa_shell(body) and (
                    self._soft_mode or self._matches_spa_shell(body, ctype)
                ):
                    ep["interesting"]   = False
                    ep["spa_catch_all"] = True
                    ep["admin_panel"]   = False
                    ep["excluded"]      = True
                    ep["exclude_reason"] = "SPA catch-all — not a real admin endpoint"
                    ep["verification"]  = "SPA catch-all shell — not a confirmed admin panel"
                    return ep
                ep["interesting"]  = True
                ep["admin_panel"]  = True
                ep["verification"] = "Admin panel indicators detected"
                return ep

            if is_html and (
                self._matches_spa_shell(body, ctype) or looks_like_spa_shell(body)
            ):
                if self._soft_mode or self._matches_spa_shell(body, ctype):
                    ep["interesting"]    = False
                    ep["spa_catch_all"]  = True
                    ep["admin_panel"]    = False
                    ep["excluded"]       = True
                    ep["exclude_reason"] = "SPA/soft-404 shell — not a real endpoint"
                    ep["verification"]   = "SPA/soft-404 shell — not a real endpoint"
                    return ep

            if "index of /" in body_lower or "<title>directory listing" in body_lower:
                ep["interesting"]       = True
                ep["directory_listing"] = True
                ep["verification"]      = "Directory listing enabled"
                ep["severity"]          = "Medium"
                return ep

            if "<form" in body_lower and ("html" in ctype or "<html" in body_lower):
                ep["interesting"]  = True
                ep["has_form"]     = True
                ep["verification"] = "HTML form surface detected"
                return ep

            ep["verification"] = "HTTP 200 — content unclassified"
            return ep

        if status == 401:
            ep["auth_required"] = True
            ep["verification"]  = "HTTP 401 — authentication required"
            return ep

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
                    if is_static_asset(path):
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
                if not loc or is_static_asset(loc):
                    continue
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
        """
        First-class OpenAPI/Swagger discovery: fetch machine-readable specs
        (Accept: application/json), and also follow /api/docs|/swagger UI
        pages to their underlying spec URL.
        """
        endpoints: List[Dict] = []
        swagger_paths = [
            "/swagger.json", "/openapi.json",
            "/api/swagger.json", "/api/openapi.json",
            "/api/docs/openapi.json", "/api/docs/json",
            "/api/docs-json", "/docs-json", "/docs/json",
            "/v1/openapi.json", "/openapi.yaml", "/openapi.yml",
            "/api/openapi.yaml", "/swagger/v1/swagger.json",
            "/api/v1/openapi.json", "/api/swagger-json",
            "/v3/api-docs", "/api/v3/api-docs", "/api-docs",
        ]
        docs_ui_paths = (
            "/api/docs", "/docs", "/swagger", "/swagger-ui",
            "/swagger-ui/", "/api/swagger", "/redoc", "/api/redoc",
            "/api/documentation", "/documentation",
        )

        for ui_path in docs_ui_paths:
            ui_url = f"{base}{ui_path}"
            parsed = await self._endpoints_from_openapi_url(ui_url, base)
            if parsed:
                return parsed
            html = await self._fetch_text(ui_url)
            if not html:
                continue
            embedded = self._endpoints_from_embedded_openapi(
                html, base, source_url=ui_url
            )
            if embedded:
                return embedded
            for ref in self._extract_openapi_refs_from_html(html, base):
                if ref.startswith("http"):
                    parsed = await self._endpoints_from_openapi_url(ref, base)
                    if parsed:
                        return parsed
                elif ref not in swagger_paths:
                    swagger_paths.append(ref)

        for path in swagger_paths:
            url = path if path.startswith("http") else f"{base}{path}"
            parsed = await self._endpoints_from_openapi_url(url, base)
            if parsed:
                return parsed
        return endpoints

    @staticmethod
    def _extract_openapi_refs_from_html(html: str, base: str) -> List[str]:
        """Pull likely OpenAPI/Swagger spec URLs from a docs UI page."""
        if not html:
            return []
        refs: List[str] = []
        patterns = [
            r"""url\s*[:=]\s*["']([^"']+(?:openapi|swagger|docs-json|docs/json|api-docs)[^"']*)["']""",
            r"""["']([^"']+/openapi\.(?:json|ya?ml))["']""",
            r"""["']([^"']+/swagger\.(?:json|ya?ml))["']""",
            r"""["']([^"']+(?:docs-json|/docs/json|/api/docs/json|/v3/api-docs))["']""",
            r"""["']((?:https?:)?//[^"']+(?:openapi|swagger)\.(?:json|ya?ml))["']""",
            r"""spec(?:Url|URL)?\s*[:=]\s*["']([^"']+)["']""",
            r"""swaggerUrl\s*[:=]\s*["']([^"']+)["']""",
            r"""configUrl\s*[:=]\s*["']([^"']+)["']""",
            r"""href=["']([^"']*(?:openapi|swagger|api-docs)[^"']*)["']""",
            r"""fetch\(\s*["']([^"']+(?:openapi|swagger|api-docs)[^"']*)["']""",
        ]
        for pat in patterns:
            for m in re.findall(pat, html, flags=re.I):
                ref = (m or "").strip()
                if not ref or ref.startswith("data:") or ref.startswith("#"):
                    continue
                if ref.startswith("//"):
                    ref = "http:" + ref
                if ref.startswith("./"):
                    ref = urljoin(base + "/", ref[2:])
                if ref.startswith("http") or ref.startswith("/"):
                    refs.append(ref)
        return list(dict.fromkeys(refs))

    @classmethod
    def _extract_embedded_openapi_specs(cls, html: str) -> List[Dict]:
        """
        Best-effort extract of OpenAPI/Swagger JSON objects embedded in docs HTML.
        Does not invent specs — only parses objects that already contain paths.
        """
        if not html or len(html) < 40:
            return []
        specs: List[Dict] = []
        decoder = json.JSONDecoder()
        markers = []
        for m in re.finditer(
            r"""["'](?:openapi|swagger)["']\s*:""", html, flags=re.I
        ):
            markers.append(m.start())
        for m in re.finditer(
            r"""(?:__redoc_state|Redoc\.init|SwaggerUIBundle)\s*[=(]""",
            html, flags=re.I,
        ):
            markers.append(m.start())
        if not markers:
            return []

        tried: set = set()
        for mark in markers[:12]:
            start = html.rfind("{", max(0, mark - 8000), mark + 1)
            if start < 0 or start in tried:
                start = html.find("{", mark, mark + 400)
            if start < 0 or start in tried:
                continue
            tried.add(start)
            chunk = html[start:start + 900_000]
            try:
                obj, _end = decoder.raw_decode(chunk)
            except Exception:
                continue
            candidates = [obj]
            if isinstance(obj, dict):
                for key in ("spec", "data", "openapi", "swaggerDoc", "definition"):
                    inner = obj.get(key)
                    if isinstance(inner, dict):
                        candidates.append(inner)
                    elif isinstance(inner, str) and inner.lstrip().startswith("{"):
                        try:
                            candidates.append(json.loads(inner))
                        except Exception:
                            pass
            for cand in candidates:
                if not isinstance(cand, dict):
                    continue
                if not (cand.get("openapi") or cand.get("swagger")):
                    continue
                paths = cand.get("paths")
                if isinstance(paths, dict) and paths:
                    specs.append(cand)
                    break
            if specs:
                break
        return specs

    def _endpoints_from_embedded_openapi(
        self, html: str, base: str, source_url: str = ""
    ) -> List[Dict]:
        for spec in self._extract_embedded_openapi_specs(html):
            parsed = self._endpoints_from_openapi_spec(
                spec, base, source_url=source_url or "embedded"
            )
            if parsed:
                return parsed
        return []

    def _endpoints_from_openapi_spec(
        self, spec: Dict, base: str, source_url: str = ""
    ) -> List[Dict]:
        """Emit path operations from a parsed OpenAPI/Swagger dict."""
        if not isinstance(spec, dict):
            return []
        if not (spec.get("openapi") or spec.get("swagger") or spec.get("paths")):
            return []
        paths = spec.get("paths") or {}
        if not isinstance(paths, dict) or not paths:
            return []

        endpoints: List[Dict] = []
        for route, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, m_data in methods.items():
                if method.lower() not in ("get", "post", "put", "delete", "patch"):
                    continue
                full_url = urljoin(base, route)
                params: List[str] = []
                if isinstance(m_data, dict):
                    for p in m_data.get("parameters") or []:
                        if isinstance(p, dict) and p.get("in") == "query" and p.get("name"):
                            params.append(str(p["name"]))
                endpoints.append({
                    "url":           full_url,
                    "method":        method.upper(),
                    "source":        "swagger",
                    "status":        None,
                    "final_url":     full_url,
                    "interesting":   True,
                    "auth_required": False,
                    "api_endpoint":  True,
                    "params":        params,
                    "openapi_spec":  source_url or "embedded",
                })
        return endpoints

    async def _endpoints_from_openapi_url(self, url: str, base: str) -> List[Dict]:
        """Fetch one OpenAPI/Swagger document and emit path operations."""
        body = await self._fetch_text_accept_json(url)
        if not body:
            body = await self._fetch_text(url)
        if not body:
            return []
        stripped = body.lstrip()
        if stripped.lower().startswith(("<!doctype", "<html")):
            return self._endpoints_from_embedded_openapi(
                body, base, source_url=url
            )
        spec = None
        try:
            spec = json.loads(body)
        except Exception:
            if re.search(r"(?m)^(openapi|swagger)\s*:", body) and "paths:" in body:
                spec = self._minimal_yaml_openapi_paths(body)
        if not isinstance(spec, dict):
            return []
        return self._endpoints_from_openapi_spec(spec, base, source_url=url)

    @staticmethod
    def _minimal_yaml_openapi_paths(text: str) -> Optional[Dict]:
        """Best-effort path key extraction from YAML OpenAPI (no full YAML dep)."""
        paths: Dict[str, Dict] = {}
        in_paths = False
        current_path = None
        for line in text.splitlines():
            if re.match(r"^paths\s*:", line):
                in_paths = True
                current_path = None
                continue
            if not in_paths:
                continue
            if re.match(r"^[A-Za-z]", line):
                break
            m_path = re.match(r"^  (/[^:]+)\s*:", line)
            if m_path:
                current_path = m_path.group(1).strip()
                paths.setdefault(current_path, {})
                continue
            m_op = re.match(
                r"^    (get|post|put|delete|patch)\s*:", line, flags=re.I
            )
            if m_op and current_path:
                paths[current_path][m_op.group(1).lower()] = {}
        if not paths:
            return None
        return {"openapi": "3.0.0", "paths": paths}

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

        def _js_priority(u: str) -> int:
            ul = u.lower()
            score = 0
            for kw, w in (
                ("main", 5), ("runtime", 4), ("vendor", 3), ("polyfill", 2),
                ("chunk", 1), ("app.", 3), ("bundle", 2),
            ):
                if kw in ul:
                    score += w
            return -score

        js_list = sorted(js_urls, key=_js_priority)[:16]
        fetch_tasks = [self._fetch_text(url) for url in js_list]
        js_bodies   = await asyncio.gather(*fetch_tasks, return_exceptions=True)

        all_sources  = list(js_bodies) + inline_scripts
        seen_keys: Set[str] = set()

        for source in all_sources:
            if not isinstance(source, str) or not source:
                continue
            for pattern in JS_ENDPOINT_PATTERNS:
                for match in re.finditer(pattern, source):
                    raw = match.group(1).strip()
                    if not raw:
                        continue
                    if not (raw.startswith("/") or raw.startswith("http")):
                        continue
                    query = ""
                    path = raw
                    try:
                        parsed_path = urllib.parse.urlparse(
                            raw if raw.startswith("http") else f"http://x{raw}"
                        )
                        if raw.startswith("http"):
                            if parsed_path.netloc and parsed_path.netloc not in base:
                                continue
                        path = parsed_path.path or ""
                        query = parsed_path.query or ""
                    except Exception:
                        continue
                    if re.search(
                        r'\.(png|jpg|gif|css|woff|woff2|svg|ico|map|ttf|eot)$',
                        path, re.I
                    ):
                        continue
                    if len(path) < 3 or path in ("/", "//"):
                        continue
                    pl = path.lower()
                    if not any(
                        pl.startswith(p) for p in (
                            "/api/", "/rest/", "/v1/", "/v2/", "/v3/", "/graphql"
                        )
                    ) and not any(
                        k in pl for k in ("/api", "/rest", "login", "search", "config")
                    ):
                        if not re.search(r"/(api|rest|graphql)/", pl):
                            continue
                    key = f"{path}?{query}" if query else path
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    params = []
                    if query:
                        params = list(urllib.parse.parse_qs(query).keys())
                    full_url = urljoin(base, path + (f"?{query}" if query else ""))
                    endpoints.append({
                        "url":          full_url,
                        "method":       "GET",
                        "source":       "js_bundle",
                        "status":       None,
                        "final_url":    full_url,
                        "interesting":  True,
                        "auth_required":False,
                        "params":       params,
                    })

        if verbose:
            print(f"     ✓ JS extraction: {len(endpoints)} endpoints "
                  f"(from {len(js_list)}/{len(js_urls)} JS files + "
                  f"{len(inline_scripts)} inline blocks)")
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
            if is_static_asset(path):
                return None

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
            if is_static_asset(url, content_type):
                return None
            auth_required = status in (401, 403)

            if final_url and final_url != url:
                asked  = (urlsplit(url).path or "/").rstrip("/") or "/"
                landed = (urlsplit(final_url).path or "/").rstrip("/") or "/"
           
                is_slash_redirect = (
                    landed == asked + "/" or asked == landed + "/"
                )
                if not is_slash_redirect and landed != asked:
                    landed_l = landed.lower()
                    authish = any(k in landed_l or k in path_lower for k in (
                        "login", "signin", "sign-in", "auth", "sso",
                        "account", "setup", "install", "register", "signup",
                    ))
                    if authish:
                        return {
                            "url":               url,
                            "method":            "GET",
                            "source":            "probe",
                            "status":            status,
                            "redirect_status":   "REDIR",
                            "final_url":         final_url,
                            "interesting":       True,
                            "auth_required":     status in (401, 403),
                            "redirects_to_auth": True,
                            "auth_endpoint":     True,
                            "params":            [],
                            "content_type":      content_type,
                            "verification":      f"Redirects to auth surface {landed}",
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

            if status == 200 and self._soft_mode:
                body = await self._fetch_text(url) or ""
                if self._matches_spa_shell(body, content_type):
                    api_ish = any(
                        k in path_lower for k in ("/api", "/rest", "/graphql")
                    )
                    rescued = None
                    if api_ish:
                        for try_url in (
                            url,
                            (url + ("&" if "?" in url else "?") + "q=test"),
                        ):
                            rescued = await self._fetch_text_accept_json(try_url)
                            if rescued and not self._matches_spa_shell(
                                rescued, "application/json"
                            ):
                                body = rescued
                                content_type = "application/json"
                                url = try_url
                                break
                            rescued = None
                    if rescued is None and self._matches_spa_shell(body, content_type):
                        logger.debug(
                            "probe: drop %s — SPA/soft-404 shell match (status 200)", url
                        )
                        return None
                content_type = content_type or (
                    "application/json" if body.lstrip()[:1] in "{[" else content_type
                )

            if status == 200 and "text/html" in content_type and not is_sensitive:
                looks_like_endpoint = any(kw in path_lower for kw in (
                    "admin", "api", "rest", "login", "signin", "sign-in", "setup",
                    "install", "register", "signup", "dashboard", "console",
                    "panel", "manage", "swagger", "debug", "shell", "graphql",
                    "security", "upload", "vulnerability", "search", ".php",
                ))
                if not looks_like_endpoint:
                    return None

                adminish = any(kw in path_lower for kw in (
                    "admin", "dashboard", "manage", "console", "panel",
                ))
                graphql_ish = "graphql" in path_lower
                if adminish or graphql_ish:
                    body = await self._fetch_text(url) or ""
                    spa_html = body and (
                        looks_like_spa_shell(body)
                        or self._matches_spa_shell(body, content_type)
                    )
                    if spa_html and adminish and not has_strong_admin_content(body):
                        logger.debug(
                            "probe: drop %s — SPA/soft-404 catch-all", url
                        )
                        return {
                            "url": url, "method": "GET", "source": "probe",
                            "status": status, "final_url": final_url or url,
                            "interesting": False, "auth_required": False,
                            "spa_catch_all": True, "excluded": True,
                            "exclude_reason": "SPA catch-all — not a real admin endpoint",
                            "params": [], "content_type": content_type,
                            "verification": "SPA catch-all — not a real admin endpoint",
                        }
                    if spa_html and graphql_ish and body.lstrip()[:1] not in "{[":
                        return {
                            "url": url, "method": "GET", "source": "probe",
                            "status": status, "final_url": final_url or url,
                            "interesting": False, "auth_required": False,
                            "spa_catch_all": True, "excluded": True,
                            "exclude_reason": "SPA catch-all — not a GraphQL API",
                            "params": [], "content_type": content_type,
                            "verification": "SPA catch-all — not a GraphQL API",
                        }

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

    async def _fetch_text_accept_json(self, url: str) -> Optional[str]:
        loop = asyncio.get_event_loop()
        try:
            return await loop.run_in_executor(
                None, lambda: self._sync_get_text(url, accept="application/json")
            )
        except Exception:
            return None

    def _sync_get_text(self, url: str, max_bytes: int = 500_000,
                       accept: str = "*/*") -> Optional[str]:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (SecurityScanner)",
                    "Accept":     accept,
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