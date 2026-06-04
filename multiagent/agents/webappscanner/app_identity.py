# agents/webappscanner/app_identity.py

import re
import json
import logging
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class AppIdentity:
    """Discovered identity of a web application."""
    name:         Optional[str]  = None
    version:      Optional[str]  = None
    technologies: List[str]      = field(default_factory=list)
    confidence:   str            = "low"
    evidence:     str            = ""
    cve_queries:  List[str]      = field(default_factory=list)

    def best_cve_query(self) -> Optional[str]:
        """Return the most specific CVE search query."""
        if self.cve_queries:
            return self.cve_queries[0]
        if self.name:
            q = self.name
            if self.version:
                q += f" {self.version}"
            return q
        return None


# ---------------------------------------------------------------------------
# Signal extractors — each tries one source
# ---------------------------------------------------------------------------

def _from_page_title(html: str) -> Tuple[Optional[str], Optional[str], str]:
    """
    Extract app name from <title> tag.
    Patterns:
      "Redmine"                    → name="Redmine"
      "My Project - Redmine"       → name="Redmine"
      "GitLab"                     → name="GitLab"
      "Jenkins [Jenkins]"          → name="Jenkins"
      "Powered by WordPress"       → name="WordPress"
    """
    m = re.search(r'<title[^>]*>([^<]{1,200})</title>', html, re.IGNORECASE)
    if not m:
        return None, None, ""

    title = m.group(1).strip()

    # Try last segment
    segments = re.split(r'\s*[-|–—·•]\s*', title)
    candidates = [segments[-1].strip(), segments[0].strip()]

    for candidate in candidates:
        candidate = re.sub(r'\s*\[.*?\]\s*$', '', candidate).strip()
        if _looks_like_app_name(candidate):
            version = _extract_version_from_string(candidate)
            name = re.sub(r'\s*\d[\d.]*\s*$', '', candidate).strip()
            return name, version, f"page title: {title!r}"

    return None, None, ""


def _from_generator_meta(html: str) -> Tuple[Optional[str], Optional[str], str]:
    """
    Extract from <meta name="generator" content="WordPress 6.4.2">
    This is the most reliable signal — apps explicitly announce themselves.
    """
    m = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']{1,200})["\']',
        html, re.IGNORECASE
    )
    if not m:
        # reverse attribute order
        m = re.search(
            r'<meta[^>]+content=["\']([^"\']{1,200})["\'][^>]+name=["\']generator["\']',
            html, re.IGNORECASE
        )
    if not m:
        return None, None, ""

    content = m.group(1).strip()
    version = _extract_version_from_string(content)
    name    = re.sub(r'\s*\d[\d.]*\s*$', '', content).strip()
    return name, version, f"generator meta: {content!r}"


def _from_powered_by(html: str, headers: Dict) -> Tuple[Optional[str], Optional[str], str]:
    """
    Extract from:
      - X-Powered-By: Express, Phusion Passenger 6.0, PHP/8.1
      - HTML: "Powered by Redmine", "Powered by Discourse"
    """
    # Header first
    powered_by = headers.get("x-powered-by", "")
    if powered_by:
        version = _extract_version_from_string(powered_by)
        name    = re.sub(r'[/\s]\d[\d.]*', '', powered_by).strip()
        # Strip generic runtimes
        generic = {"php", "express", "asp.net", "node.js", "python"}
        if name.lower() not in generic and _looks_like_app_name(name):
            return name, version, f"X-Powered-By: {powered_by!r}"

    # HTML "Powered by X" pattern
    m = re.search(
        r'[Pp]owered\s+by\s+<[^>]*>([^<]{2,60})</[^>]*>|'
        r'[Pp]owered\s+by\s+([A-Z][a-zA-Z0-9_.\s]{1,40}?)(?:\s*v?[\d.]+)?[\s<"\']',
        html
    )
    if m:
        name = (m.group(1) or m.group(2) or "").strip()
        if _looks_like_app_name(name):
            version = _extract_version_from_string(name)
            name    = re.sub(r'\s*\d[\d.]*\s*$', '', name).strip()
            return name, version, f"HTML powered-by: {name!r}"

    return None, None, ""


def _from_js_bundles(html: str) -> Tuple[Optional[str], Optional[str], str]:
    """
    Detect frontend framework from script src paths and inline JS globals.
    Passes through Cloudflare and all CDNs unchanged — content is never modified.
    Works for ANY modern SPA or framework-based application.
    """
    patterns = {
        "Next.js":     [r'/_next/static/',    r'__NEXT_DATA__',      r'"next":\s*"[\d.]+'],
        "Nuxt":        [r'/_nuxt/',           r'__NUXT__',           r'"nuxt":\s*"[\d.]+'],
        "React":       [r'react\.development\.js', r'react-dom',     r'__reactFiber',
                        r'data-reactroot',    r'_reactRootContainer'],
        "Vue":         [r'vue\.runtime',      r'__vue_app__',        r'data-v-app',
                        r'createApp\('],
        "Angular":     [r'ng-version=',       r'zone\.js',           r'_nghost',
                        r'angular\.min',      r'ng-app=',            r'router-outlet'],
        "Gatsby":      [r'___gatsby',         r'/page-data/',        r'gatsby-chunk'],
        "Remix":       [r'__remixContext',    r'@remix-run',         r'remix\.run'],
        "SvelteKit":   [r'__sveltekit',      r'svelte/internal',    r'@sveltejs'],
        "Ember":       [r'ember\.debug',      r'Ember\.VERSION',     r'ember-application'],
        "Backbone":    [r'backbone\.js',      r'Backbone\.View',     r'backbone\.min'],
        "Alpine.js":   [r'alpine\.js',        r'x-data=',            r'alpinejs'],
        "WordPress":   [r'/wp-content/',      r'/wp-includes/',      r'wp-json',
                        r'wp-emoji',          r'wpApiSettings'],
        "Shopify":     [r'Shopify\.theme',    r'cdn\.shopify\.com',
                        r'shopify\.com/s/files'],
        "Webflow":     [r'webflow\.com/js',   r'data-wf-page',       r'webflow\.js'],
        "Squarespace": [r'squarespace\.com',  r'static\.squarespace'],
        "Wix":         [r'static\.parastorage\.com', r'wix\.com/pages'],
        "HubSpot":     [r'js\.hubspot\.com',  r'hubspot\.com/hs-scripts'],
        "Ghost":       [r'ghost\.org',        r'ghost/core',         r'ghost-sdk'],
        # Note: Do NOT add platform names like Gradio, Streamlit here.
        # These are product names, not universal structural signals.
        # Detection of ML platforms happens via AIFingerprintAgent
        # using endpoint probing and response header analysis.
    }

    for framework, signals in patterns.items():
        if any(re.search(p, html, re.IGNORECASE) for p in signals):
            # Try to extract version for frameworks that embed it
            version = None
            if framework == "Angular":
                vm = re.search(r'ng-version=["\']([^"\']+)["\']', html)
                version = vm.group(1) if vm else None
            elif framework == "Next.js":
                vm = re.search(r'"next":\s*"([\d.]+)"', html)
                version = vm.group(1) if vm else None
            elif framework == "WordPress":
                vm = re.search(r'ver=([\d.]+)', html)
                version = vm.group(1) if vm else None
            return framework, version, f"JS bundle: {framework}"

    return None, None, ""


def _from_html_structure(html: str) -> Tuple[Optional[str], Optional[str], str]:
    """
    Detect CMS and platform from structural HTML patterns.
    Covers WordPress, Shopify, Wix, Squarespace, Drupal, Joomla, etc.
    These signals are embedded in the HTML body and pass through CDNs unchanged.
    """
    checks = [
        # Meta generator tags — most reliable CMS signal
        (r'<meta[^>]+generator[^>]+WordPress[\s"\']*([0-9.]*)',   "WordPress",    1),
        (r'<meta[^>]+generator[^>]+Drupal[\s"\']*([0-9.]*)',      "Drupal",       1),
        (r'<meta[^>]+generator[^>]+Joomla[^"\']*',                "Joomla",       None),
        (r'<meta[^>]+generator[^>]+Wix\.com',                     "Wix",          None),
        (r'<meta[^>]+generator[^>]+Squarespace',                  "Squarespace",  None),
        (r'<meta[^>]+generator[^>]+Webflow',                      "Webflow",      None),
        (r'<meta[^>]+generator[^>]+Ghost[\s"\']*([0-9.]*)',       "Ghost",        1),
        (r'<meta[^>]+generator[^>]+HubSpot',                      "HubSpot CMS",  None),
        (r'<meta[^>]+generator[^>]+TYPO3[\s"\']*([0-9.]*)',       "TYPO3",        1),
        (r'<meta[^>]+generator[^>]+Craft CMS[\s"\']*([0-9.]*)',   "Craft CMS",    1),
        # SPA root elements
        (r'<div[^>]+id=["\']__nuxt["\']',                         "Nuxt",         None),
        (r'<div[^>]+id=["\']__next["\']',                         "Next.js",      None),
        (r'<app-root[\s>]',                                        "Angular",      None),
        (r'data-reactroot',                                        "React",        None),
        # CMS structural patterns
        (r'/sites/default/files/',                                 "Drupal",       None),
        (r'/components/com_',                                      "Joomla",       None),
        (r'cdn\.shopify\.com',                                     "Shopify",      None),
        (r'static\.parastorage\.com',                              "Wix",          None),
        # API namespaces that identify platform
        (r'/wp-json/wp/v2/',                                       "WordPress",    None),
        (r'Drupal\.settings\s*=',                                  "Drupal",       None),
        (r'Joomla\.optionsStorage',                                "Joomla",       None),
    ]

    for pattern, name, version_group in checks:
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            version = None
            if version_group is not None and m.lastindex and m.lastindex >= version_group:
                v = m.group(version_group)
                version = v.strip() if v and v.strip() else None
            return name, version, f"HTML structure: {name}"

    return None, None, ""


def _from_cookies(response_headers: Dict) -> Tuple[Optional[str], Optional[str], str]:
    """
    Detect backend framework from session cookie names.
    Cookie names are set by the ORIGIN server and pass through CDNs/WAFs unchanged.
    This is often the ONLY passive technique that reveals backend tech behind Cloudflare.
    """
    cookie_header = response_headers.get("set-cookie", "")
    if not cookie_header:
        return None, None, ""

    mapping = {
        "PHPSESSID":            ("PHP",              None),
        "JSESSIONID":           ("Java/Tomcat",       None),
        "ASP.NET_SessionId":    ("ASP.NET",           None),
        "ASPSESSIONID":         ("ASP.NET",           None),
        "_rails_session":       ("Ruby on Rails",     None),
        "laravel_session":      ("Laravel",           None),
        "laravel_token":        ("Laravel",           None),
        "django_session":       ("Django",            None),
        "csrftoken":            ("Django",            None),
        "wp-settings":          ("WordPress",         None),
        "wordpress_":           ("WordPress",         None),
        "shopify_session":      ("Shopify",           None),
        "_session_id":          ("Ruby on Rails",     None),
        "ci_session":           ("CodeIgniter",       None),
        "CFID":                 ("ColdFusion",        None),
        "CFTOKEN":              ("ColdFusion",        None),
        "connect.sid":          ("Node.js/Express",   None),
        "rack.session":         ("Ruby/Rack",         None),
        "symfony":              ("Symfony/PHP",       None),
        "CONCRETE5":            ("Concrete CMS",      None),
        "mediawiki_session":    ("MediaWiki",         None),
    }

    for cookie_name, (tech, version) in mapping.items():
        if cookie_name.lower() in cookie_header.lower():
            return tech, version, f"Session cookie: {cookie_name}"

    return None, None, ""


def _from_server_header(headers: Dict) -> Tuple[Optional[str], Optional[str], str]:
    """
    Extract from Server: nginx/1.24.0, Apache/2.4.51, etc.
    Returns the server software as a technology (not primary app name).
    """
    server = headers.get("server", "")
    if not server:
        return None, None, ""
    m = re.match(r'^([A-Za-z][A-Za-z0-9_.-]+?)(?:/(\d[\d.]*))?\s', server + " ")
    if m:
        name    = m.group(1)
        version = m.group(2)
        return name, version, f"Server: {server!r}"
    return None, None, ""


def _from_html_comments(html: str) -> Tuple[Optional[str], Optional[str], str]:
    """
    Extract from HTML comments like:
      <!-- This site runs GitLab -->
      <!-- Powered by Discourse -->
      <!-- Redmine v5.1 -->
    """
    for m in re.finditer(r'<!--\s*(.*?)\s*-->', html[:5000]):
        comment = m.group(1).strip()
        if 10 < len(comment) < 80:
            name_m = re.search(
                r'(?:runs?|by|powered by|using)\s+([A-Z][a-zA-Z0-9\s]{2,30})',
                comment, re.IGNORECASE
            )
            if name_m:
                name = name_m.group(1).strip()
                if _looks_like_app_name(name):
                    version = _extract_version_from_string(comment)
                    return name, version, f"HTML comment: {comment!r}"
    return None, None, ""


def _from_unique_html_patterns(html: str) -> Tuple[Optional[str], Optional[str], str]:
    """
    Extract from unique HTML fingerprints that reliably identify applications.
    """
    # Pattern: data-app or data-application attributes
    data_app = re.search(
        r'data-(?:app|application|platform|software)=["\']([^"\']{2,40})["\']',
        html, re.IGNORECASE
    )
    if data_app:
        name = data_app.group(1).strip()
        if _looks_like_app_name(name):
            return name, None, f"data-app attribute: {name!r}"

    # Pattern: API namespace in script src / href
    api_ns = re.search(
        r'(?:src|href)=["\'][^"\']*?/([a-z][a-z0-9-]{2,20})/(?:js|css|assets|static)/',
        html, re.IGNORECASE
    )
    if api_ns:
        ns = api_ns.group(1)
        # Exclude path segments that are library/framework names embedded in
        # bundle paths (e.g. /gradio/assets/, /react/static/) — these are
        # dependencies being served as assets, not the app's identity.
        # App identity comes from generator meta, powered-by, or js_bundles.
        _ASSET_NS_BLOCKLIST = {
            "static", "assets", "public", "vendor", "dist", "build",
            "node_modules", "lib", "libs", "pkg", "packages",
            "gradio", "svelte", "react", "vue", "angular", "next",
            "nuxt", "gatsby", "remix", "ember", "backbone",
        }
        if _looks_like_app_name(ns) and ns.lower() not in _ASSET_NS_BLOCKLIST:
            return ns.capitalize(), None, f"asset namespace: /{ns}/"

    return None, None, ""


def _from_version_api(base_url: str) -> Tuple[Optional[str], Optional[str], str]:
    """
    Try common version/info API endpoints that self-hosted apps expose.
    Covers GitLab, Redmine, Grafana, Nextcloud, Jenkins, Flowise, etc.
    """
    version_paths = [
        "/version",
        "/api/version",
        "/api/v1/version",
        "/api/v2/version",
        "/rest/api/version",
        "/rest/api/2/serverInfo",   # Jira
        "/api/v4/version",          # GitLab
        "/info",
        "/api/info",
        "/api/v1/info",
        "/status",
        "/api/status",
        "/health",
        "/about",
        "/api/about",
        "/_about",
        "/api/v1/settings/about",   # Gitea
        "/wp-json/wp/v2/",          # WordPress REST
        "/ocs/v1.php/config",       # Nextcloud
        "/api/index.php/v1/config", # Nextcloud alt
    ]

    for path in version_paths:
        url = base_url.rstrip("/") + path
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0 (SecurityScanner)"
                }
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    ct = resp.headers.get("Content-Type", "")
                    if "json" in ct:
                        body = resp.read(4096).decode("utf-8", errors="replace")
                        data = json.loads(body)
                        name    = _find_in_json(data, ("name", "application", "app",
                                                        "software", "product"))
                        version = _find_in_json(data, ("version", "server_version",
                                                        "app_version", "release",
                                                        "version_string"))
                        if name or version:
                            return name, version, f"API {path}: {body[:80]!r}"
        except Exception:
            continue

    return None, None, ""


def _from_robots_txt(base_url: str) -> Tuple[Optional[str], Optional[str], str]:
    """
    Parse robots.txt for app identity comments.
    Many apps add their name as a comment at the top.
    """
    try:
        url = base_url.rstrip("/") + "/robots.txt"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            body = resp.read(2048).decode("utf-8", errors="replace")

        for line in body.splitlines()[:5]:
            line = line.strip()
            if line.startswith("#"):
                comment = line.lstrip("#").strip()
                if _looks_like_app_name(comment) and len(comment) < 40:
                    return comment, None, f"robots.txt comment: {comment!r}"
    except Exception:
        pass

    return None, None, ""


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------

async def detect_app_identity(base_url: str,
                               html: str,
                               response_headers: Dict,
                               verbose: bool = False) -> AppIdentity:
    """
    Detect the identity of any web application using all available signals.
    Returns an AppIdentity with name, version, technologies, and CVE search queries.

    Detection layers (in priority order):
      1. generator_meta   — <meta name="generator"> (most explicit)
      2. powered_by       — X-Powered-By header / HTML "Powered by X"
      3. js_bundles       — JS bundle paths / globals (survives CDN)
      4. html_structure   — CMS structural patterns (survives CDN)
      5. cookies          — Session cookie names (reveals backend behind CDN)
      6. version_api      — /version /api/version etc (self-hosted apps)
      7. html_comments    — <!-- Powered by X -->
      8. html_patterns    — CSS class prefixes, data-app attributes
      9. robots_txt       — robots.txt comments
     10. page_title       — <title> tag (least reliable)
    """
    import asyncio

    # Normalize headers to lowercase keys once
    if not isinstance(response_headers, dict):
        response_headers = dict(response_headers)
    response_headers = {k.lower(): v for k, v in response_headers.items()}

    signals: List[Tuple[str, Optional[str], str, int]] = []
    # Each entry: (name, version_or_none, evidence, confidence_score)

    # ── Synchronous extractors (run on HTML + headers already in memory) ──
    extractors = [
        ("generator_meta",  lambda: _from_generator_meta(html)),
        ("powered_by",      lambda: _from_powered_by(html, response_headers)),
        ("js_bundles",      lambda: _from_js_bundles(html)),
        ("html_structure",  lambda: _from_html_structure(html)),
        ("cookies",         lambda: _from_cookies(response_headers)),
        ("page_title",      lambda: _from_page_title(html)),
        ("html_comments",   lambda: _from_html_comments(html)),
        ("html_patterns",   lambda: _from_unique_html_patterns(html)),
    ]

    confidence_scores = {
        "generator_meta":  100,  # app explicitly announces itself
        "powered_by":       80,  # header or HTML disclosure
        "js_bundles":       85,  # unambiguous framework asset paths
        "html_structure":   80,  # structural CMS patterns
        "cookies":          75,  # session cookie names — backend only
        "html_comments":    60,  # developer comments
        "html_patterns":    50,  # CSS/data attribute heuristics
        "page_title":       40,  # can be misleading
    }

    for extractor_name, fn in extractors:
        try:
            name, version, evidence = fn()
            if name:
                score = confidence_scores[extractor_name]
                signals.append((name, version, evidence, score))
                if verbose:
                    print(f"      [{extractor_name}] {name!r} v{version} — {evidence}")
        except Exception as e:
            logger.debug(f"Extractor {extractor_name} failed: {e}")

    # ── Async network sources (probe remote endpoints) ─────────────────
    loop = asyncio.get_event_loop()

    try:
        name, version, evidence = await loop.run_in_executor(
            None, lambda: _from_version_api(base_url)
        )
        if name:
            signals.append((name, version, evidence, 90))
            if verbose:
                print(f"      [version_api] {name!r} v{version} — {evidence}")
    except Exception:
        pass

    try:
        name, version, evidence = await loop.run_in_executor(
            None, lambda: _from_robots_txt(base_url)
        )
        if name:
            signals.append((name, version, evidence, 55))
            if verbose:
                print(f"      [robots_txt] {name!r} — {evidence}")
    except Exception:
        pass

    # ── Collect technology stack from ALL sources ──────────────────────
    # Layer 1: headers (CDN-visible — may be stripped by Cloudflare/WAF)
    technologies = _extract_technologies_from_headers(response_headers)

    # Layer 2: add framework/platform names discovered via signals.
    # We use the signals list directly rather than re-running extractors,
    # which previously caused duplicates (e.g. SvelteKit appearing twice).
    # Each signal already ran in the extractors loop above.
    for sig_name, sig_version, _, _ in signals:
        if sig_name:
            entry = f"{sig_name}/{sig_version}" if sig_version else sig_name
            technologies.append(entry)

    # Dedup technologies case-insensitively, preserve first occurrence
    seen_lower: set = set()
    technologies_deduped = []
    for t in technologies:
        if t.lower() not in seen_lower:
            seen_lower.add(t.lower())
            technologies_deduped.append(t)
    technologies = technologies_deduped

    # ── Choose best app name from signals ─────────────────────────────
    if not signals:
        identity = AppIdentity(
            name         = None,
            technologies = technologies,
            confidence   = "low",
            evidence     = "no app identity signals found"
        )
        _build_cve_queries(identity, technologies)
        return identity

    # Sort by confidence score descending, pick highest
    signals.sort(key=lambda s: s[3], reverse=True)
    best_name, best_version, best_evidence, best_score = signals[0]

    confidence = (
        "high"   if best_score >= 80 else
        "medium" if best_score >= 50 else
        "low"
    )

    # Collect evidence from top 3 signals
    all_evidence = "; ".join(s[2] for s in signals[:3] if s[2])

    identity = AppIdentity(
        name         = best_name,
        version      = best_version,
        technologies = technologies,
        confidence   = confidence,
        evidence     = all_evidence,
    )
    _build_cve_queries(identity, technologies)

    if verbose:
        print(f"      App identity: {identity.name!r} "
              f"v{identity.version} [{confidence}]")
        print(f"      Technologies: {identity.technologies[:5]}")
        print(f"      CVE queries:  {identity.cve_queries[:2]}")

    return identity


def _build_cve_queries(identity: AppIdentity,
                        technologies: List[str]) -> None:
    """
    Build ordered list of CVE search queries from most to least specific.

    Most specific: "WordPress 6.4.2" → version-exact CVE match
    Less specific: "WordPress"        → all WordPress CVEs
    Fallback:      "PHP"              → framework CVEs
    """
    queries = []

    if identity.name:
        if identity.version:
            queries.append(f"{identity.name} {identity.version}")
        queries.append(identity.name)

    generic_tech = {
        "nginx", "apache", "iis", "node.js", "php",
        "python", "ruby", "java", "cloudflare", "aws cloudfront"
    }
    specific_tech = [t for t in technologies
                     if t.lower().split("/")[0] not in generic_tech]
    generic_only  = [t for t in technologies
                     if t.lower().split("/")[0] in generic_tech]

    for t in specific_tech[:2]:
        if t not in queries:
            queries.append(t)

    if not queries or (not identity.name and not specific_tech):
        for t in generic_only[:2]:
            queries.append(t)

    identity.cve_queries = queries


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _looks_like_app_name(s: str) -> bool:
    """
    Heuristic: does this string look like an application name?
    """
    if not s or not isinstance(s, str):
        return False
    s = s.strip()
    if len(s) < 2 or len(s) > 40:
        return False
    if not re.match(r'^[A-Za-z]', s):
        return False
    if '/' in s:
        return False

    last_word = s.split()[-1]
    is_version   = bool(re.match(r'^\d+[\d.]*$', last_word))
    # Allow single-word names ending in .js (Next.js, Vue.js, Node.js, ml5.js)
    # Block multi-word strings whose last word looks like a filename (e.g. "main.css")
    is_js_framework = bool(re.match(r'^[A-Za-z][A-Za-z0-9]*\.js$', last_word))
    has_file_ext = (
        bool(re.search(r'\.[a-z]{2,4}$', last_word))
        and not is_version
        and not is_js_framework
    )
    if has_file_ext:
        return False

    generic = {
        "home", "index", "page", "welcome", "about", "blog", "news",
        "login", "signin", "register", "signup", "contact", "search",
        "static", "assets", "public", "main", "app", "site", "web",
        "error", "404", "403", "500", "forbidden", "not found",
        "dashboard", "admin", "panel", "portal", "platform",
        "loading", "please wait", "undefined", "null", "true", "false",
        # Common JS bundle/library names that appear in asset paths
        "immutable", "vendor", "runtime", "polyfill", "chunk", "bundle",
        "commons", "manifest", "framework", "core", "utils", "helpers",
        "styles", "fonts", "icons", "images", "media", "dist", "build",
        "client", "server", "worker", "sw", "service",
    }
    if s.lower() in generic:
        return False

    return True


def _extract_version_from_string(s: str) -> Optional[str]:
    """Extract version number from a string like 'Redmine 5.1.2' → '5.1.2'"""
    m = re.search(r'\bv?(\d+\.\d+(?:\.\d+)*)\b', s)
    return m.group(1) if m else None


def _find_in_json(data, keys: tuple) -> Optional[str]:
    """Find a value in a JSON dict by trying multiple key names."""
    if not isinstance(data, dict):
        return None
    for key in keys:
        val = data.get(key)
        if val and isinstance(val, str) and len(val) < 80:
            return val
        for v in data.values():
            if isinstance(v, dict):
                nested = v.get(key)
                if nested and isinstance(nested, str):
                    return nested
    return None


def _extract_technologies_from_headers(headers: Dict) -> List[str]:
    """
    Extract confirmed technologies from HTTP response headers.
    NOTE: Behind Cloudflare/WAF, most of these will be stripped.
    Use body-derived extractors (_from_js_bundles, _from_html_structure,
    _from_cookies) for CDN-obscured targets.
    """
    techs = []

    # Normalize keys
    if not isinstance(headers, dict):
        headers = dict(headers)
    headers = {k.lower(): v for k, v in headers.items()}

    # Server header: "nginx/1.24.0", "Apache/2.4.51 (Ubuntu)", "cloudflare"
    server = headers.get("server", "")
    if server:
        m = re.match(r'^([A-Za-z][A-Za-z0-9_.-]+?)(?:/([0-9][0-9.]*))?' + r'', server)
        if m:
            name = m.group(1)
            ver  = m.group(2)
            # Normalize known CDN/server names to canonical casing
            _NAME_MAP = {
                "cloudflare": "Cloudflare", "nginx": "nginx",
                "apache": "Apache", "iis": "IIS",
                "litespeed": "LiteSpeed", "caddy": "Caddy",
                "gunicorn": "Gunicorn", "openresty": "OpenResty",
            }
            name = _NAME_MAP.get(name.lower(), name)
            techs.append(f"{name}/{ver}" if ver else name)

    # X-Powered-By: "PHP/8.1.2", "Express", "Phusion Passenger 6.0"
    powered = headers.get("x-powered-by", "")
    if powered:
        parts = [p.strip() for p in powered.split(",")]
        for part in parts:
            m = re.match(r'^([A-Za-z][A-Za-z0-9_.-]+?)(?:\s+|/)(\d[\d.]*)?', part)
            if m:
                name = m.group(1).strip()
                # Guard: reject header-name-like strings
                if (len(name) >= 3 and "-" not in name) or name.lower() in (
                    "php", "express", "node.js", "passenger"
                ):
                    ver = m.group(2)
                    techs.append(f"{name}/{ver}" if ver else name)

    # X-Runtime → Ruby on Rails
    if "x-runtime" in headers:
        techs.append("Ruby on Rails")

    # X-AspNet-Version → .NET
    if "x-aspnet-version" in headers:
        techs.append(f".NET/{headers['x-aspnet-version']}")

    # X-Application-Context → Spring Boot
    if "x-application-context" in headers:
        techs.append("Spring Boot")

    # Via → CDN/proxy
    via = headers.get("via", "")
    if via and len(via) < 80:
        techs.append(f"via: {via}")

    # CF-Ray → Cloudflare
    if "cf-ray" in headers:
        techs.append("Cloudflare")

    # X-Amz → AWS CloudFront
    if "x-amz-cf-id" in headers or "x-amz-request-id" in headers:
        techs.append("AWS CloudFront")

    return techs