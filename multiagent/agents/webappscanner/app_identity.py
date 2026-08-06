import re
import json
import logging
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import asyncio

logger = logging.getLogger(__name__)

_APP_IDENTITY_MIN_CONFIDENCE = 88


@dataclass
class AppIdentity:
    name:         Optional[str]  = None
    version:      Optional[str]  = None
    technologies: List[str]      = field(default_factory=list)
    confidence:   str            = "low"
    evidence:     str            = ""
    cve_queries:  List[str]      = field(default_factory=list)

    def best_cve_query(self) -> Optional[str]:
        if self.cve_queries:
            return self.cve_queries[0]
        if self.name:
            q = self.name
            if self.version:
                q += f" {self.version}"
            return q
        return None


def _from_generator_meta(html: str) -> Tuple[Optional[str], Optional[str], str]:
    m = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']{1,200})["\']',
        html, re.IGNORECASE
    )
    if not m:
        m = re.search(
            r'<meta[^>]+content=["\']([^"\']{1,200})["\'][^>]+name=["\']generator["\']',
            html, re.IGNORECASE
        )
    if not m:
        return None, None, ""

    content = m.group(1).strip()
    version = _extract_version_from_string(content)
    name    = re.sub(r'\s*\d[\d.]*\s*$', '', content).strip()
    name    = re.sub(r'[!]', '', name).strip()
    if not _looks_like_app_name(name):
        return None, None, ""
    return name, version, f"generator meta: {content!r}"


def _from_powered_by(html: str, headers: Dict) -> Tuple[Optional[str], Optional[str], str]:
    powered_by = headers.get("x-powered-by", "")
    if powered_by:
        version = _extract_version_from_string(powered_by)
        name    = re.sub(r'[/\s]\d[\d.]*', '', powered_by).strip()
        if _looks_like_app_name(name):
            return name, version, f"X-Powered-By: {powered_by!r}"

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


def _from_page_title(html: str) -> Tuple[Optional[str], Optional[str], str]:
    m = re.search(r'<title[^>]*>([^<]{1,200})</title>', html, re.IGNORECASE)
    if not m:
        return None, None, ""

    title    = m.group(1).strip()
    segments = re.split(r'\s*[-|–—·•]\s*', title)
    candidates = [segments[-1].strip(), segments[0].strip()]

    for candidate in candidates:
        candidate = re.sub(r'\s*\[.*?\]\s*$', '', candidate).strip()
        if _looks_like_app_name(candidate):
            version = _extract_version_from_string(candidate)
            name    = re.sub(r'\s*\d[\d.]*\s*$', '', candidate).strip()
            return name, version, f"page title: {title!r}"

    return None, None, ""


def _from_html_comments(html: str) -> Tuple[Optional[str], Optional[str], str]:
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


def _from_data_attributes(html: str) -> Tuple[Optional[str], Optional[str], str]:
    m = re.search(
        r'data-(?:app|application|platform|software)=["\']([^"\']{2,40})["\']',
        html, re.IGNORECASE
    )
    if m:
        name = m.group(1).strip()
        if _looks_like_app_name(name):
            return name, None, f"data attribute: {name!r}"
    return None, None, ""


def _from_wp_json(base_url: str) -> Tuple[Optional[str], Optional[str], str]:
    """
    WordPress REST root + generator — definitive CMS identity when exposed.
    Also notes /wp-json/wp/v2/users reachability for author enumeration surface.
    """
    base = base_url.rstrip("/")
    name: Optional[str] = "WordPress"
    version: Optional[str] = None
    evidence_parts: List[str] = []

    # Root index often includes site name; version may appear in namespaces/GMT
    for path in ("/wp-json", "/wp-json/"):
        try:
            req = urllib.request.Request(
                base + path,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0 (SecurityScanner)",
                },
            )
            with urllib.request.urlopen(req, timeout=4) as resp:
                if resp.status != 200:
                    continue
                ct = resp.headers.get("Content-Type", "")
                body = resp.read(8192).decode("utf-8", errors="replace")
                if "json" not in ct and not body.lstrip().startswith("{"):
                    continue
                data = json.loads(body)
                evidence_parts.append(f"wp-json root HTTP 200")
                # Some installs expose generator / version in extras
                ver = _find_in_json(
                    data,
                    ("version", "wp_version", "wordpress_version", "generator"),
                )
                if ver and re.search(r"\d+\.\d+", str(ver)):
                    version = _extract_version_from_string(str(ver)) or str(ver)
                # Confirm it looks like WP REST
                if isinstance(data, dict) and (
                    "namespaces" in data or "routes" in data or "name" in data
                ):
                    break
        except Exception:
            continue

    # Generator-style version from wp/v2 settings or types is rare; try users
    # only as surface evidence (enumeration), not for version.
    try:
        req = urllib.request.Request(
            base + "/wp-json/wp/v2/users",
            headers={
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0 (SecurityScanner)",
            },
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            if resp.status == 200:
                body = resp.read(4096).decode("utf-8", errors="replace")
                if body.lstrip().startswith("["):
                    users = json.loads(body)
                    if isinstance(users, list) and users:
                        evidence_parts.append(
                            f"wp/v2/users enumerates {len(users)} author(s)"
                        )
    except Exception:
        pass

    if not evidence_parts:
        return None, None, ""
    return name, version, "; ".join(evidence_parts)


def _from_version_api(base_url: str) -> Tuple[Optional[str], Optional[str], str]:
    version_paths = [
        "/version",
        "/api/version",
        "/api/v1/version",
        "/api/v2/version",
        "/rest/api/version",
        "/rest/api/2/serverInfo",
        "/api/v4/version",
        "/info",
        "/api/info",
        "/api/v1/info",
        "/status",
        "/api/status",
        "/health",
        "/api/health",
        "/about",
        "/api/about",
        "/_about",
        "/api/v1/settings/about",
        "/wp-json",
        "/wp-json/wp/v2/",
        "/ocs/v1.php/config",
        "/api/index.php/v1/config",
    ]

    for path in version_paths:
        url = base_url.rstrip("/") + path
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "Accept":     "application/json",
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


def _pick_preferred_wappalyzer_app(
    wappalyzer_technologies: List,
) -> Optional[Dict]:
    """
    Choose the strongest app-level tech from Wappalyzer output.
    Prefer CMS; never wipe an existing best signal via for/else.
    """
    preferred: Optional[Dict] = None
    for tech in wappalyzer_technologies or []:
        if not isinstance(tech, dict):
            continue
        name = (tech.get("name") or "").strip()
        if not name or _is_infra_or_framework_name(name):
            continue
        category = (tech.get("category") or "").strip()
        # Framework/Language/Server are stack, not product identity
        if category in ("Framework", "Language", "Server", "CDN", "Analytics"):
            continue
        if category == "CMS":
            return tech  # CMS is authoritative
        if category == "Other" and name not in (
            "Ubuntu", "Debian", "HTTP/2", "HTTP/3", "HSTS", "OpenSSL",
        ):
            # Prefer versioned app-like names over bare platform hints
            if preferred is None or (
                tech.get("version") and not preferred.get("version")
            ):
                preferred = tech
    return preferred


async def detect_app_identity(
    base_url: str,
    html: str,
    response_headers: Dict,
    wappalyzer_technologies: Optional[List] = None,
    wappalyzer_cms: Optional[str] = None,
    verbose: bool = False,
) -> AppIdentity:
    """
    Derive authoritative app name/version for CVE targeting.

    ``wappalyzer_technologies`` is the fingerprint stack list (dicts with
    name/version/category). ``wappalyzer_cms`` is an optional CMS name hint
    kept for backward compatibility.
    """
    if not isinstance(response_headers, dict):
        response_headers = dict(response_headers)
    response_headers = {k.lower(): v for k, v in response_headers.items()}
    wappalyzer_technologies = list(wappalyzer_technologies or [])

    signals: List[Tuple[str, Optional[str], str, int]] = []

    extractors = [
        ("generator_meta",   lambda: _from_generator_meta(html)),
        ("powered_by",       lambda: _from_powered_by(html, response_headers)),
        ("html_comments",    lambda: _from_html_comments(html)),
        ("data_attributes",  lambda: _from_data_attributes(html)),
        ("page_title",       lambda: _from_page_title(html)),
    ]

    confidence_scores = {
        "generator_meta":   100,
        "powered_by":        80,
        "html_comments":     60,
        "data_attributes":   55,
        "page_title":        40,
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

    loop = asyncio.get_event_loop()

    try:
        name, version, evidence = await loop.run_in_executor(
            None, lambda: _from_version_api(base_url)
        )
        if name or version:
            # WordPress REST often returns version without a product name
            if not name and version:
                name = "WordPress"
            signals.append((name, version, evidence, 95 if version else 90))
            if verbose:
                print(f"      [version_api] {name!r} v{version} — {evidence}")
    except Exception:
        pass

    try:
        name, version, evidence = await loop.run_in_executor(
            None, lambda: _from_wp_json(base_url)
        )
        if name:
            signals.append((name, version, evidence, 100 if version else 90))
            if verbose:
                print(f"      [wp_json] {name!r} v{version} — {evidence}")
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

    technologies = _extract_technologies_from_headers(response_headers)
    for tech in wappalyzer_technologies:
        if isinstance(tech, dict):
            name = tech.get("name")
            version = tech.get("version")
            if name:
                entry = f"{name}/{version}" if version else name
                technologies.append(entry)
        elif isinstance(tech, str) and tech.strip():
            technologies.append(tech.strip())

    for sig_name, sig_version, _, _ in signals:
        if sig_name:
            entry = f"{sig_name}/{sig_version}" if sig_version else sig_name
            technologies.append(entry)

    seen_lower: set = set()
    technologies_deduped = []
    for t in technologies:
        if t.lower() not in seen_lower:
            seen_lower.add(t.lower())
            technologies_deduped.append(t)
    technologies = technologies_deduped

    if not signals and not wappalyzer_technologies and not wappalyzer_cms:
        identity = AppIdentity(
            name         = None,
            technologies = technologies,
            confidence   = "low",
            evidence     = "no app identity signals found"
        )
        _build_cve_queries(identity, technologies)
        return identity

    # Drop infrastructure/framework names that slipped through extractors
    signals = [
        s for s in signals
        if s[0] and _looks_like_app_name(s[0]) and not _is_infra_or_framework_name(s[0])
    ]
    signals.sort(key=lambda s: s[3], reverse=True)

    best = next(
        (s for s in signals if s[3] >= _APP_IDENTITY_MIN_CONFIDENCE),
        signals[0] if signals else None,
    )

    best_name: Optional[str] = None
    best_version: Optional[str] = None
    best_evidence: str = ""
    best_score: int = 0
    if best:
        best_name, best_version, best_evidence, best_score = best

    # Wappalyzer CMS / preferred app can override or fill gaps — never wipe.
    preferred_app = _pick_preferred_wappalyzer_app(wappalyzer_technologies)
    if preferred_app and preferred_app.get("name"):
        pref_name = preferred_app["name"]
        pref_ver = preferred_app.get("version")
        pref_cat = preferred_app.get("category") or ""
        if pref_cat == "CMS":
            # Authoritative CMS identity
            if not best_name or best_score < 100:
                best_name = pref_name
                best_score = max(best_score, 85)
            if pref_ver and (
                not best_version
                or (best_name or "").lower() == pref_name.lower()
            ):
                best_version = pref_ver
            best_evidence = (
                f"{best_evidence}; wappalyzer CMS: {pref_name}"
                if best_evidence else f"wappalyzer CMS: {pref_name}"
            )
        elif not best_name:
            best_name = pref_name
            best_version = pref_ver or best_version
            best_score = max(best_score, 60)
            best_evidence = f"wappalyzer: {pref_name}"

    if wappalyzer_cms and not best_name:
        best_name = wappalyzer_cms
        best_score = max(best_score, 70)
        best_evidence = best_evidence or f"wappalyzer_cms hint: {wappalyzer_cms}"

    version_api_signal = next(
        (s for s in signals if "API" in s[2] and s[1]),
        None
    )
    if version_api_signal and best_name:
        api_name    = version_api_signal[0]
        api_version = version_api_signal[1]
        if api_name and api_version:
            if api_name.lower() == best_name.lower() or not best_version:
                best_name    = api_name
                best_version = api_version

    confidence = (
        "high"   if best_score >= 80 else
        "medium" if best_score >= 50 else
        "low"
    )

    all_evidence = "; ".join(s[2] for s in signals[:3] if s[2])
    if best_evidence and best_evidence not in all_evidence:
        all_evidence = (
            f"{all_evidence}; {best_evidence}" if all_evidence else best_evidence
        )

    identity = AppIdentity(
        name         = best_name,
        version      = best_version,
        technologies = technologies,
        confidence   = confidence,
        evidence     = all_evidence,
    )
    _build_cve_queries(identity, technologies)

    if verbose:
        print(f"      App identity: {identity.name!r} v{identity.version} [{confidence}]")
        print(f"      CVE queries:  {identity.cve_queries[:2]}")

    return identity


def _build_cve_queries(identity: AppIdentity,
                        technologies: List[str]) -> None:
    queries = []
    if identity.name:
        if identity.version:
            queries.append(f"{identity.name} {identity.version}")
        queries.append(identity.name)
    for t in technologies[:2]:
        if t not in queries:
            queries.append(t)
    identity.cve_queries = queries


# Runtimes / frameworks / servers are stack signals, not product identity.
_INFRA_OR_FRAMEWORK_NAMES = {
    "express", "node", "nodejs", "node.js", "nginx", "apache", "httpd",
    "iis", "tomcat", "jetty", "uvicorn", "gunicorn", "werkzeug", "php",
    "python", "ruby", "rails", "django", "flask", "fastapi", "laravel",
    "symfony", "spring", "spring boot", "koa", "fastify", "nestjs",
    "next.js", "nextjs", "nuxt", "react", "vue", "angular", "svelte",
    "jquery", "bootstrap", "webpack", "vite", "caddy", "traefik",
    "cloudflare", "varnish", "haproxy", "openresty", "passenger",
    "puma", "unicorn", "webrick", "cherrypy", "tornado", "aiohttp",
    "asp.net", "asp.net core", ".net", "kestrel", "http/2", "http/3",
    "openssl", "ubuntu", "debian", "alpine", "centos", "redhat",
}


def _is_infra_or_framework_name(s: str) -> bool:
    n = re.sub(r"\s+", " ", (s or "").strip().lower())
    n = re.sub(r"\s*\d[\d.]*\s*$", "", n).strip()
    if not n:
        return True
    if n in _INFRA_OR_FRAMEWORK_NAMES:
        return True
    # x-powered-by style "Express" / "PHP/8.2"
    base = n.split("/")[0].strip()
    return base in _INFRA_OR_FRAMEWORK_NAMES


def _looks_like_app_name(s: str) -> bool:
    if not s or not isinstance(s, str):
        return False
    s = s.strip()
    if len(s) < 3 or len(s) > 40:
        return False
    if not re.match(r'^[A-Za-z]', s):
        return False
    if '/' in s:
        return False
    if ':' in s or ';' in s:
        return False
    if re.match(r'^\d+$', s):
        return False
    # Never promote stack/runtime names to product identity
    if _is_infra_or_framework_name(s):
        return False

    last_word       = s.split()[-1]
    is_version      = bool(re.match(r'^\d+[\d.]*$', last_word))
    is_js_name      = bool(re.match(r'^[A-Za-z][A-Za-z0-9]*\.js$', last_word))
    has_file_ext    = (
        bool(re.search(r'\.[a-z]{2,4}$', last_word))
        and not is_version
        and not is_js_name
    )
    if has_file_ext:
        return False

    if len(s.split()) == 1 and s.islower() and len(s) <= 8:
        return False

    return True


def _extract_version_from_string(s: str) -> Optional[str]:
    m = re.search(r'\bv?(\d+\.\d+(?:\.\d+)*)\b', s)
    return m.group(1) if m else None


def _find_in_json(data, keys: tuple) -> Optional[str]:
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
    techs = []

    if not isinstance(headers, dict):
        headers = dict(headers)
    headers = {k.lower(): v for k, v in headers.items()}

    server = headers.get("server", "")
    if server:
        m = re.match(r'^(.+?)(?:/(\d+(?:\.\d+)+))?$', server)
        if m:
            name = m.group(1).capitalize() if m.group(1).islower() else m.group(1)
            ver  = m.group(2)
            techs.append(f"{name}/{ver}" if ver else name)

    powered = headers.get("x-powered-by", "")
    if powered:
        for part in [p.strip() for p in powered.split(",")]:
            m = re.match(r'^(.*?)(?:\s+v?(\d+(?:\.\d+)+)|/(\d+(?:\.\d+)+))?$', part)
            if m:
                name = m.group(1).strip()
                if len(name) >= 3:
                    ver = m.group(2)
                    techs.append(f"{name}/{ver}" if ver else name)

    for header_key, val in headers.items():
        if header_key not in ("server", "x-powered-by", "content-type",
                              "content-length", "date", "connection",
                              "cache-control", "set-cookie", "vary",
                              "transfer-encoding", "accept-ranges"):
            if re.match(r'^x-', header_key) and val and len(val) < 60:
                techs.append(f"{header_key}: {val}")

    return techs