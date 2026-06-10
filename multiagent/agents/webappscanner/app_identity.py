import re
import json
import logging
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

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


async def detect_app_identity(base_url: str,
                               html: str,
                               response_headers: Dict,
                               verbose: bool = False) -> AppIdentity:
    import asyncio

    if not isinstance(response_headers, dict):
        response_headers = dict(response_headers)
    response_headers = {k.lower(): v for k, v in response_headers.items()}

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

    technologies = _extract_technologies_from_headers(response_headers)

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

    if not signals:
        identity = AppIdentity(
            name         = None,
            technologies = technologies,
            confidence   = "low",
            evidence     = "no app identity signals found"
        )
        _build_cve_queries(identity, technologies)
        return identity

    signals.sort(key=lambda s: s[3], reverse=True)

    best = next(
        (s for s in signals if s[3] >= _APP_IDENTITY_MIN_CONFIDENCE),
        None
    )

    if best:
        best_name, best_version, best_evidence, best_score = best
    else:
        best_name, best_version, best_evidence, best_score = None, None, "", 0

    confidence = (
        "high"   if best_score >= 80 else
        "medium" if best_score >= 50 else
        "low"
    )

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
        m = re.match(r'^([A-Za-z][A-Za-z0-9_.-]+?)(?:/([0-9][0-9.]*))?', server)
        if m:
            name = m.group(1).capitalize() if m.group(1).islower() else m.group(1)
            ver  = m.group(2)
            techs.append(f"{name}/{ver}" if ver else name)

    powered = headers.get("x-powered-by", "")
    if powered:
        for part in [p.strip() for p in powered.split(",")]:
            m = re.match(r'^([A-Za-z][A-Za-z0-9_.-]+?)(?:\s+|/)(\d[\d.]*)?', part)
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