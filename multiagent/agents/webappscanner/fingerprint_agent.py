import json
import logging
import re
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

try:
    from bs4 import BeautifulSoup
    _BS4 = True
except ImportError:
    _BS4 = False

logger = logging.getLogger(__name__)

_SIGNAL_CONF: Dict[str, float] = {
    "headers": 0.95,
    "meta":    0.90,
    "scripts": 0.75,
    "html":    0.60,
    "cookies": 0.55,
    "url":     0.60,
}

_MIN_CONF = 0.60

_CAT_MAP: Dict[str, str] = {
    "CMS":                   "CMS",
    "Blog":                  "CMS",
    "LMS":                   "CMS",
    "Message boards":        "CMS",
    "WordPress plugins":     "CMS",
    "WordPress themes":      "CMS",
    "Drupal extensions":     "CMS",
    "Joomla extensions":     "CMS",
    "Web frameworks":        "Framework",
    "JavaScript frameworks": "Framework",
    "Mobile frameworks":     "Framework",
    "Ecommerce":             "Framework",
    "Programming languages": "Language",
    "Web servers":           "Server",
    "Reverse proxies":       "Server",
    "Caching":               "Other",  # plugins like WP Rocket — not a web server
    "Media servers":         "Server",
    "CDN":                   "CDN",
    "Databases":             "Database",
    "Analytics":             "Analytics",
    "Tag managers":          "Analytics",
    "Security":              "Other",
    "Operating systems":     "Other",
    "Miscellaneous":         "Other",
}


def _normalise_category(wappalyzer_cat_name: str) -> str:
    return _CAT_MAP.get(wappalyzer_cat_name, "Other")


def _collapse_premium_duplicates(techs: List[Dict]) -> List[Dict]:
    """
    Collapse "<X> Premium" + "<X>" at the same (or missing) version into one
    stack entry so CVE rows are not double-counted (e.g. Yoast SEO).
    Prefer the non-Premium name; keep the higher confidence / versioned row.
    """
    if not techs:
        return techs
    by_name = {
        (t.get("name") or ""): t
        for t in techs
        if isinstance(t, dict) and t.get("name")
    }
    drop: Set[str] = set()
    for name, t in list(by_name.items()):
        if not name.endswith(" Premium"):
            continue
        base = name[: -len(" Premium")].rstrip()
        if base not in by_name:
            continue
        v_prem = (t.get("version") or "").strip()
        v_base = (by_name[base].get("version") or "").strip()
        if not v_prem or not v_base or v_prem == v_base:
            # Merge version/confidence onto base if needed, then drop Premium
            base_t = by_name[base]
            if not base_t.get("version") and v_prem:
                base_t["version"] = v_prem
            try:
                if float(t.get("confidence") or 0) > float(base_t.get("confidence") or 0):
                    base_t["confidence"] = t.get("confidence")
            except (TypeError, ValueError):
                pass
            drop.add(name)
    if not drop:
        return techs
    return [t for t in techs if (t.get("name") or "") not in drop]


def _to_list(value) -> List[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value if v]


def _parse_pattern(raw: str) -> Dict:
    parts = raw.split("\\;")
    result: Dict = {"regex": re.compile(r"(?!x)x"), "confidence": 100, "version_tpl": None}
    try:
        result["regex"] = re.compile(parts[0], re.IGNORECASE | re.DOTALL)
    except re.error:
        pass
    for part in parts[1:]:
        if ":" in part:
            k, _, v = part.partition(":")
            k = k.strip()
            v = v.strip()
            if k == "confidence":
                try:
                    result["confidence"] = max(0, min(100, int(v)))
                except ValueError:
                    pass
            elif k == "version":
                result["version_tpl"] = v
    return result


def _apply_version_tpl(m: re.Match, tpl: Optional[str]) -> Optional[str]:
    if not tpl or not m:
        return None
    version = tpl
    for i, group in enumerate(m.groups(), 1):
        version = version.replace(f"\\{i}", group or "")
    version = re.sub(r"[\s._-]+$", "", version)
    return version or None


class WappalyzerDB:
    _ENTHEC_BASE  = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies"
    _ENTHEC_CATS  = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/categories.json"
    _ALIASIO_BASE = "https://raw.githubusercontent.com/AliasIO/wappalyzer/master/src/technologies"
    _ALIASIO_CATS = "https://raw.githubusercontent.com/AliasIO/wappalyzer/master/src/technologies/_categories.json"
    _CACHE        = Path.home() / ".cache" / "yurarag" / "wappalyzer.json"
    _TTL_DAYS     = 7

    def __init__(self) -> None:
        self.technologies: Dict = {}
        self.categories:   Dict = {}
        self._loaded = False

    def load(self) -> bool:
        if self._loaded:
            return True
        return self._from_cache() or self._fetch_and_cache()

    def category_label(self, cat_ids: List) -> str:
        for cat_id in cat_ids:
            raw = self.categories.get(str(cat_id), {}).get("name", "")
            if raw:
                return _normalise_category(raw)
        return "Other"

    def _from_cache(self) -> bool:
        try:
            if not self._CACHE.exists():
                return False
            age_days = (datetime.now() - datetime.fromtimestamp(
                self._CACHE.stat().st_mtime)).days
            if age_days >= self._TTL_DAYS:
                return False
            data = json.loads(self._CACHE.read_text(encoding="utf-8"))
            self.technologies = data["technologies"]
            self.categories   = data["categories"]
            self._loaded = True
            return True
        except Exception as e:
            logger.debug(f"Wappalyzer cache read failed: {e}")
            return False

    def _get(self, url: str) -> Optional[str]:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0 (SecurityScanner/1.0)"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.read().decode("utf-8")
        except Exception as e:
            logger.debug(f"Wappalyzer fetch {url}: {e}")
            return None

    def _fetch_and_cache(self) -> bool:
        technologies, categories = self._fetch_enthec()
        if not technologies:
            technologies, categories = self._fetch_aliasio()
        if not technologies:
            return False
        self.technologies = technologies
        self.categories   = categories
        self._loaded = True
        try:
            self._CACHE.parent.mkdir(parents=True, exist_ok=True)
            self._CACHE.write_text(
                json.dumps({"technologies": technologies, "categories": categories}),
                encoding="utf-8",
            )
        except Exception as e:
            logger.warning(f"Wappalyzer cache write failed: {e}")
        return True

    def _fetch_enthec(self) -> Tuple[Dict, Dict]:
        technologies: Dict = {}
        categories:   Dict = {}
        raw = self._get(self._ENTHEC_CATS)
        if raw:
            try:
                data = json.loads(raw)
                if data and isinstance(next(iter(data.values()), None), dict):
                    categories = data
                else:
                    categories = data.get("categories", data)
            except Exception as e:
                logger.debug(f"enthec categories parse error: {e}")
        for letter in "abcdefghijklmnopqrstuvwxyz":
            raw = self._get(f"{self._ENTHEC_BASE}/{letter}.json")
            if raw:
                try:
                    data = json.loads(raw)
                    if "technologies" in data:
                        technologies.update(data["technologies"])
                    else:
                        technologies.update(data)
                except Exception as e:
                    logger.debug(f"enthec {letter}.json parse error: {e}")
        return technologies, categories

    def _fetch_aliasio(self) -> Tuple[Dict, Dict]:
        technologies: Dict = {}
        categories:   Dict = {}
        raw = self._get(self._ALIASIO_CATS)
        if raw:
            try:
                data = json.loads(raw)
                categories = data.get("categories", data)
            except Exception as e:
                logger.debug(f"AliasIO categories parse error: {e}")
        for letter in "abcdefghijklmnopqrstuvwxyz":
            raw = self._get(f"{self._ALIASIO_BASE}/{letter}.json")
            if raw:
                try:
                    data = json.loads(raw)
                    technologies.update(data.get("technologies", data))
                except Exception as e:
                    logger.debug(f"AliasIO {letter}.json parse error: {e}")
        return technologies, categories


class WappalyzerMatcher:
    def __init__(self, db: WappalyzerDB) -> None:
        self.db = db

    def match_all(self, signals: Dict) -> List[Dict]:
        best: Dict[str, Dict] = {}
        for tech_name, tech in self.db.technologies.items():
            dt = self._match_one(tech_name, tech, signals)
            if dt is None:
                continue
            existing = best.get(tech_name)
            if existing is None or dt["confidence"] > existing["confidence"]:
                best[tech_name] = dt
        matched = [t for t in best.values() if t["confidence"] >= _MIN_CONF]
        matched.sort(key=lambda t: t["confidence"], reverse=True)
        return matched

    def _match_one(self, name: str, tech: Dict, signals: Dict) -> Optional[Dict]:
        headers = signals.get("headers", {})
        html    = signals.get("html", "")
        scripts = signals.get("scripts", [])
        meta    = signals.get("meta", {})
        cookies = signals.get("cookies", {})
        url     = signals.get("url", "")

        best: Optional[Tuple[float, str, Optional[str]]] = None

        def _update(conf: float, evidence: str, version: Optional[str]) -> None:
            nonlocal best
            if best is None or conf > best[0]:
                best = (conf, evidence, version)

        for hdr_name, raw_pat in (tech.get("headers") or {}).items():
            val = headers.get(hdr_name.lower(), "")
            if not val:
                continue
            p = _parse_pattern(str(raw_pat))
            m = p["regex"].search(val)
            if m:
                conf = _SIGNAL_CONF["headers"] * (p["confidence"] / 100)
                _update(conf, f"{hdr_name} header: {val[:80]}", _apply_version_tpl(m, p["version_tpl"]))

        meta_pats = tech.get("meta") or {}
        if isinstance(meta_pats, str):
            meta_pats = {"generator": meta_pats}
        for meta_name, raw_pat in meta_pats.items():
            val = meta.get(meta_name.lower(), "")
            if not val:
                continue
            p = _parse_pattern(str(raw_pat))
            m = p["regex"].search(val)
            if m:
                conf = _SIGNAL_CONF["meta"] * (p["confidence"] / 100)
                _update(conf, f"meta {meta_name}: {val[:80]}", _apply_version_tpl(m, p["version_tpl"]))

        for raw_pat in _to_list(tech.get("scripts")):
            p = _parse_pattern(raw_pat)
            for script_url in scripts:
                m = p["regex"].search(script_url)
                if m:
                    conf = _SIGNAL_CONF["scripts"] * (p["confidence"] / 100)
                    _update(conf, f"script: {script_url[:100]}", _apply_version_tpl(m, p["version_tpl"]))

        for raw_pat in _to_list(tech.get("html")):
            p = _parse_pattern(raw_pat)
            m = p["regex"].search(html)
            if m:
                conf = _SIGNAL_CONF["html"] * (p["confidence"] / 100)
                _update(conf, f"html: {m.group(0)[:80]}", _apply_version_tpl(m, p["version_tpl"]))

        cookie_pats = tech.get("cookies") or {}
        if isinstance(cookie_pats, str):
            cookie_pats = {"": cookie_pats}
        for ck_name_pat, raw_val_pat in cookie_pats.items():
            for ck_name, ck_val in cookies.items():
                try:
                    if ck_name_pat and not re.search(ck_name_pat, ck_name, re.I):
                        continue
                except re.error:
                    continue
                p = _parse_pattern(str(raw_val_pat) if raw_val_pat else ".*")
                m = p["regex"].search(ck_val)
                if m:
                    conf = _SIGNAL_CONF["cookies"] * (p["confidence"] / 100)
                    _update(conf, f"cookie {ck_name}: {ck_val[:60]}", _apply_version_tpl(m, p["version_tpl"]))

        for raw_pat in _to_list(tech.get("url")):
            p = _parse_pattern(raw_pat)
            m = p["regex"].search(url)
            if m:
                conf = _SIGNAL_CONF["url"] * (p["confidence"] / 100)
                _update(conf, f"url: {url[:100]}", _apply_version_tpl(m, p["version_tpl"]))

        if best is None or best[0] < _MIN_CONF:
            return None

        conf, evidence, version = best
        cats     = tech.get("cats", [])
        category = self.db.category_label(cats)

        return {
            "name":       name,
            "version":    version,
            "category":   category,
            "confidence": round(conf, 3),
            "evidence":   evidence,
        }


_SERVER_SIGS = {
    "nginx":    r"nginx(?:/(\S+))?",
    "Apache":   r"Apache(?:/(\S+))?",
    "IIS":      r"Microsoft-IIS(?:/(\S+))?",
    "Caddy":    r"Caddy",
    "gunicorn": r"gunicorn(?:/(\S+))?",
    "Tomcat":   r"Apache-Coyote|Tomcat",
    "lighttpd": r"lighttpd(?:/(\S+))?",
}
_FRAMEWORK_SIGS = {
    "Laravel":    r"laravel_session",
    "Django":     r"csrftoken|django",
    "Rails":      r"_rails_session|X-Runtime",
    "FastAPI":    r"fastapi|uvicorn",
    "Spring":     r"JSESSIONID|X-Application-Context",
    "ASP.NET":    r"ASP\.NET|X-AspNet-Version",
    "Next.js":    r"__NEXT_DATA__|x-nextjs",
    "Nuxt":       r"__nuxt|_nuxt",
    "Cloudflare": r"cf-ray|cf-cache-status",
}
_CMS_SIGS = {
    "WordPress": r"wp-content|wp-includes|wordpress",
    "Drupal":    r"Drupal|drupal",
    "Joomla":    r"Joomla|joomla",
    "Magento":   r"Magento|mage",
    "Shopify":   r"shopify|myshopify\.com",
}
_LANG_SIGS = {
    "PHP":    r"\.php|X-Powered-By: PHP|PHPSESSID",
    "Python": r"python|django|flask|fastapi",
    "Ruby":   r"\.rb|rack\.|_rails",
    "Java":   r"JSESSIONID|\.jsp|\.do\b",
    "Node":   r"X-Powered-By: Express|node\.js",
    ".NET":   r"X-AspNet-Version|\.aspx|ASP\.NET",
    "Go":     r"Go-http-client|gorilla",
}


def _rule_match(text: str, sigs: Dict[str, str]) -> Optional[Tuple[str, Optional[str]]]:
    for name, pattern in sigs.items():
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            ver = m.group(1) if m.lastindex else None
            return name, ver
    return None


def _rule_detect(headers: Dict, html_hints: List[str]) -> List[Dict]:
    combined = (
        " ".join(f"{k}: {v}" for k, v in headers.items())
        + " " + " ".join(html_hints)
    )
    cat_map = {"server": "Server", "language": "Language", "framework": "Framework", "cms": "CMS"}
    results = []
    for field, sigs in [("server", _SERVER_SIGS), ("language", _LANG_SIGS),
                         ("framework", _FRAMEWORK_SIGS), ("cms", _CMS_SIGS)]:
        match = _rule_match(combined, sigs)
        if match:
            name, ver = match
            results.append({
                "name":       name,
                "version":    ver,
                "category":   cat_map[field],
                "confidence": 0.60,
                "evidence":   f"rule-based {field} match",
            })
    return results


_CAT_HINT_TPL: Dict[str, str] = {
    "CMS":       "Check {name} version against CVE database; probe admin interface",
    "Framework": "Test {name} for debug mode and framework-specific CVEs",
    "Server":    "Verify {name} version; check for default config and known CVEs",
    "Language":  "Check {name} version for injection and runtime CVEs",
    "CDN":       "Verify CDN security headers (CSP, HSTS, X-Frame-Options)",
    "Database":  "Test for {name} injection and default credential exposure",
}


def _rule_vuln_hints(detected: List[Dict]) -> List[str]:
    hints = []
    seen_cats: set = set()
    for tech in detected:
        tpl = _CAT_HINT_TPL.get(tech["category"])
        if tpl and tech["category"] not in seen_cats:
            display = tech["name"]
            if tech.get("version"):
                display += f" {tech['version']}"
            hints.append(tpl.format(name=display))
            seen_cats.add(tech["category"])
    if not hints:
        hints.append("Review HTTP security headers (CSP, HSTS, X-Frame-Options, Referrer-Policy)")
    return hints[:5]


def _parse_cookies(headers: Dict) -> Dict[str, str]:
    cookies: Dict[str, str] = {}
    raw_vals = headers.get("set-cookie", "")
    candidates = raw_vals if isinstance(raw_vals, list) else ([raw_vals] if raw_vals else [])
    for raw in candidates:
        first = raw.split(";")[0].strip()
        if "=" in first:
            name, _, value = first.partition("=")
            cookies[name.strip()] = value.strip()
    return cookies


class TechFingerprintAgent:
    def __init__(self, openai_client, llm_model: str) -> None:
        self.openai_client = openai_client
        self.llm_model     = llm_model
        self._db           = WappalyzerDB()
        self._matcher      = WappalyzerMatcher(self._db)

    async def fingerprint(self, target_url: str,
                          page_html: Optional[str] = None,
                          response_headers: Optional[Dict] = None,
                          verbose: bool = False) -> Dict:
        if verbose:
            print(f"\n Fingerprinting: {target_url}")

        headers: Dict = response_headers or {}
        if not headers:
            headers = await self._fetch_headers(target_url, verbose)

        signals = self._extract_signals(target_url, page_html or "", headers)

        db_loaded = self._db.load()
        if verbose:
            if db_loaded:
                print(f"   Wappalyzer DB: {len(self._db.technologies)} technologies")
            else:
                print("   Wappalyzer DB: unavailable — using rule-based fallback")

        detected: List[Dict] = []
        if db_loaded:
            detected = self._matcher.match_all(signals)
            detected = _collapse_premium_duplicates(detected)
            if verbose:
                print(f"   Wappalyzer: {len(detected)} technologies detected")
                for dt in detected[:6]:
                    print(f"     [{dt['category']:10s}] {dt['name']:30s} conf={dt['confidence']:.2f}")

        unverified_hints: List[str] = []
        vuln_hints:       List[str] = []

        if len(detected) < 2:
            if verbose:
                print("   Invoking LLM synthesis (Wappalyzer insufficient)...")
            llm_result = await self._llm_synthesize(target_url, signals, detected)
            for tech_name in llm_result.get("technologies", []):
                if not any(d["name"].lower() == tech_name.lower() for d in detected):
                    unverified_hints.append(tech_name)
            vuln_hints = llm_result.get("vuln_hints", [])
            if not detected:
                detected = _rule_detect(headers, signals.get("html_hints", []))
        else:
            vuln_hints = _rule_vuln_hints(detected)

        stack = self._build_stack(headers, detected, vuln_hints, unverified_hints)

        if verbose:
            print(f"   Stack: {stack.get('stack_summary', 'Unknown')}")

        return stack

    def _extract_signals(self, url: str, html: str, headers: Dict) -> Dict:
        headers_lower = {k.lower(): v for k, v in headers.items()}
        scripts:    List[str]      = []
        meta:       Dict[str, str] = {}
        html_hints: List[str]      = []

        if html:
            if _BS4:
                try:
                    soup   = BeautifulSoup(html, "lxml")
                    scripts = [s["src"] for s in soup.find_all("script", src=True)]
                    meta    = {
                        t["name"].lower(): t["content"]
                        for t in soup.find_all("meta", attrs={"name": True, "content": True})
                    }
                    html_hints = scripts[:]
                except Exception:
                    pass
            else:
                scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
                meta    = {
                    k.lower(): v
                    for k, v in re.findall(
                        r'<meta\s+name=["\']([^"\']+)["\'][^>]+content=["\']([^"\']+)["\']',
                        html, re.I,
                    )
                }

        cookies = _parse_cookies(headers_lower)

        return {
            "headers":    headers_lower,
            "html":       html,
            "scripts":    scripts,
            "meta":       meta,
            "cookies":    cookies,
            "url":        url,
            "html_hints": html_hints,
        }

    async def _fetch_headers(self, url: str, verbose: bool = False) -> Dict:
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sync_fetch_headers, url, verbose)

    def _sync_fetch_headers(self, url: str, verbose: bool = False) -> Dict:
        headers: Dict = {}
        for method in ("HEAD", "GET"):
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"},
                    method=method,
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    headers = dict(resp.headers)
                if verbose and headers:
                    print(f"   Fetched {len(headers)} headers via {method}")
                return headers
            except Exception as e:
                logger.debug(f"Header {method} failed for {url}: {e}")
        return headers

    def _build_stack(self, headers: Dict,
                     detected: List[Dict],
                     vuln_hints: List[str],
                     unverified_hints: List[str]) -> Dict:
        by_cat: Dict[str, List[Dict]] = {}
        for dt in detected:
            by_cat.setdefault(dt["category"], []).append(dt)

        def _top(cat: str) -> Optional[str]:
            items = by_cat.get(cat, [])
            if not items:
                return None
            dt = items[0]
            return f"{dt['name']} {dt['version']}".strip() if dt.get("version") else dt["name"]

        server    = _top("Server")
        language  = _top("Language")
        framework = _top("Framework")
        cms       = _top("CMS")
        cdn       = _top("CDN")

        summary_parts = [p for p in [server, language, cms or framework, cdn] if p]
        if not summary_parts:
            summary_parts = [
                (f"{dt['name']} {dt['version']}".strip() if dt.get("version") else dt["name"])
                for dt in detected[:3]
            ]
        stack_summary = " · ".join(summary_parts) if summary_parts else "Unknown"

        best_conf = max((dt["confidence"] for dt in detected), default=0.0)
        if best_conf >= 0.85:
            confidence = "High"
        elif best_conf >= 0.60:
            confidence = "Medium"
        else:
            confidence = "Low"

        return {
            "server":           server,
            "language":         language,
            "framework":        framework,
            "frontend":         None,
            "cms":              cms,
            "cdn":              cdn,
            "waf":              None,
            "stack_summary":    stack_summary,
            "confidence":       confidence,
            "vuln_hints":       vuln_hints,
            "headers":          headers,
            "technologies":     detected,
            "unverified_hints": unverified_hints,
        }

    async def _llm_synthesize(self, url: str, signals: Dict,
                               wap_detected: List[Dict]) -> Dict:
        headers_summary = "\n".join(
            f"  {k}: {v}"
            for k, v in list(signals.get("headers", {}).items())[:20]
        )
        meta_summary = ", ".join(
            f"{k}={v[:40]}"
            for k, v in list(signals.get("meta", {}).items())[:5]
        ) or "none"
        wap_summary = (
            ", ".join(
                (f"{d['name']} {d['version']}".strip() if d.get("version") else d["name"])
                for d in wap_detected
            ) or "none confirmed"
        )

        prompt = f"""You are a web technology fingerprinting expert.

Target URL: {url}

HTTP Response Headers:
{headers_summary or "  (none captured)"}

Meta tags: {meta_summary}
Wappalyzer-confirmed technologies: {wap_summary}

Based on the evidence above, produce a JSON object:
{{
  "technologies": ["<tech name only — no version, no UI text>"],
  "vuln_hints":   ["<specific, actionable security check for this stack>"]
}}

Rules:
- technologies: list of short identifier names only. Max 5.
  Do NOT include: generic words, UI text, marketing phrases, descriptions, sentences,
  strings longer than 30 characters, strings containing "!", " - ", or "free".
- vuln_hints: 3-5 specific checks for THIS stack only.

Respond with JSON only. No markdown."""

        empty: Dict = {"technologies": [], "vuln_hints": []}
        try:
            response = self.openai_client.chat.completions.create(
                model=self.llm_model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
                max_tokens=400,
            )
            raw = response.choices[0].message.content.strip()
            if raw.startswith("```"):
                raw = re.sub(r"```[a-z]*\n?", "", raw).strip("` \n")
            result = json.loads(raw)
            if not isinstance(result, dict):
                return empty
            techs = [
                t for t in (result.get("technologies") or [])
                if isinstance(t, str)
                and 2 < len(t.strip()) <= 30
                and "!" not in t
                and " - " not in t
                and "free" not in t.lower()
                and len(t.split()) <= 3
            ]
            result["technologies"] = techs[:5]
            result["vuln_hints"]   = (result.get("vuln_hints") or [])[:5]
            return result
        except Exception as e:
            logger.warning(f"LLM fingerprint fallback failed: {e}")
            return empty