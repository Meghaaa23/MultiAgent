import os
import json
import logging
import asyncio
import re
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

CONFIDENCE_HIGH   = "High"
CONFIDENCE_MEDIUM = "Medium"
CONFIDENCE_LOW    = "Low"

_SKIP_CVE = {
    "cloudflare", "aws cloudfront", "fastly", "akamai", "cloudflair",
    "via", "unknown", "hosted ai platform", "cdn", "waf",
    "fontawesome", "font awesome", "bootstrap", "jquery",
    "google analytics", "google tag manager", "google fonts",
    "youtube", "vimeo", "intercom", "hotjar",
}

_GENERIC_RUNTIMES = {
    "nginx", "apache", "iis", "node.js", "nodejs", "python",
    "ruby", "java", "php", "gunicorn", "caddy", "lighttpd",
    "openresty", "tomcat", "jetty",
    "vue", "react", "angular", "svelte", "webpack", "vite",
    "typescript", "javascript", "css", "html",
}

_CVE_WORTHY_CATEGORIES = {"CMS"}
_CVE_WORTHY_WITH_VERSION = {"Framework", "Server"}


class CVEVerificationPipeline:

    NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    OSV_BASE = "https://api.osv.dev/v1/query"

    def __init__(self, web_search_function=None, nvd_api_key: str = ""):
        self.web_search  = web_search_function
        self.nvd_api_key = nvd_api_key or os.environ.get("NVD_API_KEY", "")
        self._cache: Dict[str, List[Dict]] = {}

    async def lookup(self, stack: Dict, verbose: bool = False) -> Optional[List[Dict]]:
        if verbose:
            print(f"\n CVE Verification Pipeline")
            print(f"   Stack: {stack.get('stack_summary', 'Unknown')}")
            if self.nvd_api_key:
                print("   NVD API key: present")
            else:
                print("   NVD API key: absent (rate-limited to 5 req/30s)")

        queries = self._build_queries(stack)

        if not queries:
            if verbose:
                print("     No queryable components — skipping CVE lookup")
            return []

        if verbose:
            print(f"   Queries: {queries}")

        tasks = [self._fetch_nvd(q, verbose) for q in queries]
        tasks += [self._fetch_osv(q, stack, verbose) for q in queries]

        results_nested = await asyncio.gather(*tasks, return_exceptions=True)

        all_cves: List[Dict] = []
        nvd_tasks_count  = len(queries)
        nvd_failed_count = 0
        for i, r in enumerate(results_nested):
            if r is None:
                if i < nvd_tasks_count:
                    nvd_failed_count += 1
            elif isinstance(r, list):
                all_cves.extend(r)

        if nvd_failed_count == nvd_tasks_count and not all_cves:
            logger.warning(
                "All NVD queries failed — likely rate-limited. "
                "Set NVD_API_KEY in .env to raise the limit."
            )
            return None

        seen: Dict[str, Dict] = {}
        for cve in all_cves:
            cid = cve.get("cve_id", "")
            if cid and cid not in seen:
                seen[cid] = cve
            elif not cid:
                title = cve.get("title", "")
                if title and title not in {v.get("title") for v in seen.values()}:
                    seen[f"no-id-{len(seen)}"] = cve

        verified = list(seen.values())
        verified.sort(key=lambda x: x.get("published", ""), reverse=True)

        if verbose:
            print(f"   ✓ Verified CVEs: {len(verified)}")
            for v in verified[:5]:
                print(f"     [{v.get('severity','?')}] {v.get('cve_id','?')} — {v.get('title','')[:60]}")

        return verified

    def _build_queries(self, stack: Dict) -> List[str]:
        queries: List[str] = []

        technologies = stack.get("technologies", [])
        if isinstance(technologies, list):
            for tech in technologies:
                if isinstance(tech, dict):
                    name     = tech.get("name", "").strip()
                    version  = tech.get("version", "")
                    category = tech.get("category", "")
                    tl       = name.lower()

                    if not name or tl in _SKIP_CVE:
                        continue

                    if version:
                        queries.append(f"{name} {version}")
                        queries.append(name)

                    elif category in _CVE_WORTHY_CATEGORIES:
                        queries.append(name)

                elif isinstance(tech, str):
                    tech = tech.strip()
                    tl   = tech.lower().split("/")[0].strip()

                    if tl in _SKIP_CVE:
                        continue
                    if len(tech) < 2 or tech.lower() in ("unknown", "none", "null"):
                        continue

                    has_version = "/" in tech or any(c.isdigit() for c in tech.split("/")[-1])

                    if has_version:
                        if "/" in tech:
                            name, ver = tech.split("/", 1)
                        else:
                            parts = tech.split()
                            name  = parts[0]
                            ver   = parts[1] if len(parts) > 1 else ""
                        name = name.strip()
                        ver  = ver.strip()
                        if ver:
                            queries.append(f"{name} {ver}")
                        queries.append(name)
                    else:
                        if tl not in _GENERIC_RUNTIMES:
                            queries.append(tech)

        legacy_components = [
            stack.get("server"),
            stack.get("language"),
            stack.get("framework"),
            stack.get("cms"),
        ]
        for component in legacy_components:
            if not component or not isinstance(component, str):
                continue
            component = component.strip()
            tl = component.lower().split("/")[0].strip()
            if tl in _SKIP_CVE:
                continue
            has_version = "/" in component or any(c.isdigit() for c in component)
            if has_version:
                if "/" in component:
                    name, ver = component.split("/", 1)
                else:
                    parts = component.split()
                    name  = parts[0]
                    ver   = parts[1] if len(parts) > 1 else ""
                queries.append(f"{name.strip()} {ver.strip()}".strip())
                queries.append(name.strip())
            elif tl not in _GENERIC_RUNTIMES:
                queries.append(component)

        summary = stack.get("stack_summary", "")
        if summary and summary not in ("Unknown", "") and not technologies:
            tl = summary.lower().split("/")[0].strip()
            if tl not in _SKIP_CVE and tl not in _GENERIC_RUNTIMES:
                queries.append(summary)

        return list(dict.fromkeys(q for q in queries if q and len(q) > 1))
    

    def _normalize_product(self, text: str) -> str:
        text = text.lower()
        text = re.sub(r"[^a-z0-9]+", " ", text)
        return " ".join(text.split())


    def _product_matches(self, keyword: str, description: str, affected: str) -> bool:
        """
        Return True only if the detected product actually appears in the
        NVD description/configuration.
        """

        product = self._normalize_product(keyword)

        # Remove version from the search term
        product = re.sub(r"\b\d+(\.\d+)*\b", "", product).strip()

        searchable = self._normalize_product(
            f"{description} {affected}"
        )

        return product in searchable

    async def _fetch_nvd(self, keyword: str, verbose: bool = False) -> Optional[List[Dict]]:
        cache_key = f"nvd:{keyword}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        results = []
        try:
            params = urllib.parse.urlencode({
                "keywordSearch":  keyword,
                "resultsPerPage": 10,
                "startIndex":     0,
            })
            url = f"{self.NVD_BASE}?{params}"

            nvd_headers = {}
            if self.nvd_api_key:
                nvd_headers["apiKey"] = self.nvd_api_key

            loop = asyncio.get_event_loop()
            raw  = await loop.run_in_executor(
                None, lambda: self._http_get(url, extra_headers=nvd_headers)
            )

            if not raw:
                return None

            data            = json.loads(raw)
            vulnerabilities = data.get("vulnerabilities", [])

            import datetime
            _min_year = datetime.datetime.now(datetime.timezone.utc).year - 10

            for item in vulnerabilities:
                cve_data  = item.get("cve", {})
                cve_id    = cve_data.get("id", "")
                published = cve_data.get("published", "")
                try:
                    if published and int(published[:4]) < _min_year:
                        continue
                except (ValueError, TypeError):
                    pass

                descs = cve_data.get("descriptions", [])
                desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "")

                metrics    = cve_data.get("metrics", {})
                cvss_score = None
                severity   = "Unknown"

                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metric_list = metrics.get(key, [])
                    if metric_list:
                        cvss_data  = metric_list[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        severity   = cvss_data.get("baseSeverity", "Unknown").capitalize()
                        break

                configs      = cve_data.get("configurations", [])
                affected_str = self._extract_affected(configs)
                if not self._product_matches(keyword, desc, affected_str):
                    if verbose:
                        print(f"Rejected {cve_id} (product mismatch)")
                    continue

                results.append({
                    "cve_id":      cve_id,
                    "title":       cve_id,
                    "description": desc[:500],
                    "severity":    severity,
                    "cvss_score":  cvss_score,
                    "affected":    affected_str,
                    "published":   published[:10] if published else "",
                    "source":      "NVD",
                    "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "confidence":  CONFIDENCE_HIGH if cvss_score else CONFIDENCE_MEDIUM,
                    "verified":    True,
                    "query":       keyword,
                })

            self._cache[cache_key] = results

        except Exception as e:
            logger.warning(f"NVD fetch failed for '{keyword}': {e}")
            return None

        return results

    def _extract_affected(self, configs: List) -> str:
        versions = []
        for config in configs:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        vi      = match.get("versionStartIncluding", "")
                        ve      = match.get("versionEndExcluding", "")
                        cpe     = match.get("criteria", "")
                        parts   = cpe.split(":")
                        product = parts[4] if len(parts) > 4 else cpe
                        if vi and ve:
                            versions.append(f"{product} >= {vi}, < {ve}")
                        elif ve:
                            versions.append(f"{product} < {ve}")
                        elif vi:
                            versions.append(f"{product} >= {vi}")
                        else:
                            versions.append(product)
        return "; ".join(versions[:3]) if versions else "See NVD for details"

    async def _fetch_osv(self, keyword: str, stack: Dict,
                         verbose: bool = False) -> List[Dict]:
        cache_key = f"osv:{keyword}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        results = []

        ecosystem_map = {
            "php":    "Packagist",
            "python": "PyPI",
            "ruby":   "RubyGems",
            "node":   "npm",
            "java":   "Maven",
            ".net":   "NuGet",
            "go":     "Go",
        }

        language  = stack.get("language", "").lower()
        techs     = stack.get("technologies", [])
        techs_str = " ".join(
            t.get("name", "") if isinstance(t, dict) else str(t)
            for t in techs
        ).lower()
        combined  = language + " " + techs_str

        ecosystem = None
        for lang, eco in ecosystem_map.items():
            if lang in combined:
                ecosystem = eco
                break

        kl = keyword.lower()
        if not ecosystem:
            if any(x in kl for x in ["gradio", "torch", "tensorflow", "fastapi",
                                       "flask", "django", "langchain", "flowise"]):
                ecosystem = "PyPI"
            elif any(x in kl for x in ["next.js", "react", "vue", "svelte",
                                         "express", "node"]):
                ecosystem = "npm"
            elif any(x in kl for x in ["wordpress", "drupal", "laravel"]):
                ecosystem = "Packagist"

        if not ecosystem:
            return []

        try:
            pkg_name = keyword.split()[0].lower()
            name_map = {
                "gradio":    "gradio",
                "next.js":   "next",
                "sveltekit": "@sveltejs/kit",
                "langchain": "langchain",
                "flowise":   "flowise",
                "wordpress": "wordpress",
                "drupal":    "drupal",
            }
            pkg_name = name_map.get(pkg_name, pkg_name)

            payload = json.dumps({
                "package": {"name": pkg_name, "ecosystem": ecosystem}
            }).encode()

            loop = asyncio.get_event_loop()
            raw  = await loop.run_in_executor(None, self._http_post, self.OSV_BASE, payload)

            if not raw:
                return []

            data = json.loads(raw)

            import datetime as _dt
            _osv_min_year = _dt.datetime.now(_dt.timezone.utc).year - 10

            for item in data.get("vulns", []):
                vuln_id = item.get("id", "")
                _pub    = item.get("published", "")
                try:
                    _year = int(_pub[:4]) if _pub else int(vuln_id[4:8])
                    if _year < _osv_min_year:
                        continue
                except (ValueError, TypeError, IndexError):
                    pass

                summary    = item.get("summary", "")
                details    = item.get("details", "")[:400]
                severity   = "Unknown"
                cvss_score = None

                for sev in item.get("severity", []):
                    if sev.get("type") in ("CVSS_V3", "CVSS_V3_1"):
                        score_str = sev.get("score", "")
                        try:
                            cvss_score = float(score_str)
                            if   cvss_score >= 9.0: severity = "Critical"
                            elif cvss_score >= 7.0: severity = "High"
                            elif cvss_score >= 4.0: severity = "Medium"
                            else:                   severity = "Low"
                        except ValueError:
                            pass

                affected_parts = []
                for aff in item.get("affected", [])[:2]:
                    for r in aff.get("ranges", []):
                        evts       = r.get("events", [])
                        introduced = next((e["introduced"] for e in evts if "introduced" in e), None)
                        fixed      = next((e["fixed"] for e in evts if "fixed" in e), None)
                        if introduced and fixed:
                            affected_parts.append(f">= {introduced}, < {fixed}")
                        elif introduced:
                            affected_parts.append(f">= {introduced}")

                results.append({
                    "cve_id":      vuln_id,
                    "title":       summary or vuln_id,
                    "description": details,
                    "severity":    severity,
                    "cvss_score":  cvss_score,
                    "affected":    "; ".join(affected_parts) or "See OSV for details",
                    "published":   _pub[:10] if _pub else "",
                    "source":      "OSV",
                    "url":         f"https://osv.dev/vulnerability/{vuln_id}",
                    "confidence":  CONFIDENCE_HIGH if cvss_score else CONFIDENCE_MEDIUM,
                    "verified":    True,
                    "query":       keyword,
                })

            self._cache[cache_key] = results

        except Exception as e:
            logger.warning(f"OSV fetch failed for '{keyword}': {e}")

        return results

    def _http_get(self, url: str, timeout: int = 10,
                  extra_headers: Optional[Dict] = None) -> Optional[str]:
        try:
            headers = {
                "User-Agent": "YuraRAG-SecurityScanner/1.0",
                "Accept":     "application/json",
            }
            if extra_headers:
                headers.update(extra_headers)
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            if e.code in (429, 403):
                logger.warning(
                    f"NVD rate limited (HTTP {e.code}) — "
                    f"add NVD_API_KEY to .env to raise the limit"
                )
            else:
                logger.warning(f"HTTP {e.code} fetching {url}")
        except Exception as e:
            logger.warning(f"GET failed for {url}: {e}")
        return None

    def _http_post(self, url: str, data: bytes, timeout: int = 10) -> Optional[str]:
        try:
            req = urllib.request.Request(
                url, data=data,
                headers={
                    "User-Agent":   "YuraRAG-SecurityScanner/1.0",
                    "Content-Type": "application/json",
                    "Accept":       "application/json",
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8")
        except Exception as e:
            logger.warning(f"POST failed for {url}: {e}")
        return None