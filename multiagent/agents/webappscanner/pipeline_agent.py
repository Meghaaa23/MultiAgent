# agents/cve_pipeline.py
"""
CVEVerificationPipeline
=======================
Implements the evidence-based CVE lookup pipeline:

  Stack fingerprint → query real DBs → return only verified CVEs

The LLM is NEVER allowed to invent or guess CVEs.
All CVEs in the final report must pass through this pipeline.

Data sources (all free, no API key required):
  1. NVD  - https://services.nvd.nist.gov/rest/json/cves/2.0
  2. OSV  - https://api.osv.dev/v1/query

Flow
----
fingerprint → build_queries → fetch_nvd + fetch_osv → deduplicate → return

FIX: _build_queries now reads from stack["technologies"] list (not the
     old field-based format). Also relaxed version requirement:
     - Versioned tech (nginx/1.24): query with AND without version
     - Named apps without version (Gradio, WordPress): query by name only
     - Generic runtimes without version (nginx, PHP): skip (too noisy)
     - CDN/infra (Cloudflare, Fastly): always skip
"""

import json
import logging
import asyncio
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

CONFIDENCE_HIGH   = "High"
CONFIDENCE_MEDIUM = "Medium"
CONFIDENCE_LOW    = "Low"

# ---------------------------------------------------------------------------
# Components to skip for CVE lookup — no application CVEs
# ---------------------------------------------------------------------------

_SKIP_CVE = {
    "cloudflare", "aws cloudfront", "fastly", "akamai", "cloudflair",
    "via", "unknown", "hosted ai platform", "cdn", "waf",
}

_GENERIC_RUNTIMES = {
    "nginx", "apache", "iis", "node.js", "nodejs", "python",
    "ruby", "java", "php", "gunicorn", "caddy", "lighttpd",
    "openresty", "tomcat", "jetty",
}


class CVEVerificationPipeline:
    """
    Query real CVE databases based on a confirmed tech stack.
    Never invents CVEs — only returns what the databases contain.
    """

    NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    OSV_BASE = "https://api.osv.dev/v1/query"

    def __init__(self, web_search_function=None):
        self.web_search = web_search_function
        self._cache: Dict[str, List[Dict]] = {}

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def lookup(self, stack: Dict, verbose: bool = False) -> List[Dict]:
        """
        Given a fingerprinted tech stack, return a deduplicated list
        of verified CVE records.
        """
        if verbose:
            print(f"\n CVE Verification Pipeline")
            print(f"   Stack: {stack.get('stack_summary', 'Unknown')}")

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
        for r in results_nested:
            if isinstance(r, list):
                all_cves.extend(r)

        # Deduplicate by CVE ID
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
        verified.sort(key=lambda x: x.get("cvss_score") or 0, reverse=True)

        if verbose:
            print(f"   ✓ Verified CVEs: {len(verified)}")
            for v in verified[:5]:
                print(f"     [{v.get('severity','?')}] "
                      f"{v.get('cve_id','?')} — "
                      f"{v.get('title','')[:60]}")

        return verified

    # ------------------------------------------------------------------
    # Query builder — FIXED
    # ------------------------------------------------------------------

    def _build_queries(self, stack: Dict) -> List[str]:
        """
        Build CVE search queries from the stack fingerprint.

        Reads from stack["technologies"] (list format) which is the
        actual format produced by _validate_stack and app_identity.

        Query strategy:
          - Versioned tech (nginx/1.24.0, WordPress/6.4):
              → query "nginx 1.24.0" AND "nginx" (specific + broad)
          - Named app without version (Gradio, SvelteKit, Next.js):
              → query "Gradio" (broad — these are real products with CVEs)
          - Generic runtime without version (nginx, PHP, python):
              → SKIP — too broad, produces irrelevant CVEs
          - CDN/infra (Cloudflare, AWS CloudFront):
              → SKIP — not applications, no useful CVEs

        Also reads from legacy fields (server, language, framework, cms)
        for backward compatibility.
        """
        queries: List[str] = []

        # ── Source 1: technologies list  ────
        technologies = stack.get("technologies", [])
        if isinstance(technologies, list):
            for tech in technologies:
                if not tech or not isinstance(tech, str):
                    continue

                tech = tech.strip()
                tl   = tech.lower().split("/")[0].strip()

                # Skip CDN/infra — no useful CVEs
                if tl in _SKIP_CVE:
                    continue

                # Skip noise strings
                if len(tech) < 2 or tech.lower() in ("unknown", "none", "null"):
                    continue

                has_version = "/" in tech or any(
                    c.isdigit() for c in tech.split("/")[-1]
                )

                if has_version:
                    # Versioned — query both specific and broad
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

        # ── Source 2: legacy field format ────
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

        # ── Source 3: stack_summary as fallback ───────────────────────
        summary = stack.get("stack_summary", "")
        if summary and summary not in ("Unknown", "") and not technologies:
            tl = summary.lower().split("/")[0].strip()
            if tl not in _SKIP_CVE and tl not in _GENERIC_RUNTIMES:
                queries.append(summary)

        # Deduplicate preserving order
        return list(dict.fromkeys(q for q in queries if q and len(q) > 1))

    # ------------------------------------------------------------------
    # NVD API
    # ------------------------------------------------------------------

    async def _fetch_nvd(self, keyword: str, verbose: bool = False) -> List[Dict]:
        """Query NVD CVE API 2.0 for a keyword."""
        cache_key = f"nvd:{keyword}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        results = []
        try:
            params = urllib.parse.urlencode({
                "keywordSearch": keyword,
                "resultsPerPage": 10,
                "startIndex": 0
            })
            url = f"{self.NVD_BASE}?{params}"

            loop = asyncio.get_event_loop()
            raw  = await loop.run_in_executor(None, self._http_get, url)

            if not raw:
                return []

            data            = json.loads(raw)
            vulnerabilities = data.get("vulnerabilities", [])

            for item in vulnerabilities:
                cve_data = item.get("cve", {})
                cve_id   = cve_data.get("id", "")
                descs    = cve_data.get("descriptions", [])
                desc     = next(
                    (d["value"] for d in descs if d.get("lang") == "en"), ""
                )

                metrics    = cve_data.get("metrics", {})
                cvss_score = None
                severity   = "Unknown"

                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metric_list = metrics.get(key, [])
                    if metric_list:
                        cvss_data  = metric_list[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        severity   = cvss_data.get(
                            "baseSeverity", "Unknown"
                        ).capitalize()
                        break

                configs      = cve_data.get("configurations", [])
                affected_str = self._extract_affected(configs)

                results.append({
                    "cve_id":      cve_id,
                    "title":       cve_id,
                    "description": desc[:500],
                    "severity":    severity,
                    "cvss_score":  cvss_score,
                    "affected":    affected_str,
                    "source":      "NVD",
                    "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "confidence":  CONFIDENCE_HIGH if cvss_score else CONFIDENCE_MEDIUM,
                    "verified":    True,
                    "query":       keyword,
                })

            self._cache[cache_key] = results

        except Exception as e:
            logger.warning(f"NVD fetch failed for '{keyword}': {e}")

        return results

    def _extract_affected(self, configs: List) -> str:
        """Extract affected version strings from NVD config nodes."""
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

    # ------------------------------------------------------------------
    # OSV API
    # ------------------------------------------------------------------

    async def _fetch_osv(self, keyword: str, stack: Dict,
                         verbose: bool = False) -> List[Dict]:
        """Query OSV (Open Source Vulnerabilities) for a package."""
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

        # Infer ecosystem from stack language or technology names
        language  = stack.get("language", "").lower()
        techs_str = " ".join(stack.get("technologies", [])).lower()
        combined  = language + " " + techs_str

        ecosystem = None
        for lang, eco in ecosystem_map.items():
            if lang in combined:
                ecosystem = eco
                break

        # Also infer from keyword itself
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
            # Normalize package name for OSV
            pkg_name = keyword.split()[0].lower()
          
            name_map = {
                "gradio":     "gradio",
                "next.js":    "next",
                "sveltekit":  "@sveltejs/kit",
                "langchain":  "langchain",
                "flowise":    "flowise",
                "wordpress":  "wordpress",
                "drupal":     "drupal",
            }
            pkg_name = name_map.get(pkg_name, pkg_name)

            payload = json.dumps({
                "package": {
                    "name":      pkg_name,
                    "ecosystem": ecosystem,
                }
            }).encode()

            loop = asyncio.get_event_loop()
            raw  = await loop.run_in_executor(
                None, self._http_post, self.OSV_BASE, payload
            )

            if not raw:
                return []

            data = json.loads(raw)

            for item in data.get("vulns", []):
                vuln_id    = item.get("id", "")
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
                        introduced = next(
                            (e["introduced"] for e in evts if "introduced" in e),
                            None
                        )
                        fixed = next(
                            (e["fixed"] for e in evts if "fixed" in e), None
                        )
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

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _http_get(self, url: str, timeout: int = 10) -> Optional[str]:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "YuraRAG-SecurityScanner/1.0",
                    "Accept":     "application/json",
                }
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            if e.code == 403:
                logger.warning(f"NVD rate limited (403) for {url}")
            else:
                logger.warning(f"HTTP {e.code} fetching {url}")
        except Exception as e:
            logger.warning(f"GET failed for {url}: {e}")
        return None

    def _http_post(self, url: str, data: bytes,
                   timeout: int = 10) -> Optional[str]:
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