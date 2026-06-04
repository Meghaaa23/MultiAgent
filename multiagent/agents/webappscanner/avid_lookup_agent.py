# agents/webappscanner/avid_lookup_agent.py
"""
AVIDLookupAgent
===============
Queries the AVID (AI Vulnerability and Incidents Database) for
AI-specific vulnerabilities found in the target's ML stack.

Instructions:
  "Search found vulnerability in AI vulnerability DB:
   1) https://avidml.org/database/
   2) https://sightline.protectai.com/"

This agent is ONLY triggered when AIFingerprintAgent detects
ML/AI components in the scanned application.

For traditional web vulnerabilities → NVD/OSV (pipeline_agent.py)
For AI/ML vulnerabilities          → AVID + Sightline (this file)

AVID database structure:
  Reports: concrete occurrences with evidence
  Vulns:   recurring failure modes

ATLAS mapping:
  AML.T0010 — ML Supply Chain Compromise
  AML.T0018 — Backdoor ML Model
  AML.T0019 — Exploit Software Dependencies
  AML.T0020 — Poison Training Data
"""

import re
import json
import asyncio
import logging
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, List, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# AVID API endpoints
# ---------------------------------------------------------------------------

AVID_BASE_URL   = "https://avidml.org"
AVID_DB_URL     = "https://avidml.org/database/"
AVID_API_URL    = "https://avidml.org/database/AVID"  # individual records


# ---------------------------------------------------------------------------
# ML library → AVID search terms mapping
# ---------------------------------------------------------------------------

LIBRARY_SEARCH_TERMS = {
    "pytorch":       ["pytorch", "torch"],
    "tensorflow":    ["tensorflow", "keras"],
    "hugging face":  ["huggingface", "transformers", "hugging"],
    "langchain":     ["langchain"],
    "llama":         ["llama", "llama.cpp", "llamaindex"],
    "openai":        ["openai"],
    "anthropic":     ["anthropic"],
    "onnx":          ["onnx"],
    "scikit-learn":  ["sklearn", "scikit"],
    "mlflow":        ["mlflow"],
    "bentoml":       ["bentoml"],
    "gradio":        ["gradio"],
    "streamlit":     ["streamlit"],
    "fastapi":       ["fastapi"],   # Common ML serving framework
    "pickle":        ["pickle", "picklescan", "deserialization"],
    "jupyter":       ["jupyter", "notebook"],
}

# ---------------------------------------------------------------------------
# Hardcoded high-priority AVID entries for AI backdoor focus
# These are the most relevant CVEs from AVID for backdoor attacks
# Used as fallback when live API is unavailable
# ---------------------------------------------------------------------------

AVID_BACKDOOR_ENTRIES = [
    {
        "avid_id":     "AVID-2026-R0035",
        "cve_id":      "CVE-2025-1716",
        "title":       "picklescan Security Scanning Bypass via pip main",
        "description": "picklescan can be bypassed allowing malicious pickle files "
                       "to evade detection. Directly enables backdoored model delivery "
                       "via ML supply chain.",
        "severity":    "High",
        "cvss_score":  7.5,
        "source":      "AVID",
        "url":         "https://avidml.org/database/AVID-2026-R0035",
        "atlas_technique": "AML.T0018.002 — Embed Malware",
        "report_type": "Advisory",
        "ai_backdoor_relevant": True,
    },
    {
        "avid_id":     "AVID-2026-R0036",
        "cve_id":      "CVE-2025-1889",
        "title":       "picklescan Bypass via Non-Standard File Extensions",
        "description": "picklescan fails to detect malicious pickle content when "
                       "non-standard file extensions are used. Attackers can deliver "
                       "backdoored models that bypass security scanning.",
        "severity":    "High",
        "cvss_score":  7.5,
        "source":      "AVID",
        "url":         "https://avidml.org/database/AVID-2026-R0036",
        "atlas_technique": "AML.T0018.002 — Embed Malware",
        "report_type": "Advisory",
        "ai_backdoor_relevant": True,
    },
    {
        "avid_id":     "AVID-2026-R0037",
        "cve_id":      "CVE-2025-1944",
        "title":       "picklescan ZIP Archive Manipulation Attack",
        "description": "A ZIP archive manipulation attack causes picklescan to crash "
                       "without detecting malicious content, allowing backdoored model "
                       "files to pass through undetected.",
        "severity":    "High",
        "cvss_score":  7.2,
        "source":      "AVID",
        "url":         "https://avidml.org/database/AVID-2026-R0037",
        "atlas_technique": "AML.T0018.002 — Embed Malware",
        "report_type": "Advisory",
        "ai_backdoor_relevant": True,
    },
    {
        "avid_id":     "AVID-2026-R0034",
        "cve_id":      "CVE-2025-1550",
        "title":       "Arbitrary Code Execution via Crafted Keras Config",
        "description": "Maliciously crafted Keras model configuration files can trigger "
                       "arbitrary code execution when the model is loaded. Classic "
                       "backdoor delivery mechanism via model deserialization.",
        "severity":    "Critical",
        "cvss_score":  9.1,
        "source":      "AVID",
        "url":         "https://avidml.org/database/AVID-2026-R0034",
        "atlas_technique": "AML.T0018 — Backdoor ML Model",
        "report_type": "Advisory",
        "ai_backdoor_relevant": True,
    },
    {
        "avid_id":     "AVID-2026-R0023",
        "cve_id":      "CVE-2024-12029",
        "title":       "Remote Code Execution via Model Deserialization in InvokeAI",
        "description": "InvokeAI allows Remote Code Execution through malicious model "
                       "deserialization. Attacker can deliver backdoored model files "
                       "that execute code upon loading.",
        "severity":    "Critical",
        "cvss_score":  9.8,
        "source":      "AVID",
        "url":         "https://avidml.org/database/AVID-2026-R0023",
        "atlas_technique": "AML.T0018.002 — Embed Malware",
        "report_type": "Advisory",
        "ai_backdoor_relevant": True,
    },
    {
        "avid_id":     "AVID-2026-R0045",
        "cve_id":      "CVE-2025-27520",
        "title":       "BentoML Allows RCE via Insecure Deserialization",
        "description": "BentoML's runner server is vulnerable to insecure deserialization "
                       "leading to Remote Code Execution. ML model serving frameworks "
                       "are prime targets for backdoor injection.",
        "severity":    "Critical",
        "cvss_score":  9.8,
        "source":      "AVID",
        "url":         "https://avidml.org/database/AVID-2026-R0045",
        "atlas_technique": "AML.T0018 — Backdoor ML Model",
        "report_type": "Advisory",
        "ai_backdoor_relevant": True,
    },
    {
        "avid_id":     "AVID-2026-R0057",
        "cve_id":      "CVE-2025-32375",
        "title":       "Insecure Deserialization leads to RCE in BentoML Runner Server",
        "description": "BentoML runner server deserializes untrusted data without "
                       "validation. Enables backdoor model delivery that executes "
                       "arbitrary code on the ML serving infrastructure.",
        "severity":    "Critical",
        "cvss_score":  9.8,
        "source":      "AVID",
        "url":         "https://avidml.org/database/AVID-2026-R0057",
        "atlas_technique": "AML.T0018.002 — Embed Malware",
        "report_type": "Advisory",
        "ai_backdoor_relevant": True,
    },
    {
        "avid_id":     "AVID-2026-R0058",
        "cve_id":      "CVE-2025-3248",
        "title":       "Langflow Unauthenticated RCE via /api/v1/validate/code",
        "description": "Langflow versions before 1.3.0 allow unauthenticated remote "
                       "code execution via the /api/v1/validate/code endpoint. "
                       "AI workflow platforms are high-value targets for backdoor attacks.",
        "severity":    "Critical",
        "cvss_score":  9.8,
        "source":      "AVID",
        "url":         "https://avidml.org/database/AVID-2026-R0058",
        "atlas_technique": "AML.T0049 — Exploit Public-Facing Application",
        "report_type": "Advisory",
        "ai_backdoor_relevant": True,
    },
]


class AVIDLookupAgent:
    """
    Queries AVID database for AI-specific vulnerabilities.
    Triggered only when AI components are detected in the target.
    """

    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self._cache: Dict[str, List[Dict]] = {}

    async def lookup(self, ai_fingerprint: Dict,
                     ml_stack: List[str],
                     verbose: bool = False) -> Dict:
        """
        Query AVID for vulnerabilities relevant to the detected ML stack.

        Parameters
        ----------
        ai_fingerprint : result from AIFingerprintAgent.fingerprint()
        ml_stack       : list of detected ML libraries/frameworks
        verbose        : print progress

        Returns
        -------
        {
          "avid_findings": [...],       # AI-specific CVEs from AVID
          "backdoor_relevant": [...],   # specifically backdoor-related
          "total_found": int,
          "sources_queried": [...],
        }
        """
        if verbose:
            print(f"\n  AVID Lookup Agent")
            print(f"   ML Stack: {ml_stack[:5]}")

        result = {
            "avid_findings":     [],
            "backdoor_relevant": [],
            "total_found":       0,
            "sources_queried":   ["AVID (avidml.org)"],
        }

        # Build search terms from detected ML stack
        search_terms = self._build_search_terms(ml_stack, ai_fingerprint)

        if verbose:
            print(f"   Search terms: {search_terms[:5]}")

        # Try live AVID API first
        live_results = await self._query_avid_live(search_terms, verbose)

        # Always include hardcoded backdoor entries relevant to detected stack
        static_results = self._get_static_backdoor_entries(ml_stack, ai_fingerprint)

        # Merge and deduplicate
        all_results = live_results + static_results
        seen_ids    = set()
        deduped     = []
        for r in all_results:
            rid = r.get("cve_id") or r.get("avid_id") or r.get("title")
            if rid and rid not in seen_ids:
                seen_ids.add(rid)
                deduped.append(r)

        # Sort by severity
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
        deduped.sort(key=lambda x: severity_order.get(x.get("severity", "Unknown"), 4))

        # Split into backdoor-relevant and general
        result["avid_findings"]     = deduped
        result["backdoor_relevant"] = [
            r for r in deduped if r.get("ai_backdoor_relevant")
        ]
        result["total_found"]       = len(deduped)

        if verbose:
            print(f"   ✓ AVID findings: {len(deduped)} total "
                  f"({len(result['backdoor_relevant'])} backdoor-relevant)")

        return result

    # ------------------------------------------------------------------
    # Build search terms from detected ML stack
    # ------------------------------------------------------------------

    def _build_search_terms(self, ml_stack: List[str],
                             ai_fingerprint: Dict) -> List[str]:
        terms = set()

        # From ML libraries
        for lib in ml_stack:
            lib_lower = lib.lower()
            for key, search_list in LIBRARY_SEARCH_TERMS.items():
                if key in lib_lower or lib_lower in key:
                    terms.update(search_list)
                    break
            # Also add the library name directly
            terms.add(lib_lower.split("/")[0])  # strip version

        # From model upload endpoints (pickle is the key backdoor vector)
        if ai_fingerprint.get("model_upload_endpoints"):
            terms.update(["pickle", "deserialization", "model loading"])

        # From chat components (LLM-specific)
        if ai_fingerprint.get("chat_components"):
            terms.update(["prompt injection", "llm", "jailbreak"])

        # Always include core backdoor terms
        terms.update(["backdoor", "model poisoning", "supply chain"])

        return list(terms)[:10]  # cap to avoid too many requests

    # ------------------------------------------------------------------
    # Query AVID live database
    # ------------------------------------------------------------------

    async def _query_avid_live(self, search_terms: List[str],
                                verbose: bool) -> List[Dict]:
        """
        Attempt to fetch live AVID data.
        AVID doesn't have a public JSON API, so we fetch the database page
        and parse the vulnerability table.
        """
        results = []

        try:
            loop = asyncio.get_event_loop()
            html = await loop.run_in_executor(
                None, lambda: self._fetch_text(AVID_DB_URL)
            )

            if not html:
                if verbose:
                    print("   ⚠ AVID live fetch failed — using cached entries")
                return results

            # Parse AVID report table from HTML
            # Table format: | Report ID | Description | Report Type | Date |
            table_pattern = re.compile(
                r'\[AVID-(\d{4}-R\d+)\]\(([^)]+)\)\s*\|\s*([^|]+)\|',
                re.MULTILINE
            )

            for match in table_pattern.finditer(html):
                avid_id     = f"AVID-{match.group(1)}"
                url         = match.group(2).strip()
                description = match.group(3).strip()

                # Filter by relevance to our search terms
                desc_lower = description.lower()
                relevant   = any(term.lower() in desc_lower
                                 for term in search_terms)

                if relevant:
                    # Extract CVE ID if present
                    cve_match = re.search(r"CVE-\d{4}-\d+", description)
                    cve_id    = cve_match.group(0) if cve_match else None

                    # Determine severity from keywords
                    severity = self._infer_severity(description)

                    results.append({
                        "avid_id":     avid_id,
                        "cve_id":      cve_id,
                        "title":       description[:120],
                        "description": description,
                        "severity":    severity,
                        "cvss_score":  None,
                        "source":      "AVID",
                        "url":         f"https://avidml.org/database/{avid_id}",
                        "atlas_technique": self._map_to_atlas(description),
                        "report_type": "Advisory",
                        "ai_backdoor_relevant": self._is_backdoor_relevant(description),
                    })

            if verbose and results:
                print(f"   ✓ Live AVID: {len(results)} relevant entries found")

        except Exception as e:
            logger.warning(f"AVID live query failed: {e}")

        return results[:20]  # cap results

    # ------------------------------------------------------------------
    # Get static backdoor entries relevant to detected stack
    # ------------------------------------------------------------------

    def _get_static_backdoor_entries(self, ml_stack: List[str],
                                      ai_fingerprint: Dict) -> List[Dict]:
        """
        Return hardcoded AVID backdoor entries relevant to detected stack.
        Always returns pickle-related entries if model uploads are detected.
        """
        relevant = []
        stack_lower = " ".join(ml_stack).lower()

        for entry in AVID_BACKDOOR_ENTRIES:
            title_lower = entry["title"].lower()
            desc_lower  = entry["description"].lower()

            # Always include if model upload endpoints found and entry is pickle-related
            if ai_fingerprint.get("model_upload_endpoints"):
                if any(kw in title_lower or kw in desc_lower
                       for kw in ["pickle", "deserialization", "model load"]):
                    relevant.append(entry)
                    continue

            # Include if library matches detected stack
            lib_keywords = ["pytorch", "tensorflow", "keras", "bentoml",
                            "langflow", "llamaindex", "mlflow", "onnx"]
            for kw in lib_keywords:
                if kw in stack_lower and kw in (title_lower + desc_lower):
                    relevant.append(entry)
                    break

            # Always include Critical severity backdoor entries
            if entry.get("severity") == "Critical" and \
               entry.get("ai_backdoor_relevant"):
                if entry not in relevant:
                    relevant.append(entry)

        return relevant

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _infer_severity(self, text: str) -> str:
        text_lower = text.lower()
        if any(kw in text_lower for kw in
               ["rce", "remote code execution", "arbitrary code", "critical"]):
            return "Critical"
        if any(kw in text_lower for kw in
               ["high", "privilege escalation", "authentication bypass"]):
            return "High"
        if any(kw in text_lower for kw in
               ["medium", "injection", "xss", "information disclosure"]):
            return "Medium"
        return "Low"

    def _is_backdoor_relevant(self, text: str) -> bool:
        backdoor_keywords = [
            "backdoor", "poison", "deserializ", "pickle", "supply chain",
            "model load", "rce", "remote code", "arbitrary code",
            "malicious model", "model tamper", "model injection",
        ]
        text_lower = text.lower()
        return any(kw in text_lower for kw in backdoor_keywords)

    def _map_to_atlas(self, text: str) -> str:
        text_lower = text.lower()
        if "pickle" in text_lower or "deserializ" in text_lower:
            return "AML.T0018.002 — Embed Malware"
        if "poison" in text_lower or "backdoor" in text_lower:
            return "AML.T0018 — Backdoor ML Model"
        if "supply chain" in text_lower:
            return "AML.T0010 — ML Supply Chain Compromise"
        if "prompt injection" in text_lower:
            return "AML.T0051 — LLM Prompt Injection"
        if "jailbreak" in text_lower:
            return "AML.T0054 — LLM Jailbreak"
        return "AML.T0019 — Exploit Software Dependencies"

    def _fetch_text(self, url: str) -> Optional[str]:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (SecurityScanner)",
                    "Accept":     "text/html,*/*"
                }
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.read(500_000).decode("utf-8", errors="replace")
        except Exception as e:
            logger.warning(f"AVID fetch failed: {e}")
            return None