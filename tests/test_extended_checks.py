"""
Tests for the DAST-class extended conventional detectors (ExtendedVulnScanner):
path traversal/LFI, SSTI, OS command injection, UNION + boolean-blind SQLi,
insecure cookie flags, cleartext transport, SSRF, IDOR.

Uses local mock HTTP servers only (no network egress). Confirmations are keyed
on deterministic evidence (file signatures, evaluated arithmetic, reflected
command-output markers, UNION marker reflection, response differentials).
"""
import asyncio
import re
import socket
import threading
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

import pytest

from multiagent.agents.webappscanner.vulnerability_tester import VulnerabilityTester
from multiagent.agents.webappscanner.extended_checks import ExtendedVulnScanner

PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
          "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")

_LONG = "A wonderful serenity has taken possession of my entire soul. " * 8
_ALT  = "Completely different content for the neighbouring object here. " * 8


def _free_port():
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


class VulnHandler(BaseHTTPRequestHandler):
    def _parse(self):
        p = urllib.parse.urlparse(self.path)
        return p.path, urllib.parse.parse_qs(p.query, keep_blank_values=True)

    def do_GET(self):  # noqa: N802
        _, q = self._parse()

        f = q.get("file", [""])[0]
        if "etc/passwd" in f or "win.ini" in f.lower():
            return self._r(PASSWD)

        tpl = q.get("tpl", [""])[0]
        m = re.search(r"(\d+)\*(\d+)", tpl)
        if m and any(t in tpl for t in ("{{", "${", "<%", "#{", "{1")):
            return self._r(f"Result: {int(m.group(1)) * int(m.group(2))}")

        cmd = q.get("cmd", [""])[0]
        cm = re.search(r"echo (\w+)", cmd)
        if cm and any(c in cmd for c in (";", "|", "`", "$(", "&")):
            return self._r(f"exec output => {cm.group(1)} <= done")

        # UNION SQLi param `q`: 3 columns; ORDER BY > 3 errors; UNION reflects marker
        qp = q.get("q", [""])[0]
        if qp:
            low = qp.lower()
            ob = re.search(r"order by (\d+)", low)
            if ob and int(ob.group(1)) > 3:
                return self._r("You have an error in your SQL syntax near ORDER BY", 200)
            if "union select" in low and "0xSURFACEUNION".lower() in low:
                return self._r("row: 0xSURFACEUNION | data | data")
            return self._r("normal product listing")

        # boolean-blind param `bq`
        bq = q.get("bq", [""])[0]
        if bq or "bq" in q:
            low = bq.lower()
            if "and '1'='2" in low:
                return self._r("No results found.")
            # baseline and AND '1'='1' return the same long content
            return self._r(_LONG)

        # IDOR param `doc`
        doc = q.get("doc", [""])[0]
        if doc:
            if doc == "5":
                return self._r("Invoice 5 owner alice total $100. " + _LONG)
            return self._r(f"Invoice {doc} owner bob total $250. " + _ALT)

        # default page with insecure + secure cookies
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "sessionid=abc123; Path=/")
        self.send_header("Set-Cookie", "theme=dark; Path=/; HttpOnly; SameSite=Lax")
        data = b"<html>home</html>"
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):  # noqa: N802
        self._r("ok")

    def _r(self, text, status=200):
        data = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


class SafeHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        import html
        p = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(p.query)
        val = (q.get("file", [""])[0] or q.get("tpl", [""])[0]
               or q.get("cmd", [""])[0] or q.get("q", [""])[0])
        body = f"<html>echo: {html.escape(val)}</html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie",
                         "sessionid=x; Path=/; HttpOnly; Secure; SameSite=Strict")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve(handler):
    port = _free_port()
    srv = HTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{port}"


@pytest.fixture(scope="module")
def vuln_base():
    return _serve(VulnHandler)


@pytest.fixture(scope="module")
def safe_base():
    return _serve(SafeHandler)


def _run(base, urls, forms=None):
    tester = VulnerabilityTester(timeout=8)
    ext = ExtendedVulnScanner(tester)
    return asyncio.run(ext.run_all(forms or [], urls, base, shared_headers=None))


def _types(findings):
    return {f["type"] for f in findings}


class TestExtendedVuln:

    def test_path_traversal_confirmed(self, vuln_base):
        f = _run(vuln_base, [f"{vuln_base}/?file=x"])
        hit = [x for x in f if "Path Traversal" in x["type"]]
        assert hit and hit[0]["status"] == "Confirmed"
        assert hit[0]["severity"] == "Critical"

    def test_ssti_confirmed(self, vuln_base):
        f = _run(vuln_base, [f"{vuln_base}/?tpl=x"])
        hit = [x for x in f if "Template Injection" in x["type"]]
        assert hit and hit[0]["status"] == "Confirmed"

    def test_command_injection_confirmed(self, vuln_base):
        f = _run(vuln_base, [f"{vuln_base}/?cmd=x"])
        hit = [x for x in f if x["type"] == "OS Command Injection"]
        assert hit and hit[0]["status"] == "Confirmed"

    def test_union_sqli_confirmed(self, vuln_base):
        f = _run(vuln_base, [f"{vuln_base}/?q=1"])
        hit = [x for x in f if "UNION-Based" in x["type"]]
        assert hit and hit[0]["status"] == "Confirmed"

    def test_boolean_blind_sqli_confirmed(self, vuln_base):
        f = _run(vuln_base, [f"{vuln_base}/?bq=1"])
        hit = [x for x in f if "Boolean-Blind" in x["type"]]
        assert hit and hit[0]["status"] == "Confirmed"

    def test_cookie_flags_confirmed(self, vuln_base):
        f = _run(vuln_base, [f"{vuln_base}/"])
        hit = [x for x in f if x["type"].startswith("Insecure Cookie Flags")]
        assert any("sessionid" in x["type"] for x in hit)

    def test_cleartext_transport(self, vuln_base):
        f = _run(vuln_base, [f"{vuln_base}/"])
        assert any("Cleartext Transport" in x["type"] for x in f)

    def test_idor_potential(self, vuln_base):
        f = _run(vuln_base, [f"{vuln_base}/?doc=5"])
        hit = [x for x in f if "IDOR" in x["type"]]
        assert hit and hit[0]["status"] == "Potential"

    def test_safe_app_no_critical_confirmed(self, safe_base):
        f = _run(safe_base, [
            f"{safe_base}/?file=x", f"{safe_base}/?tpl=x",
            f"{safe_base}/?cmd=x",  f"{safe_base}/?q=1",
        ])
        criticals = [x for x in f
                     if x["status"] == "Confirmed" and x["severity"] == "Critical"]
        assert criticals == []
        # a properly-flagged cookie must not be reported
        assert not any(x["type"].startswith("Insecure Cookie Flags") for x in f)
