#!/usr/bin/env python3
"""Run the scanner against a live target and score it against ground truth."""
import argparse, asyncio, json, os, sys
from pathlib import Path
from urllib.parse import urlsplit

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dotenv import load_dotenv
load_dotenv()

from openai import AzureOpenAI
from agents.webappscanner.web_scanner_agent import WebScannerAgent

GT_DIR = Path(__file__).resolve().parent.parent / "ground_truth"
TARGETS = {
    "wrongsecrets": "http://localhost:3007",
    "hackazon":     "http://localhost:3008",
    "dvwa":         "http://localhost:3001",
    "webgoat":      "http://localhost:3002/WebGoat",
    "juiceshop":    "http://localhost:3000",
}

_NORM = [
    ("sql injection (time", "sqli-blind"), ("blind", "sqli-blind"),
    ("sql injection", "sqli"), ("sqli", "sqli"),
    ("command injection", "cmdi"), ("os command", "cmdi"),
    ("server-side template", "ssti"), ("ssti", "ssti"),
    ("path traversal", "path-traversal"), ("file inclusion", "lfi"), ("lfi", "lfi"),
    ("stored cross-site", "xss-stored"), ("stored xss", "xss-stored"),
    ("dom", "xss-dom"), ("reflected xss", "xss-reflected"),
    ("cross-site scripting", "xss-reflected"), ("xss", "xss-reflected"),
    ("csrf", "csrf"), ("cross site request", "csrf"),
    ("open redirect", "open-redirect"),
    ("cors", "cors"),
    ("actuator", "sensitive-exposure"), ("graphql introspection", "sensitive-exposure"),
    ("directory listing", "sensitive-exposure"),
    ("metrics endpoint", "sensitive-exposure"), ("exposed metrics", "sensitive-exposure"),
    ("api documentation", "sensitive-exposure"), ("swagger", "sensitive-exposure"),
    ("openapi", "sensitive-exposure"),
    ("information disclosure: server", "server_header"), ("server header", "server_header"),
    ("x-powered-by", "server_header"),
    ("missing security header", "missing_header"), ("missing clickjacking", "missing_header"),
    ("content security policy", "missing_header"), ("content-security-policy", "missing_header"),
    ("sensitive file", "sensitive-exposure"), ("phpinfo", "sensitive-exposure"),
    ("unauthenticated admin", "sensitive-exposure"),
    ("hardcoded", "hardcoded-secret"),
]

def canon(t: str) -> str:
    tl = (t or "").lower().strip()
    for frag, c in _NORM:
        if frag in tl:
            return c
    return tl

def path_of(u: str) -> str:
    try:
        p = urlsplit(u).path or "/"
    except Exception:
        return u
    return p.rstrip("/") or "/"

def xss_family(c):
    return c.startswith("xss")

def matches(finding_c, finding_path, exp_c, exp_path):
    tmatch = finding_c == exp_c or (xss_family(finding_c) and xss_family(exp_c)) \
        or (finding_c.startswith("sqli") and exp_c.startswith("sqli"))
    if not tmatch:
        return False
    if exp_path in ("/", ""):
        return True
    fp, ep = path_of(finding_path), path_of(exp_path)
    return fp == ep or fp.endswith(ep) or ep.endswith(fp)

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("app", choices=list(TARGETS))
    ap.add_argument("--user"); ap.add_argument("--password")
    a = ap.parse_args()

    url = TARGETS[a.app]
    client = AzureOpenAI(
        api_key=os.getenv("AZURE_OPENAI_API_KEY"),
        azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
        api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-01"),
    )
    model = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
    scanner = WebScannerAgent(client, model)

    auth = None
    if a.user and a.password:
        auth = {"username": a.user, "password": a.password,
                "login_url": "", "success_indicator": ""}

    print(f"\n### Scanning {a.app} ({url}) auth={'yes' if auth else 'no'}")
    res = await scanner.scan_application(
        target_url=url, verbose=True, auth=auth)

    vulns = res.get("vulnerabilities") or []
    found = [(canon(v.get("type")), v.get("location") or url, v.get("status"), v.get("type"))
             for v in vulns]
    print(f"\n### RAW FINDINGS ({len(found)}):")
    for c, loc, st, raw in found:
        print(f"  [{st}] {raw}  -> {c}  @ {path_of(loc)}")

    gt_path = GT_DIR / f"{a.app}.json"
    if not gt_path.exists():
        print(f"\n(no ground truth at {gt_path})"); return
    gt = json.loads(gt_path.read_text(encoding="utf-8"))
    expected = gt.get("expected_findings", [])
    required = [e for e in expected if e.get("required")]

    tp, matched_exp = [], set()
    for c, loc, st, raw in found:
        for i, e in enumerate(expected):
            if matches(c, loc, canon(e.get("type")), e.get("path", "/")):
                tp.append((raw, e["id"])); matched_exp.add(i); break
    fp = [(raw, path_of(loc)) for c, loc, st, raw in found
          if not any(matches(c, loc, canon(e.get("type")), e.get("path","/")) for e in expected)]
    fn = [e for i, e in enumerate(expected) if e.get("required") and i not in matched_exp]
    fn_bb = [e for e in fn if e.get("blackbox_detectable")]

    print(f"\n### SCORE vs ground truth ({a.app}):")
    print(f"  TP (matched expected): {len(set(matched_exp))}")
    for raw, eid in tp: print(f"     + {eid}  ({raw})")
    print(f"  FP (not in GT): {len(fp)}")
    for raw, p in fp: print(f"     ! {raw} @ {p}")
    print(f"  FN required total: {len(fn)}  | FN blackbox-detectable: {len(fn_bb)}")
    for e in fn_bb: print(f"     - MISSED(bb) {e['id']} [{e['type']}] {e.get('path')}")
    claimed = len(found)
    prec = (claimed - len(fp)) / claimed if claimed else 1.0
    req_bb_total = sum(1 for e in required if e.get("blackbox_detectable"))
    matched_req_bb = sum(1 for i, e in enumerate(expected)
                         if i in matched_exp and e.get("required")
                         and e.get("blackbox_detectable"))
    rec_bb = matched_req_bb / req_bb_total if req_bb_total else None
    rec_all = len({i for i in matched_exp if expected[i].get("required")}) / len(required) if required else None
    print(f"  precision={prec:.2f}  "
          f"recall_blackbox={rec_bb if rec_bb is None else round(rec_bb,2)}  "
          f"recall_all={rec_all if rec_all is None else round(rec_all,2)}")

asyncio.run(main())
