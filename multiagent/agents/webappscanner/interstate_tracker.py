"""Black Widow pillar 3 — inter-page data dependencies."""

from __future__ import annotations

import html as html_lib
import re
import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

CANARY_PREFIX = "bwist"
_CANARY_RE = re.compile(r"\bbwist[a-z0-9]{8,16}\b", re.I)

_PLANT_SKIP_TYPES = frozenset({
    "hidden", "submit", "button", "checkbox", "radio", "file",
    "password", "number", "tel", "date", "time", "datetime-local",
    "month", "week", "color", "range", "image", "reset",
})

_SQLI_HINTS = (
    "search", "q", "query", "keyword", "id", "user", "cat", "category",
    "sort", "filter", "name",
)
_STORED_HINTS = (
    "comment", "message", "post", "review", "guestbook", "feedback",
    "bio", "profile", "title", "content", "body", "description",
)
_CSRF_STATE_HINTS = (
    "password", "transfer", "delete", "admin", "checkout", "payment",
    "profile", "update", "save", "settings", "account", "order",
)


def _norm_url(url: str) -> str:
    try:
        p = urlparse(url or "")
    except Exception:
        return (url or "").rstrip("/").lower()
    path = (p.path or "/").rstrip("/") or "/"
    return f"{(p.netloc or '').lower()}{path.lower()}"


@dataclass
class TaintSource:
    token: str
    url: str
    form_action: str
    field: str
    task: str = ""


@dataclass
class TaintFlow:
    token: str
    source_url: str
    source_action: str
    source_field: str
    sink_url: str
    escaped: bool
    snippet: str = ""


def stored_xss_payload(marker: str) -> str:
    """HTML-breakout payload whose success is document.title == marker."""
    return f'"><svg/onload=document.title="{marker}">'


XSS_ORACLE_SOURCE = """
window.xss = function (id) {
  var marker = String(id || "");
  try { document.title = marker; } catch (e) {}
  window.__xss_hit = marker;
};
"""

_SAFE_XSS_TYPES = frozenset({
    "", "text", "search", "email", "url", "textarea", "password",
})
_AGGRESSIVE_XSS_TYPES = frozenset({
    "hidden", "radio", "checkbox", "select", "select-one", "select-multiple", "file",
})
_SKIP_XSS_TYPES = frozenset({
    "submit", "button", "image", "reset",
})


def xss_oracle_payload(marker: str) -> str:
    """Payload that calls the in-page xss(id) function."""
    safe = (marker or "").replace("\\", "").replace('"', "")
    return f'"><img src=x onerror=xss("{safe}")>'


def iter_xss_fields(fields: Sequence[Dict]) -> List[Tuple[str, str, str]]:
    """(phase, name, type) with safe inputs before hidden/select/file."""
    safe: List[Tuple[str, str, str]] = []
    aggressive: List[Tuple[str, str, str]] = []
    for field in fields or []:
        if not isinstance(field, dict):
            continue
        name = field.get("name") or ""
        if not name:
            continue
        itype = (field.get("type") or "text").lower()
        low = name.lower()
        if any(k in low for k in ("csrf", "token", "nonce", "authenticity")):
            continue
        if itype in _SKIP_XSS_TYPES:
            continue
        if itype in _AGGRESSIVE_XSS_TYPES:
            aggressive.append(("aggressive", name, itype))
        else:
            safe.append(("safe", name, itype if itype in _SAFE_XSS_TYPES else "text"))
    return safe + aggressive


def stored_xss_executed(title: str, marker: str) -> bool:
    return bool(marker) and marker.lower() in (title or "").lower()


def stored_xss_breakout(html: str, marker: str) -> bool:
    """Marker sits in live markup on the sink (not HTML-escaped)."""
    if not html or not marker or marker not in html:
        return False
    idx = html.lower().find(marker.lower())
    window = html[max(0, idx - 80): idx + len(marker) + 80].lower()
    if "&lt;" in window and "<svg" not in window and "<img" not in window:
        return False
    return any(tok in window for tok in ("<svg", "<img", "onload", "onerror", "<script"))


@dataclass
class InterstateTracker:
    sources: Dict[str, TaintSource] = field(default_factory=dict)
    flows: List[TaintFlow] = field(default_factory=list)
    _seen_flow: set = field(default_factory=set)

    def make_token(self) -> str:
        return f"{CANARY_PREFIX}{secrets.token_hex(5)}"

    def should_plant(self, field_name: str, field_type: str) -> bool:
        itype = (field_type or "text").lower()
        if itype in _PLANT_SKIP_TYPES:
            return False
        name = (field_name or "").lower()
        if any(k in name for k in ("pass", "csrf", "token", "nonce")):
            return False
        return bool(field_name)

    def plant(
        self,
        field_name: str,
        field_type: str,
        url: str,
        form_action: str,
        task: str = "",
    ) -> Optional[str]:
        if not self.should_plant(field_name, field_type):
            return None
        token = self.make_token()
        self.sources[token] = TaintSource(
            token=token,
            url=url or "",
            form_action=form_action or url or "",
            field=field_name,
            task=task,
        )
        return token

    def observe(self, page_html: str, page_url: str) -> List[TaintFlow]:
        """Record tokens that appear on a page other than their source."""
        if not page_html or not self.sources:
            return []
        found: List[TaintFlow] = []
        page_key = _norm_url(page_url)
        for token, src in self.sources.items():
            if token not in page_html and token.lower() not in page_html.lower():
                continue
            if _norm_url(src.url) == page_key:
                continue
            idx = page_html.lower().find(token.lower())
            snippet = page_html[max(0, idx - 40): idx + len(token) + 40] if idx >= 0 else ""
            escaped = html_lib.escape(token) in page_html and token not in page_html
            key = (token, page_key)
            if key in self._seen_flow:
                continue
            self._seen_flow.add(key)
            flow = TaintFlow(
                token=token,
                source_url=src.url,
                source_action=src.form_action,
                source_field=src.field,
                sink_url=page_url,
                escaped=escaped,
                snippet=snippet[:160],
            )
            self.flows.append(flow)
            found.append(flow)
        return found

    def observe_regex(self, page_html: str, page_url: str) -> List[TaintFlow]:
        """Also catch tokens if sources dict was rebuilt from HTML only."""
        extra = []
        for match in _CANARY_RE.findall(page_html or ""):
            token = match.lower()
            if token in self.sources:
                continue
            extra.append(match)
        return extra

    def summary(self) -> Dict:
        unescaped = sum(1 for f in self.flows if not f.escaped)
        return {
            "tokens_planted": len(self.sources),
            "flows": len(self.flows),
            "unescaped_flows": unescaped,
            "source_actions": sorted({s.form_action for s in self.sources.values() if s.form_action}),
            "sink_urls": sorted({f.sink_url for f in self.flows if f.sink_url}),
        }

    def to_dict(self) -> Dict:
        return {
            "sources": [
                {
                    "token": s.token,
                    "url": s.url,
                    "form_action": s.form_action,
                    "field": s.field,
                    "task": s.task,
                }
                for s in self.sources.values()
            ],
            "flows": [
                {
                    "token": f.token,
                    "source_url": f.source_url,
                    "source_action": f.source_action,
                    "source_field": f.source_field,
                    "sink_url": f.sink_url,
                    "escaped": f.escaped,
                    "snippet": f.snippet,
                }
                for f in self.flows
            ],
            "summary": self.summary(),
        }


def rank_forms(forms: Sequence[Dict], flows: Sequence[TaintFlow]) -> List[Dict]:
    """Prefer inter-state sources, then SQLi/CSRF/stored-shaped actions."""
    source_actions = {_norm_url(f.source_action) for f in flows if f.source_action}
    sink_urls = {_norm_url(f.sink_url) for f in flows if f.sink_url}

    scored: List[Tuple[int, int, Dict]] = []
    for i, form in enumerate(forms or []):
        action = (form.get("action") or form.get("route") or "").strip()
        method = (form.get("method") or "get").lower()
        inputs = form.get("inputs") or form.get("fields") or []
        names = " ".join(
            (inp.get("name") or "") for inp in inputs if isinstance(inp, dict)
        ).lower()
        action_l = action.lower()
        score = 0
        key = _norm_url(action)
        if key in source_actions:
            score += 8
        if key in sink_urls:
            score += 4
        if any(h in names or h in action_l for h in _SQLI_HINTS):
            score += 3
        if any(h in names or h in action_l for h in _STORED_HINTS):
            score += 3
        if method == "post" and any(h in action_l for h in _CSRF_STATE_HINTS):
            score += 3
        elif method == "post":
            score += 1
        trace = form.get("reach_trace") or []
        if trace:
            score += 2 + min(len(trace), 4)
        scored.append((score, i, form))
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [form for _, _, form in scored]


def rank_urls(urls: Sequence[str], flows: Sequence[TaintFlow]) -> List[str]:
    sink_urls = {_norm_url(f.sink_url) for f in flows if f.sink_url}
    source_urls = {_norm_url(f.source_url) for f in flows if f.source_url}
    scored: List[Tuple[int, int, str]] = []
    for i, url in enumerate(urls or []):
        key = _norm_url(url)
        score = 0
        if key in sink_urls:
            score += 5
        if key in source_urls:
            score += 3
        low = (url or "").lower()
        if any(h in low for h in _SQLI_HINTS + _STORED_HINTS):
            score += 2
        if "?" in (url or ""):
            score += 1
        scored.append((score, i, url))
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [url for _, _, url in scored]


def stored_reflection_findings(flows: Sequence[TaintFlow]) -> List[Dict]:
    """Unescaped inter-page canaries are stored-reflection surfaces."""
    findings: List[Dict] = []
    seen: set = set()
    for flow in flows:
        if flow.escaped:
            continue
        key = (_norm_url(flow.source_action), _norm_url(flow.sink_url), flow.source_field)
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "type": "Stored Reflection Surface",
            "severity": "Medium",
            "status": "Potential",
            "location": flow.sink_url or flow.source_action,
            "parameter": flow.source_field,
            "details": (
                "Benign crawl token planted at "
                f"{flow.source_action or flow.source_url} field "
                f"{flow.source_field!r} later appeared unescaped on "
                f"{flow.sink_url}. Inter-page data flow (Black Widow pillar 3)."
            ),
            "poc": (
                f"Token {flow.token} sourced from {flow.source_field} "
                f"observed on {flow.sink_url}"
            ),
            "cwe": "CWE-79",
            "impact": (
                "User-controlled data persists across pages and is rendered "
                "without HTML encoding — stored XSS / second-order injection surface."
            ),
            "remediation": "Encode output at every sink; track inter-page data flows.",
            "evidence": {
                "request": f"FILL {flow.source_action} {flow.source_field}={flow.token}",
                "response_status": 200,
                "response_body_snippet": flow.snippet,
                "response_headers": {},
                "payload_reflected": True,
                "verified": False,
                "confidence": "Medium",
                "confirmation_method": "interstate_canary",
                "source_url": flow.source_url,
                "sink_url": flow.sink_url,
            },
            "confidence": "Medium",
            "category": "vulnerability",
        })
    return findings


def class_coverage_metrics(
    findings: Sequence[Dict],
    forms_exercised: Sequence[Dict],
    nav_summary: Optional[Dict] = None,
    interstate_summary: Optional[Dict] = None,
) -> Dict:
    def _count(pred) -> int:
        return sum(1 for f in findings if pred(f))

    def _class_pred(needles: Tuple[str, ...]):
        def inner(f: Dict) -> bool:
            t = (f.get("type") or "").lower()
            return any(n in t for n in needles)
        return inner

    xss_p = _class_pred(("xss", "stored reflection"))
    sqli_p = _class_pred(("sql",))
    csrf_p = _class_pred(("csrf",))

    attempted = {"xss": 0, "sqli": 0, "csrf": 0}
    for rec in forms_exercised or []:
        tests = {(t or "").lower() for t in (rec.get("tests_run") or [])}
        if any("xss" in t for t in tests):
            attempted["xss"] += 1
        if any("sql" in t for t in tests):
            attempted["sqli"] += 1
        if any("csrf" in t for t in tests):
            attempted["csrf"] += 1

    nav = nav_summary or {}
    inter = interstate_summary or {}
    return {
        "xss_attempted": attempted["xss"],
        "xss_confirmed": _count(lambda f: xss_p(f) and f.get("status") == "Confirmed"),
        "xss_potential": _count(lambda f: xss_p(f) and f.get("status") == "Potential"),
        "sqli_attempted": attempted["sqli"],
        "sqli_confirmed": _count(lambda f: sqli_p(f) and f.get("status") == "Confirmed"),
        "sqli_potential": _count(lambda f: sqli_p(f) and f.get("status") == "Potential"),
        "csrf_attempted": attempted["csrf"],
        "csrf_confirmed": _count(lambda f: csrf_p(f) and f.get("status") == "Confirmed"),
        "csrf_potential": _count(lambda f: csrf_p(f) and f.get("status") == "Potential"),
        "nav_states": int(nav.get("states") or 0),
        "nav_edges": int(nav.get("edges") or 0),
        "nav_unique_urls": int(nav.get("unique_urls") or 0),
        "interstate_tokens_planted": int(inter.get("tokens_planted") or 0),
        "interstate_flows": int(inter.get("flows") or 0),
        "interstate_unescaped": int(inter.get("unescaped_flows") or 0),
        "traces_recorded": int(nav.get("traces_recorded") or 0),
        "frontier_taken": int(nav.get("frontier_taken") or 0),
        "frontier_remaining": int(nav.get("frontier_remaining") or 0),
        "replay_probes": int(nav.get("replay_probes") or 0),
    }
