"""
chat_surface.py — conversational-surface discovery and ownership classification.

Implements the SURFACE separation of chat interfaces into three operator classes:

  * application_owned   — a first-party AI chatbot backed by the target's own
                          model surface (same-origin inference endpoints and/or a
                          self-hosted AI framework).
  * third_party_widget  — an embedded AI chatbot loaded from a third-party vendor
                          (e.g. Chatbase, Voiceflow, Botpress).
  * human_operated      — a live-chat / helpdesk widget whose primary operator is a
                          human agent (e.g. Intercom, Zendesk, LiveChat, Tawk.to).

Classification uses three heterogeneous signal sources, in order of strength:
  1. Third-party vendor signatures — script/iframe host (compared against the
     target origin) and inline JS-global markers.
  2. Human-operator textual signals in the rendered DOM ("an agent will reply",
     "average response time", …).
  3. Same-origin model-backed chat UI (assistant/chatbot DOM markers + a
     same-origin chat endpoint and/or a detected first-party AI framework).

The module is dependency-free and operates on already-rendered HTML so it can be
unit-tested against static fixtures.
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Dict, List, Optional

# Ownership categories (the three-way separation).
OWNERSHIP_APPLICATION_OWNED  = "application_owned"
OWNERSHIP_THIRD_PARTY_WIDGET = "third_party_widget"
OWNERSHIP_HUMAN_OPERATED     = "human_operated"


# Third-party chat/support vendor signatures.
#   kind == "human_support" -> live chat / helpdesk staffed primarily by humans
#                              -> classified as human_operated.
#   kind == "ai"            -> third-party embedded AI chatbot builder/widget
#                              -> classified as third_party_widget.
# Vendors may offer both AI and human channels; `kind` records the vendor's
# primary product identity and is reported alongside the finding for auditability.
VENDOR_SIGNATURES: Dict[str, Dict] = {
    "Intercom":       {"kind": "human_support", "hosts": ["intercom.io", "intercomcdn.com", "intercom.com"],
                       "js": [r"intercomsettings", r"widget\.intercom\.io", r"\bintercom\s*\("]},
    "Drift":          {"kind": "human_support", "hosts": ["drift.com", "driftt.com"],
                       "js": [r"drift\.load", r"\bdriftt\b", r"js\.driftt\.com"]},
    "Zendesk":        {"kind": "human_support", "hosts": ["zdassets.com", "zendesk.com", "zopim.com"],
                       "js": [r"\bze\s*\(", r"\bzopim\b", r"static\.zdassets\.com", r"zEmbed"]},
    "LiveChat":       {"kind": "human_support", "hosts": ["livechatinc.com", "livechat.com"],
                       "js": [r"__lc\b", r"livechatinc", r"cdn\.livechatinc\.com"]},
    "Tawk.to":        {"kind": "human_support", "hosts": ["tawk.to"],
                       "js": [r"tawk_api", r"embed\.tawk\.to"]},
    "Crisp":          {"kind": "human_support", "hosts": ["crisp.chat"],
                       "js": [r"\$crisp", r"client\.crisp\.chat"]},
    "Freshchat":      {"kind": "human_support", "hosts": ["freshchat.com", "freshworks.com"],
                       "js": [r"fcwidget", r"wchat\.freshchat\.com", r"\bfreshchat\b"]},
    "Olark":          {"kind": "human_support", "hosts": ["olark.com"],
                       "js": [r"\bolark\b"]},
    "HubSpot":        {"kind": "human_support", "hosts": ["hs-scripts.com", "hubspot.com", "hs-banner.com"],
                       "js": [r"hubspotconversations", r"js\.hs-scripts\.com"]},
    "LivePerson":     {"kind": "human_support", "hosts": ["liveperson.net", "liveperson.com", "lpsnmedia.net"],
                       "js": [r"lptag", r"\bliveperson\b"]},
    "Gorgias":        {"kind": "human_support", "hosts": ["gorgias.chat", "gorgias.io"],
                       "js": [r"\bgorgias\b"]},
    "Kustomer":       {"kind": "human_support", "hosts": ["kustomerapp.com", "kustomer.com"],
                       "js": [r"\bkustomer\b"]},
    "Tidio":          {"kind": "human_support", "hosts": ["tidio.co", "tidiochat.com"],
                       "js": [r"\btidio\b", r"code\.tidio\.co"]},
    # AI-first third-party widgets.
    "Chatbase":       {"kind": "ai", "hosts": ["chatbase.co"],
                       "js": [r"\bchatbase\b", r"www\.chatbase\.co"]},
    "Voiceflow":      {"kind": "ai", "hosts": ["voiceflow.com"],
                       "js": [r"\bvoiceflow\b", r"widget\.voiceflow\.com"]},
    "Botpress":       {"kind": "ai", "hosts": ["botpress.cloud", "botpress.com"],
                       "js": [r"\bbotpress\b", r"cdn\.botpress\.cloud"]},
    "Landbot":        {"kind": "ai", "hosts": ["landbot.io"],
                       "js": [r"\blandbot\b"]},
    "Ada":            {"kind": "ai", "hosts": ["ada.support", "ada.cx"],
                       "js": [r"adaembed", r"ada\.support"]},
    "Kommunicate":    {"kind": "ai", "hosts": ["kommunicate.io"],
                       "js": [r"\bkommunicate\b"]},
}


# Rendered-DOM phrases that indicate a human agent operates the chat.
HUMAN_OPERATOR_PATTERNS = [
    r"agent is typing",
    r"an agent will (?:be with|assist|help|reply|respond)",
    r"connect(?:ing)? (?:you )?(?:to|with) (?:a|an|our) (?:agent|representative|human|team|specialist)",
    r"average response time",
    r"we(?:'|\u2019)?ll (?:get back|reply|respond)",
    r"we (?:usually|typically) reply",
    r"leave (?:us )?a message and (?:we|our)",
    r"our team will (?:get back|respond|reply)",
    r"you(?:'|\u2019)?re now chatting with",
    r"wait time",
    r"live agent",
    r"talk to (?:a|an) (?:human|agent|representative)",
]

# Rendered-DOM markers of a conversational AI UI (assistant/chatbot).
AI_CHAT_DOM_PATTERNS = [
    r'role=["\']assistant["\']',
    r'data-role=["\'](?:bot|assistant)["\']',
    r'data-message-role=["\']assistant["\']',
    r'aria-label=["\'][^"\']*(?:ai|assistant|chatbot)[^"\']*["\']',
    r'class=["\'][^"\']*(?:chat-?bot|ai-?assistant|message-?list|chat-?window)[^"\']*["\']',
    r'<[^>]+(?:id|class)=["\'][^"\']*chat[^"\']*["\'][^>]*>',
]

_CHAT_PATH_RE = re.compile(
    r"/(chat|completions|generate|messages|ask|conversation|converse|prediction|run|invoke)",
    re.I,
)


def _host_of(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return ""


def _registrable(host: str) -> str:
    """Coarse eTLD+1 (last two labels). Good enough to compare first- vs third-party."""
    parts = [p for p in host.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _is_third_party(src_host: str, target_host: str) -> bool:
    if not src_host:
        return False
    return _registrable(src_host) != _registrable(target_host)


def _same_origin(url: str, target_host: str) -> bool:
    h = _host_of(url)
    if not h:
        # relative path -> same origin
        return not url.startswith("http")
    return _registrable(h) == _registrable(target_host)


def _is_chat_path(url: str) -> bool:
    try:
        return bool(_CHAT_PATH_RE.search(urllib.parse.urlparse(url).path))
    except Exception:
        return False


def has_ai_chat_dom(html: str) -> bool:
    if not html:
        return False
    return any(re.search(p, html, re.I) for p in AI_CHAT_DOM_PATTERNS)


def extract_script_and_iframe_srcs(html: str) -> List[str]:
    """Return every <script src> and <iframe src> URL found in the HTML."""
    if not html:
        return []
    srcs: List[str] = []
    for m in re.finditer(r'<(?:script|iframe)[^>]+src=["\']([^"\']+)["\']', html, re.I):
        srcs.append(m.group(1))
    return srcs


def classify_chat_surfaces(
    html: str,
    target_origin: str,
    *,
    script_srcs: Optional[List[str]] = None,
    app_framework: str = "",
    ml_endpoints: Optional[List[str]] = None,
    is_ai_powered: bool = False,
) -> List[Dict]:
    """
    Classify conversational surfaces on a rendered page into the three ownership
    categories. Returns a list of chat-component dicts, each with keys:
    type, ownership, vendor, kind, source, confidence, evidence.
    """
    html = html or ""
    low = html.lower()
    target_host = (target_origin or "").lower().split("//")[-1].split("/")[0].split(":")[0]
    srcs = script_srcs if script_srcs is not None else extract_script_and_iframe_srcs(html)
    ml_endpoints = ml_endpoints or []

    components: List[Dict] = []
    matched_vendor_kinds: set = set()

    # 1. Third-party vendor detection (host of external resource + inline JS markers).
    for vendor, sig in VENDOR_SIGNATURES.items():
        source = None
        for src in srcs:
            host = _host_of(src if src.startswith("http") else "http://" + src.lstrip("/"))
            if host and any(h in host for h in sig["hosts"]) and _is_third_party(host, target_host):
                source = f"external_src:{host}"
                break
        if source is None:
            for pat in sig["js"]:
                if re.search(pat, low):
                    source = f"inline_js:{pat}"
                    break
        if source is None:
            continue

        kind = sig["kind"]
        ownership = (OWNERSHIP_HUMAN_OPERATED if kind == "human_support"
                     else OWNERSHIP_THIRD_PARTY_WIDGET)
        matched_vendor_kinds.add(kind)
        components.append({
            "type":       "chat_widget",
            "ownership":  ownership,
            "vendor":     vendor,
            "kind":       kind,
            "source":     source,
            "confidence": "high",
            "evidence":   [f"{vendor} vendor signature via {source}"],
        })

    # 2. Human-operator textual signals (add a human_operated surface if no
    #    human-support vendor was already identified).
    human_hits = [p for p in HUMAN_OPERATOR_PATTERNS if re.search(p, low)]
    if human_hits and "human_support" not in matched_vendor_kinds:
        components.append({
            "type":       "chat_widget",
            "ownership":  OWNERSHIP_HUMAN_OPERATED,
            "vendor":     "unknown",
            "kind":       "human_support",
            "source":     "dom_text",
            "confidence": "medium",
            "evidence":   [f"human-operator phrase matched: /{h}/" for h in human_hits[:3]],
        })

    # 3. Application-owned AI chatbot: a same-origin model-backed chat surface.
    ai_dom = has_ai_chat_dom(html)
    same_origin_chat = [e for e in ml_endpoints
                        if _same_origin(e, target_host) and _is_chat_path(e)]
    app_signals: List[str] = []
    if app_framework:
        app_signals.append(f"first-party AI framework: {app_framework}")
    if same_origin_chat:
        app_signals.append(f"same-origin chat endpoint(s): {same_origin_chat[:3]}")
    if ai_dom:
        app_signals.append("assistant/chatbot DOM markers present")

    # Require a chat-UI signal AND a same-origin model surface (framework or endpoint).
    if (ai_dom or app_framework) and (same_origin_chat or app_framework):
        confidence = "high" if (same_origin_chat and app_framework) else "medium"
        components.append({
            "type":       "chat_ui",
            "ownership":  OWNERSHIP_APPLICATION_OWNED,
            "vendor":     app_framework or "custom",
            "kind":       "ai",
            "source":     "same_origin",
            "confidence": confidence,
            "evidence":   app_signals or ["same-origin conversational AI surface"],
        })

    return components


def summarize_ownership(components: List[Dict]) -> Dict[str, int]:
    """Count discovered chat components by ownership category."""
    counts = {
        OWNERSHIP_APPLICATION_OWNED:  0,
        OWNERSHIP_THIRD_PARTY_WIDGET: 0,
        OWNERSHIP_HUMAN_OPERATED:     0,
    }
    for c in components:
        o = c.get("ownership")
        if o in counts:
            counts[o] += 1
    return counts
