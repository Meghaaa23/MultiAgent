"""
Shared XSS reflection-context analysis.

Principle for the whole scanner: code observes → code confirms → LLM explains.
A payload that is merely *reflected* in an HTTP response is NOT proof of XSS —
the reflection may be HTML-entity-encoded, attribute-quoted, or placed in a
non-executable context (textarea, comment, JSON string). Only *execution*
(an alert()/DOM sink firing under a real browser) is a true confirmation.

This module gives both VulnerabilityTester and AttackVerificationAgent a single,
consistent way to judge a reflection so the two agents never disagree:

    verdict = classify_reflection(body, payload)

    "executable"  -> payload reflected verbatim in a context where the injected
                     markup is likely to run (raw '<', '>' survived, not inside
                     an obviously inert context). High-confidence *Potential*;
                     becomes *Confirmed* only if a browser proves execution.
    "encoded"     -> payload reflected but HTML/URL-encoded (angle brackets
                     neutralised). The application is escaping output — not a
                     finding on its own.
    "text_only"   -> a benign marker string reflected but the active characters
                     ('<', '>') were stripped/encoded. Not executable.
    "absent"      -> payload not present in the response body.
"""
import html
import re
import urllib.parse
from typing import Dict


_INERT_CONTEXT_PATTERNS = [
    # payload sitting inside a context where raw markup does not execute
    (re.compile(r"<textarea[^>]*>(?:(?!</textarea>).)*$", re.I | re.S), "textarea"),
    (re.compile(r"<!--(?:(?!-->).)*$", re.S), "html_comment"),
    (re.compile(r"<title[^>]*>(?:(?!</title>).)*$", re.I | re.S), "title"),
]


def _encoded_variants(payload: str) -> set:
    variants = set()
    esc = html.escape(payload, quote=True)
    if esc != payload:
        variants.add(esc)
    esc2 = html.escape(payload, quote=False)
    if esc2 != payload:
        variants.add(esc2)
    variants.add(
        payload.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    variants.add(payload.replace("<", "&#60;").replace(">", "&#62;"))
    variants.add(payload.replace("<", "%3C").replace(">", "%3E"))
    variants.add(urllib.parse.quote(payload))
    variants.discard(payload)
    return {v for v in variants if v}


def _has_active_chars(payload: str) -> bool:
    return ("<" in payload and ">" in payload) or payload.lower().startswith("javascript:")


def classify_reflection(body: str, payload: str) -> str:
    """Return one of: 'executable', 'encoded', 'text_only', 'absent'."""
    if not body or not payload:
        return "absent"

    raw_present = payload in body

    if raw_present and _has_active_chars(payload):
        # Check whether the *raw* occurrence lands in an obviously inert context.
        idx = body.find(payload)
        prefix = body[:idx]
        for pat, _label in _INERT_CONTEXT_PATTERNS:
            if pat.search(prefix):
                return "encoded"  # neutralised by context, treat as non-executable
        return "executable"

    encoded = any(v in body for v in _encoded_variants(payload))
    if encoded:
        return "encoded"

    if raw_present:
        # payload present but has no active characters (e.g. a bare marker) —
        # the dangerous '<'/'>' were not part of what survived
        return "text_only"

    return "absent"


def reflection_summary(body: str, payload: str) -> Dict:
    verdict = classify_reflection(body, payload)
    return {
        "verdict": verdict,
        "executable": verdict == "executable",
        "reflected": verdict in ("executable", "encoded", "text_only"),
    }
