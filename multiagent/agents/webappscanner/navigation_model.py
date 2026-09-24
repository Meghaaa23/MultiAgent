"""Black Widow pillar 1 — navigation modeling.

States are (host+path, form signature, cookie names). Edges are the
CLICK / FILL_FORM actions that moved the shared crawl session. The graph
is the paper-facing coverage artifact: how deep the crawler went, not
just how many URLs it listed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urlunparse


def normalize_state_url(url: str) -> str:
    try:
        p = urlparse(url or "")
    except Exception:
        return (url or "").rstrip("/")
    path = (p.path or "/").rstrip("/") or "/"
    return urlunparse((
        (p.scheme or "http").lower(),
        (p.netloc or "").lower(),
        path,
        "",
        "",
        "",
    ))


def form_signature(forms: List[Dict]) -> str:
    parts: List[str] = []
    for form in forms or []:
        inputs = form.get("fields") or form.get("inputs") or []
        names = sorted(
            (inp.get("name") or "")
            for inp in inputs
            if isinstance(inp, dict) and inp.get("name")
        )
        action = (form.get("action") or form.get("route") or "").strip()
        method = (form.get("method") or "get").lower()
        parts.append(f"{method}|{action}|{','.join(names)}")
    return ";".join(sorted(parts))


@dataclass(frozen=True)
class NavState:
    url: str
    form_sig: str
    cookie_names: Tuple[str, ...]
    title: str = ""

    @property
    def key(self) -> str:
        cookies = ",".join(self.cookie_names)
        return f"{self.url}::{self.form_sig}::{cookies}"


@dataclass
class NavEdge:
    src: str
    dst: str
    command: str
    task: str
    reasoning: str = ""


@dataclass
class NavigationGraph:
    states: Dict[str, NavState] = field(default_factory=dict)
    edges: List[NavEdge] = field(default_factory=list)
    _edge_keys: Set[Tuple[str, str, str]] = field(default_factory=set)

    def add_state(
        self,
        url: str,
        forms: Optional[List[Dict]] = None,
        cookie_names: Optional[List[str]] = None,
        title: str = "",
    ) -> NavState:
        state = NavState(
            url=normalize_state_url(url),
            form_sig=form_signature(forms or []),
            cookie_names=tuple(sorted({c for c in (cookie_names or []) if c})),
            title=(title or "")[:120],
        )
        self.states.setdefault(state.key, state)
        return state

    def add_edge(
        self,
        src: NavState,
        dst: NavState,
        command: str,
        task: str = "",
        reasoning: str = "",
    ) -> None:
        key = (src.key, dst.key, command)
        if src.key == dst.key or key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self.edges.append(NavEdge(
            src=src.url,
            dst=dst.url,
            command=command,
            task=task,
            reasoning=(reasoning or "")[:160],
        ))

    def unique_urls(self) -> List[str]:
        seen: Set[str] = set()
        out: List[str] = []
        for state in self.states.values():
            if state.url not in seen:
                seen.add(state.url)
                out.append(state.url)
        return out

    def summary(self) -> Dict:
        commands: Dict[str, int] = {}
        for edge in self.edges:
            commands[edge.command] = commands.get(edge.command, 0) + 1
        return {
            "states": len(self.states),
            "unique_urls": len(self.unique_urls()),
            "edges": len(self.edges),
            "commands": commands,
        }

    def to_dict(self) -> Dict:
        return {
            "states": [
                {
                    "url": s.url,
                    "title": s.title,
                    "form_sig": s.form_sig,
                    "cookie_names": list(s.cookie_names),
                }
                for s in self.states.values()
            ],
            "edges": [
                {
                    "src": e.src,
                    "dst": e.dst,
                    "command": e.command,
                    "task": e.task,
                }
                for e in self.edges
            ],
            "summary": self.summary(),
        }
