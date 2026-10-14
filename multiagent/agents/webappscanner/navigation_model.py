"""Black Widow pillar 1 — navigation modeling."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
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


def pack_replay_step(href: str, text: str = "", frame: str = "") -> str:
    """One recorded click. Plain URLs stay plain so older traces still replay."""
    if not text and not frame:
        return href or ""
    return "\x1f".join([href or "", text or "", frame or ""])


def parse_replay_step(raw) -> Dict[str, str]:
    if isinstance(raw, dict):
        return {
            "op": raw.get("op") or "click",
            "href": raw.get("href") or "",
            "text": raw.get("text") or "",
            "frame": raw.get("frame") or "",
        }
    text = str(raw or "")
    if "\x1f" in text:
        href, label, frame = (text.split("\x1f") + ["", ""])[:3]
        return {"op": "click", "href": href, "text": label, "frame": frame}
    return {"op": "click", "href": text, "text": "", "frame": ""}


def frontier_key(href: str) -> str:
    if (href or "").startswith("event:"):
        return "event:" + href[6:].strip().lower()
    return normalize_state_url(href)


def replay_script(
    seed: str,
    trace: Sequence,
    next_href: str = "",
) -> List[Dict[str, str]]:
    """Concrete steps to reach a state, then optionally take one more edge."""
    steps: List[Dict[str, str]] = []
    if seed:
        steps.append({"op": "goto", "href": seed, "text": "", "frame": ""})
    for item in trace or []:
        if not item:
            continue
        step = parse_replay_step(item)
        step["op"] = "click"
        steps.append(step)
    if next_href:
        step = parse_replay_step(next_href)
        step["op"] = "click" if not str(next_href).startswith("event:") else "event"
        if str(next_href).startswith("event:"):
            step["text"] = str(next_href)[6:]
            step["href"] = ""
        steps.append(step)
    return steps


def paper_coverage_row(nav_summary: Optional[Dict], findings: Sequence[Dict]) -> Dict:
    """Counts comparable to YuraScanner / Black Widow crawl tables."""
    nav = nav_summary or {}
    if isinstance(nav.get("summary"), dict):
        nav = nav["summary"]
    in_page = []
    for finding in findings or []:
        ev = finding.get("evidence") or {}
        if ev.get("confirmation_method") == "js_execution_after_replay":
            if finding.get("status") == "Confirmed":
                in_page.append(ev.get("field_phase") or "safe")
    return {
        "states": int(nav.get("states") or 0),
        "edges": int(nav.get("edges") or 0),
        "frontier_taken": int(nav.get("frontier_taken") or 0),
        "traces_recorded": int(nav.get("traces_recorded") or 0),
        "replay_probes": int(nav.get("replay_probes") or 0),
        "xss_confirmed_in_page": len(in_page),
        "xss_safe_phase": sum(1 for phase in in_page if phase == "safe"),
        "xss_aggressive_phase": sum(1 for phase in in_page if phase == "aggressive"),
    }


@dataclass(frozen=True)
class FrontierEdge:
    """An unexplored click discovered on a state, plus how to get back there."""
    seed: str
    trace: Tuple[str, ...]
    href: str

    @property
    def key(self) -> str:
        return frontier_key(self.href)


@dataclass
class NavigationGraph:
    states: Dict[str, NavState] = field(default_factory=dict)
    edges: List[NavEdge] = field(default_factory=list)
    frontier: List[FrontierEdge] = field(default_factory=list)
    frontier_taken: int = 0
    traces_recorded: int = 0
    replay_probes: int = 0
    _edge_keys: Set[Tuple[str, str, str]] = field(default_factory=set)
    _frontier_keys: Set[str] = field(default_factory=set)

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

    def enqueue_unexplored(
        self,
        seed: str,
        trace: Sequence[str],
        hrefs: Iterable[str],
        visited: Iterable[str],
    ) -> int:
        """Queue click targets that are not yet states. BW edge frontier."""
        visited_norms = {normalize_state_url(u) for u in visited if u}
        state_urls = {s.url for s in self.states.values()}
        added = 0
        clean_trace = tuple(str(h) for h in (trace or []) if h)[:16]
        for href in hrefs:
            if not href or href.startswith(("javascript:", "mailto:", "data:")):
                continue
            key = frontier_key(href)
            if not key or key in self._frontier_keys:
                continue
            if not href.startswith("event:"):
                if not urlparse(href).netloc:
                    continue
                if key in visited_norms or key in state_urls:
                    continue
            self._frontier_keys.add(key)
            self.frontier.append(FrontierEdge(seed=seed or "", trace=clean_trace, href=href))
            added += 1
        return added

    def pop_frontier(self, visited: Iterable[str]) -> Optional[FrontierEdge]:
        """Next unexplored edge whose destination is still unvisited."""
        visited_norms = {normalize_state_url(u) for u in visited if u}
        while self.frontier:
            edge = self.frontier.pop(0)
            if edge.key in visited_norms:
                continue
            self.frontier_taken += 1
            return edge
        return None

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
            "frontier_remaining": len(self.frontier),
            "frontier_taken": self.frontier_taken,
            "traces_recorded": self.traces_recorded,
            "replay_probes": self.replay_probes,
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
