
import asyncio
import json
import re
import logging
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse, urljoin, urlsplit

from .navigation_model import (
    NavigationGraph, normalize_state_url, pack_replay_step, paper_coverage_row,
    replay_script,
)
from .interstate_tracker import (
    InterstateTracker,
    XSS_ORACLE_SOURCE,
    iter_xss_fields,
    stored_xss_payload,
    stored_xss_executed,
    stored_xss_breakout,
    xss_oracle_payload,
)

logger = logging.getLogger(__name__)
from . import auth_session as _auth
from . import ssrf_guard
from . import scan_limits

import sys as _sys

_PW_LOOP_WARNING_EMITTED = False

def _playwright_subprocess_hint(exc: Exception) -> Optional[str]:
    """Return an actionable message when Playwright failed because the running"""
    if _sys.platform != "win32":
        return None
    try:
        loop_name = type(asyncio.get_event_loop()).__name__
    except Exception:
        loop_name = "?"
    if not (isinstance(exc, NotImplementedError) or "Selector" in loop_name):
        return None
    return (
        f"Playwright could not launch a browser on the {loop_name} loop, and the "
        f"Proactor compatibility bridge did not engage. Crawling, form discovery "
        f"and injection for this run are degraded to passive HTTP checks. This is "
        f"unexpected; if it persists, start the server without --reload "
        f"(e.g. `python main.py`) so a ProactorEventLoop is used directly."
    )

def _warn_playwright_loop_once(exc: Exception) -> bool:
    """Emit the subprocess-loop remediation at most once. Returns True if the"""
    global _PW_LOOP_WARNING_EMITTED
    hint = _playwright_subprocess_hint(exc)
    if not hint:
        return False
    if not _PW_LOOP_WARNING_EMITTED:
        logger.error(hint)
        print("  !! " + hint)
        _PW_LOOP_WARNING_EMITTED = True
    return True

import threading as _threading

_browser_loop: "Optional[asyncio.AbstractEventLoop]" = None
_browser_loop_lock = _threading.Lock()

def _loop_supports_subprocess(loop: "Optional[asyncio.AbstractEventLoop]" = None) -> bool:
    if _sys.platform != "win32":
        return True
    try:
        loop = loop or asyncio.get_event_loop()
    except Exception:
        return True
    return "Selector" not in type(loop).__name__

def _get_browser_loop() -> "asyncio.AbstractEventLoop":
    """Lazily start (once) a ProactorEventLoop on a background daemon thread."""
    global _browser_loop
    with _browser_loop_lock:
        if _browser_loop is not None and not _browser_loop.is_closed():
            return _browser_loop
        loop = (asyncio.ProactorEventLoop() if _sys.platform == "win32"
                else asyncio.new_event_loop())

        def _run() -> None:
            asyncio.set_event_loop(loop)
            loop.run_forever()

        _threading.Thread(target=_run, name="playwright-loop", daemon=True).start()
        _browser_loop = loop
        return loop

async def _run_browser_coro(coro):
    """Await ``coro`` on a subprocess-capable loop."""
    if _loop_supports_subprocess():
        return await coro
    loop = _get_browser_loop()
    fut = asyncio.run_coroutine_threadsafe(coro, loop)
    try:
        return await asyncio.wrap_future(fut)
    except asyncio.CancelledError:
        fut.cancel()
        raise

class BrowserController:
    """Yura-style browser agent: task extraction → multi-step execution → surface collection."""

    def __init__(self, openai_client, llm_model: str = "Qwen-2.5"):
        self.openai_client  = openai_client
        self.llm_model      = llm_model
        self.action_history: List[Dict] = []

        self._pw = None
        self._browser = None
        self._context = None
        self._page = None
        self._session_base: str = ""
        self._visited_urls: Set[str] = set()
        self._network_apis: Set[str] = set()
        self.nav_graph = NavigationGraph()
        self.taint = InterstateTracker()
        self._current_task_name: str = ""
        self.crawl_findings: List[Dict] = []
        self._confirmed_flow_keys: Set[tuple] = set()
        self._reach_trace: List[str] = []
        self._seed_url: str = ""
        self._trace_keys: Set[tuple] = set()
        # Runtime browser state, distinct from import availability:
        #   None  = no browser launch attempted yet
        #   True  = a real browser rendered at least one page
        #   False = a launch was attempted but failed and we fell back to urllib
        # The import succeeding does NOT mean a browser binary is present, so
        # downstream code must consult this, not `_has_playwright`, to know
        # whether dynamic (SPA/JS) surface was actually covered.
        self.browser_launch_ok: Optional[bool] = None

        try:
            from playwright.async_api import async_playwright
            self._has_playwright = True
            print(" Browser Controller initialized (Playwright)")
        except ImportError:
            self._has_playwright = False
            logger.warning("Playwright not installed — using urllib fallback")
            print(" Browser Controller initialized (urllib fallback)")

    _API_PATH_HINTS = (
        "/api/", "/rest/", "/graphql", "/query", "/v1/", "/v2/", "/v3/",
        "/login", "/search", "/config", "/admin", "/users", "/user/",
        "/products", "/auth",
    )

    def _is_harvestable_api_url(self, url: str) -> bool:
        """True for same-host XHR-like URLs worth seeding into vuln tests."""
        if not url or not url.startswith(("http://", "https://")):
            return False
        try:
            p = urlsplit(url)
        except Exception:
            return False
        base_host = urlsplit(self._session_base).netloc if self._session_base else ""
        if base_host and p.netloc and p.netloc != base_host:
            return False
        path = (p.path or "").lower()
        if re.search(
            r"\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|webp)(\?|$)", path
        ):
            return False
        if any(h in path for h in self._API_PATH_HINTS):
            return True
        if p.query and path not in ("/", ""):
            return True
        return False

    def _attach_network_listener(self) -> None:
        """Record API/XHR URLs from the shared Playwright context."""
        if self._context is None:
            return

        def _on_request(request) -> None:
            try:
                rtype = (request.resource_type or "").lower()
                url = request.url or ""
                if rtype in ("xhr", "fetch", "websocket") or self._is_harvestable_api_url(url):
                    if self._is_harvestable_api_url(url):
                        clean = url.split("#", 1)[0]
                        self._network_apis.add(clean)
            except Exception:
                pass

        try:
            self._context.on("request", _on_request)
        except Exception as e:
            logger.debug("network listener attach failed: %s", e)

    async def capture_page(self, url: str) -> Dict:
        """Capture page HTML and interactive elements."""
        if self._has_playwright:
            return await _run_browser_coro(self._playwright_capture(url))
        return await self._urllib_capture(url)

    async def capture_ui_elements(self, url: str) -> List[Dict]:

        page_data = await self.capture_page(url)
        return page_data.get("elements", [])

    async def _playwright_capture(self, url: str) -> Dict:
        from playwright.async_api import async_playwright
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True, args=["--no-sandbox"]
                )
                context = await browser.new_context()
                await _auth.prepare_context(context)
                await ssrf_guard.install_browser_guard(context)
                page = await context.new_page()
                await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                await page.wait_for_timeout(2000)

                html     = await page.content()
                elements = await self._extract_elements_playwright(page)

                await browser.close()
                self.browser_launch_ok = True
                return {"html": html, "elements": elements, "url": url}
        except Exception as e:
            if self.browser_launch_ok is None:
                self.browser_launch_ok = False
            if not _warn_playwright_loop_once(e):
                logger.warning(f"Playwright capture failed: {e}")
            return await self._urllib_capture(url)

    async def _urllib_capture(self, url: str) -> Dict:
        """Fallback: fetch HTML with urllib, extract elements with regex."""
        import urllib.request
        try:
            headers = {"User-Agent": "Mozilla/5.0 (SecurityScanner)"}
            req = urllib.request.Request(url, headers=headers)
            loop = asyncio.get_event_loop()
            raw  = await loop.run_in_executor(
                None, lambda: urllib.request.urlopen(req, timeout=15).read(1_000_000)
            )
            html     = raw.decode("utf-8", errors="replace")
            elements = self._extract_elements_from_html(html, base_url=url)
            return {"html": html, "elements": elements, "url": url}
        except Exception as e:
            logger.warning(f"urllib capture failed: {e}")
            return {"html": "", "elements": [], "url": url}

    async def _extract_elements_playwright(self, page) -> List[Dict]:
        """SENSORS: extract interactive elements via Playwright JS evaluation."""
        try:
            elements = await page.evaluate("""
                () => {
                    const result = [];

                    // Clickable elements
                    const clickables = document.querySelectorAll(
                        'a, button, [onclick], [role="button"]'
                    );
                    clickables.forEach((elem, idx) => {
                        if (elem.offsetParent !== null && idx < 30) {
                            result.push({
                                type:  'clickable',
                                tag:   elem.tagName.toLowerCase(),
                                text:  (elem.innerText || elem.textContent || '')
                                           .trim().substring(0, 100),
                                id:    elem.id || `elem-${idx}`,
                                href:  elem.href || ''
                            });
                        }
                    });

                    // Forms — include hidden inputs so CSRF tokens are visible
                    const forms = document.querySelectorAll('form');
                    forms.forEach((form, idx) => {
                        const inputs = form.querySelectorAll(
                            'input, textarea, select'
                        );
                        if (inputs.length > 0) {
                            // Use getAttribute, not form.action/method/id: a
                            // control named "action"/"method"/"id" clobbers
                            // those DOM properties and returns the element
                            // (which serialises to an object), not the string.
                            let formAction = '';
                            try {
                                formAction = new URL(
                                    form.getAttribute('action') || '',
                                    location.href).href;
                            } catch (e) {
                                formAction = form.getAttribute('action') || '';
                            }
                            const formMethod = form.getAttribute('method') || 'get';
                            const formId = form.getAttribute('id') || `form-${idx}`;
                            result.push({
                                type:   'form',
                                tag:    'form',
                                id:     formId,
                                action: formAction,
                                method: formMethod,
                                inputs: Array.from(inputs).map(inp => ({
                                    name:        inp.name        || '',
                                    type:        inp.type        || 'text',
                                    id:          inp.id          || '',
                                    placeholder: inp.placeholder || ''
                                }))
                            });
                        }
                    });

                    // All same-origin links (classic SSR apps rarely put params in menus)
                    const origin = location.origin;
                    const links = document.querySelectorAll('a[href]');
                    links.forEach(link => {
                        const href = link.href || '';
                        if (!href || href.startsWith('javascript:') || href.startsWith('mailto:')) {
                            return;
                        }
                        if (href.startsWith(origin) || href.startsWith('/')) {
                            result.push({
                                type: 'link',
                                href: href,
                                text: (link.innerText || '').trim().substring(0, 60)
                            });
                        }
                    });

                    return result;
                }
            """)
            return elements or []
        except Exception as e:
            logger.debug(f"Playwright element extraction failed: {e}")
            return []

    def _extract_elements_from_html(self, html: str, base_url: str = "") -> List[Dict]:
        """Regex-based element extraction (urllib fallback)."""
        elements = []
        base = self._base_url(base_url)

        form_re = re.compile(
            r'<form([^>]*)>(.*?)</form>',
            re.IGNORECASE | re.DOTALL
        )
        input_re = re.compile(
            r'<input([^>]*)>',
            re.IGNORECASE
        )
        attr_re = re.compile(r'(\w+)=["\']([^"\']*)["\']', re.IGNORECASE)

        for fi, form_m in enumerate(form_re.finditer(html)):
            attrs      = dict(attr_re.findall(form_m.group(1)))
            action     = attrs.get("action", "")
            method     = attrs.get("method", "get")
            form_body  = form_m.group(2)

            inp_list = []
            for inp_m in input_re.finditer(form_body):
                inp_attrs = dict(attr_re.findall(inp_m.group(1)))
                inp_list.append({
                    "name":  inp_attrs.get("name",  ""),
                    "type":  inp_attrs.get("type",  "text"),
                    "id":    inp_attrs.get("id",    ""),
                })

            if not action:
                action = base_url
            elif not action.startswith("http"):
                action = urljoin(base_url, action)

            elements.append({
                "type":   "form",
                "tag":    "form",
                "id":     f"form-{fi}",
                "action": action,
                "method": method,
                "inputs": inp_list
            })

        base_host = urlsplit(base_url).netloc if base_url else ""
        for href in re.findall(r'href=["\']([^"\'#]+)["\']', html, re.I):
            if href.lower().startswith(("javascript:", "mailto:", "data:")):
                continue
            full = urljoin(base_url, href) if not href.startswith("http") else href
            if base_host and urlsplit(full).netloc not in ("", base_host):
                continue
            elements.append({"type": "link", "href": full})

        return elements

    def _format_ui_elements(self, elements: List[Dict]) -> str:
        """Compact, token-efficient representation of UI elements for LLM prompt."""
        lines = []
        for i, el in enumerate(elements, 1):
            t = el.get("type", "")
            if t == "form":
                inputs     = el.get("inputs", [])
                inp_names  = [
                    inp.get("name", "") for inp in inputs if inp.get("name")
                ]
                lines.append(
                    f"{i}. FORM  action={el.get('action','?')}  "
                    f"method={el.get('method','get')}  "
                    f"inputs=[{', '.join(inp_names)}]"
                )
            elif t == "link":
                lines.append(f"{i}. LINK  href={el.get('href','?')}")
            elif t == "clickable":
                lines.append(
                    f"{i}. CLICK  <{el.get('tag','?')}> "
                    f"text=\"{el.get('text','')[:50]}\"  "
                    f"href={el.get('href','')}"
                )
            else:
                lines.append(f"{i}. {t.upper()}  {json.dumps(el)[:120]}")
        return "\n".join(lines) if lines else "(no elements found)"

    async def generate_tasks(self, elements: List[Dict],
                             page_description: str,
                             openai_client,
                             llm_model: str,
                             target_url: str = "",
                             deep: bool = True) -> List[Dict]:
        filtered = [
            e for e in elements
            if e.get("type") in ("form", "link", "clickable")
        ]

        if not filtered:
            filtered = [{"type": "link", "href": target_url}]

        chunk_size  = 50
        max_chunks  = scan_limits.scan_max_input_chunks() if deep else 6
        chunks      = [
            filtered[i:i + chunk_size]
            for i in range(0, len(filtered), chunk_size)
        ][:max_chunks]

        all_tasks: List[Dict] = []

        for idx, chunk in enumerate(chunks, 1):
            prompt = f"""You are a web security tester analyzing a web application.

URL: {target_url}
Page: {page_description or "(no description)"}
UI Elements (chunk {idx}/{len(chunks)}):
{self._format_ui_elements(chunk)}

Generate 4-6 realistic deep-crawl security tasks for black-box unauthenticated probing.
Focus on:
- Public login / search / contact forms (probe without real credentials)
- Multi-step navigation into publicly reachable secondary pages
- Search / id / filter parameters (SQL injection-shaped surfaces)
- State-changing anonymous POST forms (CSRF-shaped surfaces)
- Comment / message / profile forms that may persist data across pages
- Input handling on search, profile, admin, and data views that do not require login

Each task must include a specific URL to navigate to.

Respond with JSON only — no explanation:
{{
    "tasks": [
        {{
            "name":        "Explore public search form",
            "description": "Submit benign input on publicly reachable forms",
            "url":         "{target_url}"
        }}
    ]
}}
"""
            try:
                resp = openai_client.chat.completions.create(
                    model=llm_model,
                    messages=[
                        {
                            "role":    "system",
                            "content": "You are a security testing expert. Respond with JSON only."
                        },
                        {"role": "user", "content": prompt}
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.3,
                    max_tokens=900
                )
                data        = json.loads(resp.choices[0].message.content)
                chunk_tasks = data.get("tasks", [])

                for t in chunk_tasks:
                    if "task" in t and "name" not in t:
                        t["name"] = t.pop("task")
                    if not t.get("url"):
                        t["url"] = target_url

                all_tasks.extend(chunk_tasks)

            except Exception as e:
                logger.warning(f"Task generation chunk {idx}/{len(chunks)} failed: {e}")

        seen:   Set[str]   = set()
        unique: List[Dict] = []
        for task in all_tasks:
            name = (task.get("name") or "").strip().lower()
            if name and name not in seen:
                seen.add(name)
                unique.append(task)

        for t in self._deterministic_tasks(filtered, target_url):
            name = (t.get("name") or "").strip().lower()
            if name and name not in seen:
                seen.add(name)
                unique.append(t)

        cap = scan_limits.scan_max_tasks() if deep else 15
        return unique if cap is None else unique[:cap]

    def _deterministic_tasks(self, elements: List[Dict],
                              target_url: str) -> List[Dict]:
        """Product-agnostic crawl tasks from forms/links (no LLM required)."""
        tasks: List[Dict] = []
        seen: Set[str] = set()

        def _add(name: str, url: str, description: str):
            key = (name or "").lower()
            if not url or key in seen:
                return
            seen.add(key)
            tasks.append({
                "name": name,
                "description": description,
                "url": url,
            })

        _add("Inspect landing page", target_url,
             "Extract forms and links from the landing page")

        for el in elements:
            if el.get("type") == "form":
                action = el.get("action") or target_url
                method = (el.get("method") or "get").upper()
                names = " ".join(
                    (i.get("name") or "")
                    for i in (el.get("inputs") or el.get("fields") or [])
                    if isinstance(i, dict)
                ).lower()
                action_l = (action or "").lower()
                if any(k in names or k in action_l for k in (
                    "search", "q", "query", "id", "filter",
                )):
                    desc = "Exercise search/id parameters for SQLi and XSS"
                elif method == "POST" and any(k in action_l for k in (
                    "update", "save", "delete", "profile", "account", "order",
                )):
                    desc = "Exercise state-changing POST for CSRF and injection"
                elif any(k in names or k in action_l for k in (
                    "comment", "message", "review", "guestbook", "bio",
                )):
                    desc = "Exercise persistent fields for inter-page stored flows"
                else:
                    desc = "Exercise form inputs for XSS, SQLi, and CSRF"
                _add(
                    f"Submit {method} form {action}",
                    action,
                    desc,
                )
            elif el.get("type") == "link":
                href = el.get("href") or ""
                if not href:
                    continue
                text = (el.get("text") or href)[:40]
                _add(f"Visit {text}", href, "Crawl linked surface for forms and params")
            if len(tasks) >= 10:
                break
        return tasks

    async def _decide_next_action(self, task: str,
                                  current_state: Dict,
                                  history: List[Dict]) -> Dict:

        state_text  = f"URL: {current_state.get('url', '')}\n"
        state_text += f"Title: {current_state.get('title', '')}\n\n"
        state_text += "Available Actions:\n"

        for c in current_state.get("clickables", [])[:10]:
            state_text += (
                f"  <{c['tag']} id={c['id']}>"
                f"{c.get('text','')[:50]}"
                f"</{c['tag']}>\n"
            )
        for f in current_state.get("forms", []):
            state_text += (
                f"  <form id={f['id']} "
                f"action=\"{f.get('action','')}\" "
                f"method=\"{f.get('method','')}\">\n"
            )
            for field in f.get("fields", [])[:5]:
                state_text += (
                    f"    <input name=\"{field['name']}\" "
                    f"type=\"{field['type']}\" />\n"
                )
            state_text += "  </form>\n"

        history_text = "\n".join(
            f"  Step {a['step']}: {a['action']}"
            for a in history[-5:]
        ) or "None"

        prompt = f"""You are Yura, an agent controlling a web browser for deep security crawling.

Task: {task}

Current Page:
{state_text}

Previous Actions:
{history_text}

Commands available:
  CLICK      {{id}} — click element / navigate
  FILL_FORM  {{id}} — fill and submit form
  STOP            — task complete or impossible

Prefer actions that reach new publicly reachable secondary pages.
Only STOP when the task is done or no useful action remains.

Output JSON only:
{{
    "command":   "CLICK" | "FILL_FORM" | "STOP",
    "target_id": 0,
    "reasoning": "why"
}}
"""
        try:
            resp = self.openai_client.chat.completions.create(
                model=self.llm_model,
                messages=[
                    {
                        "role":    "system",
                        "content": "You are a web automation agent. Output valid JSON only."
                    },
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.3,
                max_tokens=200
            )
            return json.loads(resp.choices[0].message.content)
        except Exception as e:
            logger.warning(f"BRIDGE decision failed: {e}")
            return {"command": "STOP", "reasoning": "Error in decision"}

    async def _wait_after_nav(self, page, ms: int = 1200) -> None:
        """Give SPAs time to render + fire XHR after a navigation/click."""
        try:
            await page.wait_for_load_state("networkidle", timeout=min(ms + 2000, 5000))
        except Exception:
            pass
        try:
            await page.wait_for_timeout(ms)
        except Exception:
            pass

    async def _execute_action(self, page, action: Dict, state: Dict) -> bool:
        """ACTUATORS: execute a BRIDGE decision on the Playwright page."""
        command   = action.get("command", "")
        target_id = action.get("target_id", 0)

        try:
            if command == "CLICK":
                clickables = state.get("clickables", [])
                if target_id < len(clickables):
                    target = clickables[target_id]
                    text = (target.get("text") or "")[:50]
                    href = (target.get("href") or "").strip()
                    if _auth.any_active() and (
                        _auth.is_logout_url(href) or _auth.is_logout_url(text)
                    ):
                        return False
                    if href and ("#/" in href or self._in_scope(href)):
                        try:
                            await page.goto(
                                href, wait_until="domcontentloaded", timeout=20000
                            )
                            await self._wait_after_nav(page, 1000)
                            return True
                        except Exception:
                            pass
                    if text:
                        await page.get_by_text(text, exact=False).first.click(
                            timeout=5000
                        )
                        await self._wait_after_nav(page, 900)
                        return True
                    try:
                        loc = page.locator("a, button, [routerLink], [onclick]")
                        await loc.nth(target_id).click(timeout=5000)
                        await self._wait_after_nav(page, 900)
                        return True
                    except Exception:
                        return False
                return False

            elif command == "FILL_FORM":
                forms = state.get("forms", [])
                if target_id < len(forms):
                    form = forms[target_id]
                    for field in form.get("fields", []):
                        name = field.get("name", "")
                        if not name:
                            continue
                        itype = field.get("type", "text")
                        if (itype or "").lower() == "hidden":
                            continue
                        value = self._dummy_value(
                            name, itype,
                            url=state.get("url") or "",
                            form_action=form.get("action") or "",
                        )
                        try:
                            await page.fill(f'[name="{name}"]', value, timeout=3000)
                        except Exception:
                            pass

                    submit = await page.query_selector(
                        'button[type="submit"], input[type="submit"], '
                        'button:has-text("Search"), button:has-text("Submit")'
                    )
                    if submit:
                        await submit.click()
                    else:
                        try:
                            await page.keyboard.press("Enter")
                        except Exception:
                            pass
                    await self._wait_after_nav(page, 1000)
                    return True
                return False

            elif command == "STOP":
                return True

        except Exception as e:
            logger.debug(f"Actuator failed: {e}")

        return False

    def _dummy_value(self, field_name: str, field_type: str,
                     url: str = "", form_action: str = "") -> str:
        """Benign dummy value; plant a unique inter-state canary when safe."""
        n = field_name.lower()
        if "password" in n or field_type == "password":
            return "TestPassword123!"
        if "email" in n or field_type == "email":
            return "test@example.com"
        if "phone" in n or "tel" in n:
            return "555-0123"
        if "url" in n or "website" in n:
            return "https://example.com"
        if field_type == "number":
            return "42"
        if field_type == "date":
            return "2024-01-01"
        if any(k in n for k in ("user", "login", "account", "name")):
            return "testuser"
        token = self.taint.plant(
            field_name, field_type,
            url=url,
            form_action=form_action,
            task=self._current_task_name,
        )
        if token:
            return token
        return "test"

    def _parse_cookie_header(self, cookie_header: str, base_url: str) -> List[Dict]:
        """Convert 'a=b; c=d' Cookie header into Playwright cookie dicts."""
        if not cookie_header:
            return []
        parsed = urlparse(base_url)
        domain = parsed.hostname or "localhost"
        secure = parsed.scheme == "https"
        out: List[Dict] = []
        for part in cookie_header.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            name, _, value = part.partition("=")
            name, value = name.strip(), value.strip()
            if not name:
                continue
            out.append({
                "name": name,
                "value": value,
                "domain": domain,
                "path": "/",
                "secure": secure,
                "httpOnly": False,
            })
        return out

    async def start_deep_session(self, base_url: str) -> bool:
        """Open one Chromium context reused across deep-crawl tasks."""
        if not self._has_playwright:
            return False
        if self._page is not None:
            return True
        try:
            from playwright.async_api import async_playwright
            self._pw = await async_playwright().start()
            self._browser = await self._pw.chromium.launch(
                headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"]
            )
            self._context = await self._browser.new_context(
                user_agent="Mozilla/5.0 (SecurityScanner/DeepCrawl)"
            )
            await _auth.prepare_context(self._context)
            await ssrf_guard.install_browser_guard(self._context)
            self._session_base = self._base_url(base_url)
            self._visited_urls = set()
            self._network_apis = set()
            self.nav_graph = NavigationGraph()
            self.taint = InterstateTracker()
            self.crawl_findings = []
            self._confirmed_flow_keys = set()
            self._reach_trace = []
            self._seed_url = ""
            self._trace_keys = set()
            self._attach_network_listener()
            await self._context.add_init_script(XSS_ORACLE_SOURCE)
            self._page = await self._context.new_page()
            return True
        except Exception as e:
            if not _warn_playwright_loop_once(e):
                logger.warning(f"start_deep_session failed: {e}")
            await self.close_deep_session()
            return False

    async def close_deep_session(self) -> None:
        try:
            if self._browser:
                await self._browser.close()
        except Exception:
            pass
        try:
            if self._pw:
                await self._pw.stop()
        except Exception:
            pass
        self._pw = None
        self._browser = None
        self._context = None
        self._page = None
        self._session_base = ""

    def _normalize_form(self, form: Dict) -> Dict:
        """Ensure forms have both fields and inputs for downstream testers."""
        fields = form.get("fields") or form.get("inputs") or []
        action = form.get("action")
        action = action if isinstance(action, str) else ""
        method = form.get("method")
        method = method if isinstance(method, str) else "get"
        form_id = form.get("id")
        form_id = form_id if isinstance(form_id, str) else ""
        if self._reach_trace:
            key = (self._seed_url or "", tuple(self._reach_trace), action)
            if key not in self._trace_keys:
                self._trace_keys.add(key)
                self.nav_graph.traces_recorded += 1
        return {
            "type":   "form",
            "action": action,
            "method": method,
            "fields": fields,
            "inputs": fields,
            "route":  action,
            "id":     form_id,
            "reach_trace": list(self._reach_trace),
            "seed_url": self._seed_url or "",
            "frame": form.get("frame") or "",
        }

    def _clickable_score(self, text: str, href: str, task_l: str = "") -> int:
        """Higher = more useful for security surface discovery."""
        t = (text or "").lower()
        h = (href or "").lower()
        score = 0
        for kw in (
            "vuln", "security", "admin", "user", "profile", "search", "product",
            "order", "account", "setup", "sqli", "xss", "csrf", "upload",
            "dashboard", "register", "login", "contact", "basket", "cart",
            "photo", "complaint", "challenge",
        ):
            if kw in t or kw in h:
                score += 2
                if task_l and kw in task_l:
                    score += 3
        if "#/" in h or "router" in h:
            score += 2
        if h and h not in self._visited_urls:
            score += 1
        return score

    def _heuristic_next_action(self, task: str, state: Dict,
                                history: List[Dict]) -> Dict:
        """Deterministic fallback when the LLM stops early or fails."""
        forms = state.get("forms") or []
        clickables = state.get("clickables") or []
        task_l = (task or "").lower()
        want_login = any(
            k in task_l for k in ("login", "auth", "sign in", "signin", "credential")
        )
        want_search = any(
            k in task_l for k in ("search", "query", "find", "product")
        )

        if want_login and forms:
            for i, f in enumerate(forms):
                types = {(fld.get("type") or "").lower() for fld in f.get("fields") or []}
                names = {(fld.get("name") or "").lower() for fld in f.get("fields") or []}
                if "password" in types or any("pass" in n for n in names):
                    return {
                        "command": "FILL_FORM",
                        "target_id": i,
                        "reasoning": "heuristic: submit login/auth form",
                    }

        if want_search and forms:
            for i, f in enumerate(forms):
                names = {(fld.get("name") or "").lower() for fld in f.get("fields") or []}
                if any(k in n for n in names for k in ("q", "query", "search", "keyword")):
                    return {
                        "command": "FILL_FORM",
                        "target_id": i,
                        "reasoning": "heuristic: submit search form",
                    }

        tried_clicks = {
            (a.get("action") or {}).get("target_id")
            for a in history
            if (a.get("action") or {}).get("command") == "CLICK"
        }
        base_host = urlsplit(self._session_base or state.get("url") or "").netloc
        ranked: List[tuple] = []
        for i, c in enumerate(clickables):
            if i in tried_clicks:
                continue
            href = c.get("href") or ""
            if not href or href.startswith(("javascript:", "mailto:")):
                if (c.get("tag") or "").lower() not in ("button", "a") and not c.get("text"):
                    continue
            if href.startswith("#") and not href.startswith("#/"):
                continue
            host = urlsplit(href).netloc if href.startswith("http") else ""
            if base_host and host and host != base_host:
                continue
            if href and href in self._visited_urls:
                continue
            text = c.get("text") or ""
            score = self._clickable_score(text, href, task_l)
            ranked.append((score, i, text, href))

        if ranked:
            ranked.sort(key=lambda x: (-x[0], x[1]))
            score, i, text, href = ranked[0]
            return {
                "command": "CLICK",
                "target_id": i,
                "reasoning": (
                    f"heuristic: explore link score={score} "
                    f"{(text or href)[:40]}"
                ),
            }

        filled = any(
            (a.get("action") or {}).get("command") == "FILL_FORM" for a in history
        )
        if forms and not filled:
            for i, f in enumerate(forms):
                names = {(fld.get("name") or "").lower() for fld in f.get("fields") or []}
                if any(k in n for n in names for k in ("q", "query", "search")):
                    return {
                        "command": "FILL_FORM",
                        "target_id": i,
                        "reasoning": "heuristic: exercise search form",
                    }
            return {
                "command": "FILL_FORM",
                "target_id": 0,
                "reasoning": "heuristic: exercise first form",
            }
        return {"command": "STOP", "reasoning": "heuristic: nothing left to explore"}

    def _href_unvisited(self, href: str) -> bool:
        if not href or href.startswith(("javascript:", "mailto:", "data:")):
            return False
        if href in self._visited_urls:
            return False
        norm = normalize_state_url(href)
        return all(normalize_state_url(u) != norm for u in self._visited_urls)

    def _action_is_useful(self, action: Dict, state: Dict,
                           history: List[Dict]) -> bool:
        """True when the action is likely to open a new graph edge."""
        command = (action or {}).get("command") or ""
        if command == "STOP" or not command:
            return False
        target_id = action.get("target_id", 0)
        if command == "CLICK":
            clickables = state.get("clickables") or []
            if not isinstance(target_id, int) or target_id >= len(clickables):
                return False
            href = clickables[target_id].get("href") or ""
            return self._href_unvisited(href)
        if command == "FILL_FORM":
            filled = {
                (a.get("action") or {}).get("target_id")
                for a in history
                if (a.get("action") or {}).get("command") == "FILL_FORM"
            }
            forms = state.get("forms") or []
            return (
                isinstance(target_id, int)
                and target_id < len(forms)
                and target_id not in filled
            )
        return False

    def _graph_next_action(self, task: str, state: Dict,
                            history: List[Dict]) -> Dict:
        """Pick the next unexplored edge from the current state (BW-style)."""
        clickables = state.get("clickables") or []
        forms = state.get("forms") or []
        task_l = (task or "").lower()
        sink_norms = {
            normalize_state_url(f.sink_url)
            for f in self.taint.flows
            if getattr(f, "sink_url", None)
        }
        tried_clicks = {
            (a.get("action") or {}).get("target_id")
            for a in history
            if (a.get("action") or {}).get("command") == "CLICK"
        }
        ranked: List[tuple] = []
        for i, c in enumerate(clickables):
            if i in tried_clicks:
                continue
            href = c.get("href") or ""
            if not self._href_unvisited(href):
                continue
            score = self._clickable_score(c.get("text") or "", href, task_l)
            if normalize_state_url(href) in sink_norms:
                score += 6
            ranked.append((score, i, href))
        if ranked:
            ranked.sort(key=lambda x: (-x[0], x[1]))
            score, i, href = ranked[0]
            return {
                "command": "CLICK",
                "target_id": i,
                "reasoning": f"graph: unvisited edge score={score} {href[:50]}",
            }

        filled = {
            (a.get("action") or {}).get("target_id")
            for a in history
            if (a.get("action") or {}).get("command") == "FILL_FORM"
        }
        for i, form in enumerate(forms):
            if i in filled:
                continue
            names = " ".join(
                (fld.get("name") or "")
                for fld in (form.get("fields") or [])
            ).lower()
            if any(k in names for k in (
                "comment", "message", "q", "query", "search", "review", "bio",
            )):
                return {
                    "command": "FILL_FORM",
                    "target_id": i,
                    "reasoning": "graph: unfilled write/search form",
                }
        for i, _form in enumerate(forms):
            if i not in filled:
                return {
                    "command": "FILL_FORM",
                    "target_id": i,
                    "reasoning": "graph: unfilled form",
                }
        return {"command": "STOP", "reasoning": "graph: no unexplored edges"}

    def _graph_is_decisive(self, task: str, state: Dict,
                            history: List[Dict]) -> bool:
        """True when one unexplored edge is clearly better than the rest."""
        action = self._graph_next_action(task, state, history)
        if not self._action_is_useful(action, state, history):
            return False
        if action.get("command") == "FILL_FORM":
            return True
        clickables = state.get("clickables") or []
        tried = {
            (a.get("action") or {}).get("target_id")
            for a in history
            if (a.get("action") or {}).get("command") == "CLICK"
        }
        task_l = (task or "").lower()
        scores: List[int] = []
        for i, c in enumerate(clickables):
            href = c.get("href") or ""
            if i in tried or not self._href_unvisited(href):
                continue
            scores.append(self._clickable_score(c.get("text") or "", href, task_l))
        if len(scores) <= 1:
            return True
        scores.sort(reverse=True)
        return scores[0] >= scores[1] + 2

    _WORKFLOW_HINTS = (
        "checkout", "cart", "comment", "post", "review", "login", "register",
        "purchase", "order", "submit", "workflow", "guestbook", "contact",
        "account", "profile", "search", "upload", "message", "shop",
    )

    def _task_is_workflow(self, task: str) -> bool:
        low = (task or "").lower()
        return any(hint in low for hint in self._WORKFLOW_HINTS)

    def _choose_crawl_action(self, task: str, graph_action: Dict,
                              llm_action: Optional[Dict], state: Dict,
                              history: List[Dict]) -> Dict:
        """A named workflow keeps the LLM on that task."""
        if (
            self._task_is_workflow(task)
            and llm_action
            and self._action_is_useful(llm_action, state, history)
        ):
            return llm_action
        if self._action_is_useful(graph_action, state, history):
            return graph_action
        if llm_action and self._action_is_useful(llm_action, state, history):
            return llm_action
        return {"command": "STOP", "reasoning": "no unexplored edge"}

    async def _select_crawl_action(self, task: str, state: Dict,
                                    history: List[Dict]) -> Dict:
        graph = self._graph_next_action(task, state, history)
        llm = None
        if self._task_is_workflow(task) or not self._action_is_useful(graph, state, history):
            llm = await self._decide_next_action(task, state, history)
        chosen = self._choose_crawl_action(task, graph, llm, state, history)
        if chosen.get("command") != "STOP":
            return chosen
        alt = self._heuristic_next_action(task, state, history)
        if self._action_is_useful(alt, state, history):
            return alt
        return chosen

    def _revisit_candidates(self, extra_urls: List[str],
                             current_url: str,
                             max_pages: int = 8) -> List[str]:
        """Pages to re-open after a write so stored tokens can be observed."""
        current = normalize_state_url(current_url)
        seen: Set[str] = set()
        out: List[tuple] = []
        for url in list(self._visited_urls) + list(extra_urls or []):
            if not url or not url.startswith(("http://", "https://")):
                continue
            if self._session_base and not url.startswith(self._session_base):
                host = urlsplit(url).netloc
                base_host = urlsplit(self._session_base).netloc
                if host and base_host and host != base_host:
                    continue
            norm = normalize_state_url(url)
            if not norm or norm == current or norm in seen:
                continue
            seen.add(norm)
            low = (url or "").lower()
            score = 0
            for kw in (
                "guest", "comment", "message", "search", "list", "view",
                "post", "topic", "thread", "profile", "product", "user",
            ):
                if kw in low:
                    score += 2
            out.append((score, url))
        out.sort(key=lambda x: (-x[0], x[1]))
        return [u for _, u in out[:max_pages]]

    def _action_href(self, action: Dict, state: Dict) -> str:
        href = (action or {}).get("href") or ""
        if href:
            return href
        target_id = (action or {}).get("target_id", 0)
        clickables = (state or {}).get("clickables") or []
        if isinstance(target_id, int) and 0 <= target_id < len(clickables):
            return clickables[target_id].get("href") or ""
        return ""

    def _note_frontier(self, state: Dict) -> None:
        hrefs = []
        for c in state.get("clickables") or []:
            href = c.get("href") or ""
            text = (c.get("text") or "").strip()
            if href and not href.startswith(("javascript:", "mailto:", "data:")):
                hrefs.append(href)
            elif text:
                hrefs.append("event:" + text[:80])
        self.nav_graph.enqueue_unexplored(
            self._seed_url or (state.get("url") or ""),
            self._reach_trace,
            hrefs,
            self._visited_urls,
        )

    def _step_target(self, page, step: Dict):
        frame_url = (step or {}).get("frame") or ""
        if not frame_url or page is None:
            return page
        for frame in page.frames:
            if frame.url and frame_url in frame.url:
                return frame
        return page

    async def _replay_one_step(self, page, step: Dict) -> bool:
        """Re-execute one recorded click or form navigation inside the page."""
        op = (step or {}).get("op") or "click"
        href = (step or {}).get("href") or ""
        text = (step or {}).get("text") or ""
        if op == "goto" and href:
            await page.goto(href, wait_until="domcontentloaded", timeout=20000)
            await self._wait_after_nav(page, 700)
            return True
        target = self._step_target(page, step)
        if op == "event" or href.startswith("event:"):
            label = text or href[6:]
            if not label:
                return False
            await target.get_by_text(label, exact=False).first.click(timeout=5000)
            await self._wait_after_nav(page, 700)
            return True
        if text:
            try:
                await target.get_by_text(text[:80], exact=False).first.click(timeout=4000)
                await self._wait_after_nav(page, 700)
                return True
            except Exception:
                pass
        if href.startswith(("http://", "https://")):
            await page.goto(href, wait_until="domcontentloaded", timeout=20000)
            await self._wait_after_nav(page, 700)
            return True
        return False

    async def _replay_clicks(self, page, seed: str, trace: List,
                              next_href: str = "") -> bool:
        """Retrace by clicking the same controls, including frames and events."""
        if page is None:
            return False
        for step in replay_script(seed, trace, next_href):
            try:
                ok = await self._replay_one_step(page, step)
            except Exception:
                ok = False
            if not ok:
                return False
        return True

    async def _drain_frontier(self, page, forms_out: List[Dict],
                               urls_out: List[str], max_edges: int = 1500) -> int:
        """Retrace and take unexplored edges until the frontier empties (coverage saturation), stopping early on a long no-new-state plateau; max_edges is only a runaway safety bound."""
        taken = 0
        no_new_state = 0
        while taken < max_edges:
            edge = self.nav_graph.pop_frontier(self._visited_urls)
            if edge is None or page is None:
                break
            states_before = len(self.nav_graph.states)
            ok = await self._replay_clicks(
                page, edge.seed, list(edge.trace), edge.href,
            )
            taken += 1
            if not ok:
                continue
            try:
                page_url = page.url
            except Exception:
                continue
            self._visited_urls.add(page_url)
            urls_out.append(page_url)
            saved_trace = list(self._reach_trace)
            saved_seed = self._seed_url
            self._seed_url = edge.seed or saved_seed
            self._reach_trace = list(edge.trace) + [edge.href]
            self._reach_trace = self._reach_trace[-16:]
            try:
                state = await self._capture_page_state(page)
                await self._record_crawl_state(page, state)
                for form in state.get("forms") or []:
                    forms_out.append(self._normalize_form(form))
                for link in state.get("links") or []:
                    if link:
                        urls_out.append(link)
                self._note_frontier(state)
            except Exception:
                pass
            self._reach_trace = saved_trace
            self._seed_url = saved_seed
            if len(self.nav_graph.states) > states_before:
                no_new_state = 0
            else:
                no_new_state += 1
                if no_new_state >= 60:
                    break
        return taken

    def _probe_field(self, form: Dict) -> str:
        for field in form.get("inputs") or form.get("fields") or []:
            if not isinstance(field, dict):
                continue
            name = field.get("name") or ""
            itype = (field.get("type") or "text").lower()
            if not name or itype in ("hidden", "submit", "button", "password", "file"):
                continue
            return name
        return ""

    def _form_has_csrf_token(self, form: Dict) -> bool:
        for field in form.get("inputs") or form.get("fields") or []:
            if not isinstance(field, dict):
                continue
            name = (field.get("name") or "").lower()
            if any(k in name for k in ("csrf", "token", "nonce", "authenticity")):
                return True
        return False

    async def _replay_probe_forms(self, page, forms: List[Dict],
                                   max_forms: int = 5) -> int:
        """Replay the path to a form, then confirm XSS/SQLi/CSRF in the browser."""
        from .interstate_tracker import rank_forms
        from .vulnerability_tester import _sqli_error_match

        if page is None:
            return 0
        ranked = rank_forms(forms or [], self.taint.flows)
        probed = 0
        seen_actions: Set[str] = set()
        for form in ranked:
            if probed >= max_forms:
                break
            plan = iter_xss_fields(form.get("inputs") or form.get("fields") or [])
            action = form.get("action") or ""
            if not plan or not action or action in seen_actions:
                continue
            seen_actions.add(action)
            field = next((name for phase, name, _typ in plan if phase == "safe"), plan[0][1])
            seed = form.get("seed_url") or self._seed_url or ""
            trace = list(form.get("reach_trace") or [])
            frame = form.get("frame") or ""
            await self._replay_clicks(page, seed, trace)
            if not await self._open_form_if_missing(page, action, plan[0][1]):
                continue
            probed += 1
            self.nav_graph.replay_probes += 1
            confirmed = False
            saw_safe = any(phase == "safe" for phase, _name, _typ in plan)
            safe_tried = False
            for phase, name, itype in plan:
                if phase == "aggressive" and confirmed:
                    continue
                if phase == "aggressive" and saw_safe and not safe_tried:
                    continue
                if phase == "safe":
                    safe_tried = True
                if phase == "aggressive":
                    await self._replay_clicks(page, seed, trace)
                    await self._open_form_if_missing(page, action, name)
                marker = self.taint.make_token()
                await self._arm_xss_oracle(page)
                posted = await self._submit_typed_field(
                    page, name, itype, xss_oracle_payload(marker), frame,
                )
                if not posted:
                    continue
                fired = await self._xss_fired(page, marker)
                html = ""
                if not fired:
                    try:
                        html = await page.content()
                    except Exception:
                        html = ""
                if fired:
                    confirmed = True
                    self._remember_crawl_finding({
                        "type": "Reflected XSS",
                        "severity": "High",
                        "status": "Confirmed",
                        "location": action,
                        "parameter": name,
                        "details": (
                            "Replayed the crawl path and the in-page xss() oracle "
                            f"ran from the {phase} field {name}."
                        ),
                        "poc": f"replay {len(trace)} step(s); FILL {name} at {action}",
                        "cwe": "CWE-79",
                        "impact": "Script execution after reaching the form through the UI.",
                        "remediation": "Encode output and validate input at this sink.",
                        "confidence": "High",
                        "category": "vulnerability",
                        "evidence": {
                            "request": f"REPLAY {seed} steps={len(trace)} {name}",
                            "response_status": 200,
                            "response_body_snippet": f"xss({marker})",
                            "response_headers": {},
                            "payload_reflected": True,
                            "verified": True,
                            "confidence": "High",
                            "confirmation_method": "js_execution_after_replay",
                            "field_phase": phase,
                            "reach_trace": trace,
                        },
                    })
                    break
                if stored_xss_breakout(html, marker):
                    self._remember_crawl_finding({
                        "type": "Reflected XSS",
                        "severity": "High",
                        "status": "Potential",
                        "location": action,
                        "parameter": name,
                        "details": (
                            "After replaying the crawl path, XSS markup was present "
                            "unescaped, without script execution in this pass."
                        ),
                        "poc": f"replay to {action}; FILL {name}",
                        "cwe": "CWE-79",
                        "impact": "Markup reaches the page after UI navigation.",
                        "remediation": "Encode output at the sink.",
                        "confidence": "Medium",
                        "category": "vulnerability",
                        "evidence": {
                            "request": f"REPLAY {action} {name}",
                            "response_status": 200,
                            "response_body_snippet": marker,
                            "response_headers": {},
                            "payload_reflected": True,
                            "verified": False,
                            "confidence": "Medium",
                            "confirmation_method": "dom_reflection_after_replay",
                            "field_phase": phase,
                            "reach_trace": trace,
                        },
                    })
                    break
            await self._replay_clicks(page, seed, trace)
            if not await self._open_form_if_missing(page, action, field):
                continue
            quoted = await self._submit_named_field(page, field, "'")
            if quoted:
                body = ""
                try:
                    body = await page.content()
                except Exception:
                    body = ""
                err = _sqli_error_match(body)
                if err:
                    self._remember_crawl_finding({
                        "type": "SQL Injection",
                        "severity": "High",
                        "status": "Confirmed",
                        "location": action,
                        "parameter": field,
                        "details": (
                            f"Replayed the crawl path and a single quote produced "
                            f"a SQL error ({err})."
                        ),
                        "poc": f"replay to {action}; FILL {field}='",
                        "cwe": "CWE-89",
                        "impact": "Database error after the same UI path used for XSS.",
                        "remediation": "Use parameterized queries.",
                        "confidence": "High",
                        "category": "vulnerability",
                        "evidence": {
                            "request": f"REPLAY {action} {field}='",
                            "response_status": 200,
                            "response_body_snippet": err,
                            "response_headers": {},
                            "payload_reflected": False,
                            "verified": True,
                            "confidence": "High",
                            "confirmation_method": "sql_error_after_replay",
                            "reach_trace": trace,
                        },
                    })
            method = (form.get("method") or "get").lower()
            action_l = action.lower()
            state_changing = method == "post" and any(
                k in action_l for k in (
                    "password", "transfer", "delete", "admin", "checkout",
                    "profile", "update", "account", "order", "settings",
                )
            )
            if state_changing and not self._form_has_csrf_token(form):
                self._remember_crawl_finding({
                    "type": "Missing CSRF Protection",
                    "severity": "Medium",
                    "status": "Potential",
                    "location": action,
                    "parameter": field,
                    "details": (
                        "State-changing form reached by replaying the crawl path "
                        "has no hidden CSRF token."
                    ),
                    "poc": f"replay {len(trace)} step(s) to {action}",
                    "cwe": "CWE-352",
                    "impact": "The same replayed surface lacks a CSRF token.",
                    "remediation": "Require a per-session CSRF token and SameSite cookies.",
                    "confidence": "Medium",
                    "category": "vulnerability",
                    "evidence": {
                        "request": f"REPLAY {action}",
                        "response_status": 200,
                        "response_body_snippet": "no csrf token on replayed form",
                        "response_headers": {},
                        "payload_reflected": False,
                        "verified": False,
                        "confidence": "Medium",
                        "confirmation_method": "replayed_form",
                        "reach_trace": trace,
                    },
                })
        return probed

    async def deep_crawl(self, tasks: List[Dict], base_url: str,
                         max_tasks: int = 15,
                         max_steps_per_task: int = 15,
                         verbose: bool = False) -> Dict:
        """Run the coverage-based deep crawl on a subprocess-capable loop."""
        return await _run_browser_coro(self._deep_crawl_impl(
            tasks, base_url, max_tasks=max_tasks,
            max_steps_per_task=max_steps_per_task, verbose=verbose))

    async def _deep_crawl_impl(self, tasks: List[Dict], base_url: str,
                         max_tasks: int = 15,
                         max_steps_per_task: int = 15,
                         verbose: bool = False) -> Dict:
        """Execute every task, then drain the navigation frontier to coverage saturation (Black Widow / YuraScanner style, no time budget)."""
        all_forms: List[Dict] = []
        all_urls: List[str] = [base_url]
        tasks_executed = 0

        session_ok = await self.start_deep_session(base_url)
        tasks_with_progress = 0
        try:
            for task in tasks[:max_tasks]:
                urls_before = len(self._visited_urls) + len(self._network_apis)
                result = await self.execute_task(
                    task, base_url,
                    max_steps=max_steps_per_task,
                    reuse_session=session_ok,
                )
                all_forms.extend(result.get("forms") or [])
                all_urls.extend(result.get("urls") or [])
                all_urls.extend(result.get("api_urls") or [])
                tasks_executed += 1
                urls_after = len(self._visited_urls) + len(self._network_apis)
                progressed = urls_after > urls_before or bool(result.get("forms"))
                if progressed:
                    tasks_with_progress += 1
                if verbose:
                    print(
                        f"   Deep task {tasks_executed}: "
                        f"{result.get('task')} → "
                        f"{len(result.get('urls') or [])} urls, "
                        f"{len(result.get('forms') or [])} forms, "
                        f"{len(result.get('api_urls') or [])} apis"
                        f"{'' if progressed else ' [no new surface]'}"
                    )
            if session_ok and self._page is not None and self.nav_graph.frontier:
                n_edges = await self._drain_frontier(self._page, all_forms, all_urls)
                if verbose and n_edges:
                    print(f"   Graph frontier: {n_edges} unexplored edge(s) retraced")
            if session_ok and self._page is not None and all_forms:
                n_probe = await self._replay_probe_forms(self._page, all_forms, max_forms=5)
                if verbose and n_probe:
                    print(f"   Replay probes: {n_probe} form(s) after action trace")
            if session_ok and self._page is not None and self.taint.sources:
                n_obs = await self._revisit_for_taint(
                    self._page, all_urls,
                    max_pages=scan_limits.scan_taint_revisit_pages(),
                )
                if verbose and n_obs:
                    print(f"   Inter-state revisit: {n_obs} page(s) re-scanned")
        finally:
            api_snapshot = sorted(self._network_apis)
            await self.close_deep_session()

        all_urls.extend(api_snapshot)
        return {
            "forms": all_forms,
            "urls": all_urls,
            "api_urls": api_snapshot,
            "tasks_executed": tasks_executed,
            "tasks_with_progress": tasks_with_progress,
            "nav_graph": self.nav_graph.to_dict(),
            "interstate": self.taint.to_dict(),
            "crawl_findings": list(self.crawl_findings),
            "paper_coverage": paper_coverage_row(
                self.nav_graph.summary(), self.crawl_findings,
            ),
        }

    async def execute_task(self, task: Dict, base_url: str,
                           max_steps: int = 15,
                           reuse_session: bool = False) -> Dict:
        """Bridge the task run onto a subprocess-capable loop."""
        return await _run_browser_coro(self._execute_task_impl(
            task, base_url, max_steps=max_steps, reuse_session=reuse_session))

    async def _execute_task_impl(self, task: Dict, base_url: str,
                           max_steps: int = 15,
                           reuse_session: bool = False) -> Dict:
        """Execute one task over a shared session, collecting forms/URLs at every visited state."""
        task_name = task.get("name") or task.get("task", "unknown")
        url       = task.get("url") or base_url
        if self._session_base and not self._in_scope(url):
            url = base_url
        # Never let the crawl navigate to a logout endpoint while authenticated;
        # it would drop the shared session. Redirect such tasks to the base URL.
        if _auth.any_active() and _auth.is_logout_url(url):
            url = base_url
        self._current_task_name = task_name

        if not self._has_playwright:
            page_data = await self._urllib_capture(url)
            forms     = [
                self._normalize_form(e)
                for e in page_data["elements"] if e.get("type") == "form"
            ]
            links     = [e["href"] for e in page_data["elements"]
                         if e.get("type") == "link" and e.get("href")]
            return {
                "task":  task_name,
                "url":   url,
                "forms": forms,
                "urls":  links,
                "html":  page_data["html"]
            }

        discovered_forms: List[Dict] = []
        discovered_urls:  Set[str]   = {url}
        owns_session = False
        urls_seen_this_task: Set[str] = {url}

        try:
            if reuse_session and self._page is not None:
                page = self._page
            else:
                from playwright.async_api import async_playwright
                self._pw = await async_playwright().start()
                self._browser = await self._pw.chromium.launch(
                    headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"]
                )
                self._context = await self._browser.new_context(
                    user_agent="Mozilla/5.0 (SecurityScanner/DeepCrawl)"
                )
                await _auth.prepare_context(self._context)
                await ssrf_guard.install_browser_guard(self._context)
                self._session_base = self._base_url(base_url)
                self._attach_network_listener()
                page = await self._context.new_page()
                self._page = page
                owns_session = True

            await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            await self._wait_after_nav(page, 1100)
            self.browser_launch_ok = True
            self.action_history = []
            self._seed_url = url
            self._reach_trace = []

            prev_nav = None
            for step in range(max_steps):
                state = await self._capture_page_state(page)
                page_url = page.url
                discovered_urls.add(page_url)
                self._visited_urls.add(page_url)
                urls_seen_this_task.add(page_url)

                for form in state.get("forms") or []:
                    nf = self._normalize_form(form)
                    if self._in_scope(nf.get("action") or page_url):
                        discovered_forms.append(nf)
                for link in state.get("links") or []:
                    if link and self._in_scope(link):
                        discovered_urls.add(link)

                nav_state, _hits = await self._record_crawl_state(page, state)
                self._note_frontier(state)
                if prev_nav is not None and self.action_history:
                    last = self.action_history[-1]
                    last_cmd = (last.get("action") or {}).get("command") or ""
                    if last.get("success") and last_cmd:
                        self.nav_graph.add_edge(
                            prev_nav, nav_state,
                            command=last_cmd,
                            task=task_name,
                            reasoning=(last.get("action") or {}).get("reasoning") or "",
                        )
                prev_nav = nav_state

                action = await self._select_crawl_action(
                    task_name, state, self.action_history
                )

                if action.get("command") == "STOP":
                    break

                success = await self._execute_action(page, action, state)
                self.action_history.append({
                    "step":    step + 1,
                    "action":  action,
                    "success": success
                })

                if not success:
                    alt = self._graph_next_action(
                        task_name, state, self.action_history
                    )
                    if alt.get("command") == "STOP":
                        alt = self._heuristic_next_action(
                            task_name, state, self.action_history
                        )
                    if alt.get("command") == "STOP":
                        break
                    success = await self._execute_action(page, alt, state)
                    self.action_history.append({
                        "step": step + 1,
                        "action": alt,
                        "success": success,
                    })
                    if not success:
                        break
                    action = alt

                if success and action.get("command") == "CLICK":
                    href = self._action_href(action, state)
                    label = str(action.get("text") or action.get("target") or "")[:80]
                    frame = str(action.get("frame") or "")
                    packed = pack_replay_step(href or "", label, frame)
                    if packed:
                        self._reach_trace.append(packed)
                        self._reach_trace = self._reach_trace[-16:]

                if success and (action.get("command") == "FILL_FORM") and self.taint.sources:
                    await self._revisit_for_taint(
                        page, list(discovered_urls), max_pages=4,
                    )

                for api in list(self._network_apis):
                    discovered_urls.add(api)

        except Exception as e:
            if self.browser_launch_ok is None:
                self.browser_launch_ok = False
            logger.warning(f"execute_task failed for '{task_name}': {e}")
        finally:
            if owns_session:
                await self.close_deep_session()

        api_urls = [u for u in discovered_urls if self._is_harvestable_api_url(u)]

        return {
            "task":  task_name,
            "url":   url,
            "forms": discovered_forms,
            "urls":  list(discovered_urls),
            "api_urls": api_urls,
            "html":  "",
            "progressed": len(urls_seen_this_task) > 1 or len(discovered_forms) > 0,
        }

    async def _revisit_for_taint(self, page, extra_urls: List[str],
                                  max_pages: int = 8) -> int:
        """Re-open other pages after a write and scan them for planted tokens."""
        if page is None or not self.taint.sources:
            return 0
        current = ""
        try:
            current = page.url
        except Exception:
            current = ""
        targets = self._revisit_candidates(list(extra_urls or []), current, max_pages)
        scanned = 0
        new_flows = []
        for url in targets:
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                await self._wait_after_nav(page, 500)
                state = await self._capture_page_state(page)
                _nav, hits = await self._record_crawl_state(page, state)
                new_flows.extend(h for h in hits if not h.escaped)
                scanned += 1
            except Exception:
                continue
        if new_flows:
            await self._confirm_stored_flows(page, new_flows)
        return scanned

    async def _arm_xss_oracle(self, page) -> None:
        try:
            await page.evaluate(XSS_ORACLE_SOURCE)
        except Exception:
            return

    async def _xss_fired(self, page, marker: str) -> bool:
        title = ""
        hit = ""
        try:
            title = await page.title()
        except Exception:
            title = ""
        try:
            hit = await page.evaluate("() => String(window.__xss_hit || '')")
        except Exception:
            hit = ""
        return stored_xss_executed(title, marker) or stored_xss_executed(hit, marker)

    def _name_selector(self, field_name: str) -> str:
        safe = (field_name or "").replace("\\", "\\\\").replace('"', '\\"')
        return f'[name="{safe}"]'

    async def _open_form_if_missing(self, page, action: str, field_name: str) -> bool:
        """True when the named control is on the page. URL open is the fallback."""
        selector = self._name_selector(field_name)
        try:
            if await page.locator(selector).count():
                return True
        except Exception:
            return False
        if not action.startswith(("http://", "https://")):
            return False
        try:
            await page.goto(action, wait_until="domcontentloaded", timeout=15000)
            await self._wait_after_nav(page, 400)
        except Exception:
            return False
        try:
            return bool(await page.locator(selector).count())
        except Exception:
            return False

    def _field_root(self, page, frame_url: str):
        if not frame_url:
            return page
        for frame in page.frames:
            if frame.url and frame_url in frame.url:
                return frame
        return page

    async def _submit_typed_field(self, page, name: str, itype: str,
                                   value: str, frame_url: str = "") -> bool:
        root = self._field_root(page, frame_url)
        kind = (itype or "text").lower()
        if kind == "file":
            return await self._submit_file_field(root, name, value)
        if kind in ("hidden", "select", "select-one", "select-multiple", "radio", "checkbox"):
            return await self._submit_dom_field(root, name, kind, value)
        return await self._submit_named_field(root, name, value)

    async def _submit_dom_field(self, root, name: str, itype: str, value: str) -> bool:
        try:
            ok = await root.evaluate(
                """([name, value, itype]) => {
                    const el = document.querySelector('[name="' + CSS.escape(name) + '"]');
                    if (!el) return false;
                    if (String(itype).indexOf('select') === 0) {
                        const opt = document.createElement('option');
                        opt.value = value;
                        opt.text = value;
                        el.appendChild(opt);
                        el.value = value;
                    } else if (itype === 'checkbox' || itype === 'radio') {
                        el.checked = true;
                        el.value = value;
                    } else {
                        el.value = value;
                    }
                    const form = el.form;
                    if (form && form.requestSubmit) form.requestSubmit();
                    else if (form) form.submit();
                    return true;
                }""",
                [name, value, itype],
            )
        except Exception:
            return False
        if not ok:
            return False
        await self._wait_after_nav(root, 500)
        return True

    async def _submit_file_field(self, root, name: str, value: str) -> bool:
        import os
        import tempfile
        path = ""
        try:
            fd, path = tempfile.mkstemp(suffix=".txt")
            os.write(fd, (value or "").encode("utf-8", "ignore"))
            os.close(fd)
            loc = root.locator(f'input[type="file"][name="{name}"]')
            await loc.first.set_input_files(path, timeout=4000)
            await root.evaluate(
                """(name) => {
                    const el = document.querySelector('input[type="file"][name="' + CSS.escape(name) + '"]');
                    const form = el && el.form;
                    if (form && form.requestSubmit) form.requestSubmit();
                    else if (form) form.submit();
                }""",
                name,
            )
            await self._wait_after_nav(root, 500)
            return True
        except Exception:
            return False
        finally:
            if path:
                try:
                    os.remove(path)
                except Exception:
                    pass

    async def _submit_named_field(self, page, field_name: str, value: str) -> bool:
        if not field_name:
            return False
        try:
            await page.fill(self._name_selector(field_name), value, timeout=3000)
        except Exception:
            return False
        try:
            submit = await page.query_selector(
                'button[type="submit"], input[type="submit"]'
            )
            if submit:
                await submit.click()
            else:
                await page.keyboard.press("Enter")
            await self._wait_after_nav(page, 800)
            return True
        except Exception:
            return False

    def _remember_crawl_finding(self, finding: Dict) -> None:
        loc = (finding.get("location") or "").rstrip("/")
        key = ((finding.get("type") or "").lower(), loc, finding.get("parameter") or "")
        if key in self._confirmed_flow_keys:
            return
        self._confirmed_flow_keys.add(key)
        self.crawl_findings.append(finding)

    async def _confirm_stored_flows(self, page, flows: List) -> None:
        """Replay the proving payload on the source, then read the sink."""
        from .vulnerability_tester import _sqli_error_match

        for flow in flows:
            src = flow.source_url or flow.source_action
            sink = flow.sink_url
            field = flow.source_field
            if not src or not sink or not field:
                continue
            marker = self.taint.make_token()
            try:
                await page.goto(src, wait_until="domcontentloaded", timeout=15000)
                await self._wait_after_nav(page, 400)
                posted = await self._submit_named_field(
                    page, field, stored_xss_payload(marker)
                )
                if not posted:
                    continue
                await page.goto(sink, wait_until="domcontentloaded", timeout=15000)
                await self._wait_after_nav(page, 600)
                title = ""
                html = ""
                try:
                    title = await page.title()
                except Exception:
                    title = ""
                try:
                    html = await page.content()
                except Exception:
                    html = ""
            except Exception:
                continue

            if stored_xss_executed(title, marker):
                self._remember_crawl_finding({
                    "type": "Stored XSS",
                    "severity": "High",
                    "status": "Confirmed",
                    "location": sink,
                    "parameter": field,
                    "details": (
                        f"Benign token from {src} field {field!r} reappeared on "
                        f"{sink}. Replaying an onload payload set document.title "
                        f"to the marker."
                    ),
                    "poc": f"POST {field} at {src}; observe title on {sink}",
                    "cwe": "CWE-79",
                    "impact": "Stored script execution in the sink page.",
                    "remediation": "Encode output at the sink; sanitize on input.",
                    "confidence": "High",
                    "category": "vulnerability",
                    "evidence": {
                        "request": f"FILL {src} {field}=<svg onload title={marker}>",
                        "response_status": 200,
                        "response_body_snippet": f"title={title!r}",
                        "response_headers": {},
                        "payload_reflected": True,
                        "verified": True,
                        "confidence": "High",
                        "confirmation_method": "js_execution",
                        "source_url": src,
                        "sink_url": sink,
                    },
                })
            elif stored_xss_breakout(html, marker):
                self._remember_crawl_finding({
                    "type": "Stored XSS",
                    "severity": "High",
                    "status": "Potential",
                    "location": sink,
                    "parameter": field,
                    "details": (
                        f"XSS markup from {src} field {field!r} is present unescaped "
                        f"on {sink}, without script execution in this pass."
                    ),
                    "poc": f"POST {field} at {src}; read HTML on {sink}",
                    "cwe": "CWE-79",
                    "impact": "Stored markup reaches another page.",
                    "remediation": "Encode output at the sink.",
                    "confidence": "Medium",
                    "category": "vulnerability",
                    "evidence": {
                        "request": f"FILL {src} {field}",
                        "response_status": 200,
                        "response_body_snippet": marker,
                        "response_headers": {},
                        "payload_reflected": True,
                        "verified": False,
                        "confidence": "Medium",
                        "confirmation_method": "dom_reflection",
                        "source_url": src,
                        "sink_url": sink,
                    },
                })

            try:
                await page.goto(src, wait_until="domcontentloaded", timeout=15000)
                await self._wait_after_nav(page, 300)
                if not await self._submit_named_field(page, field, "'"):
                    continue
                body = ""
                try:
                    body = await page.content()
                except Exception:
                    body = ""
                await page.goto(sink, wait_until="domcontentloaded", timeout=15000)
                await self._wait_after_nav(page, 400)
                try:
                    body = (body or "") + "\n" + (await page.content() or "")
                except Exception:
                    pass
                error = _sqli_error_match(body or "")
                if error:
                    self._remember_crawl_finding({
                        "type": "SQL Injection",
                        "severity": "Critical",
                        "status": "Confirmed",
                        "location": src,
                        "parameter": field,
                        "details": (
                            f"Quote probe on stored field {field!r} produced a "
                            f"database error (source {src}, sink {sink}): {error[:150]}"
                        ),
                        "poc": f"POST {field}=' at {src}",
                        "cwe": "CWE-89",
                        "impact": "Second-order SQL injection via a stored field.",
                        "remediation": "Use parameterised queries for stored values.",
                        "confidence": "High",
                        "category": "vulnerability",
                        "evidence": {
                            "request": f"FILL {src} {field}='",
                            "response_status": 200,
                            "response_body_snippet": error[:400],
                            "response_headers": {},
                            "payload_reflected": True,
                            "verified": True,
                            "confidence": "High",
                            "confirmation_method": "pattern",
                            "source_url": src,
                            "sink_url": sink,
                        },
                    })
            except Exception:
                continue

    async def _cookie_names(self) -> List[str]:
        if self._context is None:
            return []
        try:
            cookies = await self._context.cookies()
            return [c.get("name") or "" for c in cookies if c.get("name")]
        except Exception:
            return []

    async def _record_crawl_state(self, page, state: Dict):
        html = ""
        try:
            html = await page.content()
        except Exception:
            html = ""
        page_url = state.get("url") or getattr(page, "url", "") or ""
        hits = self.taint.observe(html, page_url)
        nav_state = self.nav_graph.add_state(
            url=page_url,
            forms=state.get("forms") or [],
            cookie_names=await self._cookie_names(),
            title=state.get("title") or "",
        )
        return nav_state, hits

    async def _capture_page_state(self, page) -> Dict:
        """Capture simplified page state for BRIDGE + link harvest."""
        try:
            url   = page.url
            title = await page.title()

            state = await page.evaluate("""
                () => {
                    const result = { clickables: [], forms: [], links: [] };
                    const origin = location.origin;

                    const clickSel = 'a, button, [onclick], [routerLink], '
                        + '[ng-reflect-router-link], mat-nav-list a, '
                        + 'mat-card a, .mat-mdc-button, [role="button"]';
                    const clickables = document.querySelectorAll(clickSel);
                    let idx = 0;
                    clickables.forEach((elem) => {
                        if (idx >= 40) return;
                        const style = window.getComputedStyle(elem);
                        if (style && style.display === 'none') return;
                        if (style && style.visibility === 'hidden') return;
                        let href = elem.href || '';
                        const rl = elem.getAttribute('routerLink')
                            || elem.getAttribute('ng-reflect-router-link')
                            || '';
                        if (!href && rl) {
                            const path = rl.replace(/^[\\['"]+|[\\]'",\\s]+$/g, '');
                            href = path.startsWith('/')
                                ? (origin + '/#' + path)
                                : (origin + '/#/' + path);
                        }
                        // Normalize bare hash SPA paths
                        if (href.includes('#') && !href.includes('#/')) {
                            /* keep */
                        }
                        result.clickables.push({
                            id:   idx,
                            tag:  elem.tagName.toLowerCase(),
                            text: (elem.innerText || elem.textContent || '')
                                      .trim().substring(0, 100),
                            href: href
                        });
                        idx += 1;
                    });

                    document.querySelectorAll('a[href]').forEach(a => {
                        const href = a.href || '';
                        if (href && (href.startsWith(origin) || href.startsWith('/')
                                     || href.includes('#/'))) {
                            result.links.push(href);
                        }
                    });

                    // Standalone search inputs (common in SPAs without <form>)
                    const looseSearch = document.querySelectorAll(
                        'input[type="search"], input[name="q"], input[name="query"], '
                        + 'input[placeholder*="Search" i], input[aria-label*="Search" i]'
                    );
                    if (looseSearch.length > 0) {
                        result.forms.push({
                            id: 0,
                            action: window.location.href,
                            method: 'get',
                            fields: Array.from(looseSearch).slice(0, 3).map(inp => ({
                                name:        inp.name || inp.getAttribute('aria-label') || 'q',
                                type:        inp.type || 'search',
                                placeholder: inp.placeholder || ''
                            }))
                        });
                    }

                    const forms = document.querySelectorAll('form');
                    forms.forEach((form, fidx) => {
                        const inputs = form.querySelectorAll(
                            'input, textarea, select'
                        );
                        if (inputs.length > 0) {
                            result.forms.push({
                                id:     result.forms.length,
                                action: form.action || window.location.href,
                                method: form.method || 'get',
                                fields: Array.from(inputs).map(inp => ({
                                    name:        inp.name        || '',
                                    type:        inp.type        || 'text',
                                    placeholder: inp.placeholder || ''
                                }))
                            });
                        }
                    });

                    return result;
                }
            """)

            clickables = list(state.get("clickables") or [])
            forms = list(state.get("forms") or [])
            for frame in page.frames:
                if frame == page.main_frame:
                    continue
                try:
                    framed = await frame.evaluate("""() => {
                        const clickables = [];
                        document.querySelectorAll('a, button, [onclick]').forEach(el => {
                            if (clickables.length >= 20) return;
                            const text = (el.innerText || el.value || '').trim().slice(0, 80);
                            const href = el.href || el.getAttribute('href') || '';
                            if (!text && !href) return;
                            clickables.push({text, href, tag: el.tagName});
                        });
                        const forms = [];
                        document.querySelectorAll('form').forEach(form => {
                            const fields = [];
                            form.querySelectorAll('input, textarea, select').forEach(inp => {
                                if (!inp.name) return;
                                fields.push({
                                    name: inp.name,
                                    type: (inp.tagName === 'SELECT' ? 'select' : (inp.type || 'text')).toLowerCase(),
                                });
                            });
                            forms.push({
                                action: form.action || location.href,
                                method: (form.method || 'get').toLowerCase(),
                                fields,
                            });
                        });
                        return {clickables, forms};
                    }""")
                except Exception:
                    continue
                frame_url = frame.url or ""
                for item in framed.get("clickables") or []:
                    item["frame"] = frame_url
                    clickables.append(item)
                for form in framed.get("forms") or []:
                    form["frame"] = frame_url
                    forms.append(form)

            return {
                "url":        url,
                "title":      title,
                "clickables": clickables,
                "forms":      forms,
                "links":      state.get("links", [])[:60],
            }
        except Exception as e:
            logger.debug(f"_capture_page_state failed: {e}")
            return {"url": "", "title": "", "clickables": [], "forms": [], "links": []}

    def _base_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")

    def _in_scope(self, url: str) -> bool:
        """True when a URL is on the target host (or is relative, hence same"""
        if not url:
            return False
        u = url.strip()
        # Exclude logout endpoints from scope while authenticated so the crawl
        # never follows a link or submits a form that ends the shared session.
        if _auth.any_active() and _auth.is_logout_url(u):
            return False
        if u[:1] in "#?" or (u.startswith("/") and not u.startswith("//")):
            return True
        if u.startswith("//"):
            probe = "http:" + u
        elif u.startswith(("http://", "https://")):
            probe = u
        else:
            return True
        base_host = urlsplit(self._session_base or "").netloc.lower()
        if not base_host:
            return True
        try:
            host = urlsplit(probe).netloc.lower()
        except Exception:
            return True
        return not host or host == base_host
