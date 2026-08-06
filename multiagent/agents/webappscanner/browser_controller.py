# agents/browser_controller.py

import asyncio
import json
import re
import logging
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse, urljoin, urlsplit

logger = logging.getLogger(__name__)


class BrowserController:
    """
    Yura-style browser agent: task extraction → multi-step execution → surface collection.

    Deep crawl keeps one anonymous Playwright context across tasks, harvesting
    forms/links at every step. Black-box unauthenticated only — no login/creds.
    """

    def __init__(self, openai_client, llm_model: str = "Qwen-2.5"):
        self.openai_client  = openai_client
        self.llm_model      = llm_model
        self.action_history: List[Dict] = []

        # Shared deep-crawl Playwright session (one browser across tasks)
        self._pw = None
        self._browser = None
        self._context = None
        self._page = None
        self._session_base: str = ""
        self._visited_urls: Set[str] = set()
        # Same-host XHR/fetch/API URLs observed during Playwright navigation
        self._network_apis: Set[str] = set()

        try:
            from playwright.async_api import async_playwright  # noqa: F401
            self._has_playwright = True
            print(" Browser Controller initialized (Playwright)")
        except ImportError:
            self._has_playwright = False
            logger.warning("Playwright not installed — using urllib fallback")
            print(" Browser Controller initialized (urllib fallback)")

    # ------------------------------------------------------------------
    # Network API harvest (public surface reach)
    # ------------------------------------------------------------------

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
        # Skip static assets
        if re.search(
            r"\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|webp)(\?|$)", path
        ):
            return False
        if any(h in path for h in self._API_PATH_HINTS):
            return True
        # Any same-host URL with query params is potentially injectable
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
                        # Strip fragments; keep query for injectables
                        clean = url.split("#", 1)[0]
                        self._network_apis.add(clean)
            except Exception:
                pass

        try:
            self._context.on("request", _on_request)
        except Exception as e:
            logger.debug("network listener attach failed: %s", e)


    # ==================================================================
    # SENSORS — page capture
    # ==================================================================

    async def capture_page(self, url: str) -> Dict:
        """
        Capture page HTML and interactive elements.

        Returns
        -------
        {
            "html":     str,
            "elements": List[Dict],   # forms + links
            "url":      str
        }
        """
        if self._has_playwright:
            return await self._playwright_capture(url)
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
                page = await context.new_page()
                await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                await page.wait_for_timeout(2000)  # wait for JS

                html     = await page.content()
                elements = await self._extract_elements_playwright(page)

                await browser.close()
                return {"html": html, "elements": elements, "url": url}
        except Exception as e:
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
        """
        SENSORS: extract interactive elements via Playwright JS evaluation.
        Returns both clickables (for BRIDGE) and forms (for vulnerability testing).
        """
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

                    // Forms
                    const forms = document.querySelectorAll('form');
                    forms.forEach((form, idx) => {
                        const inputs = form.querySelectorAll(
                            'input:not([type="hidden"]), textarea, select'
                        );
                        if (inputs.length > 0) {
                            result.push({
                                type:   'form',
                                tag:    'form',
                                id:     form.id || `form-${idx}`,
                                action: form.action  || '',
                                method: form.method  || 'get',
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

        # Forms — handle both attribute orderings
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
                action = base_url  # empty action posts to current page
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

        # All same-host links (not only query-string URLs)
        base_host = urlsplit(base_url).netloc if base_url else ""
        for href in re.findall(r'href=["\']([^"\'#]+)["\']', html, re.I):
            if href.lower().startswith(("javascript:", "mailto:", "data:")):
                continue
            full = urljoin(base_url, href) if not href.startswith("http") else href
            if base_host and urlsplit(full).netloc not in ("", base_host):
                continue
            elements.append({"type": "link", "href": full})

        return elements

    # =================
    # TASK GENERATION 
    # =================

    def _format_ui_elements(self, elements: List[Dict]) -> str:
        """
        Compact, token-efficient representation of UI elements for LLM prompt.
        Much cheaper than json.dumps() on the full element list.
        """
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
        # Deep crawl needs clickables (menus/nav) as well as forms/links
        filtered = [
            e for e in elements
            if e.get("type") in ("form", "link", "clickable")
        ]

        if not filtered:
            filtered = [{"type": "link", "href": target_url}]

        chunk_size  = 50
        max_chunks  = 8 if deep else 6
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
- CRUD-shaped form submission on anonymous surfaces
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

        # Always merge deterministic coverage tasks (links/forms) for depth
        for t in self._deterministic_tasks(filtered, target_url):
            name = (t.get("name") or "").strip().lower()
            if name and name not in seen:
                seen.add(name)
                unique.append(t)


        return unique[:(20 if deep else 15)]

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
                _add(
                    f"Submit {method} form {action}",
                    action,
                    "Exercise form inputs for injection and auth testing",
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

    # ==================================================================
    # BRIDGE — LLM decision-making
    # ==================================================================

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

    # ==================================================================
    # ACTUATORS — action execution
    # ==================================================================

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
        """
        ACTUATORS: execute a BRIDGE decision on the Playwright page.
        Returns True on success, False on failure.
        """
        command   = action.get("command", "")
        target_id = action.get("target_id", 0)

        try:
            if command == "CLICK":
                clickables = state.get("clickables", [])
                if target_id < len(clickables):
                    target = clickables[target_id]
                    text = (target.get("text") or "")[:50]
                    href = (target.get("href") or "").strip()
                    # Prefer direct navigation for hash/router SPA links
                    if href and (
                        "#/" in href
                        or href.startswith(self._session_base or "http")
                    ):
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
                    # Fallback: click by index among visible anchors/buttons
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
                        value = self._dummy_value(name, field.get("type", "text"))
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

    def _dummy_value(self, field_name: str, field_type: str) -> str:
        """Generate benign dummy value for form fields (unauthenticated probe)."""
        n = field_name.lower()
        if "password" in n or field_type == "password":
            return "TestPassword123!"
        if "email" in n or field_type == "email":
            return "test@example.com"
        if any(k in n for k in ("user", "login", "account", "name")):
            return "testuser"
        if "phone" in n or "tel" in n:
            return "555-0123"
        if "url" in n or "website" in n:
            return "https://example.com"
        if field_type == "number":
            return "42"
        if field_type == "date":
            return "2024-01-01"
        return "test"

    # ==================================================================
    # Deep-crawl session (shared Playwright context across tasks)
    # ==================================================================

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
            self._session_base = self._base_url(base_url)
            self._visited_urls = set()
            self._network_apis = set()
            self._attach_network_listener()
            self._page = await self._context.new_page()
            return True
        except Exception as e:
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
        return {
            "type":   "form",
            "action": form.get("action") or "",
            "method": (form.get("method") or "get"),
            "fields": fields,
            "inputs": fields,
            "route":  form.get("action") or "",
            "id":     form.get("id"),
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
                # Task alignment only counts when the link itself matches
                if task_l and kw in task_l:
                    score += 3
        # SPA hash routes and router links are high value
        if "#/" in h or "router" in h:
            score += 2
        if h and h not in self._visited_urls:
            score += 1
        return score

    def _heuristic_next_action(self, task: str, state: Dict,
                                history: List[Dict]) -> Dict:
        """
        Deterministic fallback when the LLM stops early or fails.
        Rank unvisited same-host links; exercise forms when useful.
        """
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
            # Allow hash SPA routes (#/search); skip empty/js/mailto
            if not href or href.startswith(("javascript:", "mailto:")):
                # Still allow buttons with no href (text click)
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
            # Prefer search-like forms over random
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

    async def deep_crawl(self, tasks: List[Dict], base_url: str,
                         max_tasks: int = 15,
                         max_steps_per_task: int = 15,
                         time_budget_seconds: float = 0,
                         verbose: bool = False) -> Dict:
        """
        Yura-style deep crawl: one shared session, multi-step tasks,
        collect forms/URLs from every visited state.
        """
        all_forms: List[Dict] = []
        all_urls: List[str] = [base_url]
        tasks_executed = 0
        started = asyncio.get_event_loop().time()

        session_ok = await self.start_deep_session(base_url)
        tasks_with_progress = 0
        try:
            for task in tasks[:max_tasks]:
                if time_budget_seconds and (
                    asyncio.get_event_loop().time() - started
                ) > time_budget_seconds:
                    if verbose:
                        print("  Deep-crawl time budget reached")
                    break
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
        }

    # ==================================================================
    # Full task execution loop  (SENSORS → BRIDGE → ACTUATORS)
    # ==================================================================

    async def execute_task(self, task: Dict, base_url: str,
                           max_steps: int = 15,
                           reuse_session: bool = False) -> Dict:
        """
        Execute a task and collect discovered forms/URLs at every step.
        When reuse_session=True, uses the shared deep-crawl context.
        """
        task_name = task.get("name") or task.get("task", "unknown")
        url       = task.get("url") or base_url

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
                self._session_base = self._base_url(base_url)
                self._attach_network_listener()
                page = await self._context.new_page()
                self._page = page
                owns_session = True

            await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            await self._wait_after_nav(page, 1100)
            self.action_history = []

            for step in range(max_steps):
                state = await self._capture_page_state(page)
                page_url = page.url
                discovered_urls.add(page_url)
                self._visited_urls.add(page_url)
                urls_seen_this_task.add(page_url)

                for form in state.get("forms") or []:
                    discovered_forms.append(self._normalize_form(form))
                for link in state.get("links") or []:
                    if link:
                        discovered_urls.add(link)

                action = await self._decide_next_action(
                    task_name, state, self.action_history
                )
                # Override early STOP whenever unexplored surface remains
                if action.get("command") == "STOP":
                    alt = self._heuristic_next_action(
                        task_name, state, self.action_history
                    )
                    if alt.get("command") != "STOP":
                        action = alt
                    elif step < max(3, max_steps // 2):
                        # Force one more heuristic attempt early in the task
                        action = alt

                if action.get("command") == "STOP":
                    break

                success = await self._execute_action(page, action, state)
                self.action_history.append({
                    "step":    step + 1,
                    "action":  action,
                    "success": success
                })

                # Soft-fail: try heuristic next instead of aborting the task
                if not success:
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

                # Fold newly observed network APIs into this task's URL set
                for api in list(self._network_apis):
                    discovered_urls.add(api)

        except Exception as e:
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

    # ==================================================================
    # SENSORS helper — page state capture
    # ==================================================================

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
                            'input:not([type="hidden"]), textarea, select'
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

            return {
                "url":        url,
                "title":      title,
                "clickables": state.get("clickables", []),
                "forms":      state.get("forms", []),
                "links":      state.get("links", [])[:60],
            }
        except Exception as e:
            logger.debug(f"_capture_page_state failed: {e}")
            return {"url": "", "title": "", "clickables": [], "forms": [], "links": []}

    # ==================================================================
    # Utility
    # ==================================================================

    def _base_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")