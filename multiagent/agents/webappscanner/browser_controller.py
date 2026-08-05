# agents/browser_controller.py

import asyncio
import json
import re
import logging
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse, urljoin, urlsplit

logger = logging.getLogger(__name__)


class BrowserController:
 

    def __init__(self, openai_client, llm_model: str = "Qwen-2.5"):
        self.openai_client  = openai_client
        self.llm_model      = llm_model
        self.action_history: List[Dict] = []

        try:
            from playwright.async_api import async_playwright  # noqa: F401
            self._has_playwright = True
            print(" Browser Controller initialized (Playwright)")
        except ImportError:
            self._has_playwright = False
            logger.warning("Playwright not installed — using urllib fallback")
            print(" Browser Controller initialized (urllib fallback)")

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
                page = await browser.new_page()
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
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (SecurityScanner)"}
            )
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
                             target_url: str = "") -> List[Dict]:
      
       
        filtered = [
            e for e in elements
            if e.get("type") in ("form", "link")
        ]

        if not filtered:
         
            filtered = [{"type": "link", "href": target_url}]

        
        chunk_size  = 50
        max_chunks  = 6
        chunks      = [
            filtered[i:i + chunk_size]
            for i in range(0, len(filtered), chunk_size)
        ][:max_chunks]

        all_tasks: List[Dict] = []

        for idx, chunk in enumerate(chunks, 1):
            prompt = f"""You are a web security tester analyzing a web application.

URL: {target_url}
UI Elements (chunk {idx}/{len(chunks)}):
{self._format_ui_elements(chunk)}

Generate 3-5 realistic security testing tasks for this section of the UI.
Focus on:
- CRUD operations (Create, Read, Update, Delete)
- Authentication and session workflows
- Form submission and input handling
- Data manipulation and access control

Each task must include a specific URL to navigate to.

Respond with JSON only — no explanation:
{{
    "tasks": [
        {{
            "name":        "Login to application",
            "description": "Test login form for injection and auth bypass",
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
                    max_tokens=800
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

        # Deterministic fallback when LLM returns nothing — still crawl real surfaces
        if not unique:
            unique = self._deterministic_tasks(filtered, target_url)

        return unique[:15]

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

        prompt = f"""You are Yura, an agent controlling a web browser.

Task: {task}

Current Page:
{state_text}

Previous Actions:
{history_text}

Commands available:
  CLICK      {{id}} — click element
  FILL_FORM  {{id}} — fill and submit form
  STOP            — task complete or impossible

Decide the next action.

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
                    text = clickables[target_id].get("text", "")[:50]
                    if text:
                        await page.get_by_text(text, exact=False).first.click(
                            timeout=5000
                        )
                        return True
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
                        'button[type="submit"], input[type="submit"]'
                    )
                    if submit:
                        await submit.click()
                    return True
                return False

            elif command == "STOP":
                return True

        except Exception as e:
            logger.debug(f"Actuator failed: {e}")

        return False

    def _dummy_value(self, field_name: str, field_type: str) -> str:
        """Generate benign dummy value for a form field."""
        n = field_name.lower()
        if "email"    in n or field_type == "email":    return "test@example.com"
        if "password" in n or field_type == "password": return "TestPassword123!"
        if "user"     in n or "login"    in n:          return "testuser"
        if "name"     in n:                             return "Test User"
        if "phone"    in n or "tel"      in n:          return "555-0123"
        if "url"      in n or "website"  in n:          return "https://example.com"
        if field_type == "number":                      return "42"
        if field_type == "date":                        return "2024-01-01"
        return "test"

    # ==================================================================
    # Full task execution loop  (SENSORS → BRIDGE → ACTUATORS)
    # ==================================================================

    async def execute_task(self, task: Dict, base_url: str) -> Dict:
        """
        Execute a task and collect discovered forms/URLs.

        Compatible with both the original API (task["task"]) and the
        new API (task["name"]).
        """
        task_name = task.get("name") or task.get("task", "unknown")
        url       = task.get("url") or base_url

        if not self._has_playwright:
            # urllib fallback: just capture the page
            page_data = await self._urllib_capture(url)
            forms     = [e for e in page_data["elements"] if e["type"] == "form"]
            links     = [e["href"] for e in page_data["elements"]
                         if e["type"] == "link"]
            return {
                "task":  task_name,
                "url":   url,
                "forms": forms,
                "urls":  links,
                "html":  page_data["html"]
            }

        from playwright.async_api import async_playwright

        discovered_forms: List[Dict] = []
        discovered_urls:  Set[str]   = {url}

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=True, args=["--no-sandbox"]
                )
                page = await browser.new_page()
                await page.goto(url, wait_until="domcontentloaded", timeout=30000)
                self.action_history = []

                for step in range(10):  # max 10 steps per task
                    state = await self._capture_page_state(page)

                    if state.get("forms"):
                        discovered_forms.extend(state["forms"])
                    discovered_urls.add(page.url)

                    action = await self._decide_next_action(
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
                    await page.wait_for_timeout(1000)

                    if not success:
                        break

                await browser.close()

        except Exception as e:
            logger.warning(f"execute_task failed for '{task_name}': {e}")

        return {
            "task":  task_name,
            "url":   url,
            "forms": discovered_forms,
            "urls":  list(discovered_urls),
            "html":  ""
        }

    # ==================================================================
    # SENSORS helper — page state capture
    # ==================================================================

    async def _capture_page_state(self, page) -> Dict:
        """Capture simplified page state for BRIDGE."""
        try:
            url   = page.url
            title = await page.title()

            state = await page.evaluate("""
                () => {
                    const result = { clickables: [], forms: [] };

                    const clickables = document.querySelectorAll('a, button, [onclick]');
                    clickables.forEach((elem, idx) => {
                        if (elem.offsetParent !== null && idx < 20) {
                            result.clickables.push({
                                id:   idx,
                                tag:  elem.tagName.toLowerCase(),
                                text: (elem.innerText || elem.textContent || '')
                                          .trim().substring(0, 100),
                                href: elem.href || ''
                            });
                        }
                    });

                    const forms = document.querySelectorAll('form');
                    forms.forEach((form, idx) => {
                        const inputs = form.querySelectorAll(
                            'input:not([type="hidden"]), textarea, select'
                        );
                        if (inputs.length > 0) {
                            result.forms.push({
                                id:     idx,
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
                "forms":      state.get("forms", [])
            }
        except Exception as e:
            logger.debug(f"_capture_page_state failed: {e}")
            return {"url": "", "title": "", "clickables": [], "forms": []}

    # ==================================================================
    # Utility
    # ==================================================================

    def _base_url(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")