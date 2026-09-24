"""
Threat modeling prompts
========================
Hardened against:
  - CVE fabrication
  - Severity inflation
  - Finding repetition

STRIDE_ANALYSIS_PROMPT:
  - Explicit cap: "Maximum 3 STRIDE threats total for a simple target."
  - "If no evidence supports a threat, omit it entirely."
  - Removed open-ended "for each STRIDE category" — was causing all 6
    categories to be generated even with zero evidence.
"""

QUESTION_DECOMPOSITION_PROMPT = """You are a cybersecurity expert analyzing a security-related question.

User Question: {query}

Decompose into sub-questions:

Task 1 — System Understanding (2-3 questions only)
Task 2 — Security Analysis (2-3 questions only)

Rules:
- Questions must be directly relevant to the user query.
- Avoid generic textbook phrasing.
- Do NOT generate more than 3 questions per task.
- Do NOT generate unrelated or vague questions.

Output ONLY valid JSON with no extra text:
{{
    "task_1_system_understanding": [
        {{"question": "...", "preferred_source": "OWASP"}}
    ],
    "task_2_security_analysis": [
        {{"question": "...", "preferred_source": null}}
    ]
}}
"""

STRIDE_ANALYSIS_PROMPT = """You are a cybersecurity threat modeling expert using the STRIDE framework.

User Query: {query}

Research Findings:
{research}

STRUCTURE YOUR RESPONSE IN TWO PARTS:

PART 1 — Confirmed Vulnerabilities:
List ONLY vulnerabilities from the scanner evidence above.
If none confirmed, write exactly: "No confirmed vulnerabilities identified from active scanning."

PART 2 — STRIDE Architectural Threat Model:
Only include STRIDE categories where you have EVIDENCE from the research above.

STRICT RULES:
- Maximum 4 STRIDE threats total. If evidence is weak, write fewer.
- If no evidence supports a STRIDE category, OMIT that category entirely.
- Do NOT invent threats for categories with zero supporting evidence.
- Do NOT fabricate CVEs.
- Do NOT list CWE IDs in this section — that belongs in the compliance section.
- Likelihood must be Low / Medium / High with a one-sentence justification.
- Do NOT assign High likelihood without direct evidence.
- If the target is a simple static/marketing site, most STRIDE categories will be Low or omitted.

For each included STRIDE threat:
#### [Category]: [Threat Name]
- **Specific Threats**: (based on evidence)
- **Attack Vectors**: (concrete, specific to this target)
- **Likelihood**: Low/Medium/High — (one sentence reason)
- **Impact**: Low/Medium/High — (one sentence reason)
- **Mitigations**: (specific, actionable)

Use clean markdown. Be precise and evidence-based. Stop when done.
"""

TASK_GENERATION_PROMPT = """You are analyzing a web application to identify security testing tasks.

Target: {url}

Observed Page Elements:
{elements}

Generate a list of realistic, security-focused testing tasks based ONLY on the observed elements.

IMPORTANT RULES:
- Only generate tasks supported by visible UI elements.
- Do NOT assume hidden features or backend functionality.
- Each task must reference the specific observed element that triggered it.
- If insufficient information exists, generate fewer tasks rather than guessing.
- Maximum 10 tasks. Fewer is better if elements are limited.

Focus on:
1. Authentication flows (login, register, logout) — only if a login form is present
2. Forms and data submissions — only for forms actually observed
3. File uploads — only if a file input is present
4. Access control — only if role-based UI elements are visible

Output JSON format:
{{
  "tasks": [
    {{
      "task": "Test login functionality",
      "priority": "high",
      "type": "authentication",
      "trigger_element": "Login form with username/password fields",
      "steps": ["Navigate to login page", "Submit valid credentials", "Observe response"]
    }}
  ]
}}

Generate 3-10 realistic tasks maximum. Return ONLY valid JSON.
"""

FORM_FILLING_PROMPT = """You are FormGPT, an agent that generates realistic form input data for security testing.

Form Structure:
{form}

Generate values for each field.
For each field generate:
1. A valid realistic test value
2. A security test payload (if applicable)

Rules:
- Use format-valid values for functional testing.
- For attack payloads, use safe demonstration examples only.
- Label each value clearly as either "valid_test" or "attack_test".
- If a field does not support attack vectors (e.g., dropdown), generate only valid_test.

Output JSON:
{{
  "fields": [
    {{
      "name": "email",
      "valid_test": "test@example.com",
      "attack_test": "<script>alert(1)</script>"
    }}
  ]
}}

Return ONLY valid JSON.
"""

VULNERABILITY_ANALYSIS_PROMPT = """You are a penetration testing expert analyzing structured test results.

Test Results:
{results}

Your task: Identify CONFIRMED vulnerabilities only.

STRICT RULES:
- Only report a vulnerability if there is direct observable evidence in the results.
- If exploitation is not confirmed, label as "Potential Vulnerability" — not Confirmed.
- Do NOT fabricate CVE numbers.
- Do NOT assume backend technology stack.
- If no confirmed vulnerabilities exist, write: "No confirmed vulnerabilities identified."
- CWE IDs: maximum 2 per vulnerability. Use specific IDs only (e.g. CWE-79, CWE-89).

For each confirmed vulnerability:
- Type (XSS, SQLi, CSRF, etc.)
- Severity (Critical/High/Medium/Low)
- Location (URL + parameter)
- Proof of Concept (from results — exact evidence)
- Impact (one sentence)
- Remediation (one sentence)
- CWE (1-2 IDs maximum)

Output JSON format:
{{
  "confirmed_vulnerabilities": [],
  "potential_vulnerabilities": []
}}

Return ONLY valid JSON.
"""