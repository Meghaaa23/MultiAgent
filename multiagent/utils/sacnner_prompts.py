"""
Prompts for web scanning operations (Hardened Version)
Includes strict anti-hallucination and evidence validation rules.
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

Focus on:
1. Authentication flows (login, register, logout)
2. CRUD operations explicitly visible
3. Forms and data submissions
4. File uploads (if present)
5. Access control boundaries visible in UI

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

Generate 5-15 realistic tasks maximum.
Return ONLY valid JSON.
"""

FORM_FILLING_PROMPT = """You are FormGPT, an agent that generates realistic form input data for both normal and security testing.

Form Structure:
{form}

Generate values for each field.

For each field, generate:
1. A valid realistic test value
2. A security test payload (if applicable)

Rules:
- Use format-valid values for functional testing.
- For attack payloads, use safe demonstration examples (e.g., "<script>alert(1)</script>" for XSS testing).
- Label each value clearly as either "valid_test" or "attack_test".
- If a field does not support attack vectors (e.g., dropdown with fixed values), generate only valid_test.

Output JSON:
{{
  "fields": [
    {{
      "name": "email",
      "valid_test": "test@example.com",
      "attack_test": "' OR 1=1--"
    }}
  ]
}}

Return ONLY valid JSON.
"""

VULNERABILITY_ANALYSIS_PROMPT = """You are a penetration testing expert analyzing structured test results.

Test Results:
{results}

Your task:
Identify CONFIRMED vulnerabilities only.

STRICT RULES:
- Only report a vulnerability if there is direct observable evidence.
- If exploitation is not confirmed, label as "Potential Vulnerability".
- Do NOT fabricate CVE numbers.
- Do NOT assume backend technology stack.
- If no confirmed vulnerabilities exist, explicitly state: "No confirmed vulnerabilities identified."

For each confirmed vulnerability provide:
- Type (XSS, SQLi, CSRF, etc.)
- Severity (Critical/High/Medium/Low)
- Location (URL + parameter)
- Proof of Concept (from results)
- Impact
- Remediation
- Relevant CWE (limit to 1–3 specific IDs only)

Output JSON format:
{{
  "confirmed_vulnerabilities": [],
  "potential_vulnerabilities": []
}}

Return ONLY valid JSON.
"""