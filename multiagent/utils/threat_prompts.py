# utils/threat_prompts.py

QUESTION_DECOMPOSITION_PROMPT = """
You are a cybersecurity expert analyzing security questions.

TASK: Break down the following security question into structured sub-questions for research.

USER QUESTION: {query}

Create two types of questions:
1. TASK 1 - System Understanding (2-3 questions): Questions about the system/technology itself
2. TASK 2 - Security Analysis (3-4 questions): Questions about vulnerabilities, attacks, and mitigations

For each question, specify a preferred source:
- CISA: For practical operational guidance, known vulnerabilities, mitigations
- IEEE: For academic research, novel attacks, experimental findings
- Intel_TDX: For Intel confidential computing specifics
- OWASP: For web application security

Return ONLY valid JSON in this exact format:
{{
    "main_topic": "brief topic description",
    "task_1_system_understanding": [
        {{
            "question": "question text",
            "preferred_source": "CISA",
            "rationale": "why this source"
        }}
    ],
    "task_2_security_analysis": [
        {{
            "question": "question text",
            "preferred_source": "CISA",
            "rationale": "why this source"
        }}
    ]
}}
"""

STRIDE_ANALYSIS_PROMPT = """
You are a cybersecurity threat modeling expert using the STRIDE framework.

USER QUESTION: {query}

RESEARCH FINDINGS:
{research}

Apply the STRIDE framework systematically:

S - Spoofing: Identity theft, impersonation attacks
T - Tampering: Data modification, integrity violations
R - Repudiation: Denial of actions, lack of audit trails
I - Information Disclosure: Data leaks, unauthorized access
D - Denial of Service: Availability attacks, resource exhaustion
E - Elevation of Privilege: Unauthorized access escalation

For EACH relevant STRIDE category:
1. Identify specific threats from the research
2. Describe attack vectors
3. Assess likelihood (Low/Medium/High) and impact (Low/Medium/High)
4. Cite sources with [Source §Section]

Format your analysis clearly with headers for each STRIDE category.
Only include categories that are relevant to the question.
"""

SYNTHESIS_PROMPT = """
You are a cybersecurity analyst creating a comprehensive threat modeling report.

USER QUESTION: {query}

STRIDE THREAT ANALYSIS:
{threat_model}

Generate a professional threat modeling report with these sections:

## 1. EXECUTIVE SUMMARY
Brief 2-3 sentence overview of key findings

## 2. SYSTEM DESCRIPTION
Describe the system/technology and its security context (from research)

## 3. THREAT ANALYSIS
For each identified threat:
- **Threat Name** (STRIDE Category - Risk Level)
- Description of the threat
- Attack vector and how it could be exploited
- Likelihood: Low/Medium/High
- Impact: Low/Medium/High
- Risk Level: Low/Medium/High/Critical
- Source citation: [Source §Section]
- Supporting evidence from research

## 4. MITIGATION RECOMMENDATIONS
Prioritized list (Must have / Should have / Could have):
- What threats does it address
- Implementation guidance
- Source citation and rationale

## 5. RISK SUMMARY
- Highest priority risks requiring immediate attention
- Quick wins for risk reduction
- Areas needing further research

## 6. REFERENCES
All sources cited in the format: [Source] Title, Section/DOI

IMPORTANT: Every finding must cite a source. Use actual content from the research provided.
"""