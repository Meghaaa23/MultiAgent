# agents/threat_modeling_agent.py

import os
import json
import openai
import pymongo
import hashlib
from typing import Dict, List, Optional
from datetime import datetime

# Redis caching
from .redis_manager import cache_result, get_cached_result

from .vector_search import VectorSearch  
from utils.threat_prompts import (
    QUESTION_DECOMPOSITION_PROMPT,
    STRIDE_ANALYSIS_PROMPT,
    SYNTHESIS_PROMPT
)

class ThreatModelingAgent:
    """
    Threat Modeling Agent with intelligent LLM-based security question detection
    
    Features:
    - LLM-based classification (no keyword maintenance needed)
    - Redis caching for performance
    - STRIDE framework analysis
    - Knowledge base search (CISA/IEEE/Intel TDX/OWASP)
    """
    
    def __init__(self, mongodb_client=None, openai_client=None):
        """Initialize threat modeling agent"""
        
        if mongodb_client:
            self.mongo_client = mongodb_client
        else:
            self.mongo_client = pymongo.MongoClient(os.getenv("MONGODB_URI"))
        
        if openai_client:
            self.openai_client = openai_client
            self.llm_model = os.getenv("LLAMA_MODEL_NAME", "Qwen-2.5")
        else:
            llama_base_url = os.getenv("LLAMA_BASE_URL", "http://localhost:8080")
            self.openai_client = openai.OpenAI(
                base_url=f"{llama_base_url}/v1",
                api_key="not-needed"
            )
            self.llm_model = os.getenv("LLAMA_MODEL_NAME", "Qwen-2.5")
        
        # Initialize vector search
        self.vector_search = VectorSearch(
            mongodb_client=self.mongo_client,
            collection_name="security_knowledge_base"
        )
        
        print(" Threat Modeling Agent initialized with LLM classification")
    
    def _generate_cache_key(self, query: str) -> str:
        """Generate cache key for query"""
        query_hash = hashlib.md5(query.lower().strip().encode()).hexdigest()
        return f"threat_model:{query_hash}"
    
    def is_security_query(self, query: str, use_llm: bool = True) -> bool:
        """
        Intelligently detect if query is security-related using LLM
        
        Args:
            query: User question
            use_llm: Use LLM classification (True) or keyword fallback (False)
            
        Returns:
            True if security-related, False otherwise
        """
        
        if not use_llm:
            return self._keyword_fallback(query)
        
        # LLM-based classification
        classification_prompt = f"""You are a cybersecurity question classifier.

Determine if the following question is related to:
- Cybersecurity
- Security vulnerabilities
- Threat modeling
- Security attacks or exploits
- Authentication/authorization security
- Data protection or privacy
- Secure systems or networks

Question: "{query}"

Think step by step:
1. Does this question involve security, threats, or vulnerabilities?
2. Is it asking about protecting systems, data, or users?
3. Does it relate to security best practices or attack prevention?

Answer ONLY with "YES" or "NO" (no explanation needed).

Examples:
- "What is SSRF?" → YES (security vulnerability)
- "What are vulnerabilities?" → YES (security concept)
- "Is the API vulnerable?" → YES (security assessment)
- "How can authentication keys be exposed?" → YES (security threat)
- "What are OAuth security risks?" → YES (security analysis)
- "What's the weather today?" → NO (not security)
- "How do I cook pasta?" → NO (not security)
- "Write me a poem about love" → NO (not security)
- "Explain quantum physics" → NO (not security)

Answer (YES or NO):"""

        try:
            response = self.openai_client.chat.completions.create(
                model=self.llm_model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security question classifier. Answer only YES or NO."
                    },
                    {
                        "role": "user",
                        "content": classification_prompt
                    }
                ],
                temperature=0.0,  # Deterministic
                max_tokens=10
            )
            
            answer = response.choices[0].message.content.strip().upper()
            
            # Extract YES/NO from response
            is_security = "YES" in answer
            
            print(f" LLM Classification: '{query[:60]}...' → {answer} → {'SECURITY' if is_security else 'NON-SECURITY'}")
            
            return is_security
            
        except Exception as e:
            print(f" LLM classification failed: {e}")
            print(f"   Falling back to keyword matching")
            return self._keyword_fallback(query)
    
    def _keyword_fallback(self, query: str) -> bool:
        """
        Fallback keyword matching if LLM classification fails
        Keep this simple as a safety net
        """
        security_keywords = [
            # Core security terms
            "threat", "vulnerability", "vulnerable", "attack", "security", 
            "exploit", "breach", "malware", "hack", "risk",
            
            # Common vulnerabilities
            "injection", "xss", "csrf", "ssrf", "sql", "rce",
            
            # Security concepts
            "authentication", "authorization", "encryption", "firewall",
            "exposure", "leak", "compromise", "penetration"
        ]
        
        query_lower = query.lower()
        is_security = any(keyword in query_lower for keyword in security_keywords)
        
        print(f" Keyword Fallback: '{query[:60]}...' → {'SECURITY' if is_security else 'NON-SECURITY'}")
        
        return is_security
    
    async def analyze(self, user_query: str, verbose: bool = True, use_cache: bool = True) -> Dict:
        """
        Complete threat modeling analysis with Redis caching
        
        Args:
            user_query: Security question
            verbose: Print progress
            use_cache: Use Redis cache
            
        Returns:
            Dict with report and reasoning chain
        """
        if verbose:
            print("\n" + "="*70)
            print(" THREAT MODELING ANALYSIS")
            print("="*70)
            print(f"Query: {user_query}")
            print("="*70 + "\n")
        
        # Check Redis cache
        if use_cache:
            cache_key = self._generate_cache_key(user_query)
            
            if verbose:
                print(" Checking Redis cache...")
            
            cached_result = get_cached_result(cache_key)
            
            if cached_result:
                if verbose:
                    print(" Cache HIT! Returning cached threat model\n")
                    print("="*70)
                    print(" ANALYSIS COMPLETE (from cache)")
                    print("="*70 + "\n")
                
                result = json.loads(cached_result)
                result["cached"] = True
                return result
            
            if verbose:
                print(" Cache MISS - performing fresh analysis\n")
        
        # Step 1: Decompose question
        if verbose:
            print(" Step 1: Decomposing security question...")
        
        decomposition = await self.decompose_query(user_query)
        
        if verbose:
            task1_count = len(decomposition.get('task_1_system_understanding', []))
            task2_count = len(decomposition.get('task_2_security_analysis', []))
            print(f" Generated {task1_count + task2_count} sub-questions\n")
        
        # Step 2: Research from knowledge base
        if verbose:
            print(" Step 2: Researching from knowledge base...")
        
        research = await self.research_sub_questions(decomposition, verbose=verbose)
        
        if verbose:
            print()
        
        # Step 3: Format research
        formatted_research = self.format_research(research)
        
        # Step 4: Apply STRIDE framework
        if verbose:
            print("  Step 4: Applying STRIDE threat modeling...")
        
        threat_model = await self.apply_stride_framework(user_query, formatted_research)
        
        if verbose:
            print(" Threat analysis complete\n")
        
        # Step 5: Generate final report
        if verbose:
            print(" Step 5: Generating comprehensive report...")
        
        final_report = await self.synthesize_report(user_query, threat_model)
        
        if verbose:
            print(" Report generated\n")
        
        # Build result
        result = {
            "query": user_query,
            "report": final_report,
            "reasoning_chain": {
                "decomposition": decomposition,
                "research_summary": self._summarize_research(research),
                "threat_model": threat_model
            },
            "timestamp": datetime.now().isoformat(),
            "cached": False
        }
        
        # Cache the result
        if use_cache:
            if verbose:
                print(" Caching result in Redis...")
            
            cache_result(cache_key, json.dumps(result), ttl=3600)  # 1 hour TTL
            
            if verbose:
                print(" Cached for future requests\n")
        
        if verbose:
            print("="*70)
            print(" ANALYSIS COMPLETE")
            print("="*70 + "\n")
        
        return result
    
    async def decompose_query(self, user_query: str) -> Dict:
        """Break down security question into sub-questions"""
        prompt = QUESTION_DECOMPOSITION_PROMPT.format(query=user_query)
        
        response = self.openai_client.chat.completions.create(
            model=self.llm_model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a cybersecurity expert who breaks down complex security questions into structured sub-questions."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            response_format={"type": "json_object"},
            temperature=0.3
        )
        
        return json.loads(response.choices[0].message.content)
    
    async def research_sub_questions(self, decomposition: Dict, verbose: bool = False) -> Dict:
        """Research each sub-question using vector search"""
        research_results = {
            "task_1": [],
            "task_2": []
        }
        
        # Research Task 1
        for idx, sq in enumerate(decomposition.get('task_1_system_understanding', []), 1):
            if verbose:
                print(f" Task 1.{idx}: {sq['question'][:60]}...")
            
            sources = [sq['preferred_source']] if sq.get('preferred_source') else None
            results = await self.vector_search.search(
                query=sq['question'],
                filters={"source": {"$in": sources}} if sources else None,
                top_k=5
            )
            
            research_results["task_1"].append({
                "question": sq['question'],
                "preferred_source": sq.get('preferred_source'),
                "findings": results
            })
            
            if verbose and results:
                print(f"      Found {len(results)} sources")
        
        # Research Task 2
        for idx, sq in enumerate(decomposition.get('task_2_security_analysis', []), 1):
            if verbose:
                print(f" Task 2.{idx}: {sq['question'][:60]}...")
            
            sources = [sq['preferred_source']] if sq.get('preferred_source') else None
            results = await self.vector_search.search(
                query=sq['question'],
                filters={"source": {"$in": sources}} if sources else None,
                top_k=5
            )
            
            research_results["task_2"].append({
                "question": sq['question'],
                "preferred_source": sq.get('preferred_source'),
                "findings": results
            })
            
            if verbose and results:
                print(f"      Found {len(results)} sources")
        
        return research_results
    
    def format_research(self, research: Dict) -> str:
        """Format research findings for LLM"""
        formatted = "### TASK 1 - System Understanding\n\n"
        
        for item in research["task_1"]:
            formatted += f"**Question:** {item['question']}\n\n"
            formatted += "**Findings:**\n\n"
            
            for idx, finding in enumerate(item["findings"][:3], 1):
                source = finding.get('source', 'Unknown')
                title = finding.get('title', 'Untitled')
                content = finding.get('content', '')[:400]
                
                formatted += f"{idx}. [{source}] {title}\n"
                formatted += f"   {content}...\n\n"
            
            formatted += "---\n\n"
        
        formatted += "### TASK 2 - Security Analysis\n\n"
        
        for item in research["task_2"]:
            formatted += f"**Question:** {item['question']}\n\n"
            formatted += "**Findings:**\n\n"
            
            for idx, finding in enumerate(item["findings"][:3], 1):
                source = finding.get('source', 'Unknown')
                title = finding.get('title', 'Untitled')
                content = finding.get('content', '')[:400]
                
                formatted += f"{idx}. [{source}] {title}\n"
                formatted += f"   {content}...\n\n"
            
            formatted += "---\n\n"
        
        return formatted
    
    async def apply_stride_framework(self, user_query: str, formatted_research: str) -> str:
        """Apply STRIDE threat modeling"""
        prompt = STRIDE_ANALYSIS_PROMPT.format(
            query=user_query,
            research=formatted_research
        )
        
        response = self.openai_client.chat.completions.create(
            model=self.llm_model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a cybersecurity threat modeling expert specializing in STRIDE analysis."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.3,
            max_tokens=3000
        )
        
        return response.choices[0].message.content
    
    async def synthesize_report(self, user_query: str, threat_model: str) -> str:
        """Generate final comprehensive report"""
        prompt = SYNTHESIS_PROMPT.format(
            query=user_query,
            threat_model=threat_model
        )
        
        response = self.openai_client.chat.completions.create(
            model=self.llm_model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a cybersecurity analyst who writes comprehensive threat modeling reports."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.3,
            max_tokens=4000
        )
        
        return response.choices[0].message.content
    
    def _summarize_research(self, research: Dict) -> Dict:
        """Summarize research for reasoning chain"""
        sources_used = set()
        total_findings = 0
        
        for item in research["task_1"] + research["task_2"]:
            total_findings += len(item["findings"])
            for finding in item["findings"]:
                sources_used.add(finding.get("source", "Unknown"))
        
        return {
            "task_1_questions": len(research["task_1"]),
            "task_2_questions": len(research["task_2"]),
            "total_findings": total_findings,
            "sources_used": list(sources_used)
        }