"""Lightweight QA helpers (document RAG removed)."""

import logging
from typing import List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_config = None

def set_config(config_list):
    """Set the LLM configuration (kept for compatibility)."""
    global _config
    _config = config_list
    logger.info("QA Agent: LLM config set")

def set_vectorstore(vectorstore=None):
    """No-op compatibility stub — document vector store removed."""
    logger.info("QA Agent: vector store disabled")

async def answer_question_from_db(question: str, filenames: Optional[List[str]] = None) -> str:
    """Compatibility stub. Document/KB retrieval has been removed."""
    logger.info("QA Agent: no document store configured; skipping retrieval")
    return (
        "No document knowledge base is configured. "
        "Answer using general cybersecurity knowledge and cite well-known "
        "standards (OWASP, NIST, CISA, MITRE) when relevant."
    )
