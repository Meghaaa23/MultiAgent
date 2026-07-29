# agents/__init__.py
"""
Multi-Agent System for Threat Modeling and Web Scanning

This package contains specialized agents for:
- Question answering (qa_agent)
- Threat modeling and web scanning (threat_modeling_agent)
- State management and caching (redis_manager)
"""

from .qa_agent import answer_question_from_db, set_config
from .redis_manager import (
    set_agent_state,
    get_agent_state,
    publish_event,
    cache_result,
    get_cached_result,
    delete_key,
    clear_all_cache,
    get_cache_stats,
    is_redis_available,
)

__all__ = [
    # QA Agent
    'answer_question_from_db',
    'set_config',

    # Redis Manager
    'set_agent_state',
    'get_agent_state',
    'publish_event',
    'cache_result',
    'get_cached_result',
    'delete_key',
    'clear_all_cache',
    'get_cache_stats',
    'is_redis_available',
]

__version__ = '1.1.0'
