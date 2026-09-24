"""
Multi-Agent System for Threat Modeling and Web Scanning.

Import submodules directly for heavy agents; this package exports QA and Redis helpers.
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
    'answer_question_from_db',
    'set_config',

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
