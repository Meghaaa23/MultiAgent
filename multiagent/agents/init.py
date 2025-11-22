# agents/__init__.py
"""
Multi-Agent System for Document Processing and RAG

This package contains specialized agents for:
- PDF processing (pdf_agent)
- Image analysis (image_agent)  
- Audio transcription (audio_agent)
- Question answering with RAG (qa_agent)
- Data ingestion and chunking (data_ingestion)
- State management and caching (redis_manager)
"""

from .audio_agent import transcribe_audio_locally, set_vectorstore as set_audio_vectorstore
from .image_agent import analyze_image_locally, set_image_vectorstore
from .pdf_agent import process_pdf_locally, set_vectorstore as set_pdf_vectorstore
from .qa_agent import answer_question_from_db, set_vectorstore as set_qa_vectorstore, set_config
from .data_ingestion import ingest_text_with_chunking, set_vectorstore as set_ingest_vectorstore
from .redis_manager import (
    set_agent_state,
    get_agent_state,
    publish_event,
    cache_result,
    get_cached_result,
    delete_key,
    clear_all_cache,
    get_cache_stats,
    is_redis_available
)

__all__ = [
    # Audio Agent
    'transcribe_audio_locally',
    'set_audio_vectorstore',
    
    # Image Agent
    'analyze_image_locally',
    'set_image_vectorstore',
    
    # PDF Agent
    'process_pdf_locally',
    'set_pdf_vectorstore',
    
    # QA Agent
    'answer_question_from_db',
    'set_qa_vectorstore',
    'set_config',
    
    # Data Ingestion
    'ingest_text_with_chunking',
    'set_ingest_vectorstore',
    
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

__version__ = '1.0.0'