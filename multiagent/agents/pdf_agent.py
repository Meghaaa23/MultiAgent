# agents/pdf_agent.py
import os
import fitz
import asyncio
import logging
from langchain_core.documents import Document
from autogen_agentchat.messages import TextMessage
from .redis_manager import set_agent_state, publish_event, cache_result, get_cached_result

logger = logging.getLogger(__name__)

vectorstore = None

def set_vectorstore(vs):
    global vectorstore
    vectorstore = vs
    logger.info("PDF agent vectorstore initialized")


async def process_pdf_locally(file_path: str) -> TextMessage:
    """Extract text from PDF and automatically process any URLs found"""
    agent_name = "pdf_agent"
    
    cached = get_cached_result(f"pdf:{file_path}")
    if cached:
        logger.info(f"Using cached PDF extraction for {file_path}")
        import ast
        try:
            pages_data = ast.literal_eval(cached)
            full_text = "\n".join([p["text"] for p in pages_data])
            
            # Process URLs from cached data
            from .url_agent import process_pdf_urls
            logger.info(" Processing URLs from cached PDF...")
            url_result = await process_pdf_urls(full_text, os.path.basename(file_path))
            logger.info(f"URL processing: {url_result.content}")
        except:
            logger.warning("Could not extract URLs from cached data")
        
        return await ingest_pdf_with_pages(file_path, cached)
    
    set_agent_state(agent_name, {"status": "running", "file": file_path})
    
    if not os.path.exists(file_path):
        msg = f"Error: PDF not found at '{file_path}'"
        logger.error(msg)
        return TextMessage(content=msg, source=agent_name)
    
    try:
        doc = await asyncio.to_thread(fitz.open, file_path)
        page_count = len(doc)
        logger.info(f"Processing {page_count} pages from {os.path.basename(file_path)}")
        
        # Extract per-page
        pages_data = []
        full_text = ""
        
        for page_num, page in enumerate(doc, start=1):
            page_text = page.get_text()
            if page_text.strip():
                pages_data.append({
                    "page_num": page_num,
                    "text": page_text.strip()
                })
                full_text += f"\n{page_text}"
        
        await asyncio.to_thread(doc.close)
        
        if not pages_data:
            warning_msg = "Warning: No text extracted from PDF"
            logger.warning(f"{warning_msg}: {file_path}")
            return TextMessage(content=warning_msg, source=agent_name)
        
        logger.info(f" Extracted {len(pages_data)} pages")
        
        cache_result(f"pdf:{file_path}", str(pages_data))
        set_agent_state(agent_name, {"status": "completed", "file": file_path})
        
        # AUTOMATIC URL PROCESSING
        from .url_agent import process_pdf_urls
        logger.info("Automatically extracting URLs from PDF...")
        url_result = await process_pdf_urls(full_text, os.path.basename(file_path))
        logger.info(f"URL processing: {url_result.content}")
        
        # Ingest PDF text
        return await ingest_pdf_with_pages(file_path, pages_data)
    
    except Exception as e:
        error_msg = f"PDF processing failed: {e}"
        logger.error(f"{error_msg} for {file_path}", exc_info=True)
        return TextMessage(content=error_msg, source=agent_name)


async def ingest_pdf_with_pages(file_path: str, pages_data) -> TextMessage:
    """Ingest PDF with page-level granularity"""
    from .data_ingestion import ingest_pdf_pages
    return await ingest_pdf_pages(file_path, pages_data)