# agents/pdf_agent.py

import os
import fitz
import asyncio
import logging
from langchain_core.documents import Document
from autogen_agentchat.messages import TextMessage
from .data_ingestion import ingest_text_with_chunking
from .redis_manager import set_agent_state, publish_event


logger = logging.getLogger(__name__)
vectorstore = None

def set_vectorstore(vs):
    global vectorstore
    vectorstore = vs

from .data_ingestion import ingest_text_with_chunking

async def process_pdf_locally(file_path: str) -> TextMessage:
    if vectorstore is None:
        raise ValueError("Vectorstore is not set. Please call set_vectorstore before processing.")

    if not os.path.exists(file_path):
        return TextMessage(content=f"Error: PDF file not found at '{file_path}'.", source="process_pdf_locally")

    try:
        import fitz
        doc = await asyncio.to_thread(fitz.open, file_path)
        extracted_text = ""
        for page in doc:
            extracted_text += page.get_text()
        await asyncio.to_thread(doc.close)

        # ingestion function
        return await ingest_text_with_chunking(file_path, extracted_text)

    except Exception as e:
        return TextMessage(content=f"PDF processing failed: {e}", source="process_pdf_locally")
