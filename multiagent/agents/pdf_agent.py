# agents/pdf_agent.py

import os
import fitz
import asyncio
import logging
from langchain_core.documents import Document
from autogen_agentchat.messages import TextMessage

logger = logging.getLogger(__name__)
vectorstore = None

def set_vectorstore(vs):
    global vectorstore
    vectorstore = vs

async def process_pdf_locally(file_path: str) -> TextMessage:
    if vectorstore is None:
        raise ValueError("Vectorstore is not set. Please call set_vectorstore before processing.")

    if not os.path.exists(file_path):
        return TextMessage(content=f"Error: PDF file not found at '{file_path}'.", source="process_pdf_locally")

    extracted_text = ""
    try:
        doc = await asyncio.to_thread(fitz.open, file_path)
        for page in doc:
            extracted_text += page.get_text()
        await asyncio.to_thread(doc.close)

        await asyncio.to_thread(vectorstore.add_documents, [
            Document(page_content=extracted_text, metadata={"filename": os.path.basename(file_path)})
        ])

        return TextMessage(
            content=f"PDF processing complete. Content added to vector DB. Preview: {extracted_text[:200]}...",
            source="process_pdf_locally"
        )
    except Exception as e:
        logger.error(f"Failed to process PDF: {e}")
        return TextMessage(
            content=f"PDF processing failed: {e}",
            source="process_pdf_locally"
        )
