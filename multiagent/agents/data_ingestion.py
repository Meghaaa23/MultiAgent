# agents/data_ingestion.py
import os
import asyncio
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_core.documents import Document
from autogen_agentchat.messages import TextMessage
import logging

logger = logging.getLogger(__name__)

vectorstore = None

def set_vectorstore(vs):
    """Set the shared vectorstore (MongoDB Atlas) from main.py"""
    global vectorstore
    vectorstore = vs


async def ingest_text_with_chunking(file_path: str, raw_text: str) -> TextMessage:
    """
    Splits text into semantic chunks and stores them in the vectorstore as embeddings.
    """

    if vectorstore is None:
        raise ValueError("Vectorstore not initialized. Please call set_vectorstore first.")

    if not raw_text.strip():
        return TextMessage(content="No text to process.", source="ingest_text_with_chunking")

    try:
        
        splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=100)
        chunks = splitter.split_text(raw_text)
        logger.info(f"Split {file_path} into {len(chunks)} chunks.")

        
        docs = [
            Document(
                page_content=chunk,
                metadata={"filename": os.path.basename(file_path), "chunk_id": i}
            )
            for i, chunk in enumerate(chunks)
        ]

        await asyncio.to_thread(vectorstore.add_documents, docs)
        
        return TextMessage(
            content=f" Ingested {len(chunks)} chunks from {os.path.basename(file_path)} into vector DB.",
            source="ingest_text_with_chunking"
        )

    except Exception as e:
        logger.error(f"Data ingestion failed for {file_path}: {e}")
        return TextMessage(content=f"Error during ingestion: {e}", source="ingest_text_with_chunking")
