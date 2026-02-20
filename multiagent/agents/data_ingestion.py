# agents/data_ingestion.py
import os
import asyncio
import ast
import logging
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_core.documents import Document
from autogen_agentchat.messages import TextMessage

logger = logging.getLogger(__name__)

vectorstore = None

def set_vectorstore(vs):
    global vectorstore
    vectorstore = vs
    logger.info("Data ingestion vectorstore initialized")


async def ingest_pdf_pages(file_path: str, pages_data) -> TextMessage:
    """Ingest PDF with page-aware chunking"""
    if vectorstore is None:
        raise ValueError("Vectorstore not initialized")
    
    if isinstance(pages_data, str):
        try:
            pages_data = ast.literal_eval(pages_data)
        except:
            logger.error("Failed to parse cached pages_data")
            return TextMessage(content="Failed to parse cached data", source="data_ingestion")
    
    if not pages_data:
        return TextMessage(content="No pages to process", source="data_ingestion")
    
    try:
        filename = os.path.basename(file_path)
        logger.info(f"Processing {len(pages_data)} pages from {filename}")
        
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=2000,
            chunk_overlap=400,
            length_function=len,
            separators=["\n\n", "\n", ". ", " ", ""]
        )
        
        docs = []
        for page in pages_data:
            page_num = page["page_num"]
            page_text = page["text"]
            
            chunks = splitter.split_text(page_text)
            
            for chunk_idx, chunk in enumerate(chunks):
                doc = Document(
                    page_content=chunk,
                    metadata={
                        "filename": filename,
                        "source_type": "pdf",
                        "content_type": "document",
                        "page": page_num,
                        "chunk_id": chunk_idx,
                        "total_chunks": len(chunks),
                        "source": file_path,
                        "char_count": len(chunk)
                    }
                )
                docs.append(doc)
        
        logger.info(f"Storing {len(docs)} PDF chunks in vector database...")
        await asyncio.to_thread(vectorstore.add_documents, docs)
        
        success_msg = f" Ingested {len(docs)} PDF chunks from {filename}"
        logger.info(success_msg)
        
        return TextMessage(content=success_msg, source="data_ingestion")
    
    except Exception as e:
        error_msg = f"PDF ingestion failed: {e}"
        logger.error(error_msg, exc_info=True)
        return TextMessage(content=error_msg, source="data_ingestion")


async def ingest_text_with_chunking(file_path: str, raw_text: str) -> TextMessage:
    """For non-PDF files (images, audio)"""
    if vectorstore is None:
        raise ValueError("Vectorstore not initialized")
    
    if not raw_text or not raw_text.strip():
        warning_msg = "No text to process"
        logger.warning(f"{warning_msg} for {file_path}")
        return TextMessage(content=warning_msg, source="data_ingestion")
    
    try:
        filename = os.path.basename(file_path)
        
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=500,
            chunk_overlap=100,
            length_function=len,
            separators=["\n\n", "\n", ". ", " ", ""]
        )
        
        chunks = splitter.split_text(raw_text)
        
        docs = []
        for i, chunk in enumerate(chunks):
            doc = Document(
                page_content=chunk,
                metadata={
                    "filename": filename,
                    "source_type": "text",
                    "content_type": "extracted",
                    "chunk_id": i,
                    "total_chunks": len(chunks),
                    "source": file_path,
                    "char_count": len(chunk)
                }
            )
            docs.append(doc)
        
        await asyncio.to_thread(vectorstore.add_documents, docs)
        
        success_msg = f" Ingested {len(chunks)} chunks from {filename}"
        logger.info(success_msg)
        
        return TextMessage(content=success_msg, source="data_ingestion")
    
    except Exception as e:
        error_msg = f"Ingestion failed: {e}"
        logger.error(error_msg, exc_info=True)
        return TextMessage(content=error_msg, source="data_ingestion")