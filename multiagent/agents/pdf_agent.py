import os
import logging
import fitz  # PyMuPDF
from pathlib import Path
from langchain_core.documents import Document
from typing import List
from autogen_agentchat.messages import TextMessage

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global vectorstore
_vectorstore = None


def set_vectorstore(vectorstore):
    """Set the vector store instance"""
    global _vectorstore
    _vectorstore = vectorstore
    logger.info(" PDF Agent: Vector store configured")


def chunk_text(text: str, chunk_size: int = 500, overlap: int = 50) -> List[str]:
    """Split text into overlapping chunks"""
    chunks = []
    start = 0
    text_length = len(text)
    
    while start < text_length:
        end = start + chunk_size
        chunk = text[start:end]
        
        if chunk.strip():  # Only add non-empty chunks
            chunks.append(chunk)
        
        start += chunk_size - overlap
    
    return chunks


async def process_pdf_locally(file_path: str) -> str:
    """Process PDF and store chunks in MongoDB"""
    try:
        logger.info(f" PDF Agent: Processing {file_path}")
        
        # Validate file exists
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return f"Error: File not found - {file_path}"
        
        # Open PDF
        try:
            pdf_document = fitz.open(file_path)
        except Exception as e:
            logger.error(f"Failed to open PDF: {e}")
            return f"Error: Could not open PDF - {str(e)}"
        
        filename = os.path.basename(file_path)
        all_chunks = []
        total_pages = len(pdf_document)
        
        logger.info(f"  PDF has {total_pages} pages")
        
        # Process each page
        for page_num in range(total_pages):
            try:
                page = pdf_document[page_num]
                text = page.get_text()
                
                # Skip empty pages
                if not text or not text.strip():
                    logger.debug(f"  Page {page_num + 1}: Empty, skipping")
                    continue
                
                # Clean the text
                text = text.strip()
                
                # Chunk the text
                chunks = chunk_text(text, chunk_size=500, overlap=50)
                
                logger.info(f"  Page {page_num + 1}: {len(text)} chars → {len(chunks)} chunks")
                
                # Create documents for each chunk
                for chunk_idx, chunk in enumerate(chunks):
                    doc = Document(
                        page_content=chunk,
                        metadata={
                            "filename": filename,
                            "page": page_num + 1,
                            "chunk": chunk_idx,
                            "source": file_path,
                            "total_pages": total_pages,
                            "source_type": "pdf",
                            "content_type": "document"
                        }
                    )
                    all_chunks.append(doc)
                    
            except Exception as e:
                logger.error(f"  Error processing page {page_num + 1}: {e}")
                continue
        
        pdf_document.close()
        
        # Store in MongoDB
        if not _vectorstore:
            logger.error(" Vector store not initialized!")
            return "Error: Vector store not initialized"
        
        if not all_chunks:
            logger.warning("  No text extracted from PDF")
            return f"Warning: No text found in {filename}"
        
        try:
            logger.info(f"  Storing {len(all_chunks)} chunks in MongoDB...")
            _vectorstore.add_documents(all_chunks)
            logger.info(f" Successfully stored {len(all_chunks)} chunks")
        except Exception as e:
            logger.error(f" Failed to store in MongoDB: {e}")
            return f"Error storing chunks: {str(e)}"
        
        return f"✓ Processed {filename}: {total_pages} pages, {len(all_chunks)} chunks"
    
    except Exception as e:
        logger.error(f" PDF processing failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return f"Error: {str(e)}"