# agents/url_agent.py
"""
URL Agent - Extracts URLs from PDFs and fetches their content
"""
import os
import re
import asyncio
import logging
from typing import List, Dict
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from langchain_core.documents import Document
from autogen_agentchat.messages import TextMessage

logger = logging.getLogger(__name__)

vectorstore = None

def set_url_vectorstore(vs):
    """Set the shared vectorstore for URL agent"""
    global vectorstore
    vectorstore = vs
    logger.info("URL agent vectorstore initialized")


def extract_urls_from_text(text: str) -> List[str]:
    """Extract URLs from text using regex"""
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, text)
    
    unique_urls = list(set(urls))
    valid_urls = [url for url in unique_urls if is_valid_url(url)]
    
    logger.info(f"Extracted {len(valid_urls)} unique URLs from text")
    return valid_urls


def is_valid_url(url: str) -> bool:
    """Validate if URL is properly formatted"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


async def fetch_url_content(url: str, timeout: int = 10) -> Dict[str, str]:
    """Fetch and extract text content from a URL"""
    try:
        logger.info(f"Fetching content from: {url}")
        
        response = await asyncio.to_thread(
            requests.get,
            url,
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )
        
        if response.status_code != 200:
            logger.warning(f"Failed to fetch {url}: HTTP {response.status_code}")
            return {"url": url, "title": "", "content": f"Failed to fetch (HTTP {response.status_code})"}
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Remove script and style elements
        for script in soup(["script", "style", "nav", "footer", "header"]):
            script.decompose()
        
        # Extract title
        title = soup.title.string if soup.title else urlparse(url).netloc
        
        # Extract text content
        text = soup.get_text(separator=' ', strip=True)
        
        # Clean up whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        # Limit content length
        max_length = 10000
        if len(text) > max_length:
            text = text[:max_length] + "... [content truncated]"
        
        logger.info(f" Fetched {len(text)} characters from {url}")
        
        return {
            "url": url,
            "title": title,
            "content": text
        }
    
    except requests.Timeout:
        logger.error(f"Timeout fetching {url}")
        return {"url": url, "title": "", "content": "Failed to fetch (timeout)"}
    
    except Exception as e:
        logger.error(f"Error fetching {url}: {e}")
        return {"url": url, "title": "", "content": f"Failed to fetch: {str(e)}"}

   

async def process_pdf_urls(pdf_text: str, pdf_filename: str) -> TextMessage:
    """
    Extract URLs from PDF text, fetch their content, and store in vectorstore.
    Skip if URLs already processed for this PDF.
    """
    if vectorstore is None:
        logger.error("Vectorstore not initialized")
        return TextMessage(content="URL processing failed: vectorstore not initialized", source="url_agent")
    
    try:
        # ==================== NEW: CHECK IF ALREADY PROCESSED ====================
        from pymongo import MongoClient
        import os
        from dotenv import load_dotenv
        
        load_dotenv()
        mongo_client = MongoClient(os.getenv("MONGODB_ATLAS_URI"))
        collection = mongo_client["multiagentllm"]["RAG"]
        
        # Check if we already have URL chunks for this PDF
        existing_url_count = collection.count_documents({
            "source_pdf": pdf_filename,
            "source_type": "url"
        })
        
        if existing_url_count > 0:
            logger.info(f" URLs already processed for {pdf_filename} ({existing_url_count} chunks in database)")
            return TextMessage(
                content=f"URLs already processed for {pdf_filename} ({existing_url_count} chunks cached)",
                source="url_agent"
            )
        # ========================================================================
        
        urls = extract_urls_from_text(pdf_text)
        
        if not urls:
            logger.info(f"No URLs found in {pdf_filename}")
            return TextMessage(content=f"No URLs found in {pdf_filename}", source="url_agent")
        
        logger.info(f"Processing {len(urls)} URLs from {pdf_filename}")
        
        # Fetch content from all URLs
        url_contents = []
        for i, url in enumerate(urls):
            content_data = await fetch_url_content(url)
            url_contents.append(content_data)
            
            if i < len(urls) - 1:
                await asyncio.sleep(0.5)
        
        # Create Document objects for each URL
        docs = []
        for i, url_data in enumerate(url_contents):
            if url_data['content'] and not url_data['content'].startswith('Failed'):
                content = url_data['content']
                chunk_size = 1000
                
                for chunk_idx, start in enumerate(range(0, len(content), chunk_size)):
                    chunk_text = content[start:start + chunk_size]
                    
                    doc = Document(
                        page_content=chunk_text,
                        metadata={
                            "filename": url_data['url'],
                            "source_type": "url",
                            "content_type": "webpage",
                            "source_pdf": pdf_filename,
                            "url": url_data['url'],
                            "url_title": url_data['title'],
                            "chunk_id": chunk_idx,
                            "total_chunks": (len(content) + chunk_size - 1) // chunk_size,
                            "char_count": len(chunk_text)
                        }
                    )
                    docs.append(doc)
        
        if not docs:
            return TextMessage(
                content=f"Found {len(urls)} URLs but couldn't fetch content from any",
                source="url_agent"
            )
        
        # Store in vectorstore
        logger.info(f"Storing {len(docs)} URL chunks in vector database...")
        await asyncio.to_thread(vectorstore.add_documents, docs)
        
        success_msg = (
            f"✓ Processed {len(urls)} URLs from {pdf_filename}. "
            f"Stored {len(docs)} chunks of URL content separately."
        )
        logger.info(success_msg)
        
        return TextMessage(content=success_msg, source="url_agent")
    
    except Exception as e:
        error_msg = f"URL processing failed: {e}"
        logger.error(error_msg, exc_info=True)
        return TextMessage(content=error_msg, source="url_agent")