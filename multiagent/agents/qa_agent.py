# agents/qa_agent.py

import os
import logging
from typing import List
from sentence_transformers import CrossEncoder

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global variables
_vectorstore = None
_config = None

# Initialize re-ranker
logger.info("Loading re-ranker model...")
reranker = CrossEncoder('cross-encoder/ms-marco-MiniLM-L-6-v2')
logger.info("✓ Re-ranker model loaded")


def set_vectorstore(vectorstore):
    """Set the vector store instance"""
    global _vectorstore
    _vectorstore = vectorstore
    logger.info("✓ QA Agent: Vector store configured")


def set_config(config_list):
    """Set the LLM configuration"""
    global _config
    _config = config_list
    logger.info("✓ QA Agent: LLM config set")


def _is_security_question(question: str) -> bool:
    """
    Quick check if question is security-related
    Used to decide whether to search knowledge base
    """
    security_keywords = [
        "security", "vulnerability", "vulnerable", "attack", "threat",
        "exploit", "breach", "malware", "hack", "risk", "injection",
        "xss", "csrf", "ssrf", "authentication", "authorization",
        "encryption", "penetration", "mitigation", "drawback", "weakness"
    ]
    question_lower = question.lower()
    return any(keyword in question_lower for keyword in security_keywords)


async def answer_question_from_db(question: str, filenames: List[str]) -> str:
    """
    Retrieve relevant document chunks using hybrid search:
    1. User documents (RAG collection)
    2. Security knowledge base (if security question)
    
    NOTE: This function ONLY retrieves and returns context.
    AutoGen handles all conversation memory and LLM calls.
    
    Args:
        question: User's question
        filenames: List of document filenames to search in (empty = search all)
        
    Returns:
        Retrieved context string with document citations
    """
    logger.info("📚 QA Agent: Retrieving context")
    logger.info(f"   Question: {question}")
    logger.info(f"   Files: {filenames if filenames else 'All documents'}")
    
    # Detect if security question
    is_security = _is_security_question(question)
    if is_security:
        logger.info("   🛡️  Detected security question - will search knowledge base too")
    
    # Check if vectorstore is initialized
    if not _vectorstore:
        logger.error("✗ Vector store not initialized!")
        return "Error: Vector store not initialized. Please check system configuration."
    
    try:
        # ========== STEP 1: DIRECT MONGODB CHECK ==========
        logger.info("📊 Step 1: Checking MongoDB directly...")
        from .mongo_support import create_mongo_client, sanitize_retrieval_error

        mongo_client = create_mongo_client()
        if mongo_client is None:
            return sanitize_retrieval_error("MongoDB client not initialized")
        rag_collection = mongo_client["multiagentllm"]["RAG"]
        
        # Check total documents in RAG
        total_docs = rag_collection.count_documents({})
        logger.info(f"   Total documents in RAG: {total_docs}")
        
        if total_docs == 0 and not is_security:
            return "No documents have been processed yet. Please upload and process documents first."
        
        # Check for specific filenames
        if filenames and len(filenames) > 0:
            for filename in filenames:
                count_filename = rag_collection.count_documents({"filename": filename})
                logger.info(f"   '{filename}': {count_filename} docs")
        
        # ========== STEP 2: SEARCH USER DOCUMENTS (RAG) ==========
        logger.info(f"🔍 Step 2: Vector search in user documents...")
        user_results = []
        
        if total_docs > 0:  # Only search if there are user documents
            if not filenames or len(filenames) == 0:
                logger.info("   Searching across all documents")
                user_results = _vectorstore.similarity_search(query=question, k=10)
                logger.info(f"   Retrieved {len(user_results)} chunks")
            else:
                # Search ALL files and combine results
                for filename in filenames:
                    logger.info(f"   Searching in: {filename}")
                    file_found = False
                    
                    # Strategy 1: Try direct filename field
                    try:
                        file_results = _vectorstore.similarity_search(
                            query=question,
                            k=10,
                            filter={"filename": filename}
                        )
                        
                        if file_results:
                            logger.info(f"      Found {len(file_results)} chunks")
                            user_results.extend(file_results)
                            file_found = True
                            
                    except Exception as e:
                        logger.debug(f"      Strategy 1 failed: {e}")
                    
                    # Strategy 2: Manual filter as fallback
                    if not file_found:
                        try:
                            logger.info(f"      Trying unfiltered search...")
                            all_results = _vectorstore.similarity_search(query=question, k=50)
                            
                            filtered_results = []
                            for doc in all_results:
                                doc_filename = doc.metadata.get('filename', '')
                                if doc_filename == filename:
                                    filtered_results.append(doc)
                            
                            if filtered_results:
                                logger.info(f"      Found {len(filtered_results)} chunks (manual filter)")
                                user_results.extend(filtered_results[:10])
                            else:
                                logger.warning(f"      No chunks found for {filename}")
                                
                        except Exception as e:
                            logger.error(f"      Strategy 2 failed: {e}")
            
            logger.info(f"   Total from user docs: {len(user_results)} chunks")
        else:
            logger.info("   No user documents to search")
        
        # ========== STEP 3: SEARCH SECURITY KNOWLEDGE BASE (if security question) ==========
        kb_results = []
        
        if is_security:
            logger.info(f"🛡️  Step 3: Searching security knowledge base...")
            
            try:
                # Import vector search for knowledge base
                from .vector_search import VectorSearch
                
                kb_search = VectorSearch(
                    mongodb_client=mongo_client,
                    collection_name="security_knowledge_base"
                )
                
                # Search knowledge base
                kb_chunks = await kb_search.search(
                    query=question,
                    top_k=5
                )
                
                # Convert to Document-like format for consistency
                from langchain_core.documents import Document
                
                for chunk in kb_chunks:
                    doc = Document(
                        page_content=chunk.get('content', ''),
                        metadata={
                            'filename': f"[{chunk.get('source', 'KB')}] {chunk.get('title', 'Knowledge Base')}",
                            'source': chunk.get('source', 'Knowledge Base'),
                            'page': 'KB',
                            'is_knowledge_base': True
                        }
                    )
                    kb_results.append(doc)
                
                logger.info(f"   Found {len(kb_results)} chunks from knowledge base")
                
            except Exception as e:
                logger.error(f"   Knowledge base search failed: {e}")
                import traceback
                logger.error(traceback.format_exc())
        
        # ========== STEP 4: COMBINE RESULTS ==========
        all_results = user_results + kb_results
        
        logger.info(f"📊 Combined results: {len(user_results)} user + {len(kb_results)} KB = {len(all_results)} total")
        
        # If no results at all, return error
        if not all_results or len(all_results) == 0:
            logger.error("✗ No chunks found")
            return "No relevant information found in the documents or knowledge base."
        
        # ========== STEP 5: RE-RANKING WITH DIVERSITY ==========
        logger.info(f"🎯 Step 5: Re-ranking {len(all_results)} chunks...")
        
        passages = [doc.page_content for doc in all_results]
        pairs = [[question, passage] for passage in passages]
        scores = reranker.predict(pairs)
        
        scored_results = list(zip(all_results, scores))
        scored_results.sort(key=lambda x: x[1], reverse=True)
        
        # Ensure diversity: include both user docs and KB if available
        top_results = []
        
        if is_security and kb_results:
            # For security questions, ensure we get both user docs and KB
            user_scored = [(doc, score) for doc, score in scored_results 
                          if not doc.metadata.get('is_knowledge_base', False)]
            kb_scored = [(doc, score) for doc, score in scored_results 
                        if doc.metadata.get('is_knowledge_base', False)]
            
            # Take top 3 from each
            top_results.extend(user_scored[:3])
            top_results.extend(kb_scored[:3])
            
            # Sort by score
            top_results.sort(key=lambda x: x[1], reverse=True)
            
            logger.info(f"   Selected {len([r for r in top_results if not r[0].metadata.get('is_knowledge_base')])} from user docs")
            logger.info(f"   Selected {len([r for r in top_results if r[0].metadata.get('is_knowledge_base')])} from KB")
        else:
            # Non-security or no KB results: just take top chunks
            top_results = scored_results[:6]
        
        logger.info(f"✓ Final selection: {len(top_results)} chunks:")
        for idx, (doc, score) in enumerate(top_results[:6], 1):
            source = doc.metadata.get('filename', 'unknown')
            page = doc.metadata.get('page', 'N/A')
            is_kb = doc.metadata.get('is_knowledge_base', False)
            source_type = "🛡️ KB" if is_kb else "📄 User"
            logger.info(f"   {idx}. {source_type} | Score: {score:.4f} | {source} | Page: {page}")
        
        # ========== STEP 6: BUILD CONTEXT ==========
        logger.info(f"📝 Step 6: Building context...")
        
        context_parts = []
        
        # Separate user docs and KB
        user_chunks = [(doc, score) for doc, score in top_results 
                      if not doc.metadata.get('is_knowledge_base', False)]
        kb_chunks = [(doc, score) for doc, score in top_results 
                    if doc.metadata.get('is_knowledge_base', False)]
        
        # Add user document context
        if user_chunks:
            context_parts.append("=== FROM YOUR UPLOADED DOCUMENTS ===\n")
            for doc, score in user_chunks:
                source = doc.metadata.get('filename', 'unknown')
                page = doc.metadata.get('page', 'N/A')
                context_parts.append(
                    f"Document: {source} (Page {page})\n{doc.page_content}\n"
                )
        
        # Add knowledge base context
        if kb_chunks:
            context_parts.append("\n=== FROM SECURITY KNOWLEDGE BASE (CISA/IEEE/OWASP/Intel) ===\n")
            for doc, score in kb_chunks:
                source = doc.metadata.get('source', 'KB')
                title = doc.metadata.get('filename', 'Knowledge Base')
                context_parts.append(
                    f"[{source}] {title}\n{doc.page_content}\n"
                )
        
        context = "\n".join(context_parts)
        logger.info(f"✓ Context: {len(context)} chars ({len(user_chunks)} user, {len(kb_chunks)} KB)")
        
        # Return the combined context - AutoGen will handle the LLM call
        return context
    
    except Exception as e:
        logger.exception(f"✗ QA Agent error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        from .mongo_support import sanitize_retrieval_error
        return sanitize_retrieval_error(e)
