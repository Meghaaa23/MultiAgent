import os
import logging
from typing import List
from openai import OpenAI
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
logger.info(" Re-ranker model loaded")


def set_vectorstore(vectorstore):
    """Set the vector store instance"""
    global _vectorstore
    _vectorstore = vectorstore
    logger.info(" QA Agent: Vector store configured")


def set_config(config_list):
    """Set the LLM configuration"""
    global _config
    _config = config_list
    logger.info(" QA Agent: LLM config set")


async def answer_question_from_db(question: str, filenames: List[str]) -> str:
    """Answer questions using vector similarity search with re-ranking"""
    
    logger.info(f" QA Agent: Processing question")
    logger.info(f"   Question: {question}")
    logger.info(f"   Files: {filenames if filenames else 'All documents'}")
    
    # Check if vectorstore is initialized
    if not _vectorstore:
        logger.error(" Vector store not initialized!")
        return "Error: Vector store not initialized. Please check system configuration."
    
    try:
        # ========== STEP 1: DIRECT MONGODB CHECK ==========
        logger.info(" Step 1: Checking MongoDB directly...")
        
        from pymongo import MongoClient
        mongodb_uri = os.getenv("MONGODB_ATLAS_URI")
        mongo_client = MongoClient(mongodb_uri)
        collection = mongo_client["multiagentllm"]["RAG"]
        
        # Check total documents
        total_docs = collection.count_documents({})
        logger.info(f"   Total documents in DB: {total_docs}")
        
        if total_docs == 0:
            return "No documents have been processed yet. Please upload and process documents first."
        
        # Check for specific filenames
        if filenames and len(filenames) > 0:
            for filename in filenames:
                count_filename = collection.count_documents({"filename": filename})
                logger.info(f"   '{filename}': {count_filename} docs")
        
        # ========== STEP 2: VECTOR SEARCH ==========
        logger.info(f"🔍 Step 2: Vector search...")
        
        results = []
        
        if not filenames or len(filenames) == 0:
            logger.info("   Searching across all documents")
            results = _vectorstore.similarity_search(query=question, k=10)
            logger.info(f"   Retrieved {len(results)} chunks")
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
                        logger.info(f" Found {len(file_results)} chunks")
                        results.extend(file_results)
                        file_found = True
                except Exception as e:
                    logger.debug(f"     Strategy 1 failed: {e}")
                
                # Strategy 2: Manual filter as fallback
                if not file_found:
                    try:
                        logger.info(f"     Trying unfiltered search...")
                        all_results = _vectorstore.similarity_search(query=question, k=50)
                        
                        filtered_results = []
                        for doc in all_results:
                            doc_filename = doc.metadata.get('filename', '')
                            if doc_filename == filename:
                                filtered_results.append(doc)
                        
                        if filtered_results:
                            logger.info(f" Found {len(filtered_results)} chunks (manual filter)")
                            results.extend(filtered_results[:10])
                        else:
                            logger.warning(f"  No chunks found for {filename}")
                    except Exception as e:
                        logger.error(f"     Strategy 2 failed: {e}")
        
        logger.info(f"   Total retrieved: {len(results)} chunks")
        
        # If no results, return error
        if not results or len(results) == 0:
            logger.error(" No chunks found")
            return "No relevant information found in the documents."
        
        # ========== STEP 3: RE-RANKING WITH DIVERSITY ==========
        logger.info(f" Step 3: Re-ranking {len(results)} chunks...")
        
        passages = [doc.page_content for doc in results]
        pairs = [[question, passage] for passage in passages]
        scores = reranker.predict(pairs)
        
        scored_results = list(zip(results, scores))
        scored_results.sort(key=lambda x: x[1], reverse=True)
        
        # Ensure diversity across files for multi-file queries
        if filenames and len(filenames) > 1:
            logger.info(f"   Multiple files - ensuring diverse selection")
            
            results_by_file = {}
            for doc, score in scored_results:
                fname = doc.metadata.get('filename', 'unknown')
                if fname not in results_by_file:
                    results_by_file[fname] = []
                results_by_file[fname].append((doc, score))
            
            top_results = []
            chunks_per_file = max(2, 6 // len(filenames))
            
            for fname in filenames:
                if fname in results_by_file:
                    file_chunks = results_by_file[fname][:chunks_per_file]
                    top_results.extend(file_chunks)
                    logger.info(f"   Selected {len(file_chunks)} from {fname}")
            
            # Add more from highest scoring if needed
            while len(top_results) < 6 and len(top_results) < len(scored_results):
                for doc, score in scored_results:
                    if (doc, score) not in top_results:
                        top_results.append((doc, score))
                        if len(top_results) >= 6:
                            break
            
            top_results.sort(key=lambda x: x[1], reverse=True)
        else:
            top_results = scored_results[:3]
        
        logger.info(f"✓ Selected {len(top_results)} chunks:")
        for idx, (doc, score) in enumerate(top_results):
            source = doc.metadata.get('filename', 'unknown')
            page = doc.metadata.get('page', 'N/A')
            logger.info(f"   {idx + 1}. Score: {score:.4f}, {source}, Page: {page}")
        
        # ========== STEP 4: BUILD CONTEXT ==========
        logger.info(f" Step 4: Building context...")
        
        context_parts = []
        for doc, score in top_results:
            source = doc.metadata.get('filename', 'unknown')
            page = doc.metadata.get('page', 'N/A')
            context_parts.append(
                f"=== Document: {source} (Page {page}) ===\n{doc.page_content}\n"
            )
        
        context = "\n".join(context_parts)
        logger.info(f"✓ Context: {len(context)} chars")
        
        # ========== STEP 5: CALL LLM ==========
        logger.info(f" Step 5: Calling LLM...")
        
        if filenames and len(filenames) > 1:
            file_list = ", ".join([f"'{f}'" for f in filenames])
            system_prompt = f"""You are a helpful AI assistant. The user uploaded multiple documents: {file_list}

When answering:
1. Clearly identify which document each piece of information comes from
2. Address each document separately if the question involves multiple documents
3. State clearly if information is only in one document
4. Be precise about sources"""
        else:
            system_prompt = "You are a helpful AI assistant that answers questions based on document context."
        
        prompt = f"""Context from documents:
{context}

Question: {question}

Instructions:
- Cite which document each piece of information comes from
- If the question involves multiple documents, address each one
- Be accurate and specific about sources"""
        
        try:
            llama_base_url = os.getenv('LLAMA_BASE_URL', 'http://localhost:8080')
            llama_model = os.getenv('LLAMA_MODEL_NAME', 'Qwen-2.5')
            
            client = OpenAI(
                base_url=f"{llama_base_url}/v1",
                api_key="not-needed"
            )
            
            response = client.chat.completions.create(
                model=llama_model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=2000,
                temperature=0.1
            )
            
            answer = response.choices[0].message.content
            logger.info(f" Answer: {len(answer)} chars")
            
            return answer
            
        except Exception as e:
            logger.error(f" LLM failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return f"Error generating answer: {str(e)}"
    
    except Exception as e:
        logger.exception(f" QA Agent error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return f"Error: {str(e)}"