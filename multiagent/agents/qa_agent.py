# agents/qa_agent.py
import asyncio
import logging
from sentence_transformers import CrossEncoder
from langchain.chains import RetrievalQA
from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate
from langchain.schema.retriever import BaseRetriever
from langchain_core.documents import Document as LCDocument
from typing import List
from autogen_agentchat.messages import TextMessage
from .redis_manager import set_agent_state, publish_event, cache_result, get_cached_result

logger = logging.getLogger(__name__)

vectorstore = None
config = None
reranker = None  # Global re-ranker instance

def set_vectorstore(vs):
    global vectorstore, reranker
    vectorstore = vs
    
    # Initialize re-ranker model
    try:
        reranker = CrossEncoder('cross-encoder/ms-marco-MiniLM-L-6-v2')
        logger.info(" QA agent vectorstore and re-ranker initialized")
    except Exception as e:
        logger.error(f"Failed to initialize re-ranker: {e}")
        reranker = None

def set_config(cfg):
    global config
    config = cfg
    logger.info("QA agent configuration set")


class CombinedRetriever(BaseRetriever):
    """Custom retriever that returns pre-fetched documents"""
    docs: List[LCDocument]
    
    def _get_relevant_documents(self, query: str) -> List[LCDocument]:
        return self.docs
    
    async def _aget_relevant_documents(self, query: str) -> List[LCDocument]:
        return self.docs


async def rerank_documents(question: str, documents: List, top_k: int = 5):
   
    if len(documents) == 0:
        return []
    
    if reranker is None:
        logger.warning("Re-ranker not initialized, returning original documents")
        return documents[:top_k]
    
    try:
        # Prepare question-document pairs for scoring
        pairs = [[question, doc.page_content] for doc in documents]
        
        
        scores = reranker.predict(pairs)
        
        # Combine documents with their scores
        doc_score_pairs = list(zip(documents, scores))
        
        # Sort by score (highest first)
        doc_score_pairs.sort(key=lambda x: x[1], reverse=True)
        
        # Extract top_k documents
        top_docs = [doc for doc, score in doc_score_pairs[:top_k]]
        top_scores = [float(score) for doc, score in doc_score_pairs[:top_k]]
        
        logger.info(
            f"Re-ranking: {len(documents)} → {len(top_docs)} chunks. "
            f"Top scores: {[f'{s:.3f}' for s in top_scores]}"
        )
        
        return top_docs
    
    except Exception as e:
        logger.error(f"Re-ranking failed: {e}, using original order")
        return documents[:top_k]


async def answer_question_from_db(question: str, filename: str = None) -> TextMessage:
    agent_name = "qa_agent"
    
    cache_key = f"qa:{filename}:{question.lower().strip()}"
    cached = get_cached_result(cache_key)
    if cached:
        return TextMessage(content=cached, source="qa_agent")
    
    set_agent_state(agent_name, {"status": "running", "question": question})
    
    if vectorstore is None or config is None:
        raise ValueError("Vectorstore or config not initialized.")
    
    try:
        pdf_docs = []
        url_docs = []
        audio_docs = []
        image_docs = []
        
        if filename:
            file_ext = filename.split('.')[-1].lower()
            
            # PDF PROCESSING
            if file_ext == 'pdf':
                logger.info(f" Retrieving chunks for: '{question}'")
                
               
                # Direct similarity search with pre_filter (MongoDB Atlas syntax)
                pdf_candidates = vectorstore.similarity_search(
                    query=question,
                    k=10,
                    pre_filter={
                        "filename": {"$eq": filename},
                        "source_type": {"$eq": "pdf"}
                    }
                )
                
                logger.info(f"   Retrieved {len(pdf_candidates)} PDF candidates")
                
                # Re-rank
                if pdf_candidates:
                    pdf_docs = await rerank_documents(question, pdf_candidates, top_k=3)
                    logger.info(f" Selected top {len(pdf_docs)} PDF chunks")
                
                # Retrieve URLs
                url_candidates = vectorstore.similarity_search(
                    query=question,
                    k=10,
                    pre_filter={
                        "source_pdf": {"$eq": filename},
                        "source_type": {"$eq": "url"}
                    }
                )
                
                logger.info(f"   Retrieved {len(url_candidates)} URL candidates")
                
                if url_candidates:
                    url_docs = await rerank_documents(question, url_candidates, top_k=2)
                    logger.info(f" Selected top {len(url_docs)} URL chunks")
            
            # AUDIO PROCESSING
            elif file_ext in ['mp3', 'wav', 'm4a']:
                audio_candidates = vectorstore.similarity_search(
                    query=question,
                    k=10,
                    pre_filter={
                        "filename": {"$eq": filename},
                        "source_type": {"$eq": "text"}
                    }
                )
                logger.info(f"   Retrieved {len(audio_candidates)} audio candidates")
                
                if audio_candidates:
                    audio_docs = await rerank_documents(question, audio_candidates, top_k=3)
                    logger.info(f" Selected top {len(audio_docs)} audio chunks")
            
            # IMAGE PROCESSING
            elif file_ext in ['jpg', 'jpeg', 'png']:
                image_candidates = vectorstore.similarity_search(
                    query=question,
                    k=10,
                    pre_filter={
                        "filename": {"$eq": filename},
                        "source_type": {"$eq": "text"}
                    }
                )
                logger.info(f"   Retrieved {len(image_candidates)} image candidates")
                
                if image_candidates:
                    image_docs = await rerank_documents(question, image_candidates, top_k=3)
                    logger.info(f"Selected top {len(image_docs)} image chunks")
        
        else:
            # No filename - search all
            logger.info("No filename specified, searching all content")
            
            all_candidates = vectorstore.similarity_search(
                query=question,
                k=30
            )
            
            # Separate by source type
            pdf_candidates = [d for d in all_candidates if d.metadata.get('source_type') == 'pdf']
            url_candidates = [d for d in all_candidates if d.metadata.get('source_type') == 'url']
            text_candidates = [d for d in all_candidates if d.metadata.get('source_type') == 'text']
            
            # Re-rank each type
            if pdf_candidates:
                pdf_docs = await rerank_documents(question, pdf_candidates, top_k=3)
            if url_candidates:
                url_docs = await rerank_documents(question, url_candidates, top_k=3)
            if text_candidates:
                audio_docs = await rerank_documents(question, text_candidates, top_k=3)
            
            logger.info(
                f"Re-ranked: {len(pdf_docs)} PDF, {len(url_docs)} URL, "
                f"{len(audio_docs)} text chunks"
            )
        
        # Combine all re-ranked documents
        all_retrieved = pdf_docs + audio_docs + image_docs + url_docs
        
        if len(all_retrieved) == 0:
            return TextMessage(
                content=f"No relevant information found in {filename if filename else 'the uploaded content'}.",
                source="qa_agent"
            )
        
        #BUILD CONTEXT
        logger.info(f" BUILDING CONTEXT from {len(all_retrieved)} chunks...")
        
        context_parts = []
        
        for i, doc in enumerate(pdf_docs, 1):
            page = doc.metadata.get('page', 'N/A')
            chunk_preview = doc.page_content[:100].replace('\n', ' ')
            logger.info(f"   PDF Chunk {i} (Page {page}): {chunk_preview}...")
            
            context_parts.append(
                f"[Page {page}]\n{doc.page_content}"
            )
        
        for i, doc in enumerate(url_docs, 1):
            url_title = doc.metadata.get('url_title', 'webpage')
            chunk_preview = doc.page_content[:100].replace('\n', ' ')
            logger.info(f"   URL Chunk {i} ({url_title}): {chunk_preview}...")
            
            context_parts.append(
                f"[URL: {url_title}]\n{doc.page_content}"
            )
        
        for i, doc in enumerate(audio_docs, 1):
            fname = doc.metadata.get('filename', 'audio')
            context_parts.append(f"[Audio: {fname}]\n{doc.page_content}")
        
        for i, doc in enumerate(image_docs, 1):
            fname = doc.metadata.get('filename', 'image')
            context_parts.append(f"[Image: {fname}]\n{doc.page_content}")
        
        full_context = "\n\n---\n\n".join(context_parts)
        
        logger.info(f" Context built: {len(full_context)} characters")
        
        if len(full_context) == 0:
            logger.error(" CONTEXT IS EMPTY!")
            return TextMessage(
                content="Failed to build context from retrieved chunks",
                source="qa_agent"
            )
        
        # CALL LLM DIRECTLY 
        from openai import OpenAI
        import re
        
        client = OpenAI(
            base_url=config[0]["base_url"],
            api_key=config[0]["openai_api_key"]
        )
        
        system_prompt = """You are a helpful assistant that answers questions based on provided document context.

        CRITICAL RULES:
        1. Answer using ONLY the context provided below
        2. Be specific and cite page numbers when relevant
        3. If the answer is in the context, explain it thoroughly in detail
        4. If the answer is NOT in the context, say "The information is not available in the provided context"
        5. Never make up information
        6. Answer with any number of words that you think is necessary"""

        user_prompt = f"""CONTEXT:
        {full_context}

        QUESTION: {question}

        ANSWER (using only the context above):"""

        logger.info("="*80)
        logger.info(" CALLING QWEN:")
        logger.info(f"   Context length: {len(full_context)} chars")
        logger.info(f"   Question: {question}")
        logger.info("="*80)
        
        response = await asyncio.to_thread(
            client.chat.completions.create,
            model=config[0]["model"],
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.0,
            max_tokens=1500
        )
        
        answer = response.choices[0].message.content.strip()
        
        # Clean thinking tags
        #answer = re.sub(r'<think>.*?</think>', '', answer, flags=re.DOTALL).strip()
        
        # Add sources
        source_parts = []

        if len(pdf_docs) > 0:
            source_parts.append(f"{len(pdf_docs)} PDF chunk{'s' if len(pdf_docs) != 1 else ''}")

        if len(audio_docs) > 0:
            source_parts.append(f"{len(audio_docs)} audio chunk{'s' if len(audio_docs) != 1 else ''}")

        if len(image_docs) > 0:
            source_parts.append(f"{len(image_docs)} image chunk{'s' if len(image_docs) != 1 else ''}")

        if len(url_docs) > 0:
            source_parts.append(f"{len(url_docs)} URL{'s' if len(url_docs) != 1 else ''}")

        if source_parts:
            source_info = f"\n\n[Sources: {', '.join(source_parts)}]"
        else:
            source_info = ""
                
        final_answer = answer + source_info
        
        logger.info("="*80)
        logger.info(" QWEN'S RESPONSE:")
        logger.info(f"   Length: {len(final_answer)} chars")
        logger.info(f"   Preview: {final_answer[:150]}...")
        logger.info("="*80)
        
        cache_result(cache_key, final_answer)
        set_agent_state(agent_name, {"status": "completed"})
        
        return TextMessage(content=final_answer, source="qa_agent")
    
    except Exception as e:
        logger.error(f" QA FAILED: {e}", exc_info=True)
        return TextMessage(content=f"Error: {e}", source="qa_agent")