import os
import shutil
import asyncio
import json
import atexit
from pathlib import Path
from typing import Dict, List
from enum import Enum

from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from pymongo import MongoClient
from langchain_mongodb import MongoDBAtlasVectorSearch
from langchain_community.embeddings import SentenceTransformerEmbeddings
from langchain_core.documents import Document
from agents.threat_modeling_agent import ThreatModelingAgent
from typing import List, Dict, Any
import logging
import traceback

from openai import OpenAI

from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_agentchat.conditions import TextMentionTermination, MaxMessageTermination
from autogen_agentchat.messages import TextMessage, UserMessage
from autogen_core.models import CreateResult, RequestUsage
from autogen_agentchat.base import Response, TaskResult
import certifi

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv()

# ============================================================================
# CONFIGURATION
# ============================================================================

class FinishReason(str, Enum):
    """Enum for completion finish reasons"""
    STOP = "stop"
    LENGTH = "length"
    FUNCTION_CALLS = "function_calls"
    CONTENT_FILTER = "content_filter"
    UNKNOWN = "unknown"
    
    def __str__(self):
        return self.value


# LLM Configuration
llama_base_url = os.getenv("LLAMA_BASE_URL", "http://localhost:8080")
llama_model = os.getenv("LLAMA_MODEL_NAME", "Qwen-2.5")

client = OpenAI(
    base_url=f"{llama_base_url}/v1", 
    api_key="not-needed"
)

config_list = [{
    "model": llama_model,
    "api_type": "openai",
    "openai_api_key": "not-needed",
    "base_url": f"{llama_base_url}/v1",
    "api_version": None
}]

# ============================================================================
# FASTAPI SETUP
# ============================================================================

app = FastAPI(
    title="Multi-Agent RAG System with Full AutoGen",
    description="AutoGen-powered multi-agent system with native conversation management",
    version="4.0.0"
)

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:4200,http://ems885-sidc-lab").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

# ============================================================================
# MONGODB & VECTOR STORE
# ============================================================================

mongodb_uri = os.getenv("MONGODB_ATLAS_URI")
if not mongodb_uri:
    raise ValueError("MONGODB_ATLAS_URI environment variable is required")

try:
    logger.info(" Connecting to MongoDB Atlas...")

    mongo_client = MongoClient(
        mongodb_uri,
        tls=True,
        tlsAllowInvalidCertificates=False,
        tlsCAFile=certifi.where()
    )

    logger.info(" MongoDB client initialized (TLS verified)")

except Exception as e:
    logger.warning(f"MongoDB initialization warning: {e}")
    logger.warning("Will attempt connection when needed")
    mongo_client = None

if mongo_client:
    try:
        collection = mongo_client["multiagentllm"]["RAG"]

        vectorstore = MongoDBAtlasVectorSearch(
            collection=collection,
            embedding=SentenceTransformerEmbeddings(model_name="all-MiniLM-L6-v2"),
            index_name="vector_index",
            text_key="page_content"
        )
        logger.info(" Vector store initialized")

    except Exception as e:
        logger.error(f" Failed to initialize vectorstore: {e}")
        vectorstore = None
else:
    logger.error(" MongoDB not available - system will not work properly")
    vectorstore = None


# ============================================================================
# AGENT IMPORTS & INITIALIZATION
# ============================================================================

from agents.audio_agent import transcribe_audio_locally, set_vectorstore as set_audio_vectorstore
from agents.image_agent import analyze_image_locally, set_image_vectorstore
from agents.pdf_agent import set_vectorstore as set_pdf_vectorstore, process_pdf_locally
from agents.qa_agent import set_vectorstore, set_config, answer_question_from_db
from agents.data_ingestion import set_vectorstore as set_ingest_vectorstore
from agents.url_agent import set_url_vectorstore

# Initialize all agents
set_image_vectorstore(vectorstore)
set_pdf_vectorstore(vectorstore)
set_vectorstore(vectorstore)
set_audio_vectorstore(vectorstore)
set_config(config_list)
set_ingest_vectorstore(vectorstore)
set_url_vectorstore(vectorstore)

try:
    threat_modeling_agent = ThreatModelingAgent(
        mongodb_client=mongo_client,
        openai_client=client  
    )
    logger.info(" Threat Modeling Agent initialized")
except Exception as e:
    logger.warning(f" Threat Modeling Agent initialization failed: {e}")
    threat_modeling_agent = None

logger.info("All agents initialized")

# ============================================================================
# CUSTOM LLM CLIENT FOR AUTOGEN
# ============================================================================

def message_to_openai_format(message):
    """Convert autogen message to OpenAI API format"""
    if isinstance(message, (UserMessage, TextMessage)):
        if hasattr(message, 'source') and message.source and message.source not in ['user', None]:
            return {"role": "assistant", "content": message.content}
        return {"role": "user", "content": message.content}
    
    elif hasattr(message, 'content'):
        if hasattr(message, 'source'):
            if message.source == 'user':
                return {"role": "user", "content": message.content}
            elif message.source:
                return {"role": "assistant", "content": message.content}
        
        message_type = type(message).__name__.lower()
        if 'assistant' in message_type:
            return {"role": "assistant", "content": message.content}
        else:
            return {"role": "user", "content": message.content}
    else:
        return {"role": "user", "content": str(message)}


def clean_message_history(messages):
    """Remove consecutive assistant messages and empty messages"""
    cleaned = []
    last_role = None
    
    for msg in messages:
        current_role = msg.get("role")
        content = msg.get("content", "")
        
        if not content or not str(content).strip():
            continue
        
        if current_role == "assistant" and last_role == "assistant":
            logger.warning(f"Skipping consecutive assistant message")
            continue
        
        cleaned.append(msg)
        last_role = current_role
    
    if cleaned and cleaned[0].get("role") == "assistant":
        cleaned = cleaned[1:]
    
    if not cleaned:
        cleaned = [{"role": "user", "content": "Hello"}]
    
    return cleaned


class LocalLlamaChatCompletionClient:
    """Chat completion client for local llama.cpp server"""
    
    def __init__(self, client, model_name):
        self.client = client
        self.model_name = model_name
        self.model_info = {
            "name": model_name,
            "max_tokens": 4096,
            "context_length": 4096,
            "vision": False,
            "supports_chat": True,
            "function_calling": False,  
            "json_output": False,
            "family": "llama"
        }

    async def create(self, messages, max_tokens=4096, temperature=0.1, top_p=0.9, stream=False, **kwargs):
        """Create a chat completion"""
        api_messages = [message_to_openai_format(m) for m in messages]
        api_messages = clean_message_history(api_messages)
        
        if not api_messages:
            return CreateResult(
                content="No valid messages to process",
                usage=RequestUsage(prompt_tokens=0, completion_tokens=0),
                finish_reason=FinishReason.STOP,
                cached=False
            )

        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.client.chat.completions.create(
                    model=self.model_name,
                    messages=api_messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    top_p=top_p,
                    stream=False
                )
            )
            
            if not response or not response.choices:
                return CreateResult(
                    content="No response from LLM", 
                    usage=RequestUsage(prompt_tokens=0, completion_tokens=0),
                    finish_reason=FinishReason.UNKNOWN, 
                    cached=False
                )

            choice = response.choices[0]
            message = choice.message
            
            usage_data = getattr(response, "usage", None)
            usage = RequestUsage(
                prompt_tokens=getattr(usage_data, "prompt_tokens", 0),
                completion_tokens=getattr(usage_data, "completion_tokens", 0)
            ) if usage_data else RequestUsage(prompt_tokens=0, completion_tokens=0)

            content = message.content if message.content else ""
            
            if choice.finish_reason == "stop":
                finish_reason = FinishReason.STOP
            elif choice.finish_reason == "length":
                finish_reason = FinishReason.LENGTH
            else:
                finish_reason = FinishReason.UNKNOWN

            return CreateResult(
                content=content, 
                usage=usage,
                finish_reason=finish_reason, 
                cached=False
            )

        except Exception as e:
            logger.exception(f"Error calling LLM: {e}")
            return CreateResult(
                content=f"Error: {str(e)}", 
                usage=RequestUsage(prompt_tokens=0, completion_tokens=0),
                finish_reason=FinishReason.UNKNOWN,
                cached=False
            )

    async def create_stream(self, messages, **kwargs):
        raise NotImplementedError("Streaming not implemented")


# Initialize model client
model_client = LocalLlamaChatCompletionClient(client, llama_model)

# ============================================================================
# AUTOGEN TEAM MANAGEMENT - PERSISTENT TEAMS PER SESSION
# ============================================================================

# Global storage for persistent AutoGen teams
session_teams: Dict[str, RoundRobinGroupChat] = {}
session_documents: Dict[str, List[str]] = {}


async def get_or_create_team(session_id: str) -> RoundRobinGroupChat:
    """
    Get existing AutoGen team for session or create new one.
    Teams persist across requests and maintain conversation history.
    """
    if session_id in session_teams:
        logger.info(f" Reusing existing team for session: {session_id}")
        return session_teams[session_id]
    
    logger.info(f" Creating new AutoGen team for session: {session_id}")
    
    # Create RAG assistant with document context
    rag_assistant = AssistantAgent(
        name="rag_assistant",
        model_client=model_client,
        system_message="""You are an intelligent RAG (Retrieval-Augmented Generation) assistant.

**Your Role:**
- Answer questions based on retrieved document content
- Remember previous questions and answers in this conversation
- Reference earlier discussion naturally when relevant
- Cite document sources accurately
- Detect and handle follow-up questions

**Guidelines:**
- If this is a follow-up question, reference previous context
- Always cite which document information comes from
- If information is insufficient, say so clearly
- Be conversational but accurate
- Maintain context across the entire conversation"""
    )
    
    # Create team with termination condition
    termination = MaxMessageTermination(max_messages=5)
    
    team = RoundRobinGroupChat(
        participants=[rag_assistant],
        termination_condition=termination
    )
    
    # Store team for future use
    session_teams[session_id] = team
    
    logger.info(f" Team created and stored for session: {session_id}")
    
    return team


def clear_session_team(session_id: str):
    """Clear AutoGen team for a session"""
    if session_id in session_teams:
        del session_teams[session_id]
        logger.info(f" Cleared team for session: {session_id}")
    
    if session_id in session_documents:
        del session_documents[session_id]


async def get_team_history(session_id: str) -> List[Dict]:
    """
    Extract conversation history from AutoGen team.
    Returns list of messages in the team's conversation.
    """
    if session_id not in session_teams:
        return []
    
    team = session_teams[session_id]
    
    # Access the team's message history
    history = []
    
    # Note: AutoGen's internal message storage
    if hasattr(team, '_message_thread'):
        for msg in team._message_thread:
            if hasattr(msg, 'content') and hasattr(msg, 'source'):
                history.append({
                    "role": "user" if msg.source == "user" else "assistant",
                    "content": msg.content
                })
    
    return history


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def safe_file_path(filename: str) -> Path:
    """Ensure filename doesn't contain path traversal attacks"""
    safe_name = os.path.basename(filename)
    
    if not safe_name or safe_name != filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    file_path = Path("uploads") / safe_name
    
    try:
        resolved_path = file_path.resolve()
        upload_dir = Path("uploads").resolve()
        if not str(resolved_path).startswith(str(upload_dir)):
            raise HTTPException(status_code=400, detail="Invalid filename")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    return file_path


MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    return {
        "status": "healthy",
        "service": "Multi-Agent RAG System with Threat Modeling",
        "version": "5.0.0",  
        "features": [
            "Full AutoGen orchestration",
            "Persistent conversation teams",
            "Native conversation memory",
            "Multi-document RAG",
            "Threat Modeling (STRIDE framework)",
            "Security Analysis (CISA/IEEE/Intel TDX)"
        ],
        "endpoints": {
            "/query/": "General queries with AutoGen (auto-routes security questions)",
            "/threat-modeling/": "Dedicated security analysis endpoint",
            "/health": "System health check",
            "/documents": "List all documents",
            "/sessions": "List active sessions"
        }
    }

@app.get("/health")
async def health_check():
    try:
        mongo_client.admin.command('ping')
        mongo_status = "connected"
    except Exception as e:
        mongo_status = f"error: {str(e)}"
    
    
    threat_modeling_status = "available" if threat_modeling_agent else "not initialized"
    
    return {
        "status": "healthy",
        "mongodb": mongo_status,
        "vectorstore": "initialized",
        "agents": "ready",
        "autogen": "enabled",
        "threat_modeling": threat_modeling_status,  
        "active_sessions": len(session_teams),
        "features": [
            "Multi-document RAG",
            "AutoGen orchestration",
            "Persistent conversations",
            "Threat modeling (STRIDE framework)",  
            "Security analysis (CISA/IEEE/Intel)"  
        ]
    }


@app.get("/documents")
async def list_all_documents():
    """List all documents available in the database"""
    try:
        from pymongo import MongoClient
        
        mongodb_uri = os.getenv("MONGODB_ATLAS_URI")
        mongo_client = MongoClient(mongodb_uri)
        collection = mongo_client["multiagentllm"]["RAG"]
        
        # Get unique filenames
        pipeline = [
            {"$group": {
                "_id": "$filename",
                "count": {"$sum": 1},
                "first_upload": {"$min": "$_id"}
            }},
            {"$sort": {"first_upload": -1}}
        ]
        
        result = collection.aggregate(pipeline)
        
        documents = []
        for doc in result:
            if doc["_id"]:
                documents.append({
                    "filename": doc["_id"],
                    "chunk_count": doc["count"]
                })
        
        return {
            "total_documents": len(documents),
            "documents": documents
        }
    
    except Exception as e:
        logger.error(f"Error listing documents: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/uploadfile/")
async def upload_multiple_files(request: Request):
    """Upload multiple files for processing"""
    try:
        logger.info("=" * 80)
        logger.info(" UPLOAD REQUEST")
        logger.info("=" * 80)
        
        form = await request.form()
        
        # Extract files
        files_list = []
        for key in form.keys():
            value = form.getlist(key) if hasattr(form, 'getlist') else [form[key]]
            for item in value:
                if hasattr(item, 'filename') and item.filename:
                    files_list.append(item)
        
        logger.info(f"Found {len(files_list)} file(s)")
        
        if not files_list:
            raise HTTPException(status_code=400, detail="No files provided")
        
        os.makedirs("uploads", exist_ok=True)
        
        uploaded_files = []
        errors = []
        
        for idx, file in enumerate(files_list):
            try:
                logger.info(f"Processing {idx + 1}/{len(files_list)}: {file.filename}")
                
                ext = file.filename.split('.')[-1].lower()
                allowed = ["pdf", "jpg", "jpeg", "png", "mp3", "wav"]
                
                if ext not in allowed:
                    errors.append({
                        "filename": file.filename,
                        "error": f"Unsupported type '.{ext}'"
                    })
                    continue
                
                file_path = safe_file_path(file.filename)
                content = await file.read()
                
                if len(content) > MAX_FILE_SIZE:
                    errors.append({
                        "filename": file.filename,
                        "error": "File too large"
                    })
                    continue
                
                with open(file_path, "wb") as buffer:
                    buffer.write(content)
                
                uploaded_files.append({
                    "filename": file.filename,
                    "file_type": ext,
                    "size_bytes": len(content),
                    "path": str(file_path)
                })
                
                logger.info(f" Saved: {file.filename}")
                
            except Exception as e:
                logger.error(f" Error: {e}")
                errors.append({
                    "filename": file.filename if hasattr(file, 'filename') else "unknown",
                    "error": str(e)
                })
        
        uploaded_filenames = [f["filename"] for f in uploaded_files]
        
        response = {
            "message": f"Processed {len(uploaded_files)}/{len(files_list)} files",
            "files": uploaded_files,
            "filenames": uploaded_filenames,
            "success": len(uploaded_files) > 0
        }
        
        if errors:
            response["errors"] = errors
        
        logger.info(f" Upload complete: {len(uploaded_files)} successful")
        
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" Upload failed: {e}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


@app.post("/query/")
async def query_with_full_autogen(request: Request):
    """
    Query with Full AutoGen - native conversation management
    Enhanced with automatic threat modeling detection
    
    Routes:
    - Security questions (no docs) → Threat Modeling Agent
    - Security questions (with docs) → AutoGen RAG (future: hybrid)
    - General questions → AutoGen RAG
    """
    try:
        logger.info("=" * 80)
        logger.info(" QUERY REQUEST")
        logger.info("=" * 80)
        
        body = await request.json()
        
        question = body.get("question")
        filenames = body.get("filenames", [])
        session_id = body.get("session_id", "default")
        uploaded_files = body.get("uploaded_files", [])
        use_all_docs = body.get("use_all_docs", False)
        force_threat_modeling = body.get("use_threat_modeling", False)  # NEW: explicit flag
        
        if not question:
            raise HTTPException(status_code=400, detail="Missing question")
        
        logger.info(f"Question: {question}")
        logger.info(f"Session: {session_id}")
        
        # ========== NEW: THREAT MODELING ROUTING LOGIC ==========
        
        # Detect if this is a security query
        is_security_query = (
            threat_modeling_agent and 
            threat_modeling_agent.is_security_query(question)
        )
        
        # Check for document context
        has_new_uploads = uploaded_files and len(uploaded_files) > 0
        has_existing_files = (
            (filenames and len(filenames) > 0) or 
            (session_id in session_documents and session_documents[session_id]) or
            use_all_docs
        )
        
        # ROUTING DECISION: Use Threat Modeling if security query without documents
        if force_threat_modeling or (is_security_query and not has_new_uploads and not has_existing_files):
            logger.info("  ROUTING: Threat Modeling Agent")
            logger.info("  Reason: Security query with no document context")
            logger.info("-" * 80)
            
            try:
                result = await threat_modeling_agent.analyze(
                    user_query=question,
                    verbose=True
                )
                
                logger.info("=" * 80)
                logger.info("✓ THREAT MODELING COMPLETE")
                logger.info(f"  Report length: {len(result['report'])} chars")
                logger.info(f"  Sources: {result['reasoning_chain']['research_summary']['sources_used']}")
                logger.info("=" * 80)
                
                return {
                    "answer": result["report"],
                    "session_id": session_id,
                    "query_type": "threat_modeling",
                    "reasoning_chain": result["reasoning_chain"],
                    "sources_used": result["reasoning_chain"]["research_summary"]["sources_used"],
                    "total_findings": result["reasoning_chain"]["research_summary"]["total_findings"],
                    "routed_to": "threat_modeling_agent",
                    "files_searched": "knowledge_base",
                    "files_processed": [],
                    "conversation_messages": 0,
                    "processing_summary": [],
                    "search_scope": "security_knowledge_base",
                    "team_persistent": False
                }
                
            except Exception as e:
                logger.error(f"  Threat modeling failed: {e}")
                logger.error(traceback.format_exc())
                logger.warning("  Falling back to AutoGen RAG flow")
                # Fall through to normal AutoGen flow below
        
        else:
            logger.info(" ROUTING: AutoGen Multi-Agent RAG")
            if is_security_query:
                logger.info("  Note: Security query but has document context - using RAG")
                logger.info("  (Future enhancement: hybrid threat modeling + document analysis)")
            logger.info("-" * 80)
        
        # ========== EXISTING AUTOGEN RAG FLOW (UNCHANGED) ==========
        
        logger.info(f"Target Files: {filenames}")
        logger.info(f"Newly Uploaded: {uploaded_files}")
        logger.info(f"Use All Docs: {use_all_docs}")
        
        # ========== STEP 1: PROCESS NEWLY UPLOADED FILES ==========
        processing_results = []
        
        if uploaded_files and len(uploaded_files) > 0:
            logger.info("📁 STEP 1: PROCESSING NEWLY UPLOADED FILES")
            logger.info("-" * 80)
            
            for filename in uploaded_files:
                file_path = safe_file_path(filename)
                
                if not file_path.exists():
                    error_msg = f"File not found: {filename}"
                    logger.error(error_msg)
                    raise HTTPException(status_code=404, detail=error_msg)
                
                ext = filename.split('.')[-1].lower()
                
                logger.info(f"  Processing NEW file: {filename} (type: {ext})")
                
                try:
                    if ext == 'pdf':
                        result = await process_pdf_locally(str(file_path))
                        if result and "Error" not in result:
                            processing_results.append(f"✓ Processed PDF: {filename}")
                            if session_id not in session_documents:
                                session_documents[session_id] = []
                            if filename not in session_documents[session_id]:
                                session_documents[session_id].append(filename)
                        else:
                            processing_results.append(f"✗ PDF Error: {filename}")
                        
                    elif ext in ['jpg', 'jpeg', 'png']:
                        result = await analyze_image_locally(str(file_path))
                        processing_results.append(f"✓ Processed Image: {filename}")
                        if session_id not in session_documents:
                            session_documents[session_id] = []
                        if filename not in session_documents[session_id]:
                            session_documents[session_id].append(filename)
                        
                    elif ext in ['mp3', 'wav']:
                        result = await transcribe_audio_locally(str(file_path))
                        processing_results.append(f"✓ Processed Audio: {filename}")
                        if session_id not in session_documents:
                            session_documents[session_id] = []
                        if filename not in session_documents[session_id]:
                            session_documents[session_id].append(filename)
                    
                    else:
                        processing_results.append(f"⚠ Unsupported: {filename}")
                    
                except Exception as e:
                    logger.error(f"  ✗ EXCEPTION processing {filename}: {e}")
                    processing_results.append(f"✗ Error: {filename} - {str(e)}")
            
            logger.info(f"✓ File processing complete")
            logger.info("-" * 80)
            
            await asyncio.sleep(0.5)
        else:
            logger.info("📁 STEP 1: NO NEW FILES")
            logger.info("-" * 80)
        
        # ========== STEP 2: DETERMINE SEARCH SCOPE ==========
        logger.info("🔍 STEP 2: DETERMINING SEARCH SCOPE")
        logger.info("-" * 80)
        
        search_filenames = []
        
        if use_all_docs:
            logger.info("  Searching ALL documents in database")
            search_filenames = []
        elif filenames and len(filenames) > 0:
            logger.info(f"  Searching specific files: {filenames}")
            search_filenames = filenames
        elif session_id in session_documents and session_documents[session_id]:
            logger.info(f"  Using session context: {session_documents[session_id]}")
            search_filenames = session_documents[session_id]
        else:
            logger.info("  No specific files - will search all documents")
            search_filenames = []
        
        logger.info(f"✓ Search scope: {search_filenames if search_filenames else 'ALL DOCUMENTS'}")
        logger.info("-" * 80)
        
        # ========== STEP 3: RETRIEVE RELEVANT CONTENT ==========
        logger.info("📚 STEP 3: RETRIEVING RELEVANT CONTENT")
        logger.info("-" * 80)
        
        try:
            # Use QA agent to get relevant context
            db_answer = await answer_question_from_db(
                question=question,
                filenames=search_filenames
            )
            
            if isinstance(db_answer, str):
                retrieved_context = db_answer
            elif hasattr(db_answer, "content"):
                retrieved_context = db_answer.content
            else:
                retrieved_context = str(db_answer)
            
            logger.info(f"✓ Retrieved context: {len(retrieved_context)} chars")
            logger.info("-" * 80)
            
        except Exception as e:
            logger.error(f"✗ Retrieval EXCEPTION: {e}")
            logger.error(traceback.format_exc())
            retrieved_context = f"Error retrieving context: {str(e)}"
        
        # ========== STEP 4: AUTOGEN TEAM CONVERSATION ==========
        logger.info("🤖 STEP 4: AUTOGEN TEAM CONVERSATION")
        logger.info("-" * 80)
        
        try:
            # Get or create persistent team for this session
            team = await get_or_create_team(session_id)
            
            # Build task message with retrieved context
            task_message = f"""**User Question:** {question}

**Retrieved Information from Documents:**
{retrieved_context}

**Instructions:**
- Answer the user's question using the retrieved information
- Reference previous conversation if this is a follow-up question
- Cite document sources when appropriate
- Be conversational and maintain context across our discussion"""

            logger.info("  Running AutoGen team (with conversation history)...")
            
            # Run team - it maintains its own conversation history!
            result: TaskResult = await team.run(task=task_message)
            
            logger.info(f"✓ AutoGen completed")
            logger.info(f"  Messages in conversation: {len(result.messages)}")
            
            # Extract final answer from team's response
            final_answer = ""
            if result.messages:
                for msg in reversed(result.messages):
                    if hasattr(msg, 'content') and msg.content:
                        content = str(msg.content).strip()
                        if content and len(content) > 20:
                            final_answer = content
                            logger.info(f"  Found answer: {len(final_answer)} chars")
                            break
            
            if not final_answer:
                logger.warning("  ⚠ No answer from AutoGen, using retrieved context")
                final_answer = retrieved_context
                
            logger.info("-" * 80)
            
        except Exception as e:
            logger.error(f"✗ AutoGen EXCEPTION: {e}")
            logger.error(traceback.format_exc())
            final_answer = retrieved_context
        
        # ========== STEP 5: BUILD RESPONSE ==========
        
        if processing_results:
            full_response = "\n".join(processing_results) + "\n\n" + final_answer
        else:
            full_response = final_answer
        
        # Get conversation history from team
        history = await get_team_history(session_id)
        
        logger.info("=" * 80)
        logger.info("✓ QUERY COMPLETE")
        logger.info(f"  Response: {len(full_response)} chars")
        logger.info(f"  Conversation messages: {len(history)}")
        logger.info(f"  Routed to: AutoGen RAG")
        logger.info("=" * 80)
        
        return {
            "answer": full_response,
            "session_id": session_id,
            "query_type": "autogen_rag",
            "files_searched": search_filenames if search_filenames else "all",
            "files_processed": uploaded_files,
            "conversation_messages": len(history),
            "processing_summary": processing_results,
            "search_scope": "all_documents" if not search_filenames else "specific_files",
            "team_persistent": True,
            "routed_to": "autogen_rag"
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"✗ QUERY FAILED: {e}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))
  

@app.post("/threat-modeling/")
async def threat_modeling_query(request: Request):
    """
    Dedicated endpoint for threat modeling and security analysis.
    Uses CISA/IEEE/Intel TDX knowledge base for security reasoning.
    """
    try:
        logger.info("=" * 80)
        logger.info("  THREAT MODELING QUERY")
        logger.info("=" * 80)
        
        body = await request.json()
        
        question = body.get("question")
        session_id = body.get("session_id", "default")
        verbose = body.get("verbose", True)
        
        if not question:
            raise HTTPException(status_code=400, detail="Missing question")
        
        if not threat_modeling_agent:
            raise HTTPException(
                status_code=503, 
                detail="Threat Modeling Agent not available. Check knowledge base setup."
            )
        
        logger.info(f"Security Question: {question}")
        logger.info(f"Session: {session_id}")
        
        # Check if it's actually a security question
        if not threat_modeling_agent.is_security_query(question):
            logger.warning("⚠ Question doesn't appear to be security-related")
            return {
                "answer": "This doesn't appear to be a security-related question. "
                         "Threat modeling is designed for cybersecurity analysis. "
                         "Please use the regular /query/ endpoint for general questions.",
                "is_security_query": False,
                "session_id": session_id
            }
        
        # Run threat modeling analysis
        logger.info("🛡️  Running threat modeling analysis...")
        
        result = await threat_modeling_agent.analyze(
            user_query=question,
            verbose=verbose
        )
        
        logger.info("=" * 80)
        logger.info(" THREAT MODELING COMPLETE")
        logger.info(f"  Report length: {len(result['report'])} chars")
        logger.info(f"  Sources used: {result['reasoning_chain']['research_summary']['sources_used']}")
        logger.info("=" * 80)
        
        return {
            "answer": result["report"],
            "session_id": session_id,
            "query_type": "threat_modeling",
            "reasoning_chain": result["reasoning_chain"],
            "timestamp": result["timestamp"],
            "sources_used": result["reasoning_chain"]["research_summary"]["sources_used"],
            "total_findings": result["reasoning_chain"]["research_summary"]["total_findings"]
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"  THREAT MODELING FAILED: {e}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/session/{session_id}/history")
async def get_session_history(session_id: str):
    """Get AutoGen conversation history for a session"""
    history = await get_team_history(session_id)
    
    if not history:
        return {
            "session_id": session_id,
            "exists": False,
            "message": "No conversation history found",
            "history": []
        }
    
    # Format into Q&A pairs
    qa_pairs = []
    for i in range(0, len(history), 2):
        if i + 1 < len(history):
            qa_pairs.append({
                "turn": (i // 2) + 1,
                "question": history[i]["content"],
                "answer": history[i + 1]["content"]
            })
    
    return {
        "session_id": session_id,
        "exists": True,
        "total_messages": len(history),
        "total_turns": len(qa_pairs),
        "history": qa_pairs
    }


@app.post("/clear-session/{session_id}")
async def clear_session(session_id: str):
    """Clear AutoGen team and conversation memory for a session"""
    clear_session_team(session_id)
    
    return {
        "message": f"Session {session_id} cleared (team destroyed)",
        "session_id": session_id,
        "success": True
    }


@app.get("/sessions")
async def list_active_sessions():
    """List all active AutoGen sessions"""
    sessions = []
    
    for session_id in session_teams.keys():
        history = await get_team_history(session_id)
        
        sessions.append({
            "session_id": session_id,
            "total_messages": len(history),
            "total_turns": len(history) // 2,
            "has_documents": session_id in session_documents,
            "documents": session_documents.get(session_id, [])
        })
    
    return {
        "total_sessions": len(sessions),
        "sessions": sessions
    }


@app.delete("/cleanup/{filename}")
async def cleanup_file(filename: str):
    """Delete an uploaded file"""
    try:
        file_path = safe_file_path(filename)
        
        if not file_path.exists():
            raise HTTPException(status_code=404, detail=f"File not found: {filename}")
        
        file_path.unlink()
        logger.info(f" Deleted: {filename}")
        
        return {"message": f"Successfully deleted {filename}"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# CLEANUP
# ============================================================================

@atexit.register
def cleanup_uploads():
    """Clean up uploaded files on server shutdown"""
    upload_dir = Path("uploads")
    if upload_dir.exists():
        file_count = 0
        for file_path in upload_dir.glob("*"):
            try:
                if file_path.is_file():
                    file_path.unlink()
                    file_count += 1
            except Exception as e:
                logger.error(f"Failed to delete {file_path}: {e}")
        if file_count > 0:
            logger.info(f" Cleaned up {file_count} files")


# ============================================================================
# STARTUP
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    
    logger.info(f" Starting Full AutoGen Multi-Agent RAG System on {host}:{port}")
    
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info"
    )