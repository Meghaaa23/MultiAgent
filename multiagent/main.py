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
from typing import List, Dict, Any
import logging
import traceback

from openai import OpenAI

from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_agentchat.conditions import TextMentionTermination, MaxMessageTermination
from autogen_agentchat.messages import TextMessage, UserMessage
from autogen_core.models import CreateResult, RequestUsage
from autogen_agentchat.base import Response
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
    title="Multi-Agent RAG System with AutoGen",
    description="AutoGen-powered multi-agent system with conversation memory",
    version="3.0.0"
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

    logger.info("✓ MongoDB client initialized (TLS verified)")

except Exception as e:
    logger.warning(f"  MongoDB initialization warning: {e}")
    logger.warning(" Will attempt connection when needed")
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
        logger.info("Vector store initialized")

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

logger.info(" All agents initialized")

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
# CONVERSATION MEMORY STORAGE
# ============================================================================

conversation_memory = {}

def get_conversation_history(session_id: str) -> List[Dict]:
    """Retrieve conversation history for a session"""
    return conversation_memory.get(session_id, [])


def add_to_conversation_history(session_id: str, role: str, content: str):
    """Add message to conversation history"""
    if session_id not in conversation_memory:
        conversation_memory[session_id] = []
    
    conversation_memory[session_id].append({
        "role": role,
        "content": content
    })
    
    # Keep last 20 messages
    if len(conversation_memory[session_id]) > 20:
        conversation_memory[session_id] = conversation_memory[session_id][-20:]


def format_conversation_context(session_id: str) -> str:
    """Format conversation history as context string"""
    history = get_conversation_history(session_id)
    
    if not history or len(history) == 0:
        return ""
    
    # Get last 5 exchanges
    recent_history = history[-10:]  # Last 5 Q&A pairs
    
    context = "\n\n**Previous Conversation:**\n"
    for msg in recent_history:
        role = "User" if msg["role"] == "user" else "Assistant"
        context += f"{role}: {msg['content'][:150]}...\n"
    
    return context

# ============================================================================
# AUTOGEN ORCHESTRATOR WITH MEMORY
# ============================================================================

async def create_conversational_assistant(session_id: str):
    """Create assistant agent for conversation only (no tool calling)"""
    
    conversation_context = format_conversation_context(session_id)
    
    system_message = f"""You are an intelligent AI assistant that helps users understand their documents.

**Your capabilities:**
- You can remember and reference previous conversations
- You provide detailed, accurate answers based on document content
- You are conversational and natural

{conversation_context}

**Instructions:**
- Be helpful and conversational
- Reference previous discussion when relevant
- Provide comprehensive answers
- If you don't know something, say so honestly"""

    # Create assistant WITHOUT tools (no function calling needed)
    return AssistantAgent(
        name="assistant",
        model_client=model_client,
        system_message=system_message
    )
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
        "service": "Multi-Agent RAG System with AutoGen Memory",
        "version": "3.0.0",
        "features": [
            "AutoGen orchestration",
            "Multi-file upload",
            "Conversation memory",
            "Intelligent agent routing"
        ]
    }


@app.get("/health")
async def health_check():
    try:
        mongo_client.admin.command('ping')
        mongo_status = "connected"
    except Exception as e:
        mongo_status = f"error: {str(e)}"
    
    return {
        "status": "healthy",
        "mongodb": mongo_status,
        "vectorstore": "initialized",
        "agents": "ready",
        "autogen": "enabled",
        "active_sessions": len(conversation_memory)
    }


@app.post("/uploadfile/")
async def upload_multiple_files(request: Request):
    """Upload multiple files for processing"""
    try:
        logger.info("=" * 80)
        logger.info(" UPLOAD REQUEST")
        logger.info("=" * 80)
        
        form = await request.form()
        logger.info(f"Form keys: {list(form.keys())}")
        
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
        
        # Create uploads directory
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
                logger.error(f"   Error: {e}")
                errors.append({
                    "filename": file.filename if hasattr(file, 'filename') else "unknown",
                    "error": str(e)
                })
        
        response = {
            "message": f"Processed {len(uploaded_files)}/{len(files_list)} files",
            "files": uploaded_files
        }
        
        if errors:
            response["errors"] = errors
        
        logger.info(f"Upload complete: {len(uploaded_files)} successful")
        
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Upload failed: {e}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


@app.post("/query/")
async def query_with_autogen_memory(request: Request):
    """Query with file processing + AutoGen memory"""
    try:
        logger.info("=" * 80)
        logger.info("QUERY WITH AUTOGEN")
        logger.info("=" * 80)
        
        body = await request.json()
        
        question = body.get("question")
        filenames = body.get("filenames", [])
        session_id = body.get("session_id", "default")
        
        if not question:
            raise HTTPException(status_code=400, detail="Missing question")
        
        logger.info(f"Question: {question}")
        logger.info(f"Files: {filenames}")
        logger.info(f"Session: {session_id}")
        logger.info(f"History: {len(get_conversation_history(session_id))} messages")
        
        # Add to memory
        add_to_conversation_history(session_id, "user", question)
        
        # ========== STEP 1: PROCESS FILES FIRST ==========
        processing_results = []
        
        if filenames and len(filenames) > 0:
            logger.info(" STEP 1: PROCESSING FILES")
            logger.info("-" * 80)
            
            for filename in filenames:
                file_path = safe_file_path(filename)
                
                if not file_path.exists():
                    error_msg = f"File not found: {filename}"
                    logger.error(error_msg)
                    raise HTTPException(status_code=404, detail=error_msg)
                
                ext = filename.split('.')[-1].lower()
                
                logger.info(f"  Processing: {filename} (type: {ext})")
                
                try:
                    if ext == 'pdf':
                        # CRITICAL: Call PDF processor and LOG the result
                        logger.info(f"    Calling process_pdf_locally for {file_path}")
                        result = await process_pdf_locally(str(file_path))
                        logger.info(f"    Result: {result}")
                        
                        if result and "Error" not in result:
                            processing_results.append(f"PDF: {filename}")
                            logger.info(f"  PDF processed successfully")
                        else:
                            processing_results.append(f" PDF Error: {filename}")
                            logger.error(f"     PDF processing returned error: {result}")
                        
                    elif ext in ['jpg', 'jpeg', 'png']:
                        logger.info(f"    Calling analyze_image_locally for {file_path}")
                        result = await analyze_image_locally(str(file_path))
                        logger.info(f"    Result: {result}")
                        processing_results.append(f"✓ Image: {filename}")
                        
                    elif ext in ['mp3', 'wav']:
                        logger.info(f"    Calling transcribe_audio_locally for {file_path}")
                        result = await transcribe_audio_locally(str(file_path))
                        logger.info(f"    Result: {result}")
                        processing_results.append(f"✓ Audio: {filename}")
                    
                    else:
                        logger.warning(f"  Unsupported file type: {ext}")
                        processing_results.append(f"  Unsupported: {filename}")
                    
                except Exception as e:
                    logger.error(f"  EXCEPTION processing {filename}: {e}")
                    logger.error(f"    Traceback:")
                    logger.error(traceback.format_exc())
                    processing_results.append(f"Error: {filename} - {str(e)}")
            
            logger.info(f"File processing complete")
            logger.info("-" * 80)
        
        # Add a small delay to ensure MongoDB indexing completes
        await asyncio.sleep(0.5)
        
        # ========== STEP 2: QUERY DATABASE ==========
        logger.info(" STEP 2: QUERYING DATABASE")
        logger.info("-" * 80)
        
        try:
            # Query MongoDB for relevant chunks
            logger.info(f"  Calling answer_question_from_db...")
            logger.info(f"    Question: {question}")
            logger.info(f"    Filenames: {filenames}")
            
            db_answer = await answer_question_from_db(
                question=question,
                filenames=filenames
            )
            
            if isinstance(db_answer, str):
                answer_from_db = db_answer
            elif hasattr(db_answer, "content"):
                answer_from_db = db_answer.content
            else:
                answer_from_db = str(db_answer)
            
            logger.info(f" Database answer received: {len(answer_from_db)} chars")
            logger.info(f"  Preview: {answer_from_db[:300]}...")
            logger.info("-" * 80)
            
        except Exception as e:
            logger.error(f" Database query EXCEPTION: {e}")
            logger.error(traceback.format_exc())
            answer_from_db = f"Error querying database: {str(e)}"
        
        # ========== STEP 3: AUTOGEN FOR CONVERSATIONAL RESPONSE ==========
        logger.info(" STEP 3: AUTOGEN CONVERSATION")
        logger.info("-" * 80)
        
        try:
            # Create assistant with memory
            assistant = await create_conversational_assistant(session_id)
            
            # Build prompt with database answer
            autogen_prompt = f"""You are answering based on information retrieved from uploaded documents.

**User's Question:** {question}

**Information Retrieved from Documents:**
{answer_from_db}

**Your Task:**
- Answer the user's question using ONLY the information provided above
- Be accurate and cite the document when appropriate
- If the information doesn't fully answer the question, say so
- Be conversational but stay factual
- If this is a follow-up question, reference our previous conversation naturally"""

            # Create team
            termination = MaxMessageTermination(max_messages=3)
            team = RoundRobinGroupChat(
                participants=[assistant],
                termination_condition=termination
            )
            
            logger.info(" Running AutoGen...")
            
            # Run AutoGen
            result = await team.run(task=autogen_prompt)
            
            logger.info(f"AutoGen completed with {len(result.messages)} messages")
            
            # Extract answer
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
                logger.warning("  No answer from AutoGen, using database answer")
                final_answer = answer_from_db
                
            logger.info("-" * 80)
            
        except Exception as e:
            logger.error(f" AutoGen EXCEPTION: {e}")
            logger.error(traceback.format_exc())
            final_answer = answer_from_db
        
        # ========== STEP 4: BUILD RESPONSE ==========
        
        # Combine processing results with answer
        if processing_results:
            full_response = "\n".join(processing_results) + "\n\n" + final_answer
        else:
            full_response = final_answer
        
        # Save to memory
        add_to_conversation_history(session_id, "assistant", full_response)
        
        logger.info("=" * 80)
        logger.info(" COMPLETE")
        logger.info(f"  Response: {len(full_response)} chars")
        logger.info(f"  Session turns: {len(get_conversation_history(session_id))}")
        logger.info("=" * 80)
        
        return {
            "answer": full_response,
            "session_id": session_id,
            "files_processed": filenames,
            "conversation_turn": len(get_conversation_history(session_id)),
            "processing_summary": processing_results
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f" QUERY FAILED WITH EXCEPTION: {e}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/clear-session/{session_id}")
async def clear_session(session_id: str):
    """Clear conversation memory for a session"""
    if session_id in conversation_memory:
        del conversation_memory[session_id]
        logger.info(f"  Cleared session: {session_id}")
        return {"message": f"Session {session_id} cleared", "success": True}
    return {"message": "Session not found", "success": False}


@app.delete("/cleanup/{filename}")
async def cleanup_file(filename: str):
    """Delete an uploaded file"""
    try:
        file_path = safe_file_path(filename)
        
        if not file_path.exists():
            raise HTTPException(status_code=404, detail=f"File not found: {filename}")
        
        file_path.unlink()
        logger.info(f"  Deleted: {filename}")
        
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
    
    logger.info(f" Starting AutoGen Multi-Agent RAG System on {host}:{port}")
    
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info"
    )
