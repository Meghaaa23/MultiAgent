import os
import shutil
import asyncio
import json
import atexit
from pathlib import Path
from typing import Dict
from enum import Enum

from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from pymongo import MongoClient
from langchain_mongodb import MongoDBAtlasVectorSearch
from langchain_community.embeddings import SentenceTransformerEmbeddings
from langchain_core.documents import Document
import logging
import traceback


from openai import OpenAI
from autogen_agentchat.agents import AssistantAgent, UserProxyAgent
from autogen_agentchat.messages import TextMessage, UserMessage, BaseMessage
from autogen_core import CancellationToken
from autogen_core.models import CreateResult, RequestUsage

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# ============================================================================
# CONFIGURATION & VALIDATION
# ============================================================================

class FinishReason(str, Enum):
    """Enum for completion finish reasons"""
    STOP = "stop"
    LENGTH = "length"
    TOOL_CALLS = "tool_calls"
    ERROR = "error"
    OTHER = "other"
    
    def __str__(self):
        return self.value



'''
# Initialize Azure OpenAI client
client = AzureOpenAI(
    api_version=api_version,
    azure_endpoint=endpoint,
    api_key=subscription_key,
)

config_list = [{
    "model": deployment_name,
    "api_type": "azure",
    "openai_api_key": subscription_key,
    "base_url": endpoint,
    "api_version": api_version
}]
'''
#LLAMA Model

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
# FASTAPI APP SETUP
# ============================================================================

app = FastAPI(
    title="Multi-Agent RAG System",
    description="Process PDFs, images, and audio files with AI agents",
    version="1.0.0"
)

# CORS configuration - frontend
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

# ============================================================================
# MONGODB & VECTOR STORE SETUP
# ============================================================================

mongodb_uri = os.getenv("MONGODB_ATLAS_URI")
if not mongodb_uri:
    raise ValueError("MONGODB_ATLAS_URI environment variable is required")

try:
    mongo_client = MongoClient(
        mongodb_uri,
        maxPoolSize=50,
        minPoolSize=10,
        maxIdleTimeMS=30000,
        connectTimeoutMS=5000,
        serverSelectionTimeoutMS=5000
    )
    # Test connection
    mongo_client.admin.command('ping')
    logger.info("Connected to MongoDB Atlas")
except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {e}")
    raise

collection = mongo_client["multiagentllm"]["RAG"]
vectorstore = MongoDBAtlasVectorSearch(
    collection=collection,
    embedding=SentenceTransformerEmbeddings(model_name="all-MiniLM-L6-v2"),
    index_name="vector_index",
    text_key="page_content"
)
logger.info(f"Vector store initialized with model: {vectorstore.embeddings}")

# ============================================================================
# AGENT IMPORTS & INITIALIZATION
# ============================================================================

from agents.audio_agent import transcribe_audio_locally, set_vectorstore as set_audio_vectorstore
from agents.image_agent import analyze_image_locally, set_image_vectorstore
from agents.pdf_agent import set_vectorstore as set_pdf_vectorstore, process_pdf_locally
from agents.qa_agent import set_vectorstore, set_config, answer_question_from_db
from agents.data_ingestion import set_vectorstore as set_ingest_vectorstore
from agents.url_agent import set_url_vectorstore

# Set vectorstore for all agents
set_image_vectorstore(vectorstore)
set_pdf_vectorstore(vectorstore)
set_vectorstore(vectorstore)
set_audio_vectorstore(vectorstore)
set_config(config_list)
set_ingest_vectorstore(vectorstore)
set_url_vectorstore(vectorstore)


# ============================================================================
# MODEL CLIENT IMPLEMENTATION
# ============================================================================


def message_to_openai_format(message):
    """Convert autogen message to OpenAI API format"""
    if isinstance(message, (UserMessage, TextMessage)):
        return {"role": "user", "content": message.content}
    
    elif hasattr(message, 'content'):
        
        message_type = type(message).__name__.lower()
        if 'assistant' in message_type:
            return {"role": "assistant", "content": message.content}
        else:
            return {"role": "system", "content": message.content}
    else:
        return {"role": "system", "content": str(message)}


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
            "function_calling": True,
            "json_output": False,
            "family": "llama"
        }

    async def create(self, messages, max_tokens=4096, temperature=0.0, top_p=0.9, stream=False, **kwargs):
        """Create a chat completion"""
        # Format messages
        api_messages = [message_to_openai_format(m) for m in messages]
        
        # Handle tools 
        autogen_tools = kwargs.get("tools", [])
        api_kwargs = {}
        
        if autogen_tools:
            functions_list = []
            for t in autogen_tools:
                try:
                    if hasattr(t, "to_openai_tool"):
                        functions_list.append(t.to_openai_tool())
                except Exception as e:
                    logger.warning(f"Failed to convert tool {t}: {e}")
            
            if functions_list:
                api_kwargs["tools"] = functions_list
                api_kwargs["tool_choice"] = kwargs.get("tool_choice", "auto")

        try:
            # Call local llama.cpp server
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.client.chat.completions.create(
                    model=self.model_name,
                    messages=api_messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    top_p=top_p,
                    stream=False,
                    **api_kwargs
                )
            )
            
            if not response or not response.choices:
                return CreateResult(
                    content="Llama server returned no response.", 
                    usage=None, 
                    finish_reason=FinishReason.ERROR, 
                    cached=False
                )

            choice = response.choices[0]
            message = choice.message
            
            # Extract usage
            usage_data = getattr(response, "usage", None)
            usage = RequestUsage(
                prompt_tokens=getattr(usage_data, "prompt_tokens", 0),
                completion_tokens=getattr(usage_data, "completion_tokens", 0)
            ) if usage_data else None

            # Handle function calls
            function_calls = []
            if getattr(message, "tool_calls", None):
                from autogen_agentchat.messages import FunctionCall
                
                for tc in message.tool_calls:
                    try:
                        args = tc.function.arguments
                        if isinstance(args, str):
                            args = json.loads(args) if args else {}
                        
                        function_calls.append(FunctionCall(
                            id=tc.id, 
                            name=tc.function.name,
                            arguments=json.dumps(args) if not isinstance(args, str) else args,
                        ))
                    except Exception as e:
                        logger.error(f"Failed to parse tool call: {e}")

            # Determine content and finish reason
            if function_calls:
                content = function_calls
                finish_reason = FinishReason.TOOL_CALLS
            else:
                
                raw_content = message.content
                content = raw_content
                
                if choice.finish_reason == "stop":
                    finish_reason = FinishReason.STOP
                elif choice.finish_reason == "length":
                    finish_reason = FinishReason.LENGTH
                else:
                    finish_reason = FinishReason.OTHER

            return CreateResult(
                content=content, 
                usage=usage,
                finish_reason=finish_reason, 
                cached=False 
            )

        except Exception as e:
            logger.exception(f"Error calling llama server at {llama_base_url}")
            return CreateResult(
                content=f"Error calling Llama: {str(e)}", 
                usage=None, 
                finish_reason=FinishReason.ERROR,
                cached=False 
            )

    async def create_stream(self, messages, **kwargs):
        raise NotImplementedError("Streaming not implemented")

# Initialize with local client
model_client = LocalLlamaChatCompletionClient(client, llama_model)

# ============================================================================
# AGENT SETUP
# ============================================================================

assistant = AssistantAgent(
    name="powerful_assistant",
    system_message="""You are a helpful and concise AI assistant.

    Always answer the user's question **directly** based on the uploaded document, image, or audio file.
    Do not explain your reasoning, do not describe your process, and do not say things like
    'let me check', 'processing', or 'retrieving'.

    If the answer is found in the retrieved text, summarize it clearly more than 500 words
    

    Your workflow is as follows:
    1. A user provides a file and a question.
    2. Identify the file type (PDF, image, or audio) and use the correct tool to process the file and add its content to the vector database.
    3. Once the content is in the database, use the 'answer_question_from_db' tool to find the answer to the user's question.
    4. Provide the final answer to the user.
    """,
    model_client=model_client,
    tools=[
        process_pdf_locally,
        analyze_image_locally,
        transcribe_audio_locally,
        answer_question_from_db
    ]
)

user_proxy = UserProxyAgent(name="user_proxy")

logger.info(" Assistant agent configured with tools")

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def safe_file_path(filename: str) -> Path:
    """
    Ensure filename doesn't contain path traversal attacks.
    
    Args:
        filename: The filename from user input
        
    Returns:
        Safe Path object
        
    Raises:
        HTTPException: If filename is invalid
    """
    # Remove any path separators and get just the filename
    safe_name = os.path.basename(filename)
    
    if not safe_name or safe_name != filename:
        raise HTTPException(status_code=400, detail="Invalid filename - path traversal not allowed")
    
    # Create path in uploads directory
    file_path = Path("uploads") / safe_name
    
    # Verify it's actually in uploads dir
    try:
        resolved_path = file_path.resolve()
        upload_dir = Path("uploads").resolve()
        if not str(resolved_path).startswith(str(upload_dir)):
            raise HTTPException(status_code=400, detail="Invalid filename")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    return file_path

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

async def validate_file_type(file: UploadFile) -> str:
    """
    Validate file type by extension.
    
    Args:
        file: Uploaded file
        
    Returns:
        File extension (lowercase)
        
    Raises:
        HTTPException: If file type is invalid
    """
    # Check extension
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")
    
    ext = file.filename.split('.')[-1].lower()
    allowed = ["pdf", "jpg", "jpeg", "png", "mp3", "wav"]
    
    if ext not in allowed:
        raise HTTPException(
            status_code=400, 
            detail=f"Unsupported file type '{ext}'. Allowed: {', '.join(allowed)}"
        )
    
    return ext

# ============================================================================
# FILE CLEANUP
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
            logger.info(f"Cleaned up {file_count} uploaded files")

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Multi-Agent RAG System",
        "version": "1.0.0"
    }

@app.get("/health")
async def health_check():
    """Detailed health check"""
    try:
        # Test MongoDB connection
        mongo_client.admin.command('ping')
        mongo_status = "connected"
    except Exception as e:
        mongo_status = f"error: {str(e)}"
    
    return {
        "status": "healthy",
        "mongodb": mongo_status,
        "vectorstore": "initialized" if vectorstore else "not initialized",
        "agents": "ready"
    }

@app.post("/uploadfile/")
async def process_file(file: UploadFile = File(...)):
    """
    Upload a file for processing.
    
    Supported formats: PDF, JPG, JPEG, PNG, MP3, WAV
    """
    try:
        logger.info(f"Received file upload: {file.filename}")
        
        # Validate file type
        ext = await validate_file_type(file)
        
        # Create safe file path
        file_path = safe_file_path(file.filename)
        
        # Create uploads directory
        os.makedirs("uploads", exist_ok=True)
        
        # Check file size
        content = await file.read()
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=400, 
                detail=f"File too large. Maximum size: {MAX_FILE_SIZE // (1024*1024)}MB"
            )
        
        # Write file
        with open(file_path, "wb") as buffer:
            buffer.write(content)
        
        logger.info(f" Saved file: {file.filename} ({len(content)} bytes)")
        
        return {
            "message": f"{file.filename} uploaded successfully",
            "filename": file.filename,
            "file_type": ext,
            "size_bytes": len(content)
        }

    except HTTPException:
        raise
    except Exception as e:
        tb = traceback.format_exc()
        logger.error(f"Upload failed: {tb}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")
    
def clean_llm_response(content: str) -> str:
    
    return content

@app.post("/query/")
async def query_agents(request: Dict[str, str]):
    question = request.get("question")
    filename = request.get("filename")
    file_type = request.get("file_type")

    ext = filename.split('.')[-1].lower()
    if file_type not in ["pdf", "jpg", "jpeg", "png", "mp3", "wav"]:
        file_type = ext
    elif file_type != ext:
        logger.warning(f"File type mismatch: got {file_type}, actual {ext}. Using {ext}.")
        file_type = ext

    if not question or not filename or not file_type:
        raise HTTPException(
            status_code=400, 
            detail="Missing required fields: question, filename, or file_type"
        )

    try:
        file_path = safe_file_path(filename)
        
        if not file_path.exists():
            raise HTTPException(
                status_code=404, 
                detail=f"File '{filename}' not found. Please upload it first."
            )

        logger.info(f"Processing query for {filename}: {question[:100]}...")

        # ==================== STEP 1: PROCESS FILE ====================
        try:
            if file_type in ["jpg", "jpeg", "png"]:
                file_processing_message = await analyze_image_locally(str(file_path))
            elif file_type == "pdf":
                file_processing_message = await process_pdf_locally(str(file_path))
            elif file_type in ["mp3", "wav"]:
                file_processing_message = await transcribe_audio_locally(str(file_path))
            else:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Unsupported file type: {file_type}"
                )
        except Exception as e:
            logger.error(f"File processing failed: {e}")
            raise HTTPException(
                status_code=500, 
                detail=f"File processing failed: {str(e)}"
            )

        logger.info(f"✓ File processing complete: {file_processing_message.content[:100]}...")

        # ==================== STEP 2: QUERY DIRECTLY ====================
        try:
            logger.info(f"🔍 Calling answer_question_from_db directly...")
            
            # CALL QA FUNCTION DIRECTLY - NO AUTOGEN WRAPPER
            answer_message = await asyncio.wait_for(
                answer_question_from_db(question=question, filename=filename),
                timeout=60.0
            )
            
            # Extract answer
            if hasattr(answer_message, "content"):
                answer = answer_message.content
            else:
                answer = str(answer_message)

            logger.info(f"✓ Query completed for {filename}")
            logger.info(f"   Answer length: {len(answer)} chars")
            logger.info(f"   Answer preview: {answer[:150]}...")

            return {"answer": answer}

        except asyncio.TimeoutError:
            logger.error("Query timeout")
            raise HTTPException(
                status_code=504, 
                detail="Request timeout - processing took too long (>60s)"
            )

    except HTTPException:
        raise
    except Exception as e:
        tb = traceback.format_exc()
        logger.error(f"Query failed:\n{tb}")
        raise HTTPException(
            status_code=500, 
            detail=f"Query processing failed: {str(e)}"
        )

@app.delete("/cleanup/{filename}")
async def cleanup_file(filename: str):
    """Delete an uploaded file"""
    try:
        file_path = safe_file_path(filename)
        
        if not file_path.exists():
            raise HTTPException(status_code=404, detail=f"File '{filename}' not found")
        
        file_path.unlink()
        logger.info(f"Deleted file: {filename}")
        
        return {"message": f"Successfully deleted {filename}"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        raise HTTPException(status_code=500, detail=f"Cleanup failed: {str(e)}")

# ============================================================================
# SERVER STARTUP
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    
    logger.info(f"Starting server on {host}:{port}")
    
    uvicorn.run(
        app, 
        host=host, 
        port=port,
        log_level="info"
    )