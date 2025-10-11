
import os
import shutil
import asyncio
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from typing import Dict
from pymongo import MongoClient
from langchain_community.vectorstores import MongoDBAtlasVectorSearch
from langchain_community.embeddings import SentenceTransformerEmbeddings
from langchain_core.documents import Document
import logging
import traceback
from autogen_agentchat import messages

from openai import AzureOpenAI

from autogen_agentchat.agents import AssistantAgent, UserProxyAgent
from autogen_agentchat.messages import TextMessage, BaseMessage
from autogen_core import CancellationToken
from autogen_core.models import CreateResult, RequestUsage
from enum import Enum, auto

class FinishReason(str, Enum):
    STOP = "stop"
    LENGTH = "length"
    TOOL_CALLS = "tool_calls"
    ERROR = "error"
    OTHER = "other"
    
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
if not endpoint.endswith("/"):
    endpoint += "/"

deployment_name = "MultiAgentLLM"
api_version = "2024-12-01-preview"
subscription_key = os.environ.get("AZURE_OPENAI_API_KEY")

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

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

mongo_client = MongoClient(os.getenv("MONGODB_ATLAS_URI"))
collection = mongo_client["multiagent"]["document_vectors"]
vectorstore = MongoDBAtlasVectorSearch(
    collection=collection,
    embedding=SentenceTransformerEmbeddings(model_name="all-MiniLM-L6-v2"),
    index_name="vector_index"
)

from agents.audio_agent import transcribe_audio_locally, set_vectorstore
from agents.image_agent import analyze_image_locally, set_image_vectorstore
from agents.pdf_agent import set_vectorstore, process_pdf_locally
from agents.qa_agent import set_vectorstore, set_config, answer_question_from_db

set_image_vectorstore(vectorstore)
set_vectorstore(vectorstore)
set_config(config_list)

model_info = {
    "name": deployment_name,
    "max_tokens": 8192,
    "context_length": 8192,
    "vision": True,
    "supports_chat": True,
    "function_calling": True,
    "json_output": False,
    "family": "azure"
}

def message_to_openai_format(message):
    from autogen_agentchat.messages import TextMessage, UserMessage

    if isinstance(message, UserMessage) or isinstance(message, TextMessage):
        return {"role": "user", "content": message.content}
    else:
        return {"role": "system", "content": getattr(message, "content", "")}

def extract_content_from_response(response):
    try:
        return response.choices[0].message.content
    except (AttributeError, IndexError):
        return None

class AzureOpenAIChatCompletionClient:
    def __init__(self, client, deployment_name):
        self.client = client
        self.deployment_name = deployment_name
        self.model_info = model_info

    async def create(self, messages, max_tokens=8192, temperature=1.0, top_p=1.0, stream=False, **kwargs):
        import asyncio

        api_messages = [message_to_openai_format(m) for m in messages]
        
        autogen_tools = kwargs.get("tools", [])
        
        api_kwargs = {}
        if autogen_tools:
            functions_list = [t.to_openai_tool() for t in autogen_tools if hasattr(t, "to_openai_tool")]

            if functions_list:
                api_kwargs["tools"] = functions_list
            

        logger.debug(f"Formatted messages for API: {api_messages}")

        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.client.chat.completions.create(
                    model=self.deployment_name,
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
                    content="AzureOpenAI returned no choices.", 
                    usage=None, 
                    is_error=True,
                    finish_reason=FinishReason.ERROR, 
                    cached=False
                )

            choice = response.choices[0]
            message = choice.message
            
            usage_data = getattr(response, "usage", None)
            usage = RequestUsage(
                prompt_tokens=getattr(usage_data, "prompt_tokens", 0),
                completion_tokens=getattr(usage_data, "completion_tokens", 0)
            ) if usage_data else None

            function_calls = []
            if getattr(message, "tool_calls", None):
                for tc in message.tool_calls:
                    function_calls.append(messages.FunctionCall(
                        id=tc.id, 
                        name=tc.function.name,
                        arguments=tc.function.arguments,
                    ))

            content = message.content
            
            if function_calls:
                finish_reason = FinishReason.TOOL_CALLS
                content = function_calls
            elif choice.finish_reason == "stop":
                finish_reason = FinishReason.STOP
            elif choice.finish_reason == "length":
                finish_reason = FinishReason.LENGTH
            else:
                finish_reason = FinishReason.OTHER

            return CreateResult(
                content=content, 
                usage=usage,
                thought=None, 
                is_error=False,
                finish_reason=finish_reason, 
                cached=False 
            )


        except Exception as e:
            logger.exception("Exception in AzureOpenAIChatCompletionClient.create")
            return CreateResult(
                content=f"Error calling AzureOpenAI: {str(e)}", 
                usage=None, 
                is_error=True,
                finish_reason=FinishReason.ERROR,
                cached=False 
            )

    async def create_stream(self, messages, **kwargs):
        raise NotImplementedError("Streaming is not implemented for this custom client.")
    
    async def __call__(self, *args, **kwargs):
        import warnings
        warnings.warn("Custom AzureOpenAIChatCompletionClient is using __call__ which is usually unnecessary. Using .create() instead.", UserWarning)
        async for result in self.create_stream(*args, **kwargs):
            yield result


model_client = AzureOpenAIChatCompletionClient(client, deployment_name)

assistant = AssistantAgent(
    name="powerful_assistant",
    system_message="""You are a powerful multi-modal assistant. You can process PDF, image, and audio files, and answer questions based on their content. You have access to specialized tools for each task.

    Your workflow is as follows:
    1. A user provides a file and a question.
    2. Identify the file type (PDF, image, or audio) and use the correct tool to process the file and add its content to the vector database.
    3. Once the content is in the database, use the 'answer_question_from_db' tool to find the answer to the user's question.
    4. Provide the final, concise answer to the user.
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

@app.post("/uploadfile/")
async def process_file(file: UploadFile = File(...)):
    try:
        logger.info(f"Received file: {file.filename}")
        file_path = f"uploads/{file.filename}"
        os.makedirs("uploads", exist_ok=True)

        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        ext = file.filename.split('.')[-1].lower()
        if ext not in ["pdf", "jpg", "jpeg", "png", "mp3", "wav"]:
             raise HTTPException(status_code=400, detail="Unsupported file type.")

        return {"message": f"{file.filename} saved successfully.", "filename": file.filename, "file_type": ext}

    except Exception as e:
        tb = traceback.format_exc()
        logger.error(f"Exception in /uploadfile/: {tb}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.post("/query/")
async def query_agents(request: Dict[str, str]):
    question = request.get("question")
    filename = request.get("filename")
    file_type = request.get("file_type")

    if not question or not filename or not file_type:
        raise HTTPException(status_code=400, detail="Missing question, filename, or file_type.")

    file_path = f"uploads/{filename}"

    try:
        if file_type in ["jpg", "jpeg", "png"]:
            file_processing_message = await analyze_image_locally(file_path)
        elif file_type == "pdf":
            file_processing_message = await process_pdf_locally(file_path)
        elif file_type in ["mp3", "wav"]:
            file_processing_message = await transcribe_audio_locally(file_path)
        else:
            raise HTTPException(status_code=400, detail="Unsupported file type.")

        response_message = await assistant.on_messages(
            messages=[
                file_processing_message,
                TextMessage(content=question, source=user_proxy.name)
            ],
            cancellation_token=CancellationToken()
        )
        if hasattr(response_message, "chat_message") and hasattr(response_message.chat_message, "content"):
            return {"answer": response_message.chat_message.content}
        return {"answer": str(response_message)}


    except Exception as e:
        tb = traceback.format_exc()
        logger.error(f"Exception in query_agents:\n{tb}")
        raise HTTPException(status_code=500, detail=f"Internal Server Error:\n{str(e)}\n\nTraceback:\n{tb}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)