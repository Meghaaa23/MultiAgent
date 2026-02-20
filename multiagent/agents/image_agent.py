# agents/image_agent.py
import asyncio
import os
from autogen_agentchat.messages import TextMessage, BaseMessage
from PIL import Image
import pytesseract
import re
import logging
from transformers import pipeline
from .data_ingestion import ingest_text_with_chunking
from .redis_manager import set_agent_state, publish_event, cache_result, get_cached_result

logger = logging.getLogger(__name__)

vectorstore = None

def set_image_vectorstore(vs):
    global vectorstore
    vectorstore = vs
    logger.info("Image agent vectorstore initialized")

_image_to_text_pipe = None

def get_image_pipeline():
    global _image_to_text_pipe
    if _image_to_text_pipe is None:
        try:
            logger.info("Loading BLIP image captioning model...")
            _image_to_text_pipe = pipeline(
                "image-to-text", 
                model="Salesforce/blip-image-captioning-large"
            )
            logger.info(" Image captioning model loaded successfully")
        except Exception as e:
            logger.error(f"Failed to initialize image-to-text pipeline: {e}")
            _image_to_text_pipe = False
    return _image_to_text_pipe if _image_to_text_pipe is not False else None

async def analyze_image_locally(image_file_path: str) -> BaseMessage:
    agent_name = "image_agent"
    
    cached = get_cached_result(f"image:{image_file_path}")  
    if cached:
        logger.info(f"Using cached analysis for {image_file_path}")
        print(f" Cached image analysis loaded ({len(cached)} characters)")
        return await ingest_text_with_chunking(image_file_path, cached)
    
    set_agent_state(agent_name, {"status": "running", "file": image_file_path})
    publish_event("agent_updates", f"{agent_name} started {image_file_path}")
    
    if not os.path.exists(image_file_path):
        msg = f"Error: Image file not found at '{image_file_path}'"
        logger.error(msg)
        set_agent_state(agent_name, {"status": "error", "error": msg})
        return TextMessage(content=msg, source=agent_name)
    
    analysis_results = ""
    
    try:
        logger.info(f"Opening image: {image_file_path}")
        image = await asyncio.to_thread(Image.open, image_file_path)
        
        logger.info("Extracting text with OCR...")
        extracted_text = await asyncio.to_thread(pytesseract.image_to_string, image)
        
        if extracted_text.strip():
            cleaned_text = re.sub(r'\s+', ' ', extracted_text.strip())
            analysis_results += f"Text from image: {cleaned_text}\n"
            logger.info(f" OCR extracted {len(cleaned_text)} characters")
        else:
            analysis_results += "No clear text detected via OCR. "
            logger.info("No text found via OCR")
    
    except Exception as e:
        error_msg = f"OCR failed: {e}"
        logger.error(f"{error_msg} for {image_file_path}")
        analysis_results += f"{error_msg}. "
    
    # Image captioning
    image_to_text_pipe = get_image_pipeline()
    
    if image_to_text_pipe:
        try:
            logger.info("Generating image caption with BLIP model...")
            result = await asyncio.to_thread(image_to_text_pipe, image)
            description = result[0]['generated_text']
            analysis_results += f"Image shows: {description}"
            logger.info(f" Generated caption: {description}")
        except Exception as e:
            error_msg = f"Image captioning failed: {e}"
            logger.error(f"{error_msg} for {image_file_path}")
            analysis_results += error_msg
    else:
        analysis_results += "Image caption model unavailable."
    
    # FIXED: If still empty, add something useful
    if not analysis_results.strip():
        analysis_results = f"Image file: {os.path.basename(image_file_path)}. Unable to extract text or generate description."
    
    logger.info(f" Image analysis complete for {os.path.basename(image_file_path)}")
    
    cache_result(f"image:{image_file_path}", analysis_results)
    
    set_agent_state(agent_name, {"status": "completed", "file": image_file_path})
    publish_event("agent_updates", f"{agent_name} completed {image_file_path}")
    
    return await ingest_text_with_chunking(image_file_path, analysis_results)