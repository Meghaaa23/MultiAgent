# agents/audio_agent.py
"""
Audio Agent - Transcribes audio files using Google Speech Recognition
Supports: WAV, MP3
"""
import os
import asyncio
import logging
import speech_recognition as sr
from langchain_core.documents import Document
from autogen_agentchat.messages import TextMessage
from .data_ingestion import ingest_text_with_chunking
from .redis_manager import set_agent_state, publish_event, cache_result, get_cached_result

logger = logging.getLogger(__name__)

vectorstore = None

def set_vectorstore(vs):
    """Set the shared vectorstore for audio agent"""
    global vectorstore
    vectorstore = vs
    logger.info("Audio agent vectorstore initialized")

async def transcribe_audio_locally(audio_file_path: str) -> TextMessage:
    """
    Transcribe audio file to text using Google Speech Recognition.
    
    Args:
        audio_file_path: Path to audio file (WAV or MP3 format)
    
    Returns:
        TextMessage containing transcription or error message
    
    Note:
        - Caches results in Redis for 1 hour
        - Automatically ingests transcription into vector database
    """
    agent_name = "audio_agent"
    
    # Check cache first
    cached = get_cached_result(f"audio:{audio_file_path}")
    if cached:
        logger.info(f"Using cached transcript for {audio_file_path}")
        print(f" Cached transcription loaded ({len(cached)} characters)")
        # Ingest the cached transcript so RAG can retrieve it
        return await ingest_text_with_chunking(audio_file_path, cached)
    
    # Update agent state
    set_agent_state(agent_name, {"status": "running", "file": audio_file_path})
    publish_event("agent_updates", f"{agent_name} started processing {audio_file_path}")
    
    # Validate file exists
    if not os.path.exists(audio_file_path):
        msg = f"Error: Audio file not found at '{audio_file_path}'"
        logger.error(msg)
        set_agent_state(agent_name, {"status": "error", "error": msg})
        return TextMessage(content=msg, source=agent_name)
    
    try:
        # Initialize recognizer
        r = sr.Recognizer()
        
        # Load and process audio file
        with sr.AudioFile(audio_file_path) as source:
            logger.info(f"Loading audio from {audio_file_path}")
            audio_data = await asyncio.to_thread(r.record, source)
            
            logger.info("Transcribing audio with Google Speech Recognition...")
            transcript = await asyncio.to_thread(r.recognize_google, audio_data)
        
        logger.info(f" Transcribed {len(transcript)} characters from {os.path.basename(audio_file_path)}")
        print(f" Audio transcription complete: {len(transcript)} characters")
        
        # Cache the result
        cache_result(f"audio:{audio_file_path}", transcript)
        
        # Update state
        set_agent_state(agent_name, {"status": "completed", "file": audio_file_path})
        publish_event("agent_updates", f"{agent_name} completed {audio_file_path}")
        
        # Ingest into vector database
        return await ingest_text_with_chunking(audio_file_path, transcript)
    
    except sr.UnknownValueError:
        error_msg = "Speech recognition could not understand the audio"
        logger.warning(f"{error_msg}: {audio_file_path}")
        set_agent_state(agent_name, {"status": "error", "error": error_msg})
        publish_event("agent_updates", f"{agent_name} failed: {error_msg}")
        return TextMessage(content=error_msg, source=agent_name)
    
    except sr.RequestError as e:
        error_msg = f"Could not request results from Google Speech Recognition service: {e}"
        logger.error(error_msg)
        set_agent_state(agent_name, {"status": "error", "error": str(e)})
        publish_event("agent_updates", f"{agent_name} failed: {e}")
        return TextMessage(content=error_msg, source=agent_name)
    
    except Exception as e:
        error_msg = f"Audio transcription failed: {e}"
        logger.error(f"{error_msg} for {audio_file_path}", exc_info=True)
        set_agent_state(agent_name, {"status": "error", "error": str(e)})
        publish_event("agent_updates", f"{agent_name} failed: {e}")
        return TextMessage(content=error_msg, source=agent_name)