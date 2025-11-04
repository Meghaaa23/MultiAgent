# agents/audio_agent.py

import os
import asyncio
import logging
import speech_recognition as sr
from langchain_core.documents import Document
from autogen_agentchat.messages import TextMessage
from .data_ingestion import ingest_text_with_chunking
from .redis_manager import set_agent_state, publish_event

logger = logging.getLogger(__name__)
vectorstore = None

def set_vectorstore(vs):
    global vectorstore
    vectorstore = vs

async def transcribe_audio_locally(audio_file_path: str) -> TextMessage:
    if vectorstore is None:
        raise ValueError("Vectorstore is not set. Please call set_vectorstore before processing.")

    if not os.path.exists(audio_file_path):
        return TextMessage(content=f"Error: Audio file not found at '{audio_file_path}'.", source="transcribe_audio_locally")

    transcript = ""
    try:
        r = sr.Recognizer()
        with sr.AudioFile(audio_file_path) as source:
            audio_data = await asyncio.to_thread(r.record, source)
        transcript = await asyncio.to_thread(r.recognize_google, audio_data)

        # Ingest with chunking
        return await ingest_text_with_chunking(audio_file_path, transcript)

    except Exception as e:
        logger.error(f"Failed to transcribe audio: {e}")
        return TextMessage(
            content=f"Audio transcription failed: {e}",
            source="transcribe_audio_locally"
        )
