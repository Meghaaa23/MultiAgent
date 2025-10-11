import asyncio
from autogen_agentchat.messages import TextMessage, BaseMessage
from langchain_core.documents import Document
from PIL import Image
import os
import pytesseract
import re
import logging
from transformers import pipeline

logger = logging.getLogger(__name__)

vectorstore = None

def set_image_vectorstore(vs):
    global vectorstore
    vectorstore = vs

# Initialize pipeline once globally
try:
    image_to_text_pipe = pipeline("image-to-text", model="Salesforce/blip-image-captioning-large")
except Exception as e:
    logger.error(f"Failed to initialize image-to-text pipeline: {e}")
    image_to_text_pipe = None

async def analyze_image_locally(image_file_path: str) -> BaseMessage:
    if vectorstore is None:
        raise ValueError("Vectorstore is not set. Please call set_image_vectorstore before processing.")

    logger.info(f"Vectorstore initialized: {vectorstore}")

    if not os.path.exists(image_file_path):
        return TextMessage(content=f"Error: Image file not found at '{image_file_path}'.", source="analyze_image_locally")

    analysis_results = ""

    try:
        image = await asyncio.to_thread(Image.open, image_file_path)
        extracted_text = await asyncio.to_thread(pytesseract.image_to_string, image)
        if extracted_text.strip():
            cleaned_text = re.sub(r'\s+', ' ', extracted_text.strip())
            analysis_results += f"Extracted text from image: {cleaned_text}\n"
    except Exception as e:
        logger.error(f"Failed to extract text from image: {e}")
        analysis_results += f"Failed to extract text from image: {e}\n"

    if image_to_text_pipe:
        try:
            description_result = await asyncio.to_thread(image_to_text_pipe, image)
            description = description_result[0]['generated_text']
            analysis_results += f"Image description: {description}"
        except Exception as e:
            logger.error(f"Failed to generate image description: {e}")
            analysis_results += f"Failed to generate image description: {e}"
    else:
        logger.warning("Image-to-text pipeline not available, skipping image description.")

    # Add to vectorstore in thread to avoid blocking
    await asyncio.to_thread(vectorstore.add_documents, [
        Document(page_content=analysis_results, metadata={"filename": os.path.basename(image_file_path)})
    ])

    return TextMessage(
        content=f"Image analysis complete. The content has been added to the vector database. Results: {analysis_results[:200]}...",
        source="analyze_image_locally"
    )
