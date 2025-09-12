import os
import uvicorn
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from typing import Dict
import shutil

load_dotenv()

from agents.audio_agent import transcribe_audio_file
from agents.image_agent import analyze_image_with_vision
from agents.pdf_agent import process_pdf_document

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/uploadfile/")
async def process_file(file: UploadFile = File(...)):
    """
    Receives a file from the UI, saves it, and directly processes it
    using the appropriate specialized function.
    """
    try:
        file_path = f"uploads/{file.filename}"
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        file_extension = file.filename.split('.')[-1].lower()
        result_message = ""

        if file_extension in ["pdf"]:
            result_message = process_pdf_document(file_path)
        elif file_extension in ["jpg", "jpeg", "png"]:
            result_message = analyze_image_with_vision(image_file_path=file_path)
        elif file_extension in ["mp3", "wav"]:
            result_message = transcribe_audio_file(audio_file_path=file_path)
        else:
            raise HTTPException(status_code=400, detail="Unsupported file type.")
            
        return {"message": result_message}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/chat/")
async def chat_with_agents(message: Dict[str, str]):
    try:
        user_message = message.get("message")
        if not user_message:
            raise HTTPException(status_code=400, detail="Message cannot be empty.")
            
        response = f"I'm sorry, I can only process files. I can't answer questions about them yet."

        return {"message": response}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)