import os
import autogen
import azure.cognitiveservices.speech as speechsdk

def get_speech_recognizer():
    speech_key = os.getenv("AZURE_AI_SPEECH_KEY")
    speech_region = os.getenv("AZURE_AI_SPEECH_ENDPOINT").split(".")[1]
    if not speech_key or not speech_region:
        raise ValueError("Speech key or region not set in environment variables.")
    
    speech_config = speechsdk.SpeechConfig(subscription=speech_key, region=speech_region)
    return speech_config

def transcribe_audio_file(audio_file_path: str) -> str:
    """Transcribes an audio file using Azure AI Speech."""
    speech_config = get_speech_recognizer()
    
    if not os.path.exists(audio_file_path):
        return "Error: Audio file not found."
    
    audio_config = speechsdk.audio.AudioConfig(filename=audio_file_path)
    
    recognizer = speechsdk.SpeechRecognizer(
        speech_config=speech_config, 
        audio_config=audio_config
    )
    
    result = recognizer.recognize_once_async().get()
    
    if result.reason == speechsdk.ResultReason.RecognizedSpeech:
        print(f"Audio Agent: Transcribed {audio_file_path}")
        return f"Audio transcription: {result.text}"
    elif result.reason == speechsdk.ResultReason.NoMatch:
        return "Audio transcription failed: No speech could be recognized."
    elif result.reason == speechsdk.ResultReason.Canceled:
        cancellation_details = result.cancellation_details
        return f"Audio transcription canceled. Reason: {cancellation_details.reason}. Error: {cancellation_details.error_details}"
    
    return "An unknown error occurred during transcription."

audio_agent = autogen.UserProxyAgent(
    name="Audio_Agent",
    human_input_mode="NEVER",
    is_termination_msg=lambda x: "TERMINATE" in x.get("content", "").upper(),
    llm_config=False,
    code_execution_config={"work_dir": "audio"}
)
audio_agent.register_function(
    function_map={
        "transcribe_audio_file": transcribe_audio_file
    }
)