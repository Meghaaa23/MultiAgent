import os
import autogen
from azure.ai.vision.imageanalysis import ImageAnalysisClient
from azure.ai.vision.imageanalysis.models import VisualFeatures
from azure.core.credentials import AzureKeyCredential

def get_vision_client():
    endpoint = os.getenv("AZURE_AI_VISION_ENDPOINT")
    key = os.getenv("AZURE_AI_VISION_KEY")
    if not endpoint or not key:
        raise ValueError("Vision endpoint or key not set in environment variables.")
    return ImageAnalysisClient(endpoint=endpoint, credential=AzureKeyCredential(key))

def analyze_image_with_vision(image_file_path: str) -> str:
    """Analyzes an image using Azure AI Vision for text and descriptions."""
    client = get_vision_client()
    
    with open(image_file_path, "rb") as file_stream:
        result = client.analyze(
            image_data=file_stream,
            visual_features=[VisualFeatures.DENSE_CAPTIONS, VisualFeatures.READ],
        )
    
    analysis_results = ""
    if result.read and result.read.blocks:
        extracted_text = " ".join([block.lines[0].text for block in result.read.blocks])
        analysis_results += f"Extracted text from image: {extracted_text}\n"
    
    if result.dense_captions and result.dense_captions.list:
        description = result.dense_captions.list[0].text
        analysis_results += f"Image description: {description}"
    
    print(f"Image Agent: Processed {image_file_path}")
    return analysis_results

image_agent = autogen.UserProxyAgent(
    name="Image_Agent",
    human_input_mode="NEVER",
    is_termination_msg=lambda x: "TERMINATE" in x.get("content", "").upper(),
    llm_config=False,
    code_execution_config={"work_dir": "images"}
)
image_agent.register_function(
    function_map={
        "analyze_image_with_vision": analyze_image_with_vision
    }
)