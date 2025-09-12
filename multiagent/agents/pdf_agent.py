import os
import autogen
from azure.ai.documentintelligence import DocumentIntelligenceClient
from azure.ai.documentintelligence.models import AnalyzeResult
from azure.core.credentials import AzureKeyCredential

def get_document_client():
    endpoint = os.getenv("AZURE_AI_DOCUMENT_INTELLIGENCE_ENDPOINT")
    key = os.getenv("AZURE_AI_DOCUMENT_INTELLIGENCE_KEY")
    if not endpoint or not key:
        raise ValueError("Document Intelligence endpoint or key not set in environment variables.")
    return DocumentIntelligenceClient(endpoint=endpoint, credential=AzureKeyCredential(key))

def process_pdf_document(file_path: str) -> str:
    """Processes a PDF document and extracts text and tables."""
    client = get_document_client()
    with open(file_path, "rb") as file_stream:
        poller = client.begin_analyze_document(
            "prebuilt-layout",
            file_stream,
            content_type="application/octet-stream",
        )
    result: AnalyzeResult = poller.result()
    
    extracted_text = result.content
    
    tables_summary = ""
    if result.tables:
        tables_summary = f"\nFound {len(result.tables)} tables.\n"

    print(f"PDF Agent: Processed {file_path}")
    # This line has been changed to return the full text.
    return f"PDF processed successfully. The document contains the following text: {extracted_text}. {tables_summary}"

# Rest of the file remains the same...
pdf_agent = autogen.UserProxyAgent(
    name="PDF_Agent",
    human_input_mode="NEVER",
    is_termination_msg=lambda x: "TERMINATE" in x.get("content", "").upper(),
    llm_config=False,
    code_execution_config={"work_dir": "pdfs"}
)
pdf_agent.register_function(
    function_map={
        "process_pdf_document": process_pdf_document
    }
)